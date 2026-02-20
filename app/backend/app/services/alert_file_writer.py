"""Alert file writer — appends enriched alerts as JSON Lines to a rotating file.

Each alert published to mxtac.enriched is serialised as a single JSON object
followed by a newline (JSONL / JSON Lines format).  The file rotates when it
reaches ``max_bytes``; up to ``backup_count`` rotated copies are kept.

File rotation is handled by Python's stdlib ``RotatingFileHandler`` so there
are no extra dependencies.  All blocking file operations run in the default
thread-pool executor to avoid stalling the asyncio event loop.
"""

from __future__ import annotations

import asyncio
import json
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from ..core.logging import get_logger
from ..pipeline.queue import MessageQueue, Topic

logger = get_logger(__name__)


class AlertFileWriter:
    """Writes enriched alert dicts as JSON Lines to a size-rotating file.

    Thread-safe: a ``threading.Lock`` guards all file operations so the
    asyncio executor threads cannot interleave writes or concurrent rotations.
    """

    def __init__(
        self,
        path: str | Path,
        max_bytes: int = 100 * 1024 * 1024,
        backup_count: int = 5,
    ) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handler = RotatingFileHandler(
            path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Synchronous helpers (run in thread-pool executor)
    # ------------------------------------------------------------------

    def _write_sync(self, line: str) -> None:
        with self._lock:
            self._handler.stream.write(line)
            self._handler.stream.flush()
            # Rotate if the file has reached or exceeded the size limit.
            if (
                self._handler.maxBytes > 0
                and self._handler.stream.tell() >= self._handler.maxBytes
            ):
                self._handler.doRollover()

    def _close_sync(self) -> None:
        with self._lock:
            self._handler.close()

    # ------------------------------------------------------------------
    # Public async interface
    # ------------------------------------------------------------------

    async def write(self, alert: dict[str, Any]) -> None:
        """Serialise *alert* as a JSON line and append it to the output file.

        Errors are logged and swallowed so that a write failure never
        interrupts the rest of the alert pipeline.
        """
        try:
            line = json.dumps(alert, default=str) + "\n"
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._write_sync, line)
        except Exception:
            logger.exception("AlertFileWriter write error (non-fatal)")

    async def close(self) -> None:
        """Flush and close the underlying file handle."""
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._close_sync)
        except Exception:
            logger.exception("AlertFileWriter close error")


async def alert_file_writer(
    queue: MessageQueue,
    path: str,
    max_bytes: int,
    backup_count: int,
) -> AlertFileWriter:
    """Subscribe an :class:`AlertFileWriter` to ``mxtac.enriched``.

    Returns the writer so the caller can close it during shutdown.
    """
    writer = AlertFileWriter(path, max_bytes=max_bytes, backup_count=backup_count)

    async def _handle(alert: dict[str, Any]) -> None:
        await writer.write(alert)

    await queue.subscribe(Topic.ENRICHED, "alert-file-writer", _handle)
    logger.info("Alert file writer subscribed to %s → %s", Topic.ENRICHED, path)
    return writer
