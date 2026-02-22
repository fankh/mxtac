"""
Suricata connector — tails the EVE JSON log file.

Required config.extra keys:
  eve_file:    str       — path to eve.json (e.g. "/var/log/suricata/eve.json")

Optional config.extra keys:
  event_types: list[str] — allowlist of event_type values to ingest.
                           Default: ["alert", "dns", "http", "tls"].
                           Only events whose ``event_type`` field matches one
                           of the listed values are yielded; all others are
                           silently dropped.  An empty list blocks all events.

Feature 6.16: Filter by event_type — alert, dns, http, tls.
Feature 6.17: Track file offset across restarts.
  The connector accepts an optional ``initial_position`` (byte offset loaded
  from a state file by the registry) and a ``checkpoint_callback`` that is
  invoked with the updated offset after every _fetch_events() cycle.  On
  first startup (no persisted state) the connector seeks to EOF so only new
  events are tailed.  On restart the saved offset is restored; if the file
  has been rotated (saved offset > current file size) the offset is reset to
  0 so the new file is read from the beginning.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from typing import Any, AsyncGenerator

from ..core.logging import get_logger
from ..pipeline.queue import Topic
from .base import BaseConnector, ConnectorConfig

logger = get_logger(__name__)


class SuricataConnector(BaseConnector):
    """Tails Suricata EVE JSON log file and publishes events to mxtac.raw.suricata."""

    def __init__(
        self,
        config: ConnectorConfig,
        queue,
        *,
        initial_position: int | None = None,
        checkpoint_callback: Callable[[int], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(config, queue)
        # Feature 6.17: restore persisted offset when provided; 0 otherwise.
        self._file_position: int = initial_position if initial_position is not None else 0
        self._has_initial_position: bool = initial_position is not None
        self._checkpoint_callback = checkpoint_callback

    @property
    def topic(self) -> str:
        return Topic.RAW_SURICATA

    async def _connect(self) -> None:
        eve_file = self.config.extra.get("eve_file", "/var/log/suricata/eve.json")
        if not os.path.isfile(eve_file):
            raise ConnectionError(f"Suricata EVE file not found: {eve_file}")

        if self._has_initial_position:
            # Feature 6.17: resuming from a persisted offset — detect log rotation.
            current_size = os.path.getsize(eve_file)
            if self._file_position > current_size:
                logger.warning(
                    "SuricataConnector log rotation detected eve_file=%s "
                    "saved_offset=%d file_size=%d, resetting to 0",
                    eve_file,
                    self._file_position,
                    current_size,
                )
                self._file_position = 0
            # else: keep the restored position to resume exactly where we stopped
        else:
            # Fresh start: seek to EOF so only new events are tailed.
            self._file_position = os.path.getsize(eve_file)

        logger.info(
            "SuricataConnector connected eve_file=%s position=%d",
            eve_file,
            self._file_position,
        )

    # Feature 6.16: default allowlist of Suricata event_type values to ingest.
    DEFAULT_EVENT_TYPES: tuple[str, ...] = ("alert", "dns", "http", "tls")

    async def _fetch_events(self) -> AsyncGenerator[dict[str, Any], None]:
        eve_file = self.config.extra.get("eve_file", "/var/log/suricata/eve.json")
        # Feature 6.16: resolve the event_type allowlist once per call.
        event_types: list[str] = self.config.extra.get(
            "event_types", list(self.DEFAULT_EVENT_TYPES)
        )
        allowed: frozenset[str] = frozenset(event_types)

        if not os.path.isfile(eve_file):
            return

        with open(eve_file, "r", errors="replace") as f:
            f.seek(self._file_position)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    # Feature 6.16: drop events whose event_type is not allowed.
                    if event.get("event_type") not in allowed:
                        continue
                    yield event
                except json.JSONDecodeError:
                    continue
            self._file_position = f.tell()

        # Feature 6.17: persist updated offset after every poll cycle so that
        # a restart resumes exactly where we left off.
        if self._checkpoint_callback is not None:
            await self._checkpoint_callback(self._file_position)
