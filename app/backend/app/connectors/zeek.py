"""
Zeek connector — watches Zeek log directory for new log lines.

Required config.extra keys:
  log_dir: str     — e.g. "/opt/zeek/logs/current"
  log_types: list  — e.g. ["conn", "dns", "http", "ssl"]
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, AsyncGenerator

from ..core.logging import get_logger
from ..pipeline.queue import Topic
from .base import BaseConnector, ConnectorConfig

logger = get_logger(__name__)

LOG_SUFFIXES = {
    "conn":  "conn.log",
    "dns":   "dns.log",
    "http":  "http.log",
    "ssl":   "ssl.log",
    "files": "files.log",
}


class ZeekConnector(BaseConnector):
    """Tails Zeek log files and publishes parsed JSON to mxtac.raw.zeek."""

    def __init__(self, config: ConnectorConfig, queue) -> None:
        super().__init__(config, queue)
        self._file_positions: dict[str, int] = {}   # path → byte offset

    @property
    def topic(self) -> str:
        return Topic.RAW_ZEEK

    async def _connect(self) -> None:
        log_dir = self.config.extra.get("log_dir", "/opt/zeek/logs/current")
        if not os.path.isdir(log_dir):
            raise ConnectionError(f"Zeek log directory not found: {log_dir}")
        logger.info("ZeekConnector connected log_dir=%s", log_dir)

    async def _fetch_events(self) -> AsyncGenerator[dict[str, Any], None]:
        log_dir   = self.config.extra.get("log_dir", "/opt/zeek/logs/current")
        log_types = self.config.extra.get("log_types", list(LOG_SUFFIXES.keys()))

        for log_type in log_types:
            filename = LOG_SUFFIXES.get(log_type)
            if not filename:
                continue

            path = Path(log_dir) / filename
            if not path.exists():
                continue

            last_pos = self._file_positions.get(str(path), 0)

            with path.open("r", errors="replace") as f:
                f.seek(last_pos)
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        event = json.loads(line)
                        event["_log_type"] = log_type
                        yield event
                    except json.JSONDecodeError:
                        # TSV format — parse fields
                        event = self._parse_tsv_line(line, log_type)
                        if event:
                            yield event

                self._file_positions[str(path)] = f.tell()

    def _parse_tsv_line(self, line: str, log_type: str) -> dict[str, Any] | None:
        """Basic TSV parser for non-JSON Zeek format. Returns None on failure."""
        try:
            parts = line.split("\t")
            if log_type == "conn" and len(parts) >= 6:
                return {
                    "_log_type": "conn",
                    "ts":        parts[0],
                    "uid":       parts[1],
                    "id.orig_h": parts[2],
                    "id.orig_p": parts[3],
                    "id.resp_h": parts[4],
                    "id.resp_p": parts[5],
                    "proto":     parts[6] if len(parts) > 6 else None,
                    "service":   parts[7] if len(parts) > 7 else None,
                    "conn_state":parts[11] if len(parts) > 11 else None,
                }
            return None
        except Exception:
            return None
