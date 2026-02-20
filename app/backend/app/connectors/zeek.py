"""
Zeek connector — watches Zeek log directory for new log lines.

Required config.extra keys:
  log_dir: str     — e.g. "/opt/zeek/logs/current"
  log_types: list  — e.g. ["conn", "dns", "http", "ssl"]
"""

from __future__ import annotations

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

        # Seek to end of each existing log file so we only tail new events
        log_types = self.config.extra.get("log_types", list(LOG_SUFFIXES.keys()))
        for log_type in log_types:
            filename = LOG_SUFFIXES.get(log_type)
            if not filename:
                continue
            path = Path(log_dir) / filename
            if path.exists():
                self._file_positions[str(path)] = os.path.getsize(str(path))

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
                    "ts":         parts[0],
                    "uid":        parts[1],
                    "id.orig_h":  parts[2],
                    "id.orig_p":  parts[3],
                    "id.resp_h":  parts[4],
                    "id.resp_p":  parts[5],
                    "proto":      parts[6]  if len(parts) > 6  else None,
                    "service":    parts[7]  if len(parts) > 7  else None,
                    "conn_state": parts[11] if len(parts) > 11 else None,
                }

            if log_type == "dns" and len(parts) >= 6:
                return {
                    "_log_type":  "dns",
                    "ts":         parts[0],
                    "uid":        parts[1],
                    "id.orig_h":  parts[2],
                    "id.orig_p":  parts[3],
                    "id.resp_h":  parts[4],
                    "id.resp_p":  parts[5],
                    "proto":      parts[6]  if len(parts) > 6  else None,
                    "query":      parts[9]  if len(parts) > 9  else None,
                    "qtype_name": parts[11] if len(parts) > 11 else None,
                    "rcode_name": parts[13] if len(parts) > 13 else None,
                    "answers":    parts[21].split(",") if len(parts) > 21 and parts[21] not in ("-", "") else [],
                }

            if log_type == "http" and len(parts) >= 6:
                return {
                    "_log_type":   "http",
                    "ts":          parts[0],
                    "uid":         parts[1],
                    "id.orig_h":   parts[2],
                    "id.orig_p":   parts[3],
                    "id.resp_h":   parts[4],
                    "id.resp_p":   parts[5],
                    "method":      parts[7]  if len(parts) > 7  else None,
                    "host":        parts[8]  if len(parts) > 8  else None,
                    "uri":         parts[9]  if len(parts) > 9  else None,
                    "user_agent":  parts[12] if len(parts) > 12 else None,
                    "status_code": parts[15] if len(parts) > 15 else None,
                }

            if log_type == "ssl" and len(parts) >= 6:
                return {
                    "_log_type":   "ssl",
                    "ts":          parts[0],
                    "uid":         parts[1],
                    "id.orig_h":   parts[2],
                    "id.orig_p":   parts[3],
                    "id.resp_h":   parts[4],
                    "id.resp_p":   parts[5],
                    "version":     parts[6]  if len(parts) > 6  else None,
                    "cipher":      parts[7]  if len(parts) > 7  else None,
                    "server_name": parts[9]  if len(parts) > 9  else None,
                    "established": parts[13] if len(parts) > 13 else None,
                }

            return None
        except Exception:
            return None


class ZeekConnectorFactory:
    """Factory for creating ZeekConnector instances from a flat configuration dict."""

    @staticmethod
    def from_dict(cfg: dict[str, Any], queue) -> "ZeekConnector":
        """Create a ZeekConnector from a flat configuration dict."""
        config = ConnectorConfig(
            name=cfg.get("name", "zeek"),
            connector_type="zeek",
            enabled=True,
            poll_interval_seconds=cfg.get("poll_interval_seconds", 60),
            extra={
                "log_dir":   cfg.get("log_dir", "/opt/zeek/logs/current"),
                "log_types": cfg.get("log_types", list(LOG_SUFFIXES.keys())),
            },
        )
        return ZeekConnector(config, queue)
