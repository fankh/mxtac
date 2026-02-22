"""
Zeek connector — watches Zeek log directory for new log lines.

Required config.extra keys:
  log_dir: str     — e.g. "/opt/zeek/logs/current"
  log_types: list  — e.g. ["conn", "dns", "http", "ssl"]

Feature 6.10: Byte offsets are persisted across restarts via an optional
checkpoint_callback.  The registry supplies initial_positions (loaded from a
state file) and a callback that writes the updated dict back to disk after
every _fetch_events() cycle.

Feature 6.11: JSON-format Zeek logs are parsed via _parse_json_line() which
applies field type coercion for well-known Zeek fields:
  - ts                              → float (Unix timestamp)
  - id.orig_p, id.resp_p           → int   (port numbers)
  - orig_bytes, resp_bytes          → int   (byte counters)
  - orig_pkts, resp_pkts            → int   (packet counters)
  - missed_bytes, orig_ip_bytes,
    resp_ip_bytes                   → int   (extended counters)
  - duration                        → float (connection duration)

Feature 6.13: Every event yielded by _fetch_events() carries a ``_path``
field set to the stem of the source log file (e.g. "conn" for conn.log,
"dns" for dns.log).  The normalizer uses this field to determine which
OCSF mapping to apply.

Feature 6.14: Every parsed event is published raw and unchanged to the
``mxtac.raw.zeek`` queue topic via BaseConnector._poll_loop().  The
``topic`` property returns ``Topic.RAW_ZEEK`` so the base class routes
all events to the correct destination automatically.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
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

    def __init__(
        self,
        config: ConnectorConfig,
        queue,
        *,
        initial_positions: dict[str, int] | None = None,
        checkpoint_callback: Callable[[dict[str, int]], Awaitable[None]] | None = None,
        status_callback: Callable[[str, str | None], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(config, queue, status_callback=status_callback)
        # Seed from persisted state; defaults to empty (fresh start)
        self._file_positions: dict[str, int] = dict(initial_positions or {})
        self._checkpoint_callback = checkpoint_callback

    @property
    def topic(self) -> str:
        return Topic.RAW_ZEEK

    async def _connect(self) -> None:
        log_dir = self.config.extra.get("log_dir", "/opt/zeek/logs/current")
        if not os.path.isdir(log_dir):
            raise ConnectionError(f"Zeek log directory not found: {log_dir}")

        log_types = self.config.extra.get("log_types", list(LOG_SUFFIXES.keys()))
        for log_type in log_types:
            filename = LOG_SUFFIXES.get(log_type)
            if not filename:
                continue
            path = Path(log_dir) / filename
            path_str = str(path)

            if path_str in self._file_positions:
                # We have a persisted offset — validate it against the current
                # file size to detect log rotation.
                if path.exists():
                    current_size = path.stat().st_size
                    if self._file_positions[path_str] > current_size:
                        logger.warning(
                            "ZeekConnector log rotation detected path=%s "
                            "saved_offset=%d file_size=%d, resetting to 0",
                            path,
                            self._file_positions[path_str],
                            current_size,
                        )
                        self._file_positions[path_str] = 0
                else:
                    # Stale entry for a file that no longer exists; clear it so
                    # we start from offset 0 when the file is (re-)created.
                    del self._file_positions[path_str]
            else:
                # No persisted offset — first startup behaviour: seek to EOF so
                # we tail only *new* events (avoid re-ingesting history).
                if path.exists():
                    self._file_positions[path_str] = path.stat().st_size

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
                    # Feature 6.11: attempt structured JSON parse first
                    event = self._parse_json_line(line, log_type)
                    if event is None:
                        # TSV format — parse fields
                        event = self._parse_tsv_line(line, log_type)
                    if event:
                        # Feature 6.13: record source filename stem so the
                        # normalizer knows which OCSF mapping to apply.
                        event["_path"] = path.stem
                        yield event

                self._file_positions[str(path)] = f.tell()

        # Feature 6.10: persist updated offsets after every poll cycle so that
        # a restart resumes exactly where we left off.
        if self._checkpoint_callback is not None:
            await self._checkpoint_callback(dict(self._file_positions))

    # ── JSON parsing (Feature 6.11) ──────────────────────────────────────────

    # Fields coerced to int in all log types
    _INT_FIELDS: frozenset[str] = frozenset({
        "id.orig_p", "id.resp_p",
        "orig_bytes", "resp_bytes",
        "orig_pkts", "resp_pkts",
        "missed_bytes", "orig_ip_bytes", "resp_ip_bytes",
    })

    def _parse_json_line(self, line: str, log_type: str) -> dict[str, Any] | None:
        """Parse a Zeek JSON log line with field type coercion.

        Returns the event dict (with _log_type set and well-known fields
        coerced to their canonical Python types) or None if the line is not
        valid JSON or not a JSON object.
        """
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return None

        if not isinstance(event, dict):
            return None

        event["_log_type"] = log_type

        # ts → float (Unix timestamp)
        if "ts" in event:
            try:
                event["ts"] = float(event["ts"])
            except (ValueError, TypeError):
                pass

        # duration → float
        if "duration" in event:
            try:
                event["duration"] = float(event["duration"])
            except (ValueError, TypeError):
                pass

        # Integer counter / port fields
        for field in self._INT_FIELDS:
            if field in event:
                try:
                    event[field] = int(event[field])
                except (ValueError, TypeError):
                    pass

        return event

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
