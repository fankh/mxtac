"""
Syslog connector — generic UDP syslog receiver (Feature 6.22).

Listens on a UDP socket for incoming RFC 3164 / RFC 5424 syslog messages.
Each received datagram is parsed and published to the ``mxtac.raw.syslog``
queue topic.

Unlike poll-based connectors, this connector is event-driven: the asyncio
datagram protocol fires on each incoming packet.  The ``_poll_loop()`` is
overridden to simply wait for the stop signal rather than periodically
calling ``_fetch_events()``.

Required config.extra keys:  (all optional — defaults shown)
  host:             str  — bind address (default "0.0.0.0")
  port:             int  — UDP port (default 514)
  max_message_size: int  — maximum accepted datagram size in bytes
                          (default 65535); oversized datagrams are dropped.

Parsed event fields:
  _source        "syslog"
  host           sender IP address
  port           sender UDP port number
  raw            raw syslog string (decoded UTF-8, errors replaced)
  facility       int — syslog facility code (0-23), or None if unparsed
  severity       int — syslog severity code (0-7), or None if unparsed
  facility_name  str — e.g. "kern", "user", "daemon", "local0", …
  severity_name  str — e.g. "emergency", "alert", "critical", "error", …
  timestamp      str — parsed ISO 8601 timestamp, or current UTC time
  hostname       str | None — hostname declared in the syslog header
  app_name       str | None — process/application name (tag in RFC 3164,
                              APP-NAME in RFC 5424)
  process_id     str | None — PID string, or None
  message        str — the syslog message body
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from ..core.logging import get_logger
from ..pipeline.queue import Topic
from .base import BaseConnector, ConnectorConfig, ConnectorStatus

logger = get_logger(__name__)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 514
DEFAULT_MAX_MESSAGE_SIZE = 65535

# ── Facility / Severity lookup tables ────────────────────────────────────────

FACILITY_NAMES: tuple[str, ...] = (
    "kern", "user", "mail", "daemon", "auth", "syslog",
    "lpr", "news", "uucp", "cron", "authpriv", "ftp",
    "reserved12", "reserved13", "reserved14", "reserved15",
    "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
)

SEVERITY_NAMES: tuple[str, ...] = (
    "emergency", "alert", "critical", "error",
    "warning", "notice", "informational", "debug",
)

# ── Regex patterns ─────────────────────────────────────────────────────────────

# Extract the PRI field (<digits>) from the beginning of any syslog message.
_PRI_RE = re.compile(r"^<(\d{1,3})>")

# RFC 3164 timestamp: "Mon DD HH:MM:SS" (month name + day + time)
_RFC3164_TS_RE = re.compile(
    r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)",
)

# RFC 3164 tag field: TAG[PID]: or TAG:
_RFC3164_TAG_RE = re.compile(
    r"([^\[\s:]+)(?:\[(\d+)\])?:\s*",
)


# ── Module-level helpers ───────────────────────────────────────────────────────


def _fill_priority(event: dict[str, Any], pri: int) -> None:
    """Decode a syslog PRI value into facility and severity fields (in-place)."""
    facility = pri >> 3
    severity = pri & 7
    event["facility"] = facility
    event["severity"] = severity
    event["facility_name"] = (
        FACILITY_NAMES[facility] if 0 <= facility < len(FACILITY_NAMES)
        else f"facility{facility}"
    )
    event["severity_name"] = (
        SEVERITY_NAMES[severity] if 0 <= severity < len(SEVERITY_NAMES)
        else f"severity{severity}"
    )


def _extract_msg_from_sd(sd_and_msg: str) -> str:
    """Extract the MSG portion from the combined SD+MSG field of an RFC 5424 message.

    The SD field is either the nil value ``-`` or one-or-more structured-data
    elements enclosed in ``[...]``.  Everything after the SD field is the MSG.
    """
    if not sd_and_msg:
        return ""
    if sd_and_msg.startswith("-"):
        # Nil SD — rest (after the "-") is the message
        return sd_and_msg[1:].lstrip()
    if sd_and_msg.startswith("["):
        # Consume all SD elements [ID PARAM=VALUE …]
        i = 0
        while i < len(sd_and_msg) and sd_and_msg[i] == "[":
            i += 1  # skip opening "["
            while i < len(sd_and_msg) and sd_and_msg[i] != "]":
                if sd_and_msg[i] == "\\":
                    i += 1  # skip escaped character
                i += 1
            if i < len(sd_and_msg):
                i += 1  # skip closing "]"
            # Skip a single space between consecutive SD elements
            if i < len(sd_and_msg) and sd_and_msg[i] == " " and (i + 1) < len(sd_and_msg) and sd_and_msg[i + 1] == "[":
                i += 1
        return sd_and_msg[i:].lstrip()
    # Unknown / unparseable SD — return as-is
    return sd_and_msg


# ── asyncio datagram protocol ─────────────────────────────────────────────────


class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol that forwards received packets to the connector."""

    def __init__(self, connector: "SyslogUDPConnector") -> None:
        self._connector = connector

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        max_size = self._connector._max_message_size
        if len(data) > max_size:
            logger.warning(
                "SyslogUDPConnector dropping oversized datagram size=%d max=%d src=%s",
                len(data),
                max_size,
                addr[0],
            )
            return
        asyncio.create_task(self._connector._handle_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.warning("SyslogUDPConnector UDP socket error: %s", exc)
        self._connector.health.errors_total += 1

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.error("SyslogUDPConnector UDP connection lost: %s", exc)


# ── Connector ─────────────────────────────────────────────────────────────────


class SyslogUDPConnector(BaseConnector):
    """UDP syslog receiver — listens for RFC 3164 / RFC 5424 messages on a UDP socket.

    Unlike poll-based connectors, events arrive asynchronously via the asyncio
    datagram protocol.  ``_poll_loop()`` is overridden to idle until stop is
    requested; all event processing occurs in ``_handle_datagram()``.
    """

    def __init__(
        self,
        config: ConnectorConfig,
        queue,
        *,
        status_callback: Callable[[str, str | None], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(config, queue, status_callback=status_callback)
        self._transport: asyncio.BaseTransport | None = None
        self._protocol: _SyslogProtocol | None = None
        self._max_message_size: int = int(
            config.extra.get("max_message_size", DEFAULT_MAX_MESSAGE_SIZE)
        )

    @property
    def topic(self) -> str:
        return Topic.RAW_SYSLOG

    # ── Connection ────────────────────────────────────────────────────────────

    async def _connect(self) -> None:
        host = self.config.extra.get("host", DEFAULT_HOST)
        port = int(self.config.extra.get("port", DEFAULT_PORT))

        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self),
            local_addr=(host, port),
        )
        self._transport = transport
        self._protocol = protocol
        logger.info(
            "SyslogUDPConnector listening name=%s host=%s port=%d",
            self.config.name,
            host,
            port,
        )

    # ── Fetch events (not used — connector is event-driven) ──────────────────

    async def _fetch_events(self) -> AsyncGenerator[dict[str, Any], None]:
        """Not used: events arrive via the UDP protocol, not periodic polling."""
        return
        yield  # satisfy the abstract async-generator requirement

    # ── Poll loop override ────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        """Event-driven connector: idle until the stop signal is received."""
        try:
            await self._stop_event.wait()
        except asyncio.CancelledError:
            pass

    # ── Datagram handler ──────────────────────────────────────────────────────

    async def _handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Parse a received UDP datagram and publish the event to the queue."""
        try:
            event = self._parse_syslog(data, addr)
            await self.queue.publish(self.topic, event)
            self.health.events_total += 1
            self.health.last_event_at = datetime.now(timezone.utc)
            logger.debug(
                "SyslogUDPConnector received event src=%s severity=%s facility=%s",
                addr[0],
                event.get("severity_name"),
                event.get("facility_name"),
            )
        except Exception as exc:
            self.health.errors_total += 1
            self.health.error_message = str(exc)
            logger.error(
                "SyslogUDPConnector error handling datagram src=%s err=%s",
                addr[0],
                exc,
            )

    # ── Syslog parser ─────────────────────────────────────────────────────────

    def _parse_syslog(self, data: bytes, addr: tuple[str, int]) -> dict[str, Any]:
        """Parse a raw syslog UDP datagram into a structured event dict.

        Attempts RFC 5424 detection first (PRI followed by a version digit),
        then falls back to RFC 3164 (traditional BSD syslog).  If neither
        format is recognised the ``message`` field contains the full raw string.
        """
        raw = data.decode("utf-8", errors="replace").rstrip("\n\r\x00")

        event: dict[str, Any] = {
            "_source":      "syslog",
            "host":         addr[0],
            "port":         addr[1],
            "raw":          raw,
            "facility":     None,
            "severity":     None,
            "facility_name": None,
            "severity_name": None,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "hostname":     None,
            "app_name":     None,
            "process_id":   None,
            "message":      raw,
        }

        pri_m = _PRI_RE.match(raw)
        if not pri_m:
            return event

        pri = int(pri_m.group(1))
        _fill_priority(event, pri)
        rest = raw[pri_m.end():]

        # ── Try RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP PID MSGID SD MSG ──
        # Split into at most 8 whitespace-separated tokens.
        # Use maxsplit=6 so we get 7 tokens: version, ts, host, app, pid, msgid,
        # and a final "sd_and_msg" field that contains the SD element(s) plus MSG.
        parts = rest.split(None, 6)
        if len(parts) >= 6 and parts[0].isdigit() and int(parts[0]) >= 1:
            # parts[0]=version, [1]=ts, [2]=host, [3]=app, [4]=pid, [5]=msgid
            # parts[6]=SD+MSG remainder (or absent when the message body is empty)
            ts   = parts[1]
            host = parts[2]
            app  = parts[3]
            pid  = parts[4]
            sd_and_msg = parts[6] if len(parts) > 6 else ""

            event["timestamp"]  = ts   if ts   != "-" else event["timestamp"]
            event["hostname"]   = None if host  == "-" else host
            event["app_name"]   = None if app   == "-" else app
            event["process_id"] = None if pid   == "-" else pid
            event["message"]    = _extract_msg_from_sd(sd_and_msg)
            return event

        # ── Try RFC 3164: TIMESTAMP HOSTNAME [TAG[PID]: ]MESSAGE ──────────────
        ts_m = _RFC3164_TS_RE.match(rest)
        if ts_m:
            event["timestamp"] = ts_m.group(1)
            event["hostname"]  = ts_m.group(2)
            msg_part = rest[ts_m.end():].lstrip()

            tag_m = _RFC3164_TAG_RE.match(msg_part)
            if tag_m:
                event["app_name"]   = tag_m.group(1)
                event["process_id"] = tag_m.group(2)
                event["message"]    = msg_part[tag_m.end():]
            else:
                event["message"] = msg_part
            return event

        # ── Fallback: PRI extracted but format unrecognised ────────────────────
        event["message"] = rest
        return event

    # ── Cleanup ───────────────────────────────────────────────────────────────

    async def stop(self) -> None:
        await super().stop()
        if self._transport is not None:
            self._transport.close()
            self._transport = None
            self._protocol = None
        logger.info("SyslogUDPConnector UDP socket closed name=%s", self.config.name)


class SyslogUDPConnectorFactory:
    """Convenience factory to create a SyslogUDPConnector from a flat config dict."""

    @staticmethod
    def from_dict(d: dict[str, Any], queue) -> SyslogUDPConnector:
        config = ConnectorConfig(
            name=d.get("name", "syslog"),
            connector_type="syslog",
            enabled=d.get("enabled", True),
            poll_interval_seconds=d.get("poll_interval_seconds", 60),
            extra={
                "host":             d.get("host", DEFAULT_HOST),
                "port":             d.get("port", DEFAULT_PORT),
                "max_message_size": d.get("max_message_size", DEFAULT_MAX_MESSAGE_SIZE),
            },
        )
        return SyslogUDPConnector(config, queue)
