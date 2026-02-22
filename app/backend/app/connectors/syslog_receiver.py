"""
Syslog receiver service — standalone UDP/TCP syslog listener (Feature 35.4).

Extends mxtac-6.22 (SyslogUDPConnector) with:
  - Non-privileged default port 1514 (map 514→1514 in Docker)
  - TCP stream support alongside UDP datagrams
  - Protocol selection: "udp" | "tcp" | "both"
  - Config-driven lifecycle: started directly from settings in main.py
    (no database connector row required)

Parsed event fields (identical to SyslogUDPConnector):
  _source        "syslog"
  host           sender IP address
  port           sender port number
  raw            raw syslog string (decoded UTF-8, errors replaced)
  facility       int — syslog facility code (0-23), or None if unparsed
  severity       int — syslog severity code (0-7), or None if unparsed
  facility_name  str — e.g. "kern", "user", "daemon", "local0", …
  severity_name  str — e.g. "emergency", "alert", "critical", "error", …
  timestamp      str — parsed ISO 8601 timestamp, or current UTC time
  hostname       str | None — hostname declared in the syslog header
  app_name       str | None — process/application name
  process_id     str | None — PID string, or None
  message        str — the syslog message body

TCP framing: non-transparent (newline-delimited), per RFC 6587 §3.4.2.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any

from ..core.logging import get_logger
from ..pipeline.queue import Topic

logger = get_logger(__name__)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 1514
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


# ── Syslog parser helpers ─────────────────────────────────────────────────────


def _extract_msg_from_sd(sd_and_msg: str) -> str:
    """Extract the MSG portion from the combined SD+MSG field of an RFC 5424 message.

    The SD field is either the nil value ``-`` or one-or-more structured-data
    elements enclosed in ``[...]``.  Everything after the SD field is the MSG.
    """
    if not sd_and_msg:
        return ""
    if sd_and_msg.startswith("-"):
        return sd_and_msg[1:].lstrip()
    if sd_and_msg.startswith("["):
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
            if (
                i < len(sd_and_msg)
                and sd_and_msg[i] == " "
                and (i + 1) < len(sd_and_msg)
                and sd_and_msg[i + 1] == "["
            ):
                i += 1
        return sd_and_msg[i:].lstrip()
    # Unknown / unparseable SD — return as-is
    return sd_and_msg


def parse_syslog(raw: str, addr: tuple[str, int]) -> dict[str, Any]:
    """Parse a raw syslog string into a structured event dict.

    Attempts RFC 5424 detection first (PRI followed by a version digit),
    then falls back to RFC 3164 (traditional BSD syslog).  If neither
    format is recognised the ``message`` field contains the full raw string.
    """
    event: dict[str, Any] = {
        "_source":       "syslog",
        "host":          addr[0],
        "port":          addr[1],
        "raw":           raw,
        "facility":      None,
        "severity":      None,
        "facility_name": None,
        "severity_name": None,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "hostname":      None,
        "app_name":      None,
        "process_id":    None,
        "message":       raw,
    }

    pri_m = _PRI_RE.match(raw)
    if not pri_m:
        return event

    pri = int(pri_m.group(1))
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

    rest = raw[pri_m.end():]

    # ── RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP PID MSGID SD MSG ────────
    # Split into at most 7 whitespace-separated tokens.
    parts = rest.split(None, 6)
    if len(parts) >= 6 and parts[0].isdigit() and int(parts[0]) >= 1:
        # parts[0]=version, [1]=ts, [2]=host, [3]=app, [4]=pid, [5]=msgid
        # parts[6]=SD+MSG remainder (may be absent when message body is empty)
        ts         = parts[1]
        host       = parts[2]
        app        = parts[3]
        pid        = parts[4]
        sd_and_msg = parts[6] if len(parts) > 6 else ""

        event["timestamp"]  = ts   if ts   != "-" else event["timestamp"]
        event["hostname"]   = None if host  == "-" else host
        event["app_name"]   = None if app   == "-" else app
        event["process_id"] = None if pid   == "-" else pid
        event["message"]    = _extract_msg_from_sd(sd_and_msg)
        return event

    # ── RFC 3164: TIMESTAMP HOSTNAME [TAG[PID]: ]MESSAGE ──────────────────────
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

    # ── Fallback: PRI extracted but format unrecognised ────────────────────────
    event["message"] = rest
    return event


# ── UDP datagram protocol ─────────────────────────────────────────────────────


class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol that forwards received packets to SyslogReceiver."""

    def __init__(self, receiver: "SyslogReceiver") -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        max_size = self._receiver._max_message_size
        if len(data) > max_size:
            logger.warning(
                "SyslogReceiver dropping oversized datagram size=%d max=%d src=%s",
                len(data),
                max_size,
                addr[0],
            )
            return
        asyncio.create_task(self._receiver._handle_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.warning("SyslogReceiver UDP socket error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.error("SyslogReceiver UDP connection lost: %s", exc)


# ── TCP client handler ────────────────────────────────────────────────────────


async def _handle_tcp_client(
    receiver: "SyslogReceiver",
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Handle a single TCP syslog client connection.

    Uses non-transparent framing (newline-delimited messages) per RFC 6587 §3.4.2,
    which is the most widely deployed TCP syslog framing in practice.

    An idle connection is dropped after 60 seconds with no data received.
    """
    peername = writer.get_extra_info("peername") or ("unknown", 0)
    addr = (str(peername[0]), int(peername[1]))
    try:
        while True:
            try:
                line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=60.0,
                )
            except asyncio.TimeoutError:
                logger.debug("SyslogReceiver TCP client idle timeout src=%s", addr[0])
                break

            if not line:
                break  # EOF — client disconnected

            raw = line.decode("utf-8", errors="replace").rstrip("\n\r\x00")
            if not raw:
                continue

            await receiver._handle_message(raw, addr)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.debug("SyslogReceiver TCP client error src=%s err=%s", addr[0], exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ── SyslogReceiver ────────────────────────────────────────────────────────────


class SyslogReceiver:
    """Standalone syslog receiver supporting UDP and/or TCP on a configurable port.

    Unlike ``SyslogUDPConnector`` (feature 6.22), this service is not backed by
    a database connector row.  It is started directly from application settings
    in ``main.py``.

    Usage::

        receiver = SyslogReceiver(
            queue,
            host="0.0.0.0",
            port=1514,
            protocol="both",
        )
        await receiver.start()
        ...
        await receiver.stop()

    Both ``_handle_datagram`` (UDP) and the TCP framing handler call the shared
    ``_handle_message`` method, which parses the raw string and publishes to the
    ``mxtac.raw.syslog`` topic.
    """

    def __init__(
        self,
        queue,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        protocol: str = "udp",
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
    ) -> None:
        self._queue = queue
        self._host = host
        self._port = port
        self._protocol = protocol.lower()
        self._max_message_size = max_message_size
        self._udp_transport: asyncio.BaseTransport | None = None
        self._tcp_server: asyncio.Server | None = None
        self._events_total: int = 0
        self._errors_total: int = 0

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Bind UDP and/or TCP sockets and begin accepting syslog messages."""
        loop = asyncio.get_event_loop()

        if self._protocol in ("udp", "both"):
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SyslogUDPProtocol(self),
                local_addr=(self._host, self._port),
            )
            self._udp_transport = transport
            logger.info(
                "SyslogReceiver UDP listening host=%s port=%d",
                self._host,
                self._port,
            )

        if self._protocol in ("tcp", "both"):
            self._tcp_server = await asyncio.start_server(
                lambda r, w: _handle_tcp_client(self, r, w),
                host=self._host,
                port=self._port,
            )
            logger.info(
                "SyslogReceiver TCP listening host=%s port=%d",
                self._host,
                self._port,
            )

    async def stop(self) -> None:
        """Close sockets and wait for the TCP server to shut down cleanly."""
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
            logger.info("SyslogReceiver UDP socket closed")

        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None
            logger.info("SyslogReceiver TCP server closed")

    # ── Event handlers ────────────────────────────────────────────────────────

    async def _handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Decode a UDP datagram and forward to ``_handle_message``."""
        raw = data.decode("utf-8", errors="replace").rstrip("\n\r\x00")
        await self._handle_message(raw, addr)

    async def _handle_message(self, raw: str, addr: tuple[str, int]) -> None:
        """Parse a syslog message (any transport) and publish to the queue."""
        try:
            event = parse_syslog(raw, addr)
            await self._queue.publish(Topic.RAW_SYSLOG, event)
            self._events_total += 1
            logger.debug(
                "SyslogReceiver event src=%s severity=%s facility=%s",
                addr[0],
                event.get("severity_name"),
                event.get("facility_name"),
            )
        except Exception as exc:
            self._errors_total += 1
            logger.error(
                "SyslogReceiver error handling message src=%s err=%s",
                addr[0],
                exc,
            )

    # ── Status ────────────────────────────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Return a status snapshot (for health checks or logging)."""
        return {
            "host":          self._host,
            "port":          self._port,
            "protocol":      self._protocol,
            "events_total":  self._events_total,
            "errors_total":  self._errors_total,
            "udp_active":    self._udp_transport is not None,
            "tcp_active":    self._tcp_server is not None,
        }
