"""Alert syslog output — sends enriched alerts to a syslog destination.

Each alert published to mxtac.enriched is serialised as a JSON object and
emitted to the configured syslog endpoint (UDP, TCP, or local Unix socket).

Alert severity levels are mapped to syslog priorities:

    critical     → LOG_CRIT     (``logging.CRITICAL``)
    high         → LOG_ERR      (``logging.ERROR``)
    medium       → LOG_WARNING  (``logging.WARNING``)
    low          → LOG_INFO     (``logging.INFO``)
    informational → LOG_DEBUG   (``logging.DEBUG``)

Blocking socket I/O runs in the default thread-pool executor to avoid
stalling the asyncio event loop.  All errors are logged and swallowed so
that a syslog failure never interrupts the rest of the alert pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
from logging.handlers import SysLogHandler
from typing import Any, Literal

from ..core.logging import get_logger
from ..pipeline.queue import MessageQueue, Topic

logger = get_logger(__name__)

# Mapping from MxTac alert level to Python logging level (controls syslog priority)
_LEVEL_MAP: dict[str, int] = {
    "critical": logging.CRITICAL,
    "high": logging.ERROR,
    "medium": logging.WARNING,
    "low": logging.INFO,
    "informational": logging.DEBUG,
}
_DEFAULT_LOG_LEVEL = logging.WARNING


class AlertSyslogHandler:
    """Sends enriched alert dicts to a syslog destination.

    Uses Python's stdlib :class:`logging.handlers.SysLogHandler` to format
    and transmit syslog messages.  A ``threading.Lock`` guards all socket
    I/O to ensure thread safety when the handler runs in the thread-pool
    executor.  Call :meth:`close` during application shutdown to release
    the underlying socket.

    *host* may be a hostname/IP address (for UDP or TCP) or a Unix socket
    path such as ``/dev/log`` (local syslog daemon).  When *host* starts
    with ``/``, the *port* and *protocol* parameters are ignored and a Unix
    domain socket is used instead.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 514,
        protocol: Literal["udp", "tcp"] = "udp",
        facility: str = "local0",
        tag: str = "mxtac-alert",
    ) -> None:
        self._tag = tag
        self._lock = threading.Lock()

        # Resolve address and socket type
        if host.startswith("/"):
            # Local Unix socket path (e.g. /dev/log, /var/run/syslog)
            address: str | tuple[str, int] = host
            socktype = socket.SOCK_DGRAM
        else:
            address = (host, port)
            socktype = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM

        # Resolve facility code from string name (e.g. "local0" → 16)
        facility_code = SysLogHandler.facility_names.get(
            facility.lower(), SysLogHandler.LOG_LOCAL0
        )

        self._syslog_handler = SysLogHandler(
            address=address,
            facility=facility_code,
            socktype=socktype,
        )
        self._syslog_handler.ident = f"{tag}: "

        # Dedicated logger so that internal app log messages (via get_logger)
        # are never forwarded to the syslog socket.
        self._syslog_logger = logging.getLogger(f"mxtac.syslog.alerts.{id(self)}")
        self._syslog_logger.propagate = False
        self._syslog_logger.setLevel(logging.DEBUG)
        self._syslog_logger.addHandler(self._syslog_handler)

    # ------------------------------------------------------------------
    # Synchronous helpers (run in thread-pool executor)
    # ------------------------------------------------------------------

    def _emit_sync(self, level: int, message: str) -> None:
        with self._lock:
            self._syslog_logger.log(level, message)

    def _close_sync(self) -> None:
        with self._lock:
            self._syslog_logger.removeHandler(self._syslog_handler)
            self._syslog_handler.close()

    # ------------------------------------------------------------------
    # Public async interface
    # ------------------------------------------------------------------

    async def send(self, alert: dict[str, Any]) -> None:
        """Serialise *alert* as JSON and emit it to syslog.

        The syslog priority is derived from ``alert["level"]``; unknown
        levels fall back to WARNING.  Errors are logged and swallowed so
        that a delivery failure never interrupts the rest of the alert
        pipeline.
        """
        try:
            level = _LEVEL_MAP.get(alert.get("level", ""), _DEFAULT_LOG_LEVEL)
            payload = json.dumps(alert, default=str)
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._emit_sync, level, payload)
        except Exception:
            logger.exception("AlertSyslogHandler send error (non-fatal)")

    async def close(self) -> None:
        """Remove the handler from the internal logger and close the syslog socket."""
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._close_sync)
        except Exception:
            logger.exception("AlertSyslogHandler close error")


async def alert_syslog_output(
    queue: MessageQueue,
    host: str = "localhost",
    port: int = 514,
    protocol: Literal["udp", "tcp"] = "udp",
    facility: str = "local0",
    tag: str = "mxtac-alert",
) -> AlertSyslogHandler:
    """Subscribe an :class:`AlertSyslogHandler` to ``mxtac.enriched``.

    Returns the handler so the caller can close it during shutdown.
    """
    handler = AlertSyslogHandler(
        host=host,
        port=port,
        protocol=protocol,
        facility=facility,
        tag=tag,
    )

    async def _handle(alert: dict[str, Any]) -> None:
        await handler.send(alert)

    await queue.subscribe(Topic.ENRICHED, "alert-syslog-output", _handle)
    logger.info(
        "Alert syslog output subscribed to %s → %s:%d (%s) facility=%s",
        Topic.ENRICHED,
        host,
        port,
        protocol,
        facility,
    )
    return handler
