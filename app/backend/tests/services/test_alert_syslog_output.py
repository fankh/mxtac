"""Tests for AlertSyslogHandler — sends enriched alerts to a syslog destination.

Coverage:
  - send(): serialises alert as JSON and passes it to _emit_sync
  - send(): maps 'critical' level → logging.CRITICAL
  - send(): maps 'high' level → logging.ERROR
  - send(): maps 'medium' level → logging.WARNING
  - send(): maps 'low' level → logging.INFO
  - send(): maps 'informational' level → logging.DEBUG
  - send(): unknown level falls back to logging.WARNING
  - send(): missing level key falls back to logging.WARNING
  - send(): non-serialisable values coerced via str()
  - send(): non-fatal — swallows errors and logs them
  - send(): delegates to _emit_sync via thread-pool executor
  - close(): removes SysLogHandler from internal syslog logger
  - close(): calls SysLogHandler.close() to release the socket
  - close(): non-fatal — swallows errors
  - __init__(): SOCK_DGRAM socktype when protocol='udp'
  - __init__(): SOCK_STREAM socktype when protocol='tcp'
  - __init__(): Unix socket path passed as address string (ignores port/protocol)
  - __init__(): Unix socket path uses SOCK_DGRAM regardless of protocol param
  - __init__(): hostname/port passed as (host, port) tuple address
  - __init__(): resolves facility name string to integer facility code
  - __init__(): unknown facility name falls back to LOG_LOCAL0
  - __init__(): sets syslog handler ident to "tag: "
  - __init__(): syslog logger propagation is False
  - alert_syslog_output(): subscribes to mxtac.enriched topic
  - alert_syslog_output(): returns AlertSyslogHandler instance
  - alert_syslog_output(): callback invokes send() when message published
  - alert_syslog_output(): forwards host/port/protocol/facility/tag to handler
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from logging.handlers import SysLogHandler as _RealSysLogHandler
from unittest.mock import MagicMock, patch

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_syslog_output import (
    AlertSyslogHandler,
    _DEFAULT_LOG_LEVEL,
    _LEVEL_MAP,
    alert_syslog_output,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    *,
    rule_id: str = "sigma-T1059",
    rule_title: str = "Command Shell Execution",
    host: str = "srv-01",
    score: float = 7.2,
    level: str = "high",
) -> dict:
    return {
        "id": "test-uuid-001",
        "rule_id": rule_id,
        "rule_title": rule_title,
        "level": level,
        "technique_ids": ["T1059"],
        "tactic_ids": ["execution"],
        "host": host,
        "time": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "event_snapshot": {"pid": 1234},
    }


@contextmanager
def _mock_syslog_class():
    """Patch SysLogHandler to prevent real socket creation.

    Yields the mock SysLogHandler *class* so callers can inspect constructor
    arguments via ``mock_cls.call_args``.  The mock instance is accessible
    via ``mock_cls.return_value``.

    Class-level attributes used by __init__ (``facility_names``, ``LOG_LOCAL0``)
    are preserved from the real SysLogHandler so facility resolution works.
    """
    mock_instance = MagicMock()
    mock_cls = MagicMock(return_value=mock_instance)
    # Preserve real class attributes so SysLogHandler.facility_names.get(...)
    # returns genuine integer codes rather than MagicMock objects.
    mock_cls.facility_names = _RealSysLogHandler.facility_names
    mock_cls.LOG_LOCAL0 = _RealSysLogHandler.LOG_LOCAL0
    with patch("app.services.alert_syslog_output.SysLogHandler", mock_cls):
        yield mock_cls


# ---------------------------------------------------------------------------
# Section 1 — send() basic behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_serialises_alert_as_json():
    """send() must pass the alert serialised as a JSON string to _emit_sync."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[str] = []

    def capture_emit(level: int, message: str) -> None:
        captured.append(message)

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        alert = _make_alert()
        await handler.send(alert)

    assert len(captured) == 1
    parsed = json.loads(captured[0])
    assert parsed["id"] == alert["id"]
    assert parsed["host"] == alert["host"]
    assert parsed["rule_id"] == alert["rule_id"]


@pytest.mark.asyncio
async def test_send_level_critical_maps_to_logging_critical():
    """send() must use logging.CRITICAL for 'critical' alerts."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured_levels: list[int] = []

    def capture_emit(level: int, message: str) -> None:
        captured_levels.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        await handler.send(_make_alert(level="critical"))

    assert captured_levels == [logging.CRITICAL]


@pytest.mark.asyncio
async def test_send_level_high_maps_to_logging_error():
    """send() must use logging.ERROR for 'high' alerts."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured_levels: list[int] = []

    def capture_emit(level: int, message: str) -> None:
        captured_levels.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        await handler.send(_make_alert(level="high"))

    assert captured_levels == [logging.ERROR]


@pytest.mark.asyncio
async def test_send_level_medium_maps_to_logging_warning():
    """send() must use logging.WARNING for 'medium' alerts."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured_levels: list[int] = []

    def capture_emit(level: int, message: str) -> None:
        captured_levels.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        await handler.send(_make_alert(level="medium"))

    assert captured_levels == [logging.WARNING]


@pytest.mark.asyncio
async def test_send_level_low_maps_to_logging_info():
    """send() must use logging.INFO for 'low' alerts."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured_levels: list[int] = []

    def capture_emit(level: int, message: str) -> None:
        captured_levels.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        await handler.send(_make_alert(level="low"))

    assert captured_levels == [logging.INFO]


@pytest.mark.asyncio
async def test_send_level_informational_maps_to_logging_debug():
    """send() must use logging.DEBUG for 'informational' alerts."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured_levels: list[int] = []

    def capture_emit(level: int, message: str) -> None:
        captured_levels.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        await handler.send(_make_alert(level="informational"))

    assert captured_levels == [logging.DEBUG]


@pytest.mark.asyncio
async def test_send_unknown_level_falls_back_to_warning():
    """send() must fall back to logging.WARNING for unrecognised level strings."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured_levels: list[int] = []

    def capture_emit(level: int, message: str) -> None:
        captured_levels.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        await handler.send(_make_alert(level="bogus-level"))

    assert captured_levels == [logging.WARNING]
    assert _DEFAULT_LOG_LEVEL == logging.WARNING


@pytest.mark.asyncio
async def test_send_missing_level_key_falls_back_to_warning():
    """send() must fall back to logging.WARNING when 'level' key is absent."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured_levels: list[int] = []

    def capture_emit(level: int, message: str) -> None:
        captured_levels.append(level)

    alert = _make_alert()
    del alert["level"]

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        await handler.send(alert)

    assert captured_levels == [logging.WARNING]


@pytest.mark.asyncio
async def test_send_coerces_non_serialisable_values():
    """send() must coerce non-JSON-serialisable values via str() (default=str)."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[str] = []

    def capture_emit(level: int, message: str) -> None:
        captured.append(message)

    alert = _make_alert()
    alert["extra"] = datetime(2026, 2, 21, 12, 0, 0)  # not JSON-serialisable by default

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        await handler.send(alert)

    assert len(captured) == 1
    parsed = json.loads(captured[0])
    assert isinstance(parsed["extra"], str)


@pytest.mark.asyncio
async def test_send_is_non_fatal_on_error():
    """send() must swallow exceptions so the pipeline is never interrupted."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    with patch.object(handler, "_emit_sync", side_effect=OSError("socket error")):
        # Must not raise
        await handler.send(_make_alert())


@pytest.mark.asyncio
async def test_send_delegates_to_emit_sync_via_executor():
    """send() must run _emit_sync in the thread-pool executor (not the event loop thread)."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    main_thread_id = threading.get_ident()
    captured_thread_ids: list[int] = []

    def capture_emit(level: int, message: str) -> None:
        captured_thread_ids.append(threading.get_ident())

    with patch.object(handler, "_emit_sync", side_effect=capture_emit):
        await handler.send(_make_alert())

    assert len(captured_thread_ids) == 1
    assert captured_thread_ids[0] != main_thread_id


# ---------------------------------------------------------------------------
# Section 2 — close() cleanup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_removes_handler_from_syslog_logger():
    """close() must remove the SysLogHandler from the internal syslog logger."""
    with _mock_syslog_class() as mock_cls:
        handler = AlertSyslogHandler()
        mock_syslog_instance = mock_cls.return_value

    removed: list = []

    def capturing_remove(h) -> None:
        removed.append(h)

    with patch.object(handler._syslog_logger, "removeHandler", side_effect=capturing_remove):
        await handler.close()

    assert mock_syslog_instance in removed


@pytest.mark.asyncio
async def test_close_calls_syslog_handler_close():
    """close() must call SysLogHandler.close() to release the underlying socket."""
    with _mock_syslog_class() as mock_cls:
        handler = AlertSyslogHandler()
        mock_syslog_instance = mock_cls.return_value

    await handler.close()

    mock_syslog_instance.close.assert_called_once()


@pytest.mark.asyncio
async def test_close_is_non_fatal_on_error():
    """close() must swallow exceptions rather than propagating them."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    with patch.object(handler, "_close_sync", side_effect=RuntimeError("close failed")):
        # Must not raise
        await handler.close()


# ---------------------------------------------------------------------------
# Section 3 — Constructor / configuration
# ---------------------------------------------------------------------------


def test_init_udp_protocol_uses_sock_dgram():
    """AlertSyslogHandler must use SOCK_DGRAM for UDP protocol."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(host="syslog.example.com", port=514, protocol="udp")

    call_kwargs = mock_cls.call_args.kwargs
    assert call_kwargs["socktype"] == socket.SOCK_DGRAM


def test_init_tcp_protocol_uses_sock_stream():
    """AlertSyslogHandler must use SOCK_STREAM for TCP protocol."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(host="syslog.example.com", port=514, protocol="tcp")

    call_kwargs = mock_cls.call_args.kwargs
    assert call_kwargs["socktype"] == socket.SOCK_STREAM


def test_init_unix_socket_path_address_is_path_string():
    """AlertSyslogHandler must pass a Unix socket path directly as the address string."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(host="/var/run/syslog")

    call_kwargs = mock_cls.call_args.kwargs
    assert call_kwargs["address"] == "/var/run/syslog"


def test_init_unix_socket_path_uses_sock_dgram_regardless_of_protocol():
    """AlertSyslogHandler must use SOCK_DGRAM for Unix paths even when protocol='tcp'."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(host="/dev/log", protocol="tcp")

    call_kwargs = mock_cls.call_args.kwargs
    assert call_kwargs["socktype"] == socket.SOCK_DGRAM


def test_init_hostname_port_address_is_tuple():
    """AlertSyslogHandler must pass (host, port) tuple as address for network connections."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(host="192.168.1.10", port=1514)

    call_kwargs = mock_cls.call_args.kwargs
    assert call_kwargs["address"] == ("192.168.1.10", 1514)


def test_init_facility_name_resolved_to_code():
    """AlertSyslogHandler must resolve facility name string to the integer facility code."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(facility="local0")

    call_kwargs = mock_cls.call_args.kwargs
    expected_code = _RealSysLogHandler.facility_names["local0"]
    assert call_kwargs["facility"] == expected_code


def test_init_unknown_facility_falls_back_to_local0():
    """AlertSyslogHandler must fall back to LOG_LOCAL0 for unknown facility names."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(facility="bogus-facility")

    call_kwargs = mock_cls.call_args.kwargs
    assert call_kwargs["facility"] == _RealSysLogHandler.LOG_LOCAL0


def test_init_sets_tag_as_handler_ident():
    """AlertSyslogHandler must set ident on the SysLogHandler as 'tag: '."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(tag="my-tag")

    mock_instance = mock_cls.return_value
    assert mock_instance.ident == "my-tag: "


def test_init_syslog_logger_propagation_is_false():
    """AlertSyslogHandler must set propagate=False on the internal syslog logger."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    assert handler._syslog_logger.propagate is False


def test_level_map_contains_all_expected_levels():
    """_LEVEL_MAP must define mappings for all five MxTac severity levels."""
    assert set(_LEVEL_MAP.keys()) == {"critical", "high", "medium", "low", "informational"}
    assert _LEVEL_MAP["critical"] == logging.CRITICAL
    assert _LEVEL_MAP["high"] == logging.ERROR
    assert _LEVEL_MAP["medium"] == logging.WARNING
    assert _LEVEL_MAP["low"] == logging.INFO
    assert _LEVEL_MAP["informational"] == logging.DEBUG


# ---------------------------------------------------------------------------
# Section 4 — alert_syslog_output() factory / queue integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_syslog_output_subscribes_to_enriched_topic():
    """alert_syslog_output() must subscribe to Topic.ENRICHED."""
    queue = InMemoryQueue()
    await queue.start()

    subscribed_topics: list[str] = []
    original_subscribe = queue.subscribe

    async def capture_subscribe(topic, group, handler):
        subscribed_topics.append(topic)
        return await original_subscribe(topic, group, handler)

    with _mock_syslog_class():
        with patch.object(queue, "subscribe", side_effect=capture_subscribe):
            handler = await alert_syslog_output(queue)

    assert Topic.ENRICHED in subscribed_topics

    await handler.close()
    await queue.stop()


@pytest.mark.asyncio
async def test_alert_syslog_output_returns_handler_instance():
    """alert_syslog_output() must return an AlertSyslogHandler for shutdown cleanup."""
    queue = InMemoryQueue()
    await queue.start()

    with _mock_syslog_class():
        handler = await alert_syslog_output(queue)

    assert isinstance(handler, AlertSyslogHandler)

    await handler.close()
    await queue.stop()


@pytest.mark.asyncio
async def test_alert_syslog_output_sends_on_publish():
    """Publishing an alert to mxtac.enriched must trigger handler.send()."""
    queue = InMemoryQueue()
    await queue.start()

    with _mock_syslog_class():
        handler = await alert_syslog_output(queue)

    captured: list[dict] = []

    async def mock_send(alert: dict) -> None:
        captured.append(alert)

    handler.send = mock_send  # type: ignore[method-assign]

    alert = _make_alert(level="critical")
    await queue.publish(Topic.ENRICHED, alert)

    await asyncio.sleep(0.05)

    await handler.close()
    await queue.stop()

    assert len(captured) == 1
    assert captured[0]["id"] == alert["id"]


@pytest.mark.asyncio
async def test_alert_syslog_output_forwards_config_to_handler():
    """alert_syslog_output() must forward host/port/protocol/facility/tag to SysLogHandler."""
    queue = InMemoryQueue()
    await queue.start()

    with _mock_syslog_class() as mock_cls:
        handler = await alert_syslog_output(
            queue,
            host="siem.corp.com",
            port=6514,
            protocol="tcp",
            facility="local7",
            tag="mxtac-soc",
        )

    call_kwargs = mock_cls.call_args.kwargs
    assert call_kwargs["address"] == ("siem.corp.com", 6514)
    assert call_kwargs["socktype"] == socket.SOCK_STREAM
    expected_facility = _RealSysLogHandler.facility_names["local7"]
    assert call_kwargs["facility"] == expected_facility
    assert mock_cls.return_value.ident == "mxtac-soc: "

    await handler.close()
    await queue.stop()
