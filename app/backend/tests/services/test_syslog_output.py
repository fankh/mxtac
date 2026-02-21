"""Tests for AlertSyslogHandler — feature 20.5: alert output to syslog.

Coverage:
  - send(): calls _emit_sync with serialised JSON payload
  - send(): maps 'critical' alert level to logging.CRITICAL
  - send(): maps 'high' alert level to logging.ERROR
  - send(): maps 'medium' alert level to logging.WARNING
  - send(): maps 'low' alert level to logging.INFO
  - send(): maps 'informational' alert level to logging.DEBUG
  - send(): unknown level falls back to logging.WARNING
  - send(): non-serialisable values coerced via default=str
  - send(): non-fatal — swallows exceptions and logs them
  - close(): removes handler from internal logger and closes syslog socket
  - alert_syslog_output(): subscribes to mxtac.enriched topic
  - alert_syslog_output(): callback sends alert when message received
  - alert_syslog_output(): returns AlertSyslogHandler instance
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from logging.handlers import SysLogHandler as _RealSysLogHandler
from unittest.mock import AsyncMock, MagicMock, patch

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
    host: str = "srv-01",
    score: float = 7.2,
    level: str = "high",
) -> dict:
    return {
        "id": "test-uuid-001",
        "rule_id": rule_id,
        "rule_title": "Command Shell Execution",
        "level": level,
        "severity_id": 4,
        "technique_ids": ["T1059"],
        "tactic_ids": ["execution"],
        "host": host,
        "time": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "event_snapshot": {"pid": 1234},
    }


@contextmanager
def _mock_syslog_class():
    """Patch SysLogHandler to prevent real socket creation in tests."""
    with patch("app.services.alert_syslog_output.SysLogHandler") as mock_cls:
        mock_cls.facility_names = _RealSysLogHandler.facility_names
        mock_cls.LOG_LOCAL0 = _RealSysLogHandler.LOG_LOCAL0
        mock_cls.return_value = MagicMock()
        yield mock_cls


# ---------------------------------------------------------------------------
# Section 1 — send() basic behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_passes_json_payload_to_emit_sync():
    """send() must serialise the alert as JSON and pass it to _emit_sync."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[tuple[int, str]] = []

    def capture(level: int, msg: str) -> None:
        captured.append((level, msg))

    with patch.object(handler, "_emit_sync", side_effect=capture):
        alert = _make_alert()
        await handler.send(alert)

    assert len(captured) == 1
    _, payload = captured[0]
    parsed = json.loads(payload)
    assert parsed["id"] == alert["id"]
    assert parsed["score"] == alert["score"]
    assert parsed["technique_ids"] == ["T1059"]


@pytest.mark.asyncio
async def test_send_level_critical_uses_logging_critical():
    """send() must map alert level 'critical' to logging.CRITICAL."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[int] = []

    def capture(level: int, msg: str) -> None:
        captured.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture):
        await handler.send(_make_alert(level="critical"))

    assert captured[0] == logging.CRITICAL


@pytest.mark.asyncio
async def test_send_level_high_uses_logging_error():
    """send() must map alert level 'high' to logging.ERROR."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[int] = []

    def capture(level: int, msg: str) -> None:
        captured.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture):
        await handler.send(_make_alert(level="high"))

    assert captured[0] == logging.ERROR


@pytest.mark.asyncio
async def test_send_level_medium_uses_logging_warning():
    """send() must map alert level 'medium' to logging.WARNING."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[int] = []

    def capture(level: int, msg: str) -> None:
        captured.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture):
        await handler.send(_make_alert(level="medium"))

    assert captured[0] == logging.WARNING


@pytest.mark.asyncio
async def test_send_level_low_uses_logging_info():
    """send() must map alert level 'low' to logging.INFO."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[int] = []

    def capture(level: int, msg: str) -> None:
        captured.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture):
        await handler.send(_make_alert(level="low"))

    assert captured[0] == logging.INFO


@pytest.mark.asyncio
async def test_send_level_informational_uses_logging_debug():
    """send() must map alert level 'informational' to logging.DEBUG."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[int] = []

    def capture(level: int, msg: str) -> None:
        captured.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture):
        await handler.send(_make_alert(level="informational"))

    assert captured[0] == logging.DEBUG


@pytest.mark.asyncio
async def test_send_unknown_level_falls_back_to_warning():
    """send() must fall back to logging.WARNING for unrecognised alert levels."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[int] = []

    def capture(level: int, msg: str) -> None:
        captured.append(level)

    with patch.object(handler, "_emit_sync", side_effect=capture):
        await handler.send(_make_alert(level="unknown-level"))

    assert captured[0] == _DEFAULT_LOG_LEVEL
    assert captured[0] == logging.WARNING


@pytest.mark.asyncio
async def test_send_missing_level_falls_back_to_warning():
    """send() must fall back to WARNING when the 'level' key is absent."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[int] = []

    def capture(level: int, msg: str) -> None:
        captured.append(level)

    alert = _make_alert()
    del alert["level"]

    with patch.object(handler, "_emit_sync", side_effect=capture):
        await handler.send(alert)

    assert captured[0] == logging.WARNING


@pytest.mark.asyncio
async def test_send_coerces_non_serialisable_values():
    """send() must coerce non-JSON-serialisable values (e.g. datetime) via str()."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    captured: list[str] = []

    def capture(level: int, msg: str) -> None:
        captured.append(msg)

    alert = _make_alert()
    alert["extra"] = datetime(2026, 2, 21, 12, 0, 0)  # not JSON-serialisable by default

    with patch.object(handler, "_emit_sync", side_effect=capture):
        await handler.send(alert)

    assert len(captured) == 1
    parsed = json.loads(captured[0])
    assert "extra" in parsed
    assert isinstance(parsed["extra"], str)


@pytest.mark.asyncio
async def test_send_is_non_fatal_on_emit_error():
    """send() must swallow exceptions so the pipeline is never interrupted."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    with patch.object(handler, "_emit_sync", side_effect=OSError("syslog unavailable")):
        # Must not raise
        await handler.send(_make_alert())


@pytest.mark.asyncio
async def test_send_all_levels_are_mapped():
    """All five alert levels must be present in _LEVEL_MAP."""
    expected_levels = {"critical", "high", "medium", "low", "informational"}
    assert set(_LEVEL_MAP.keys()) == expected_levels


# ---------------------------------------------------------------------------
# Section 2 — close()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_removes_handler_from_internal_logger():
    """close() must remove the SysLogHandler from the dedicated internal logger."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    # Handler should be attached initially
    assert handler._syslog_handler in handler._syslog_logger.handlers

    await handler.close()

    # Handler must be detached after close
    assert handler._syslog_handler not in handler._syslog_logger.handlers


@pytest.mark.asyncio
async def test_close_calls_syslog_handler_close():
    """close() must call close() on the underlying SysLogHandler."""
    with _mock_syslog_class() as mock_cls:
        mock_syslog_instance = mock_cls.return_value
        handler = AlertSyslogHandler()

    await handler.close()

    mock_syslog_instance.close.assert_called_once()


@pytest.mark.asyncio
async def test_close_is_non_fatal_on_error():
    """close() must swallow exceptions and not propagate them."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    with patch.object(handler, "_close_sync", side_effect=RuntimeError("socket error")):
        # Must not raise
        await handler.close()


# ---------------------------------------------------------------------------
# Section 3 — constructor / configuration
# ---------------------------------------------------------------------------


def test_init_uses_udp_socktype_by_default():
    """AlertSyslogHandler must use SOCK_DGRAM (UDP) when protocol='udp'."""
    import socket

    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(host="syslog.example.com", port=514, protocol="udp")

    _, kwargs = mock_cls.call_args
    # SysLogHandler may be called positionally or with keyword args
    call_args = mock_cls.call_args
    # Extract socktype from args or kwargs
    if call_args.kwargs.get("socktype") is not None:
        socktype = call_args.kwargs["socktype"]
    else:
        socktype = call_args.args[2] if len(call_args.args) > 2 else None

    assert socktype == socket.SOCK_DGRAM


def test_init_uses_tcp_socktype_for_tcp_protocol():
    """AlertSyslogHandler must use SOCK_STREAM (TCP) when protocol='tcp'."""
    import socket

    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(host="syslog.example.com", port=601, protocol="tcp")

    call_args = mock_cls.call_args
    if call_args.kwargs.get("socktype") is not None:
        socktype = call_args.kwargs["socktype"]
    else:
        socktype = call_args.args[2] if len(call_args.args) > 2 else None

    assert socktype == socket.SOCK_STREAM


def test_init_sets_ident_tag():
    """AlertSyslogHandler must set the syslog ident to '<tag>: '."""
    with _mock_syslog_class() as mock_cls:
        mock_instance = mock_cls.return_value
        AlertSyslogHandler(tag="my-app")

    assert mock_instance.ident == "my-app: "


def test_init_unix_socket_path_uses_string_address():
    """When host starts with '/', the address must be the path string directly."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(host="/dev/log")

    call_args = mock_cls.call_args
    if call_args.kwargs.get("address") is not None:
        address = call_args.kwargs["address"]
    else:
        address = call_args.args[0]

    assert address == "/dev/log"


def test_init_resolves_facility_name():
    """AlertSyslogHandler must resolve the facility string to a numeric code."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(facility="local3")

    call_args = mock_cls.call_args
    if call_args.kwargs.get("facility") is not None:
        facility = call_args.kwargs["facility"]
    else:
        facility = call_args.args[1] if len(call_args.args) > 1 else None

    expected = _RealSysLogHandler.facility_names["local3"]
    assert facility == expected


def test_init_unknown_facility_falls_back_to_local0():
    """An unrecognised facility string must fall back to LOG_LOCAL0."""
    with _mock_syslog_class() as mock_cls:
        AlertSyslogHandler(facility="bogus-facility")

    call_args = mock_cls.call_args
    if call_args.kwargs.get("facility") is not None:
        facility = call_args.kwargs["facility"]
    else:
        facility = call_args.args[1] if len(call_args.args) > 1 else None

    assert facility == _RealSysLogHandler.LOG_LOCAL0


def test_internal_logger_does_not_propagate():
    """The internal syslog logger must not propagate to the root logger."""
    with _mock_syslog_class():
        handler = AlertSyslogHandler()

    assert handler._syslog_logger.propagate is False


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
    """Publishing to mxtac.enriched must trigger a syslog send."""
    queue = InMemoryQueue()
    await queue.start()

    with _mock_syslog_class():
        handler = await alert_syslog_output(queue)

    captured: list[dict] = []

    async def mock_send(alert: dict) -> None:
        captured.append(alert)

    handler.send = mock_send  # type: ignore[method-assign]

    alert = _make_alert()
    await queue.publish(Topic.ENRICHED, alert)

    # Give the consumer task a moment to process
    await asyncio.sleep(0.05)

    await handler.close()
    await queue.stop()

    assert len(captured) == 1
    assert captured[0]["id"] == alert["id"]


@pytest.mark.asyncio
async def test_alert_syslog_output_passes_config_to_handler():
    """alert_syslog_output() must forward all config params to AlertSyslogHandler."""
    queue = InMemoryQueue()
    await queue.start()

    with _mock_syslog_class() as mock_cls:
        handler = await alert_syslog_output(
            queue,
            host="10.0.0.1",
            port=601,
            protocol="tcp",
            facility="local7",
            tag="my-siem",
        )

    # Verify the SysLogHandler was constructed with the correct address
    call_args = mock_cls.call_args
    if call_args.kwargs.get("address") is not None:
        address = call_args.kwargs["address"]
    else:
        address = call_args.args[0]

    assert address == ("10.0.0.1", 601)
    assert handler._tag == "my-siem"
    assert mock_cls.return_value.ident == "my-siem: "

    await handler.close()
    await queue.stop()
