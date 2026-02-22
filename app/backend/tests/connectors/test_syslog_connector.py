"""
Tests for SyslogUDPConnector (Feature 6.22).

Generic UDP syslog receiver on port 514.

Coverage:
  Initialization:
    - topic is mxtac.raw.syslog
    - topic literal string is "mxtac.raw.syslog"
    - _transport is None before connect
    - _protocol is None before connect
    - health status is INACTIVE on init
    - max_message_size defaults to 65535
    - max_message_size configurable via extra

  _fetch_events():
    - returns an empty async generator (event-driven connector)
    - yields no events

  _poll_loop():
    - returns when stop event is set
    - returns when cancelled

  _connect():
    - calls create_datagram_endpoint with correct host and port
    - sets _transport after connect
    - sets _protocol after connect
    - uses default host "0.0.0.0"
    - uses default port 514
    - uses configured host from extra
    - uses configured port from extra
    - raises when bind fails

  _handle_datagram():
    - publishes event to queue
    - increments health.events_total
    - updates health.last_event_at
    - error during publish increments health.errors_total
    - error during publish sets health.error_message

  _SyslogProtocol:
    - datagram_received schedules _handle_datagram task
    - oversized datagram is dropped (not scheduled)
    - error_received increments connector errors_total

  _parse_syslog():
    RFC 3164 parsing:
      - extracts facility and severity from PRI
      - extracts timestamp from header
      - extracts hostname from header
      - extracts app_name (tag) from header
      - extracts process_id (pid) from tag
      - extracts message body
      - message without tag still returns hostname
      - always sets _source to "syslog"
      - always sets host and port from addr
      - always sets raw field

    RFC 5424 parsing:
      - detects RFC 5424 format by version field
      - extracts facility and severity from PRI
      - extracts ISO 8601 timestamp
      - extracts hostname
      - extracts app_name
      - extracts process_id
      - nil hostname ("-") maps to None
      - nil app_name ("-") maps to None
      - nil process_id ("-") maps to None
      - nil timestamp ("-") falls back to current UTC time
      - extracts message after nil SD
      - extracts message after structured data element

    Fallback behaviour:
      - no PRI: message is raw string, facility/severity are None
      - malformed PRI value > 191: facility/severity still computed
      - binary-safe: non-UTF-8 bytes are replaced, not raised

    Priority decoding:
      - PRI=0: facility=kern, severity=emergency
      - PRI=1: facility=kern, severity=alert
      - PRI=8: facility=user, severity=emergency
      - PRI=13: facility=user, severity=notice
      - PRI=34: facility=auth, severity=critical
      - PRI=165: facility=local4, severity=notice
      - all 8 severity names present
      - out-of-range facility uses "facility{N}" name

  stop():
    - closes the transport
    - sets _transport to None
    - sets _protocol to None

  Registry integration:
    - build_connector creates SyslogUDPConnector from DB row
    - SyslogUDPConnector has status_callback set by build_connector
    - connector name matches DB row
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from app.connectors.base import ConnectorConfig, ConnectorStatus
from app.connectors.syslog import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_MAX_MESSAGE_SIZE,
    FACILITY_NAMES,
    SEVERITY_NAMES,
    SyslogUDPConnector,
    SyslogUDPConnectorFactory,
    _SyslogProtocol,
    _extract_msg_from_sd,
    _fill_priority,
)
from app.pipeline.queue import InMemoryQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_config(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
    **extra_overrides: Any,
) -> ConnectorConfig:
    return ConnectorConfig(
        name="syslog-test",
        connector_type="syslog",
        enabled=True,
        poll_interval_seconds=60,
        extra={
            "host": host,
            "port": port,
            "max_message_size": max_message_size,
            **extra_overrides,
        },
    )


def _make_connector(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
    **extra_overrides: Any,
) -> SyslogUDPConnector:
    return SyslogUDPConnector(
        _make_config(host=host, port=port, max_message_size=max_message_size, **extra_overrides),
        InMemoryQueue(),
    )


def _encode(msg: str) -> bytes:
    return msg.encode("utf-8")


async def _collect_fetch(conn: SyslogUDPConnector) -> list[dict]:
    results = []
    async for event in conn._fetch_events():
        results.append(event)
    return results


# ── Initialization ─────────────────────────────────────────────────────────────


class TestSyslogConnectorInit:
    def test_topic_is_raw_syslog(self) -> None:
        conn = _make_connector()
        assert conn.topic == Topic.RAW_SYSLOG

    def test_topic_literal_string(self) -> None:
        conn = _make_connector()
        assert conn.topic == "mxtac.raw.syslog"

    def test_transport_is_none_before_connect(self) -> None:
        conn = _make_connector()
        assert conn._transport is None

    def test_protocol_is_none_before_connect(self) -> None:
        conn = _make_connector()
        assert conn._protocol is None

    def test_health_status_inactive_on_init(self) -> None:
        conn = _make_connector()
        assert conn.health.status == ConnectorStatus.INACTIVE

    def test_max_message_size_defaults_to_65535(self) -> None:
        conn = _make_connector()
        assert conn._max_message_size == DEFAULT_MAX_MESSAGE_SIZE

    def test_max_message_size_configurable(self) -> None:
        conn = _make_connector(max_message_size=2048)
        assert conn._max_message_size == 2048


# ── _fetch_events() ────────────────────────────────────────────────────────────


class TestSyslogFetchEvents:
    async def test_returns_empty_async_generator(self) -> None:
        conn = _make_connector()
        events = await _collect_fetch(conn)
        assert events == []

    async def test_yields_no_events(self) -> None:
        conn = _make_connector()
        count = 0
        async for _ in conn._fetch_events():
            count += 1
        assert count == 0


# ── _poll_loop() ───────────────────────────────────────────────────────────────


class TestSyslogPollLoop:
    async def test_returns_when_stop_event_set(self) -> None:
        conn = _make_connector()
        conn._stop_event.set()
        # Should return immediately without blocking
        await asyncio.wait_for(conn._poll_loop(), timeout=1.0)

    async def test_returns_when_cancelled(self) -> None:
        conn = _make_connector()
        task = asyncio.create_task(conn._poll_loop())
        await asyncio.sleep(0)  # let the task start
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass  # expected behaviour: cancel propagates to the caller


# ── _connect() ─────────────────────────────────────────────────────────────────


class TestSyslogConnect:
    async def test_calls_create_datagram_endpoint(self) -> None:
        conn = _make_connector(host="127.0.0.1", port=5140)

        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport, mock_protocol)),
        ) as mock_create:
            await conn._connect()
            mock_create.assert_called_once()
            _, kwargs = mock_create.call_args
            assert kwargs.get("local_addr") == ("127.0.0.1", 5140)

    async def test_sets_transport_after_connect(self) -> None:
        conn = _make_connector()
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport, mock_protocol)),
        ):
            await conn._connect()
        assert conn._transport is mock_transport

    async def test_sets_protocol_after_connect(self) -> None:
        conn = _make_connector()
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport, mock_protocol)),
        ):
            await conn._connect()
        assert conn._protocol is mock_protocol

    async def test_uses_default_host(self) -> None:
        conn = _make_connector()
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport, mock_protocol)),
        ) as mock_create:
            await conn._connect()
            _, kwargs = mock_create.call_args
            host, _ = kwargs["local_addr"]
            assert host == DEFAULT_HOST

    async def test_uses_default_port(self) -> None:
        conn = _make_connector()
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport, mock_protocol)),
        ) as mock_create:
            await conn._connect()
            _, kwargs = mock_create.call_args
            _, port = kwargs["local_addr"]
            assert port == DEFAULT_PORT

    async def test_uses_configured_host(self) -> None:
        conn = _make_connector(host="192.168.1.10")
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport, mock_protocol)),
        ) as mock_create:
            await conn._connect()
            _, kwargs = mock_create.call_args
            host, _ = kwargs["local_addr"]
            assert host == "192.168.1.10"

    async def test_uses_configured_port(self) -> None:
        conn = _make_connector(port=5141)
        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport, mock_protocol)),
        ) as mock_create:
            await conn._connect()
            _, kwargs = mock_create.call_args
            _, port = kwargs["local_addr"]
            assert port == 5141

    async def test_raises_when_bind_fails(self) -> None:
        conn = _make_connector(port=9)  # low port may require root
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(side_effect=OSError("Address already in use")),
        ):
            with pytest.raises(OSError):
                await conn._connect()


# ── _handle_datagram() ─────────────────────────────────────────────────────────


class TestSyslogHandleDatagram:
    async def test_publishes_event_to_queue(self) -> None:
        queue = InMemoryQueue()
        await queue.start()

        conn = SyslogUDPConnector(_make_config(), queue)
        data = _encode("<34>Oct 11 22:14:15 myhost su: test message\n")
        addr = ("10.0.0.1", 12345)

        published: list[tuple[str, dict]] = []

        async def _capture(topic: str, msg: dict) -> None:
            published.append((topic, msg))

        with patch.object(queue, "publish", side_effect=_capture):
            await conn._handle_datagram(data, addr)

        assert len(published) == 1
        topic, event = published[0]
        assert topic == Topic.RAW_SYSLOG
        assert event["host"] == "10.0.0.1"
        await queue.stop()

    async def test_increments_events_total(self) -> None:
        conn = _make_connector()
        assert conn.health.events_total == 0

        with patch.object(conn.queue, "publish", new=AsyncMock()):
            await conn._handle_datagram(
                _encode("<13>Oct  1 12:00:00 host1 myapp: hello"),
                ("1.2.3.4", 9999),
            )

        assert conn.health.events_total == 1

    async def test_updates_last_event_at(self) -> None:
        conn = _make_connector()
        assert conn.health.last_event_at is None

        with patch.object(conn.queue, "publish", new=AsyncMock()):
            await conn._handle_datagram(
                _encode("<13>Oct  1 12:00:00 host1 myapp: hello"),
                ("1.2.3.4", 9999),
            )

        assert conn.health.last_event_at is not None

    async def test_publish_error_increments_errors_total(self) -> None:
        conn = _make_connector()
        with patch.object(
            conn.queue, "publish", new=AsyncMock(side_effect=RuntimeError("queue full"))
        ):
            await conn._handle_datagram(
                _encode("<13>Oct  1 12:00:00 host1 myapp: hello"),
                ("1.2.3.4", 9999),
            )

        assert conn.health.errors_total == 1

    async def test_publish_error_sets_error_message(self) -> None:
        conn = _make_connector()
        with patch.object(
            conn.queue, "publish", new=AsyncMock(side_effect=RuntimeError("queue full"))
        ):
            await conn._handle_datagram(
                _encode("<13>Oct  1 12:00:00 host1 myapp: hello"),
                ("1.2.3.4", 9999),
            )

        assert "queue full" in conn.health.error_message


# ── _SyslogProtocol ────────────────────────────────────────────────────────────


class TestSyslogProtocol:
    async def test_datagram_received_schedules_handle_datagram(self) -> None:
        conn = _make_connector()
        conn._handle_datagram = AsyncMock()
        protocol = _SyslogProtocol(conn)

        data = _encode("<34>Oct 11 22:14:15 myhost su: test\n")
        addr = ("10.0.0.2", 12000)

        protocol.datagram_received(data, addr)
        await asyncio.sleep(0)  # allow the scheduled task to run

        conn._handle_datagram.assert_called_once_with(data, addr)

    async def test_oversized_datagram_is_dropped(self) -> None:
        conn = _make_connector(max_message_size=100)
        conn._handle_datagram = AsyncMock()
        protocol = _SyslogProtocol(conn)

        large_data = b"X" * 200
        protocol.datagram_received(large_data, ("10.0.0.3", 12001))
        await asyncio.sleep(0)

        conn._handle_datagram.assert_not_called()

    def test_error_received_increments_errors_total(self) -> None:
        conn = _make_connector()
        protocol = _SyslogProtocol(conn)
        assert conn.health.errors_total == 0
        protocol.error_received(OSError("network error"))
        assert conn.health.errors_total == 1


# ── _parse_syslog() — RFC 3164 ─────────────────────────────────────────────────


class TestParseRFC3164:
    """RFC 3164 (BSD syslog) format parsing."""

    def test_extracts_facility_from_pri(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode("<34>Oct 11 22:14:15 host su: msg"), ("127.0.0.1", 1))
        # PRI=34 → facility=4 (auth)
        assert event["facility"] == 4

    def test_extracts_severity_from_pri(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode("<34>Oct 11 22:14:15 host su: msg"), ("127.0.0.1", 1))
        # PRI=34 → severity=2 (critical)
        assert event["severity"] == 2

    def test_extracts_timestamp(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(
            _encode("<34>Oct 11 22:14:15 mymachine su: message"), ("127.0.0.1", 1)
        )
        assert event["timestamp"] == "Oct 11 22:14:15"

    def test_extracts_hostname(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(
            _encode("<34>Oct 11 22:14:15 mymachine su: message"), ("127.0.0.1", 1)
        )
        assert event["hostname"] == "mymachine"

    def test_extracts_app_name_from_tag(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(
            _encode("<34>Oct 11 22:14:15 host su: message"), ("127.0.0.1", 1)
        )
        assert event["app_name"] == "su"

    def test_extracts_process_id_from_tag(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(
            _encode("<34>Oct 11 22:14:15 host myapp[1234]: message"), ("127.0.0.1", 1)
        )
        assert event["process_id"] == "1234"

    def test_extracts_message_body(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(
            _encode("<34>Oct 11 22:14:15 host su: hello world"), ("127.0.0.1", 1)
        )
        assert event["message"] == "hello world"

    def test_message_without_tag(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(
            _encode("<34>Oct 11 22:14:15 mymachine raw message here"), ("127.0.0.1", 1)
        )
        assert event["hostname"] == "mymachine"
        assert event["message"] is not None

    def test_source_field_is_syslog(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode("<34>Oct 11 22:14:15 host su: msg"), ("127.0.0.1", 1))
        assert event["_source"] == "syslog"

    def test_host_field_from_addr(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode("<34>Oct 11 22:14:15 host su: msg"), ("192.168.1.50", 514))
        assert event["host"] == "192.168.1.50"

    def test_port_field_from_addr(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode("<34>Oct 11 22:14:15 host su: msg"), ("127.0.0.1", 54321))
        assert event["port"] == 54321

    def test_raw_field_is_original_string(self) -> None:
        msg = "<34>Oct 11 22:14:15 host su: original"
        conn = _make_connector()
        event = conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))
        assert event["raw"] == msg

    def test_space_padded_day(self) -> None:
        """RFC 3164 allows single-digit days padded with a space: 'Jan  1 ...'"""
        conn = _make_connector()
        event = conn._parse_syslog(
            _encode("<13>Jan  1 00:00:00 myhost crond[99]: task started"), ("127.0.0.1", 1)
        )
        assert event["hostname"] == "myhost"
        assert event["app_name"] == "crond"
        assert event["process_id"] == "99"

    def test_facility_name_is_auth(self) -> None:
        # PRI=34 → facility=4 → "auth"
        conn = _make_connector()
        event = conn._parse_syslog(_encode("<34>Oct 11 22:14:15 host su: msg"), ("127.0.0.1", 1))
        assert event["facility_name"] == "auth"

    def test_severity_name_is_critical(self) -> None:
        # PRI=34 → severity=2 → "critical"
        conn = _make_connector()
        event = conn._parse_syslog(_encode("<34>Oct 11 22:14:15 host su: msg"), ("127.0.0.1", 1))
        assert event["severity_name"] == "critical"


# ── _parse_syslog() — RFC 5424 ─────────────────────────────────────────────────


class TestParseRFC5424:
    """RFC 5424 syslog format parsing."""

    _SAMPLE = (
        "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - message body"
    )

    def test_detects_rfc5424_format(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode(self._SAMPLE), ("127.0.0.1", 1))
        # RFC 5424: timestamp is ISO 8601
        assert "T" in event["timestamp"] or event["timestamp"].startswith("2003")

    def test_extracts_facility(self) -> None:
        conn = _make_connector()
        # PRI=165 → facility=20 (local4)
        event = conn._parse_syslog(_encode(self._SAMPLE), ("127.0.0.1", 1))
        assert event["facility"] == 20

    def test_extracts_severity(self) -> None:
        conn = _make_connector()
        # PRI=165 → severity=5 (notice)
        event = conn._parse_syslog(_encode(self._SAMPLE), ("127.0.0.1", 1))
        assert event["severity"] == 5

    def test_extracts_iso_timestamp(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode(self._SAMPLE), ("127.0.0.1", 1))
        assert event["timestamp"] == "2003-08-24T05:14:15.000003-07:00"

    def test_extracts_hostname(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode(self._SAMPLE), ("127.0.0.1", 1))
        assert event["hostname"] == "192.0.2.1"

    def test_extracts_app_name(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode(self._SAMPLE), ("127.0.0.1", 1))
        assert event["app_name"] == "myproc"

    def test_extracts_process_id(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode(self._SAMPLE), ("127.0.0.1", 1))
        assert event["process_id"] == "8710"

    def test_nil_hostname_maps_to_none(self) -> None:
        msg = "<165>1 2003-08-24T05:14:15Z - myproc 8710 - - the message"
        conn = _make_connector()
        event = conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))
        assert event["hostname"] is None

    def test_nil_app_name_maps_to_none(self) -> None:
        msg = "<165>1 2003-08-24T05:14:15Z myhost - 8710 - - the message"
        conn = _make_connector()
        event = conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))
        assert event["app_name"] is None

    def test_nil_process_id_maps_to_none(self) -> None:
        msg = "<165>1 2003-08-24T05:14:15Z myhost myapp - - - the message"
        conn = _make_connector()
        event = conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))
        assert event["process_id"] is None

    def test_nil_timestamp_falls_back_to_utc_now(self) -> None:
        msg = "<165>1 - myhost myapp 123 - - the message"
        conn = _make_connector()
        before = datetime.now(timezone.utc)
        event = conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))
        after = datetime.now(timezone.utc)
        # Timestamp should be a valid ISO string close to now
        ts = datetime.fromisoformat(event["timestamp"])
        assert before.timestamp() - 1 <= ts.timestamp() <= after.timestamp() + 1

    def test_extracts_message_after_nil_sd(self) -> None:
        msg = "<165>1 2003-08-24T05:14:15Z host app 1 - - the actual message"
        conn = _make_connector()
        event = conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))
        assert event["message"] == "the actual message"

    def test_extracts_message_after_structured_data(self) -> None:
        msg = '<165>1 2003-08-24T05:14:15Z host app 1 - [exampleSDID@32473 iut="3"] actual message'
        conn = _make_connector()
        event = conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))
        assert "actual message" in event["message"]

    def test_facility_name_is_local4(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode(self._SAMPLE), ("127.0.0.1", 1))
        assert event["facility_name"] == "local4"

    def test_severity_name_is_notice(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(_encode(self._SAMPLE), ("127.0.0.1", 1))
        assert event["severity_name"] == "notice"


# ── _parse_syslog() — fallback and edge cases ──────────────────────────────────


class TestParseSyslogEdgeCases:
    def test_no_pri_returns_raw_message(self) -> None:
        msg = "plain text without PRI"
        conn = _make_connector()
        event = conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))
        assert event["message"] == msg
        assert event["facility"] is None
        assert event["severity"] is None

    def test_binary_safe_non_utf8_bytes(self) -> None:
        data = b"<34>Oct 11 22:14:15 host su: \xff\xfe invalid bytes"
        conn = _make_connector()
        # Should not raise
        event = conn._parse_syslog(data, ("127.0.0.1", 1))
        assert "_source" in event

    def test_empty_bytes(self) -> None:
        conn = _make_connector()
        event = conn._parse_syslog(b"", ("127.0.0.1", 1))
        assert event["_source"] == "syslog"
        assert event["facility"] is None

    def test_trailing_newline_stripped(self) -> None:
        msg = "<34>Oct 11 22:14:15 host su: message\n"
        conn = _make_connector()
        event = conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))
        assert event["raw"] == msg.rstrip("\n\r\x00")


# ── Priority decoding ─────────────────────────────────────────────────────────


class TestPriorityDecoding:
    """Verify PRI → facility/severity decoding for well-known values."""

    def _parse_pri(self, pri: int) -> dict:
        conn = _make_connector()
        msg = f"<{pri}>Oct 11 22:14:15 host tag: msg"
        return conn._parse_syslog(_encode(msg), ("127.0.0.1", 1))

    def test_pri_0_facility_kern(self) -> None:
        event = self._parse_pri(0)
        assert event["facility"] == 0
        assert event["facility_name"] == "kern"

    def test_pri_0_severity_emergency(self) -> None:
        event = self._parse_pri(0)
        assert event["severity"] == 0
        assert event["severity_name"] == "emergency"

    def test_pri_1_severity_alert(self) -> None:
        event = self._parse_pri(1)
        assert event["severity"] == 1
        assert event["severity_name"] == "alert"

    def test_pri_8_facility_user(self) -> None:
        event = self._parse_pri(8)
        assert event["facility"] == 1
        assert event["facility_name"] == "user"

    def test_pri_13_facility_user_severity_notice(self) -> None:
        event = self._parse_pri(13)
        assert event["facility"] == 1
        assert event["severity"] == 5
        assert event["facility_name"] == "user"
        assert event["severity_name"] == "notice"

    def test_pri_34_facility_auth_severity_critical(self) -> None:
        event = self._parse_pri(34)
        assert event["facility"] == 4
        assert event["severity"] == 2
        assert event["facility_name"] == "auth"
        assert event["severity_name"] == "critical"

    def test_pri_165_facility_local4_severity_notice(self) -> None:
        event = self._parse_pri(165)
        assert event["facility"] == 20
        assert event["severity"] == 5
        assert event["facility_name"] == "local4"
        assert event["severity_name"] == "notice"

    def test_all_8_severity_levels_present(self) -> None:
        assert len(SEVERITY_NAMES) == 8
        names = set(SEVERITY_NAMES)
        for expected in ("emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"):
            assert expected in names

    def test_out_of_range_facility_uses_generic_name(self) -> None:
        event: dict[str, Any] = {
            "facility": None, "severity": None,
            "facility_name": None, "severity_name": None,
        }
        # facility 30 is out of the 0-23 standard range
        _fill_priority(event, 30 * 8)
        assert event["facility"] == 30
        assert event["facility_name"] == "facility30"


# ── _extract_msg_from_sd() helper ─────────────────────────────────────────────


class TestExtractMsgFromSd:
    def test_nil_sd_returns_msg(self) -> None:
        assert _extract_msg_from_sd("- hello world") == "hello world"

    def test_empty_string_returns_empty(self) -> None:
        assert _extract_msg_from_sd("") == ""

    def test_single_sd_element_returns_msg(self) -> None:
        result = _extract_msg_from_sd('[origin ip="10.0.0.1"] the message')
        assert result == "the message"

    def test_multiple_sd_elements_returns_msg(self) -> None:
        result = _extract_msg_from_sd('[a k="v"][b k2="v2"] msg after')
        assert result == "msg after"

    def test_unknown_format_returns_raw(self) -> None:
        raw = "some unknown sd format"
        assert _extract_msg_from_sd(raw) == raw


# ── stop() ────────────────────────────────────────────────────────────────────


class TestSyslogStop:
    async def test_stop_closes_transport(self) -> None:
        conn = _make_connector()
        mock_transport = MagicMock()
        conn._transport = mock_transport
        conn._stop_event.set()  # prevent _poll_loop from blocking

        await conn.stop()

        mock_transport.close.assert_called_once()

    async def test_stop_sets_transport_to_none(self) -> None:
        conn = _make_connector()
        mock_transport = MagicMock()
        conn._transport = mock_transport
        conn._stop_event.set()

        await conn.stop()

        assert conn._transport is None

    async def test_stop_sets_protocol_to_none(self) -> None:
        conn = _make_connector()
        conn._transport = MagicMock()
        conn._protocol = MagicMock()
        conn._stop_event.set()

        await conn.stop()

        assert conn._protocol is None

    async def test_stop_when_transport_is_none_does_not_raise(self) -> None:
        conn = _make_connector()
        # transport is None (never connected)
        conn._stop_event.set()
        await conn.stop()  # must not raise


# ── Registry integration ──────────────────────────────────────────────────────


class TestSyslogRegistryIntegration:
    def test_build_connector_creates_syslog_connector(self) -> None:
        import json
        from app.connectors.registry import build_connector

        mock_db_conn = MagicMock()
        mock_db_conn.id = "syslog-uuid-001"
        mock_db_conn.name = "syslog-main"
        mock_db_conn.connector_type = "syslog"
        mock_db_conn.enabled = True
        mock_db_conn.config_json = json.dumps({"host": "0.0.0.0", "port": 514})
        mock_db_conn.last_seen_at = None

        conn = build_connector(mock_db_conn, InMemoryQueue())
        assert isinstance(conn, SyslogUDPConnector)

    def test_build_connector_sets_status_callback(self) -> None:
        import json
        from app.connectors.registry import build_connector

        mock_db_conn = MagicMock()
        mock_db_conn.id = "syslog-uuid-002"
        mock_db_conn.name = "syslog-cb"
        mock_db_conn.connector_type = "syslog"
        mock_db_conn.enabled = True
        mock_db_conn.config_json = json.dumps({})
        mock_db_conn.last_seen_at = None

        conn = build_connector(mock_db_conn, InMemoryQueue())
        assert isinstance(conn, SyslogUDPConnector)
        assert conn._status_callback is not None

    def test_build_connector_name_matches_db_row(self) -> None:
        import json
        from app.connectors.registry import build_connector

        mock_db_conn = MagicMock()
        mock_db_conn.id = "syslog-uuid-003"
        mock_db_conn.name = "syslog-prod"
        mock_db_conn.connector_type = "syslog"
        mock_db_conn.enabled = True
        mock_db_conn.config_json = json.dumps({"port": 5140})
        mock_db_conn.last_seen_at = None

        conn = build_connector(mock_db_conn, InMemoryQueue())
        assert conn.config.name == "syslog-prod"

    def test_syslog_connector_type_in_registry(self) -> None:
        from app.connectors.registry import CONNECTOR_TYPES
        assert "syslog" in CONNECTOR_TYPES
        assert CONNECTOR_TYPES["syslog"] is SyslogUDPConnector

    def test_raw_syslog_topic_exists(self) -> None:
        from app.pipeline.queue import Topic
        assert hasattr(Topic, "RAW_SYSLOG")
        assert Topic.RAW_SYSLOG == "mxtac.raw.syslog"


# ── Factory ────────────────────────────────────────────────────────────────────


class TestSyslogFactory:
    def test_factory_creates_syslog_connector(self) -> None:
        conn = SyslogUDPConnectorFactory.from_dict({"name": "syslog-test"}, InMemoryQueue())
        assert isinstance(conn, SyslogUDPConnector)

    def test_factory_sets_name(self) -> None:
        conn = SyslogUDPConnectorFactory.from_dict({"name": "my-syslog"}, InMemoryQueue())
        assert conn.config.name == "my-syslog"

    def test_factory_default_name(self) -> None:
        conn = SyslogUDPConnectorFactory.from_dict({}, InMemoryQueue())
        assert conn.config.name == "syslog"

    def test_factory_sets_host(self) -> None:
        conn = SyslogUDPConnectorFactory.from_dict({"host": "10.0.0.1"}, InMemoryQueue())
        assert conn.config.extra["host"] == "10.0.0.1"

    def test_factory_sets_port(self) -> None:
        conn = SyslogUDPConnectorFactory.from_dict({"port": 5141}, InMemoryQueue())
        assert conn.config.extra["port"] == 5141

    def test_factory_sets_max_message_size(self) -> None:
        conn = SyslogUDPConnectorFactory.from_dict({"max_message_size": 4096}, InMemoryQueue())
        assert conn._max_message_size == 4096
