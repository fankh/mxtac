"""
Tests for SyslogReceiver (Feature 35.4).

Standalone UDP/TCP syslog receiver started from config settings.

Coverage:
  Initialization:
    - defaults: host "0.0.0.0", port 1514, protocol "udp", max_message_size 65535
    - custom host/port/protocol/max_message_size stored on instance
    - udp_transport is None before start
    - tcp_server is None before start
    - events_total is 0 on init
    - errors_total is 0 on init

  start() — UDP:
    - calls create_datagram_endpoint with correct host and port
    - sets _udp_transport after start
    - _tcp_server remains None for protocol="udp"

  start() — TCP:
    - calls asyncio.start_server with correct host and port
    - sets _tcp_server after start
    - _udp_transport remains None for protocol="tcp"

  start() — both:
    - binds both UDP and TCP
    - sets _udp_transport and _tcp_server

  stop():
    - closes UDP transport and sets _udp_transport to None
    - closes TCP server and sets _tcp_server to None
    - safe when nothing is started (no-op)

  _handle_datagram():
    - decodes bytes and calls _handle_message
    - strips trailing newline / null bytes

  _handle_message():
    - publishes parsed event to Topic.RAW_SYSLOG
    - increments _events_total on success
    - increments _errors_total on publish error
    - does not raise on publish error

  _SyslogUDPProtocol:
    - datagram_received schedules _handle_datagram task
    - oversized datagram is dropped (no task created)
    - error_received logs warning (does not raise)
    - connection_lost with exception logs error

  TCP handler:
    - newline-delimited message is passed to _handle_message
    - multiple messages in a session each call _handle_message
    - empty line is skipped
    - EOF closes connection cleanly
    - idle timeout closes connection cleanly

  parse_syslog():
    RFC 3164:
      - extracts facility and severity from PRI
      - extracts timestamp from header
      - extracts hostname from header
      - extracts app_name (tag) from header
      - extracts process_id (PID) from tag
      - extracts message body
      - message without tag still sets hostname
      - always sets _source to "syslog"
      - always sets host and port from addr
      - always sets raw field

    RFC 5424:
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

    Fallback:
      - no PRI: message is raw string, facility/severity are None
      - binary-safe: non-UTF-8 bytes replaced, no raise

    Priority decoding:
      - PRI=0: facility=kern, severity=emergency
      - PRI=1: facility=kern, severity=alert
      - PRI=8: facility=user, severity=emergency
      - PRI=13: facility=user, severity=notice
      - PRI=34: facility=auth, severity=critical
      - PRI=165: facility=local4, severity=notice
      - out-of-range facility uses "facility{N}" name

  get_status():
    - returns host, port, protocol, events_total, errors_total
    - udp_active True only when UDP transport is set
    - tcp_active True only when TCP server is set

  Config integration:
    - syslog_enabled defaults to False
    - syslog_port defaults to 1514
    - syslog_protocol defaults to "udp"
    - syslog_max_message_size defaults to 65535
"""

from __future__ import annotations

import asyncio
from datetime import timezone
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from app.connectors.syslog_receiver import (
    DEFAULT_HOST,
    DEFAULT_MAX_MESSAGE_SIZE,
    DEFAULT_PORT,
    FACILITY_NAMES,
    SEVERITY_NAMES,
    SyslogReceiver,
    _SyslogUDPProtocol,
    _extract_msg_from_sd,
    _handle_tcp_client,
    parse_syslog,
)
from app.pipeline.queue import InMemoryQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_receiver(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    protocol: str = "udp",
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
) -> SyslogReceiver:
    return SyslogReceiver(
        InMemoryQueue(),
        host=host,
        port=port,
        protocol=protocol,
        max_message_size=max_message_size,
    )


# ── Initialization ─────────────────────────────────────────────────────────────


class TestSyslogReceiverInit:
    def test_default_host(self) -> None:
        r = _make_receiver()
        assert r._host == DEFAULT_HOST

    def test_default_port(self) -> None:
        r = _make_receiver()
        assert r._port == DEFAULT_PORT

    def test_default_port_is_1514(self) -> None:
        r = _make_receiver()
        assert r._port == 1514

    def test_default_protocol(self) -> None:
        r = _make_receiver()
        assert r._protocol == "udp"

    def test_default_max_message_size(self) -> None:
        r = _make_receiver()
        assert r._max_message_size == DEFAULT_MAX_MESSAGE_SIZE

    def test_custom_host(self) -> None:
        r = _make_receiver(host="127.0.0.1")
        assert r._host == "127.0.0.1"

    def test_custom_port(self) -> None:
        r = _make_receiver(port=9999)
        assert r._port == 9999

    def test_custom_protocol_tcp(self) -> None:
        r = _make_receiver(protocol="tcp")
        assert r._protocol == "tcp"

    def test_custom_protocol_both(self) -> None:
        r = _make_receiver(protocol="both")
        assert r._protocol == "both"

    def test_protocol_lowercased(self) -> None:
        r = _make_receiver(protocol="UDP")
        assert r._protocol == "udp"

    def test_custom_max_message_size(self) -> None:
        r = _make_receiver(max_message_size=4096)
        assert r._max_message_size == 4096

    def test_udp_transport_none_before_start(self) -> None:
        r = _make_receiver()
        assert r._udp_transport is None

    def test_tcp_server_none_before_start(self) -> None:
        r = _make_receiver()
        assert r._tcp_server is None

    def test_events_total_zero_on_init(self) -> None:
        r = _make_receiver()
        assert r._events_total == 0

    def test_errors_total_zero_on_init(self) -> None:
        r = _make_receiver()
        assert r._errors_total == 0


# ── start() ────────────────────────────────────────────────────────────────────


class TestSyslogReceiverStartUDP:
    async def test_calls_create_datagram_endpoint(self) -> None:
        r = _make_receiver(host="127.0.0.1", port=5514, protocol="udp")

        mock_transport = MagicMock()
        mock_protocol = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport, mock_protocol)),
        ) as mock_cde:
            await r.start()
            mock_cde.assert_called_once()
            _, kwargs = mock_cde.call_args
            assert kwargs["local_addr"] == ("127.0.0.1", 5514)

    async def test_sets_udp_transport(self) -> None:
        r = _make_receiver(protocol="udp")
        mock_transport = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport, MagicMock())),
        ):
            await r.start()

        assert r._udp_transport is mock_transport

    async def test_tcp_server_remains_none_for_udp(self) -> None:
        r = _make_receiver(protocol="udp")

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(MagicMock(), MagicMock())),
        ):
            await r.start()

        assert r._tcp_server is None


class TestSyslogReceiverStartTCP:
    async def test_calls_start_server(self) -> None:
        r = _make_receiver(host="127.0.0.1", port=5514, protocol="tcp")
        mock_server = MagicMock()

        with patch(
            "app.connectors.syslog_receiver.asyncio.start_server",
            new=AsyncMock(return_value=mock_server),
        ) as mock_ss:
            await r.start()
            mock_ss.assert_called_once()
            _, kwargs = mock_ss.call_args
            assert kwargs["host"] == "127.0.0.1"
            assert kwargs["port"] == 5514

    async def test_sets_tcp_server(self) -> None:
        r = _make_receiver(protocol="tcp")
        mock_server = MagicMock()

        with patch(
            "app.connectors.syslog_receiver.asyncio.start_server",
            new=AsyncMock(return_value=mock_server),
        ):
            await r.start()

        assert r._tcp_server is mock_server

    async def test_udp_transport_remains_none_for_tcp(self) -> None:
        r = _make_receiver(protocol="tcp")

        with patch(
            "app.connectors.syslog_receiver.asyncio.start_server",
            new=AsyncMock(return_value=MagicMock()),
        ):
            await r.start()

        assert r._udp_transport is None


class TestSyslogReceiverStartBoth:
    async def test_binds_both_udp_and_tcp(self) -> None:
        r = _make_receiver(protocol="both")
        mock_transport = MagicMock()
        mock_server = MagicMock()

        with (
            patch.object(
                asyncio.get_event_loop(),
                "create_datagram_endpoint",
                new=AsyncMock(return_value=(mock_transport, MagicMock())),
            ),
            patch(
                "app.connectors.syslog_receiver.asyncio.start_server",
                new=AsyncMock(return_value=mock_server),
            ),
        ):
            await r.start()

        assert r._udp_transport is mock_transport
        assert r._tcp_server is mock_server


# ── stop() ─────────────────────────────────────────────────────────────────────


class TestSyslogReceiverStop:
    async def test_closes_udp_transport(self) -> None:
        r = _make_receiver(protocol="udp")
        mock_transport = MagicMock()
        r._udp_transport = mock_transport

        await r.stop()

        mock_transport.close.assert_called_once()
        assert r._udp_transport is None

    async def test_closes_tcp_server(self) -> None:
        r = _make_receiver(protocol="tcp")
        mock_server = MagicMock()
        mock_server.wait_closed = AsyncMock()
        r._tcp_server = mock_server

        await r.stop()

        mock_server.close.assert_called_once()
        mock_server.wait_closed.assert_called_once()
        assert r._tcp_server is None

    async def test_stop_noop_when_nothing_started(self) -> None:
        r = _make_receiver()
        # Must not raise
        await r.stop()
        assert r._udp_transport is None
        assert r._tcp_server is None

    async def test_stop_closes_both(self) -> None:
        r = _make_receiver(protocol="both")
        mock_transport = MagicMock()
        mock_server = MagicMock()
        mock_server.wait_closed = AsyncMock()
        r._udp_transport = mock_transport
        r._tcp_server = mock_server

        await r.stop()

        mock_transport.close.assert_called_once()
        mock_server.close.assert_called_once()


# ── _handle_datagram() ─────────────────────────────────────────────────────────


class TestHandleDatagram:
    async def test_decodes_bytes_and_calls_handle_message(self) -> None:
        r = _make_receiver()
        raw_msg = "<34>1 2024-01-01T00:00:00Z host app - - - test"
        data = raw_msg.encode("utf-8")
        addr = ("10.0.0.1", 12345)

        called_with: list[tuple] = []

        async def _mock_handle(msg: str, a: tuple) -> None:
            called_with.append((msg, a))

        r._handle_message = _mock_handle  # type: ignore[method-assign]
        await r._handle_datagram(data, addr)

        assert len(called_with) == 1
        assert called_with[0][0] == raw_msg
        assert called_with[0][1] == addr

    async def test_strips_trailing_newline(self) -> None:
        r = _make_receiver()
        data = b"<34>plain message\n"
        addr = ("10.0.0.2", 514)

        received: list[str] = []

        async def _mock_handle(msg: str, a: tuple) -> None:
            received.append(msg)

        r._handle_message = _mock_handle  # type: ignore[method-assign]
        await r._handle_datagram(data, addr)

        assert received[0] == "<34>plain message"

    async def test_strips_trailing_null(self) -> None:
        r = _make_receiver()
        data = b"<34>plain message\x00"
        addr = ("10.0.0.3", 514)

        received: list[str] = []

        async def _mock_handle(msg: str, a: tuple) -> None:
            received.append(msg)

        r._handle_message = _mock_handle  # type: ignore[method-assign]
        await r._handle_datagram(data, addr)

        assert received[0] == "<34>plain message"

    async def test_non_utf8_bytes_replaced(self) -> None:
        r = _make_receiver()
        data = b"<34>bad \xff byte"
        addr = ("10.0.0.4", 514)

        received: list[str] = []

        async def _mock_handle(msg: str, a: tuple) -> None:
            received.append(msg)

        r._handle_message = _mock_handle  # type: ignore[method-assign]
        # Must not raise; replacement character should appear
        await r._handle_datagram(data, addr)
        assert len(received) == 1
        assert "\ufffd" in received[0]


# ── _handle_message() ──────────────────────────────────────────────────────────


class TestHandleMessage:
    async def test_publishes_event_to_raw_syslog(self) -> None:
        queue = MagicMock()
        queue.publish = AsyncMock()
        r = SyslogReceiver(queue, protocol="udp")

        raw = "<34>1 2024-01-15T00:00:00Z myhost myapp - - - hello"
        await r._handle_message(raw, ("192.168.1.1", 51000))

        queue.publish.assert_called_once()
        topic = queue.publish.call_args[0][0]
        assert topic == Topic.RAW_SYSLOG

    async def test_increments_events_total(self) -> None:
        queue = MagicMock()
        queue.publish = AsyncMock()
        r = SyslogReceiver(queue, protocol="udp")

        await r._handle_message("test message", ("192.168.1.1", 514))
        assert r._events_total == 1

        await r._handle_message("another", ("192.168.1.1", 514))
        assert r._events_total == 2

    async def test_increments_errors_total_on_publish_failure(self) -> None:
        queue = MagicMock()
        queue.publish = AsyncMock(side_effect=RuntimeError("queue full"))
        r = SyslogReceiver(queue, protocol="udp")

        await r._handle_message("test", ("10.0.0.1", 514))
        assert r._errors_total == 1

    async def test_does_not_raise_on_publish_failure(self) -> None:
        queue = MagicMock()
        queue.publish = AsyncMock(side_effect=RuntimeError("queue error"))
        r = SyslogReceiver(queue, protocol="udp")

        # Must not raise
        await r._handle_message("test", ("10.0.0.1", 514))

    async def test_published_event_has_source_field(self) -> None:
        queue = MagicMock()
        queue.publish = AsyncMock()
        r = SyslogReceiver(queue, protocol="udp")

        await r._handle_message("test msg", ("10.0.0.1", 514))

        event = queue.publish.call_args[0][1]
        assert event["_source"] == "syslog"


# ── _SyslogUDPProtocol ─────────────────────────────────────────────────────────


class TestSyslogUDPProtocol:
    async def test_datagram_received_schedules_handle_datagram(self) -> None:
        r = _make_receiver()
        received: list[tuple] = []

        async def _fake_handle(data: bytes, addr: tuple) -> None:
            received.append((data, addr))

        r._handle_datagram = _fake_handle  # type: ignore[method-assign]
        protocol = _SyslogUDPProtocol(r)

        data = b"<34>test"
        addr = ("10.0.0.1", 5000)
        protocol.datagram_received(data, addr)

        # Let the scheduled task run
        await asyncio.sleep(0)

        assert len(received) == 1
        assert received[0] == (data, addr)

    async def test_oversized_datagram_is_dropped(self) -> None:
        r = _make_receiver(max_message_size=10)
        scheduled: list = []

        async def _fake_handle(data: bytes, addr: tuple) -> None:
            scheduled.append(data)

        r._handle_datagram = _fake_handle  # type: ignore[method-assign]
        protocol = _SyslogUDPProtocol(r)

        # 11 bytes > max 10
        protocol.datagram_received(b"A" * 11, ("10.0.0.1", 514))
        await asyncio.sleep(0)

        assert scheduled == []

    async def test_within_size_limit_is_forwarded(self) -> None:
        r = _make_receiver(max_message_size=100)
        received: list = []

        async def _fake_handle(data: bytes, addr: tuple) -> None:
            received.append(data)

        r._handle_datagram = _fake_handle  # type: ignore[method-assign]
        protocol = _SyslogUDPProtocol(r)

        data = b"A" * 100  # exactly at limit
        protocol.datagram_received(data, ("10.0.0.1", 514))
        await asyncio.sleep(0)

        assert received == [data]

    def test_error_received_does_not_raise(self) -> None:
        r = _make_receiver()
        protocol = _SyslogUDPProtocol(r)
        # Must not raise
        protocol.error_received(OSError("network unreachable"))

    def test_connection_lost_with_exception_does_not_raise(self) -> None:
        r = _make_receiver()
        protocol = _SyslogUDPProtocol(r)
        # Must not raise
        protocol.connection_lost(OSError("connection reset"))

    def test_connection_lost_with_none_does_not_raise(self) -> None:
        r = _make_receiver()
        protocol = _SyslogUDPProtocol(r)
        # Normal close — must not raise
        protocol.connection_lost(None)


# ── TCP handler ────────────────────────────────────────────────────────────────


class TestHandleTCPClient:
    async def test_single_message_calls_handle_message(self) -> None:
        r = _make_receiver(protocol="tcp")
        received: list[tuple] = []

        async def _fake_handle(msg: str, addr: tuple) -> None:
            received.append((msg, addr))

        r._handle_message = _fake_handle  # type: ignore[method-assign]

        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("192.168.1.50", 40000))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        reader.feed_data(b"<34>test message\n")
        reader.feed_eof()

        await _handle_tcp_client(r, reader, writer)

        assert len(received) == 1
        assert received[0][0] == "<34>test message"
        assert received[0][1] == ("192.168.1.50", 40000)

    async def test_multiple_messages_each_call_handle_message(self) -> None:
        r = _make_receiver(protocol="tcp")
        received: list[str] = []

        async def _fake_handle(msg: str, addr: tuple) -> None:
            received.append(msg)

        r._handle_message = _fake_handle  # type: ignore[method-assign]

        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("10.0.0.1", 12000))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        reader.feed_data(b"<10>first\n<20>second\n<30>third\n")
        reader.feed_eof()

        await _handle_tcp_client(r, reader, writer)

        assert received == ["<10>first", "<20>second", "<30>third"]

    async def test_empty_line_is_skipped(self) -> None:
        r = _make_receiver(protocol="tcp")
        received: list[str] = []

        async def _fake_handle(msg: str, addr: tuple) -> None:
            received.append(msg)

        r._handle_message = _fake_handle  # type: ignore[method-assign]

        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("10.0.0.1", 12000))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        reader.feed_data(b"<10>first\n\n<30>third\n")
        reader.feed_eof()

        await _handle_tcp_client(r, reader, writer)

        assert received == ["<10>first", "<30>third"]

    async def test_eof_closes_writer(self) -> None:
        r = _make_receiver(protocol="tcp")
        r._handle_message = AsyncMock()  # type: ignore[method-assign]

        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("10.0.0.1", 12000))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        reader.feed_eof()

        await _handle_tcp_client(r, reader, writer)

        writer.close.assert_called_once()
        writer.wait_closed.assert_called_once()

    async def test_idle_timeout_closes_connection(self) -> None:
        r = _make_receiver(protocol="tcp")
        r._handle_message = AsyncMock()  # type: ignore[method-assign]

        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("10.0.0.1", 12000))
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        # Patch wait_for to immediately raise TimeoutError so the test is fast
        with patch(
            "app.connectors.syslog_receiver.asyncio.wait_for",
            side_effect=asyncio.TimeoutError,
        ):
            await _handle_tcp_client(r, reader, writer)

        writer.close.assert_called_once()


# ── parse_syslog() — RFC 3164 ──────────────────────────────────────────────────


class TestParseSyslogRFC3164:
    def test_extracts_facility_from_pri(self) -> None:
        # PRI=165 → facility=20 (local4), severity=5 (notice)
        raw = "<165>Jan  1 00:00:00 host sshd[123]: Login attempt"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility"] == 20

    def test_extracts_severity_from_pri(self) -> None:
        raw = "<165>Jan  1 00:00:00 host sshd[123]: Login attempt"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["severity"] == 5

    def test_extracts_timestamp(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost myapp: message"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["timestamp"] == "Jan 15 10:30:45"

    def test_extracts_hostname(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost myapp: message"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["hostname"] == "myhost"

    def test_extracts_app_name_tag(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost sshd: Login accepted"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["app_name"] == "sshd"

    def test_extracts_process_id(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost sshd[4567]: Login accepted"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["process_id"] == "4567"

    def test_extracts_message_body(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost sshd[4567]: Login accepted from 1.2.3.4"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["message"] == "Login accepted from 1.2.3.4"

    def test_hostname_present_without_tag(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost just a plain message"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["hostname"] == "myhost"

    def test_source_always_syslog(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost app: msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["_source"] == "syslog"

    def test_host_from_addr(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost app: msg"
        event = parse_syslog(raw, ("192.168.5.5", 8000))
        assert event["host"] == "192.168.5.5"

    def test_port_from_addr(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost app: msg"
        event = parse_syslog(raw, ("192.168.5.5", 8000))
        assert event["port"] == 8000

    def test_raw_field_set(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost app: msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["raw"] == raw

    def test_process_id_none_without_pid(self) -> None:
        raw = "<34>Jan 15 10:30:45 myhost sshd: no pid here"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["process_id"] is None


# ── parse_syslog() — RFC 5424 ──────────────────────────────────────────────────


class TestParseSyslogRFC5424:
    def test_detects_rfc5424_by_version(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45.123Z myhost myapp 42 MSGID - hello"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        # RFC 5424 sets process_id from the PID field
        assert event["process_id"] == "42"

    def test_extracts_facility(self) -> None:
        # PRI=34 → facility=4 (auth)
        raw = "<34>1 2024-01-15T10:30:45Z myhost myapp 1 - - msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility"] == 4

    def test_extracts_severity(self) -> None:
        # PRI=34 → severity=2 (critical)
        raw = "<34>1 2024-01-15T10:30:45Z myhost myapp 1 - - msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["severity"] == 2

    def test_extracts_iso_timestamp(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45.000Z myhost myapp - - - msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["timestamp"] == "2024-01-15T10:30:45.000Z"

    def test_extracts_hostname(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45Z targethost myapp - - - msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["hostname"] == "targethost"

    def test_extracts_app_name(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45Z myhost sshd - - - Accepted"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["app_name"] == "sshd"

    def test_extracts_process_id(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45Z myhost myapp 9999 - - msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["process_id"] == "9999"

    def test_nil_hostname_maps_to_none(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45Z - myapp - - - msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["hostname"] is None

    def test_nil_app_name_maps_to_none(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45Z myhost - - - - msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["app_name"] is None

    def test_nil_process_id_maps_to_none(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45Z myhost myapp - - - msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["process_id"] is None

    def test_nil_timestamp_falls_back_to_utc(self) -> None:
        raw = "<34>1 - myhost myapp - - - msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        # Should be a valid ISO timestamp (not "-")
        assert event["timestamp"] != "-"
        assert "T" in event["timestamp"] or len(event["timestamp"]) > 5

    def test_extracts_message_after_nil_sd(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45Z myhost myapp 1 MSGID - the message body"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["message"] == "the message body"

    def test_extracts_message_after_structured_data(self) -> None:
        raw = "<34>1 2024-01-15T10:30:45Z myhost myapp 1 - [exampleSDID@32473 iut=\"3\"] message after SD"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["message"] == "message after SD"


# ── parse_syslog() — fallback ──────────────────────────────────────────────────


class TestParseSyslogFallback:
    def test_no_pri_returns_raw_as_message(self) -> None:
        raw = "no priority field here"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["message"] == raw

    def test_no_pri_facility_is_none(self) -> None:
        raw = "plain message without pri"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility"] is None

    def test_no_pri_severity_is_none(self) -> None:
        raw = "plain message without pri"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["severity"] is None

    def test_binary_safe_non_utf8_replaced(self) -> None:
        # Non-UTF-8 bytes are already decoded by _handle_datagram, so
        # parse_syslog receives a string. Test with a replacement char.
        raw = "plain \ufffd message"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert "\ufffd" in event["message"]


# ── parse_syslog() — priority decoding ────────────────────────────────────────


class TestPriority:
    def test_pri_0_facility_kern_severity_emergency(self) -> None:
        raw = "<0>Jan  1 00:00:00 host app: msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility"] == 0
        assert event["severity"] == 0
        assert event["facility_name"] == "kern"
        assert event["severity_name"] == "emergency"

    def test_pri_1_facility_kern_severity_alert(self) -> None:
        raw = "<1>Jan  1 00:00:00 host app: msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility"] == 0
        assert event["severity"] == 1
        assert event["severity_name"] == "alert"

    def test_pri_8_facility_user_severity_emergency(self) -> None:
        raw = "<8>Jan  1 00:00:00 host app: msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility"] == 1
        assert event["severity"] == 0
        assert event["facility_name"] == "user"
        assert event["severity_name"] == "emergency"

    def test_pri_13_facility_user_severity_notice(self) -> None:
        raw = "<13>Jan  1 00:00:00 host app: msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility"] == 1
        assert event["severity"] == 5
        assert event["facility_name"] == "user"
        assert event["severity_name"] == "notice"

    def test_pri_34_facility_auth_severity_critical(self) -> None:
        raw = "<34>Jan  1 00:00:00 host app: msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility"] == 4
        assert event["severity"] == 2
        assert event["facility_name"] == "auth"
        assert event["severity_name"] == "critical"

    def test_pri_165_facility_local4_severity_notice(self) -> None:
        raw = "<165>Jan  1 00:00:00 host app: msg"
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility"] == 20
        assert event["severity"] == 5
        assert event["facility_name"] == "local4"
        assert event["severity_name"] == "notice"

    def test_all_severity_names_present(self) -> None:
        expected = ["emergency", "alert", "critical", "error",
                    "warning", "notice", "informational", "debug"]
        assert list(SEVERITY_NAMES) == expected

    def test_out_of_range_facility_uses_fallback_name(self) -> None:
        # PRI=191 → facility=23 (local7), PRI=192+ wraps beyond table
        # Manually construct an event with a facility beyond the table.
        raw = "<200>Jan  1 00:00:00 host app: msg"  # facility=25, severity=0
        event = parse_syslog(raw, ("10.0.0.1", 514))
        assert event["facility_name"] == "facility25"


# ── _extract_msg_from_sd() ─────────────────────────────────────────────────────


class TestExtractMsgFromSD:
    def test_nil_sd_returns_rest(self) -> None:
        assert _extract_msg_from_sd("- the message") == "the message"

    def test_empty_string_returns_empty(self) -> None:
        assert _extract_msg_from_sd("") == ""

    def test_structured_data_element_extracted(self) -> None:
        sd = '[exampleSDID@32473 iut="3" eventSource="web"] message here'
        assert _extract_msg_from_sd(sd) == "message here"

    def test_multiple_sd_elements_extracted(self) -> None:
        sd = '[a key="val"][b x="y"] final message'
        assert _extract_msg_from_sd(sd) == "final message"

    def test_escaped_bracket_handled(self) -> None:
        sd = '[sd key="v\\"]extra"] msg after'
        result = _extract_msg_from_sd(sd)
        assert "msg after" in result


# ── get_status() ───────────────────────────────────────────────────────────────


class TestGetStatus:
    def test_returns_host(self) -> None:
        r = _make_receiver(host="192.168.1.1")
        assert r.get_status()["host"] == "192.168.1.1"

    def test_returns_port(self) -> None:
        r = _make_receiver(port=1514)
        assert r.get_status()["port"] == 1514

    def test_returns_protocol(self) -> None:
        r = _make_receiver(protocol="both")
        assert r.get_status()["protocol"] == "both"

    def test_returns_events_total(self) -> None:
        r = _make_receiver()
        r._events_total = 42
        assert r.get_status()["events_total"] == 42

    def test_returns_errors_total(self) -> None:
        r = _make_receiver()
        r._errors_total = 7
        assert r.get_status()["errors_total"] == 7

    def test_udp_active_false_before_start(self) -> None:
        r = _make_receiver()
        assert r.get_status()["udp_active"] is False

    def test_udp_active_true_when_transport_set(self) -> None:
        r = _make_receiver()
        r._udp_transport = MagicMock()
        assert r.get_status()["udp_active"] is True

    def test_tcp_active_false_before_start(self) -> None:
        r = _make_receiver()
        assert r.get_status()["tcp_active"] is False

    def test_tcp_active_true_when_server_set(self) -> None:
        r = _make_receiver()
        r._tcp_server = MagicMock()
        assert r.get_status()["tcp_active"] is True


# ── Config integration ─────────────────────────────────────────────────────────


class TestConfigIntegration:
    def test_syslog_enabled_defaults_false(self) -> None:
        from app.core.config import settings
        assert settings.syslog_enabled is False

    def test_syslog_port_defaults_1514(self) -> None:
        from app.core.config import settings
        assert settings.syslog_port == 1514

    def test_syslog_protocol_defaults_udp(self) -> None:
        from app.core.config import settings
        assert settings.syslog_protocol == "udp"

    def test_syslog_max_message_size_defaults_65535(self) -> None:
        from app.core.config import settings
        assert settings.syslog_max_message_size == 65535
