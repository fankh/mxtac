"""
Tests for ZeekConnector.

Feature 6.9 — Tail Zeek log directory — conn.log, dns.log, http.log, ssl.log:
  - Initialization: file_positions empty on init, topic is RAW_ZEEK, health inactive
  - _connect(): raises ConnectionError on missing directory, initializes file positions
    to end of existing log files, ignores non-existent files, only initializes
    configured log types
  - _fetch_events(): skips non-existent files, yields JSON events tagged with _log_type,
    skips # comment lines, skips blank lines, falls back to TSV parser on non-JSON,
    skips unparseable TSV lines, tracks file position after read, does not re-read
    already consumed lines, picks up newly appended lines, reads from multiple log types,
    yields multiple events from one file
  - _parse_tsv_line(): parses conn/dns/http/ssl TSV, returns None for unknown log type,
    returns None for too-few fields, returns None on exception
  - Publish (via _poll_loop): events published to mxtac.raw.zeek, topic is literal string,
    payload published unchanged, events_total increments per event, no publish when
    fetch yields nothing, errors caught without crash, errors_total increments, last_event_at
    updated after publish
  - ZeekConnectorFactory: creates ZeekConnector, name/log_dir/log_types/poll_interval
    defaults and overrides, connector_type is "zeek"
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from app.connectors.base import ConnectorConfig, ConnectorStatus
from app.connectors.zeek import LOG_SUFFIXES, ZeekConnector, ZeekConnectorFactory
from app.pipeline.queue import InMemoryQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_config(log_dir: str = "/opt/zeek/logs/current", **extra_overrides: Any) -> ConnectorConfig:
    return ConnectorConfig(
        name="zeek-test",
        connector_type="zeek",
        enabled=True,
        poll_interval_seconds=60,
        extra={
            "log_dir":   log_dir,
            "log_types": ["conn", "dns", "http", "ssl"],
            **extra_overrides,
        },
    )


# ── Initialization ─────────────────────────────────────────────────────────────


class TestZeekConnectorInit:
    def test_file_positions_empty_on_init(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        assert conn._file_positions == {}

    def test_topic_is_raw_zeek(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        assert conn.topic == Topic.RAW_ZEEK

    def test_topic_literal_string(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        assert conn.topic == "mxtac.raw.zeek"

    def test_health_status_is_inactive(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        assert conn.health.status == ConnectorStatus.INACTIVE


# ── _connect() ─────────────────────────────────────────────────────────────────


class TestZeekConnectorConnect:
    async def test_connect_raises_on_missing_directory(self) -> None:
        conn = ZeekConnector(_make_config("/nonexistent/zeek/path"), InMemoryQueue())
        with pytest.raises(ConnectionError, match="/nonexistent/zeek/path"):
            await conn._connect()

    async def test_connect_succeeds_with_valid_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            await conn._connect()  # must not raise

    async def test_connect_initializes_positions_to_end_of_existing_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            conn_log.write_text('{"ts": "1.0"}\n{"ts": "2.0"}\n')
            expected_size = conn_log.stat().st_size

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            await conn._connect()

            assert conn._file_positions[str(conn_log)] == expected_size

    async def test_connect_ignores_nonexistent_log_files(self) -> None:
        """Files not yet created must not appear in _file_positions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            await conn._connect()
            assert conn._file_positions == {}

    async def test_connect_initializes_multiple_existing_log_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ("conn.log", "dns.log"):
                (Path(tmpdir) / name).write_text("line1\n")

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            await conn._connect()

            assert str(Path(tmpdir) / "conn.log") in conn._file_positions
            assert str(Path(tmpdir) / "dns.log") in conn._file_positions

    async def test_connect_only_initializes_configured_log_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ("conn.log", "ssl.log"):
                (Path(tmpdir) / name).write_text("data\n")

            conn = ZeekConnector(
                ConnectorConfig(
                    name="zeek-test",
                    connector_type="zeek",
                    enabled=True,
                    poll_interval_seconds=60,
                    extra={"log_dir": tmpdir, "log_types": ["conn"]},
                ),
                InMemoryQueue(),
            )
            await conn._connect()

            assert str(Path(tmpdir) / "conn.log") in conn._file_positions
            assert str(Path(tmpdir) / "ssl.log") not in conn._file_positions


# ── _fetch_events() ────────────────────────────────────────────────────────────


class TestZeekConnectorFetchEvents:
    async def test_yields_nothing_when_no_log_files_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]
            assert events == []

    async def test_yields_json_events_from_conn_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            conn_log.write_text('{"ts": "1.0", "uid": "Conn001"}\n')

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]

            assert len(events) == 1
            assert events[0]["uid"] == "Conn001"

    async def test_json_event_tagged_with_log_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            conn_log.write_text('{"ts": "1.0"}\n')

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]

            assert events[0]["_log_type"] == "conn"

    async def test_dns_log_events_tagged_dns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dns_log = Path(tmpdir) / "dns.log"
            dns_log.write_text('{"ts": "1.0", "query": "example.com"}\n')

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]

            assert events[0]["_log_type"] == "dns"

    async def test_skips_comment_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            conn_log.write_text("#separator \\x09\n#fields ts uid\n")

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]
            assert events == []

    async def test_skips_blank_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            conn_log.write_text('\n\n{"ts": "1.0"}\n\n')

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]
            assert len(events) == 1

    async def test_falls_back_to_tsv_on_non_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            # Valid TSV conn line with ≥12 fields
            tsv = "\t".join(["1.0", "Conn1", "10.0.0.1", "1234", "1.1.1.1", "53",
                              "tcp", "dns", "-", "-", "-", "S1"])
            conn_log.write_text(tsv + "\n")

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]

            assert len(events) == 1
            assert events[0]["_log_type"] == "conn"
            assert events[0]["id.orig_h"] == "10.0.0.1"

    async def test_skips_unparseable_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            conn_log.write_text("this is not json or valid tsv\n")

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]
            assert events == []

    async def test_tracks_file_position_after_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            conn_log.write_text('{"ts": "1.0"}\n')
            expected_pos = conn_log.stat().st_size

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            [e async for e in conn._fetch_events()]

            assert conn._file_positions[str(conn_log)] == expected_pos

    async def test_does_not_re_read_already_consumed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            conn_log.write_text('{"ts": "1.0"}\n')

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            first_batch = [e async for e in conn._fetch_events()]
            assert len(first_batch) == 1

            second_batch = [e async for e in conn._fetch_events()]
            assert second_batch == []

    async def test_picks_up_newly_appended_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            conn_log.write_text('{"ts": "1.0"}\n')

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            [e async for e in conn._fetch_events()]  # consume existing line

            with conn_log.open("a") as f:
                f.write('{"ts": "2.0"}\n')

            second_batch = [e async for e in conn._fetch_events()]
            assert len(second_batch) == 1
            assert second_batch[0]["ts"] == "2.0"

    async def test_reads_from_multiple_log_type_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "conn.log").write_text('{"ts": "1.0", "uid": "conn1"}\n')
            (Path(tmpdir) / "dns.log").write_text('{"ts": "2.0", "uid": "dns1"}\n')

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]

            log_types = {e["_log_type"] for e in events}
            assert "conn" in log_types
            assert "dns" in log_types

    async def test_yields_multiple_events_from_single_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_log = Path(tmpdir) / "conn.log"
            lines = [json.dumps({"ts": str(i), "uid": f"uid{i}"}) for i in range(5)]
            conn_log.write_text("\n".join(lines) + "\n")

            conn = ZeekConnector(_make_config(tmpdir), InMemoryQueue())
            events = [e async for e in conn._fetch_events()]
            assert len(events) == 5


# ── _parse_tsv_line() ──────────────────────────────────────────────────────────


class TestZeekConnectorParseTsvLine:
    def _conn(self) -> ZeekConnector:
        return ZeekConnector(_make_config(), InMemoryQueue())

    # conn.log ─────────────────────────────────────────────────────────────────

    def test_parses_conn_tsv_minimum_fields(self) -> None:
        conn = self._conn()
        line = "\t".join(["1.0", "uid1", "10.0.0.1", "1234", "1.1.1.1", "80"])
        result = conn._parse_tsv_line(line, "conn")
        assert result is not None
        assert result["_log_type"] == "conn"
        assert result["id.orig_h"] == "10.0.0.1"
        assert result["id.resp_p"] == "80"

    def test_parses_conn_tsv_proto_and_service(self) -> None:
        conn = self._conn()
        line = "\t".join(["1.0", "uid1", "10.0.0.1", "1234", "1.1.1.1", "80", "tcp", "http"])
        result = conn._parse_tsv_line(line, "conn")
        assert result is not None
        assert result["proto"] == "tcp"
        assert result["service"] == "http"

    def test_parses_conn_tsv_conn_state(self) -> None:
        conn = self._conn()
        parts = ["1.0", "uid1", "10.0.0.1", "1234", "1.1.1.1", "80",
                 "tcp", "http", "-", "-", "-", "S1"]
        result = conn._parse_tsv_line("\t".join(parts), "conn")
        assert result is not None
        assert result["conn_state"] == "S1"

    def test_conn_tsv_conn_state_none_when_too_few_parts(self) -> None:
        conn = self._conn()
        line = "\t".join(["1.0", "uid1", "10.0.0.1", "1234", "1.1.1.1", "80", "tcp"])
        result = conn._parse_tsv_line(line, "conn")
        assert result is not None
        assert result["conn_state"] is None

    # dns.log ──────────────────────────────────────────────────────────────────

    def test_parses_dns_tsv_log_type(self) -> None:
        conn = self._conn()
        parts = ["1.0", "uid1", "10.0.0.1", "1234", "8.8.8.8", "53",
                 "udp", "-", "-", "example.com"]
        result = conn._parse_tsv_line("\t".join(parts), "dns")
        assert result is not None
        assert result["_log_type"] == "dns"

    def test_parses_dns_tsv_query(self) -> None:
        conn = self._conn()
        parts = ["1.0", "uid1", "10.0.0.1", "1234", "8.8.8.8", "53",
                 "udp", "-", "-", "example.com"]
        result = conn._parse_tsv_line("\t".join(parts), "dns")
        assert result is not None
        assert result["query"] == "example.com"

    def test_parses_dns_tsv_addresses(self) -> None:
        conn = self._conn()
        parts = ["1.0", "uid1", "10.0.0.1", "1234", "8.8.8.8", "53"]
        result = conn._parse_tsv_line("\t".join(parts), "dns")
        assert result is not None
        assert result["id.orig_h"] == "10.0.0.1"
        assert result["id.resp_h"] == "8.8.8.8"

    # http.log ─────────────────────────────────────────────────────────────────

    def test_parses_http_tsv_log_type(self) -> None:
        conn = self._conn()
        parts = ["1.0", "uid1", "10.0.0.1", "1234", "1.2.3.4", "80",
                 "-", "GET", "example.com", "/index.html"]
        result = conn._parse_tsv_line("\t".join(parts), "http")
        assert result is not None
        assert result["_log_type"] == "http"

    def test_parses_http_tsv_method_host_uri(self) -> None:
        conn = self._conn()
        parts = ["1.0", "uid1", "10.0.0.1", "1234", "1.2.3.4", "80",
                 "-", "GET", "example.com", "/path"]
        result = conn._parse_tsv_line("\t".join(parts), "http")
        assert result is not None
        assert result["method"] == "GET"
        assert result["host"] == "example.com"
        assert result["uri"] == "/path"

    # ssl.log ──────────────────────────────────────────────────────────────────

    def test_parses_ssl_tsv_log_type(self) -> None:
        conn = self._conn()
        parts = ["1.0", "uid1", "10.0.0.1", "1234", "1.2.3.4", "443",
                 "TLSv12", "TLS_AES_256_GCM_SHA384"]
        result = conn._parse_tsv_line("\t".join(parts), "ssl")
        assert result is not None
        assert result["_log_type"] == "ssl"

    def test_parses_ssl_tsv_version_and_cipher(self) -> None:
        conn = self._conn()
        parts = ["1.0", "uid1", "10.0.0.1", "1234", "1.2.3.4", "443",
                 "TLSv12", "TLS_AES_256_GCM_SHA384"]
        result = conn._parse_tsv_line("\t".join(parts), "ssl")
        assert result is not None
        assert result["version"] == "TLSv12"
        assert result["cipher"] == "TLS_AES_256_GCM_SHA384"

    # edge cases ───────────────────────────────────────────────────────────────

    def test_returns_none_for_unknown_log_type(self) -> None:
        conn = self._conn()
        result = conn._parse_tsv_line("1.0\tuid\t10.0.0.1\t-\t-\t-", "files")
        assert result is None

    def test_conn_returns_none_for_too_few_fields(self) -> None:
        conn = self._conn()
        result = conn._parse_tsv_line("1.0\tuid1", "conn")
        assert result is None

    def test_dns_returns_none_for_too_few_fields(self) -> None:
        conn = self._conn()
        result = conn._parse_tsv_line("1.0\tuid1", "dns")
        assert result is None

    def test_http_returns_none_for_too_few_fields(self) -> None:
        conn = self._conn()
        result = conn._parse_tsv_line("1.0\tuid1", "http")
        assert result is None

    def test_ssl_returns_none_for_too_few_fields(self) -> None:
        conn = self._conn()
        result = conn._parse_tsv_line("1.0\tuid1", "ssl")
        assert result is None

    def test_returns_none_on_empty_string(self) -> None:
        conn = self._conn()
        result = conn._parse_tsv_line("", "conn")
        assert result is None


# ── Publish (via _poll_loop) ───────────────────────────────────────────────────


class TestZeekConnectorPublish:
    """Events from _fetch_events() are published to mxtac.raw.zeek."""

    async def test_events_published_to_raw_zeek_topic(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        published_topics: list[str] = []
        original_publish = conn.queue.publish

        async def capture(topic: str, msg: dict) -> None:
            published_topics.append(topic)
            await original_publish(topic, msg)

        conn.queue.publish = capture  # type: ignore[method-assign]

        async def mock_fetch():
            yield {"uid": "abc", "_log_type": "conn"}
            conn._stop_event.set()

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert published_topics == [Topic.RAW_ZEEK]

    async def test_topic_is_literal_mxtac_raw_zeek_string(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        published_topics: list[str] = []
        original_publish = conn.queue.publish

        async def capture(topic: str, msg: dict) -> None:
            published_topics.append(topic)
            await original_publish(topic, msg)

        conn.queue.publish = capture  # type: ignore[method-assign]

        async def mock_fetch():
            yield {"uid": "abc"}
            conn._stop_event.set()

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert published_topics[0] == "mxtac.raw.zeek"

    async def test_event_payload_published_unchanged(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        event = {"uid": "xyz", "_log_type": "dns", "query": "evil.com"}
        published_msgs: list[dict] = []
        original_publish = conn.queue.publish

        async def capture(topic: str, msg: dict) -> None:
            published_msgs.append(msg)
            await original_publish(topic, msg)

        conn.queue.publish = capture  # type: ignore[method-assign]

        async def mock_fetch():
            yield event
            conn._stop_event.set()

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert published_msgs == [event]

    async def test_all_events_in_single_cycle_are_published(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        events = [{"uid": str(i)} for i in range(5)]
        published_msgs: list[dict] = []
        original_publish = conn.queue.publish

        async def capture(topic: str, msg: dict) -> None:
            published_msgs.append(msg)
            await original_publish(topic, msg)

        conn.queue.publish = capture  # type: ignore[method-assign]

        async def mock_fetch():
            for e in events:
                yield e
            conn._stop_event.set()

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert published_msgs == events

    async def test_events_total_increments_per_published_event(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        events = [{"uid": str(i)} for i in range(4)]

        async def mock_fetch():
            for e in events:
                yield e
            conn._stop_event.set()

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert conn.health.events_total == 4

    async def test_last_event_at_set_after_publish(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        assert conn.health.last_event_at is None

        async def mock_fetch():
            yield {"uid": "1"}
            conn._stop_event.set()

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert conn.health.last_event_at is not None

    async def test_no_publish_when_fetch_yields_nothing(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        published: list[dict] = []
        original_publish = conn.queue.publish

        async def capture(topic: str, msg: dict) -> None:
            published.append(msg)
            await original_publish(topic, msg)

        conn.queue.publish = capture  # type: ignore[method-assign]

        async def mock_fetch():
            conn._stop_event.set()
            return
            yield  # noqa: unreachable — makes this an async generator

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert published == []

    async def test_events_total_unchanged_when_fetch_yields_nothing(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())

        async def mock_fetch():
            conn._stop_event.set()
            return
            yield  # noqa: unreachable

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert conn.health.events_total == 0

    async def test_fetch_error_does_not_crash_poll_loop(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())

        async def mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("file read error")
            yield  # noqa: unreachable

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()  # must not raise

    async def test_fetch_error_increments_errors_total(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())

        async def mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("file read error")
            yield  # noqa: unreachable

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert conn.health.errors_total == 1

    async def test_fetch_error_stores_error_message(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())

        async def mock_fetch():
            conn._stop_event.set()
            raise ValueError("unexpected log format")
            yield  # noqa: unreachable

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert conn.health.error_message == "unexpected log format"

    async def test_multiple_events_all_published_to_raw_zeek_topic(self) -> None:
        conn = ZeekConnector(_make_config(), InMemoryQueue())
        events = [{"uid": str(i)} for i in range(8)]
        published_topics: list[str] = []
        original_publish = conn.queue.publish

        async def capture(topic: str, msg: dict) -> None:
            published_topics.append(topic)
            await original_publish(topic, msg)

        conn.queue.publish = capture  # type: ignore[method-assign]

        async def mock_fetch():
            for e in events:
                yield e
            conn._stop_event.set()

        conn._fetch_events = mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert len(published_topics) == 8
        assert all(t == Topic.RAW_ZEEK for t in published_topics)


# ── ZeekConnectorFactory ───────────────────────────────────────────────────────


class TestZeekConnectorFactory:
    def test_from_dict_returns_zeek_connector_instance(self) -> None:
        conn = ZeekConnectorFactory.from_dict(
            {"log_dir": "/opt/zeek/logs/current"},
            InMemoryQueue(),
        )
        assert isinstance(conn, ZeekConnector)

    def test_from_dict_default_name_is_zeek(self) -> None:
        conn = ZeekConnectorFactory.from_dict({}, InMemoryQueue())
        assert conn.config.name == "zeek"

    def test_from_dict_sets_custom_name(self) -> None:
        conn = ZeekConnectorFactory.from_dict(
            {"name": "zeek-prod"},
            InMemoryQueue(),
        )
        assert conn.config.name == "zeek-prod"

    def test_from_dict_sets_log_dir_in_extra(self) -> None:
        conn = ZeekConnectorFactory.from_dict(
            {"log_dir": "/custom/zeek/logs"},
            InMemoryQueue(),
        )
        assert conn.config.extra["log_dir"] == "/custom/zeek/logs"

    def test_from_dict_default_log_dir(self) -> None:
        conn = ZeekConnectorFactory.from_dict({}, InMemoryQueue())
        assert conn.config.extra["log_dir"] == "/opt/zeek/logs/current"

    def test_from_dict_sets_poll_interval(self) -> None:
        conn = ZeekConnectorFactory.from_dict(
            {"poll_interval_seconds": 30},
            InMemoryQueue(),
        )
        assert conn.config.poll_interval_seconds == 30

    def test_from_dict_default_poll_interval_is_60(self) -> None:
        conn = ZeekConnectorFactory.from_dict({}, InMemoryQueue())
        assert conn.config.poll_interval_seconds == 60

    def test_from_dict_connector_type_is_zeek(self) -> None:
        conn = ZeekConnectorFactory.from_dict({}, InMemoryQueue())
        assert conn.config.connector_type == "zeek"

    def test_from_dict_sets_custom_log_types(self) -> None:
        conn = ZeekConnectorFactory.from_dict(
            {"log_types": ["conn", "dns"]},
            InMemoryQueue(),
        )
        assert conn.config.extra["log_types"] == ["conn", "dns"]

    def test_from_dict_default_log_types_include_main_types(self) -> None:
        conn = ZeekConnectorFactory.from_dict({}, InMemoryQueue())
        log_types = conn.config.extra["log_types"]
        assert "conn" in log_types
        assert "dns" in log_types
        assert "http" in log_types
        assert "ssl" in log_types
