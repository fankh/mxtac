"""
Tests for VelociraptorConnector.

Feature 6.23 — Velociraptor connector — forensic artifacts:

Initialization:
  - client is None on init
  - last_fetched_at defaults to ~1 hour ago when no initial timestamp given
  - initial_last_fetched_at is used when provided
  - topic is mxtac.raw.velociraptor
  - topic literal string is "mxtac.raw.velociraptor"
  - health status is INACTIVE on init
  - _backoff_delay starts at BACKOFF_BASE on init
  - checkpoint_callback defaults to None

_connect():
  - creates httpx AsyncClient on first connect
  - raises ConnectionError when api_url is missing
  - raises ConnectionError when api_key is missing
  - raises ConnectionError when health probe returns no rows
  - raises HTTPStatusError on non-2xx response
  - reuses existing client on re-connect (no second instantiation)
  - sets org_id header when org_id is configured
  - does not set org_id header when org_id is empty
  - strips trailing slash from api_url

_run_vql():
  - yields nothing when client is None
  - yields rows from a streaming response
  - adds _source field with value "velociraptor" to each row
  - skips log-only packets (no Response field)
  - skips blank lines
  - skips non-JSON lines (logs debug message)
  - skips rows that are empty dicts
  - raises RuntimeError on error packet (error field present)
  - raises RuntimeError on Error field (capital E)
  - raises HTTPStatusError on non-2xx streaming response
  - skips packets where Response JSON is malformed

_fetch_events():
  - yields nothing when client is None
  - uses default VQL when artifacts and vql are empty
  - uses artifact VQL when artifacts list is configured
  - uses custom VQL when vql key is configured (overrides artifacts)
  - passes since_epoch derived from _last_fetched_at into VQL
  - passes page_size into VQL template
  - yields events from multiple artifact queries in sequence
  - advances _last_fetched_at after successful fetch
  - calls checkpoint_callback with updated timestamp
  - does not call checkpoint_callback when it is None
  - default VQL contains since_epoch and page_size
  - artifact VQL contains artifact name, since_epoch, and page_size

Exponential backoff:
  - _backoff_delay starts at BACKOFF_BASE (1.0 s)
  - BACKOFF_MAX is exactly 60.0 seconds
  - fetch error doubles _backoff_delay
  - doubling beyond BACKOFF_MAX is capped at BACKOFF_MAX
  - when at BACKOFF_MAX, another error keeps it at BACKOFF_MAX
  - successful cycle resets _backoff_delay to BACKOFF_BASE
  - error does NOT reset _backoff_delay to BACKOFF_BASE

Poll loop integration:
  - publishes each event to mxtac.raw.velociraptor topic
  - health.events_total increments per published event
  - health.last_event_at updated after first publish
  - no publish when fetch yields nothing
  - fetch error caught without crash; health.errors_total increments
  - fetch error stores exception message in health.error_message
  - status_callback called with ACTIVE after successful cycle
  - status_callback called with ERROR after failed cycle

stop():
  - closes httpx client and clears reference
  - safe to call when client is None
  - sets health status to INACTIVE

VelociraptorConnectorFactory:
  - creates VelociraptorConnector instance
  - name defaults to 'velociraptor'
  - poll_interval_seconds defaults to 300
  - required keys (api_url, api_key) are present in extra
  - artifacts defaults to empty list
  - vql defaults to empty string
  - page_size defaults to DEFAULT_PAGE_SIZE
  - verify_ssl defaults to True
  - timeout defaults to 30
  - org_id defaults to empty string
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.connectors.base import ConnectorConfig, ConnectorStatus
from app.connectors.velociraptor import (
    BACKOFF_BASE,
    BACKOFF_MAX,
    DEFAULT_PAGE_SIZE,
    VelociraptorConnector,
    VelociraptorConnectorFactory,
    _ARTIFACT_VQL_TEMPLATE,
    _DEFAULT_VQL_TEMPLATE,
)
from app.pipeline.queue import InMemoryQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_config(**extra_overrides) -> ConnectorConfig:
    return ConnectorConfig(
        name="velociraptor-test",
        connector_type="velociraptor",
        enabled=True,
        poll_interval_seconds=300,
        extra={
            "api_url": "https://velociraptor.test:8889",
            "api_key": "test-api-key",
            "verify_ssl": False,
            **extra_overrides,
        },
    )


class _FakeStreamCtx:
    """Fake async context manager returned by client.stream(...)."""

    def __init__(self, resp: MagicMock) -> None:
        self._resp = resp

    async def __aenter__(self) -> MagicMock:
        return self._resp

    async def __aexit__(self, *args: object) -> None:
        pass


def _make_streaming_response(
    lines: list[str],
    status_code: int = 200,
) -> MagicMock:
    """Build a mock httpx streaming Response that yields *lines* via aiter_lines()."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code

    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    else:
        resp.raise_for_status.return_value = None

    async def _aiter_lines_fn():
        for line in lines:
            yield line

    resp.aiter_lines = MagicMock(side_effect=lambda: _aiter_lines_fn())
    return resp


def _rows_packet(*rows: dict) -> str:
    """JSON-encode a streaming packet containing *rows*."""
    return json.dumps({"Response": json.dumps(list(rows)), "timestamp": 1234567890})


def _log_packet(msg: str = "query completed") -> str:
    """JSON-encode a log-only streaming packet (no Response field)."""
    return json.dumps({"log": msg, "timestamp": 1234567890})


def _error_packet(msg: str, capital: bool = False) -> str:
    """JSON-encode an error streaming packet."""
    key = "Error" if capital else "error"
    return json.dumps({key: msg, "timestamp": 1234567890})


def _health_response_lines() -> list[str]:
    """Return NDJSON lines for a successful health probe."""
    return [_rows_packet({"version": "0.7.0", "_source": "velociraptor"}), _log_packet()]


def _make_stream_client(responses: list[MagicMock]) -> MagicMock:
    """Build a mock httpx.AsyncClient whose .stream() is pre-loaded with *responses*."""
    client = MagicMock()
    client.stream = MagicMock(
        side_effect=[_FakeStreamCtx(r) for r in responses]
    )
    client.aclose = AsyncMock()
    return client


async def _collect(conn: VelociraptorConnector) -> list[dict]:
    """Collect all events from conn._fetch_events()."""
    results = []
    async for event in conn._fetch_events():
        results.append(event)
    return results


async def _collect_vql(conn: VelociraptorConnector, vql: str) -> list[dict]:
    """Collect all rows from conn._run_vql(vql)."""
    results = []
    async for row in conn._run_vql(vql):
        results.append(row)
    return results


# ── Initialization ─────────────────────────────────────────────────────────────


class TestVelociraptorConnectorInit:
    def test_client_is_none_on_init(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        assert conn._client is None

    def test_last_fetched_at_defaults_to_approximately_1_hour_ago(self) -> None:
        before = datetime.now(timezone.utc)
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        after = datetime.now(timezone.utc)
        delta = before - conn._last_fetched_at
        assert 55 * 60 < delta.total_seconds() < 65 * 60
        assert conn._last_fetched_at < after

    def test_initial_last_fetched_at_used_when_provided(self) -> None:
        ts = datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
        conn = VelociraptorConnector(_make_config(), InMemoryQueue(), initial_last_fetched_at=ts)
        assert conn._last_fetched_at == ts

    def test_topic_is_raw_velociraptor(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        assert conn.topic == Topic.RAW_VELOCIRAPTOR

    def test_topic_literal_string(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        assert conn.topic == "mxtac.raw.velociraptor"

    def test_health_status_is_inactive(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        assert conn.health.status == ConnectorStatus.INACTIVE

    def test_backoff_delay_starts_at_base(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        assert conn._backoff_delay == BACKOFF_BASE

    def test_checkpoint_callback_defaults_to_none(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        assert conn._checkpoint_callback is None


# ── _connect() ─────────────────────────────────────────────────────────────────


class TestVelociraptorConnectorConnect:
    async def test_connect_creates_http_client(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response(_health_response_lines()),
        ])

        with patch("httpx.AsyncClient", return_value=mock_client):
            await conn._connect()

        assert conn._client is not None

    async def test_connect_raises_when_api_url_missing(self) -> None:
        conn = VelociraptorConnector(_make_config(api_url=""), InMemoryQueue())
        with pytest.raises(ConnectionError, match="api_url"):
            await conn._connect()

    async def test_connect_raises_when_api_key_missing(self) -> None:
        conn = VelociraptorConnector(_make_config(api_key=""), InMemoryQueue())
        with pytest.raises(ConnectionError, match="api_key"):
            await conn._connect()

    async def test_connect_raises_when_health_probe_returns_no_rows(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        # Stream returns only log messages, no Response rows
        mock_client = _make_stream_client([
            _make_streaming_response([_log_packet("starting"), _log_packet("done")]),
        ])
        conn._client = mock_client

        with pytest.raises(ConnectionError, match="no response"):
            await conn._connect()

    async def test_connect_raises_on_non_2xx_response(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response([], status_code=503),
        ])
        conn._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            await conn._connect()

    async def test_connect_reuses_existing_client(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        existing_client = _make_stream_client([
            _make_streaming_response(_health_response_lines()),
        ])
        conn._client = existing_client

        with patch("httpx.AsyncClient") as mock_cls:
            await conn._connect()
            mock_cls.assert_not_called()

        assert conn._client is existing_client

    async def test_connect_sets_org_id_header_when_configured(self) -> None:
        conn = VelociraptorConnector(_make_config(org_id="my-org"), InMemoryQueue())
        captured_headers: dict = {}

        def _fake_client_factory(**kwargs):
            captured_headers.update(kwargs.get("headers", {}))
            return _make_stream_client([
                _make_streaming_response(_health_response_lines()),
            ])

        with patch("httpx.AsyncClient", side_effect=_fake_client_factory):
            await conn._connect()

        assert "Grpc-Metadata-Velociraptor-Org-Id" in captured_headers
        assert captured_headers["Grpc-Metadata-Velociraptor-Org-Id"] == "my-org"

    async def test_connect_does_not_set_org_id_header_when_empty(self) -> None:
        conn = VelociraptorConnector(_make_config(org_id=""), InMemoryQueue())
        captured_headers: dict = {}

        def _fake_client_factory(**kwargs):
            captured_headers.update(kwargs.get("headers", {}))
            return _make_stream_client([
                _make_streaming_response(_health_response_lines()),
            ])

        with patch("httpx.AsyncClient", side_effect=_fake_client_factory):
            await conn._connect()

        assert "Grpc-Metadata-Velociraptor-Org-Id" not in captured_headers

    async def test_connect_strips_trailing_slash_from_api_url(self) -> None:
        conn = VelociraptorConnector(
            _make_config(api_url="https://velociraptor.test:8889/"),
            InMemoryQueue(),
        )
        mock_client = _make_stream_client([
            _make_streaming_response(_health_response_lines()),
        ])
        conn._client = mock_client

        # Should not raise — trailing slash is stripped
        await conn._connect()


# ── _run_vql() ─────────────────────────────────────────────────────────────────


class TestVelociraptorRunVQL:
    async def test_yields_nothing_when_client_is_none(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        rows = await _collect_vql(conn, "SELECT 1 FROM scope()")
        assert rows == []

    async def test_yields_rows_from_streaming_response(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        expected_rows = [
            {"client_id": "C.abc123", "flow_id": "F.001"},
            {"client_id": "C.def456", "flow_id": "F.002"},
        ]
        mock_client = _make_stream_client([
            _make_streaming_response([_rows_packet(*expected_rows)]),
        ])
        conn._client = mock_client

        rows = await _collect_vql(conn, "SELECT * FROM flows()")
        assert len(rows) == 2
        assert rows[0]["client_id"] == "C.abc123"
        assert rows[1]["client_id"] == "C.def456"

    async def test_adds_source_field_to_each_row(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response([_rows_packet({"col": "val"})]),
        ])
        conn._client = mock_client

        rows = await _collect_vql(conn, "SELECT col FROM scope()")
        assert rows[0]["_source"] == "velociraptor"

    async def test_skips_log_only_packets(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response([
                _log_packet("starting query"),
                _rows_packet({"id": "1"}),
                _log_packet("query completed"),
            ]),
        ])
        conn._client = mock_client

        rows = await _collect_vql(conn, "SELECT * FROM scope()")
        assert len(rows) == 1
        assert rows[0]["id"] == "1"

    async def test_skips_blank_lines(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response(["", "  ", _rows_packet({"id": "ok"})]),
        ])
        conn._client = mock_client

        rows = await _collect_vql(conn, "SELECT * FROM scope()")
        assert len(rows) == 1

    async def test_skips_non_json_lines(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response(["not-json-at-all", _rows_packet({"id": "valid"})]),
        ])
        conn._client = mock_client

        rows = await _collect_vql(conn, "SELECT * FROM scope()")
        # non-JSON line is skipped; valid row still returned
        assert len(rows) == 1
        assert rows[0]["id"] == "valid"

    async def test_skips_empty_dict_rows(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        # Response contains one empty dict and one valid dict
        packet = json.dumps({
            "Response": json.dumps([{}, {"id": "valid"}]),
            "timestamp": 1234,
        })
        mock_client = _make_stream_client([
            _make_streaming_response([packet]),
        ])
        conn._client = mock_client

        rows = await _collect_vql(conn, "SELECT * FROM scope()")
        assert len(rows) == 1
        assert rows[0]["id"] == "valid"

    async def test_raises_runtime_error_on_error_packet(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response([_error_packet("permission denied")]),
        ])
        conn._client = mock_client

        with pytest.raises(RuntimeError, match="VQL error"):
            await _collect_vql(conn, "SELECT * FROM scope()")

    async def test_raises_runtime_error_on_capital_error_field(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response([_error_packet("access denied", capital=True)]),
        ])
        conn._client = mock_client

        with pytest.raises(RuntimeError, match="VQL error"):
            await _collect_vql(conn, "SELECT * FROM scope()")

    async def test_raises_http_status_error_on_non_2xx(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response([], status_code=401),
        ])
        conn._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            await _collect_vql(conn, "SELECT * FROM scope()")

    async def test_skips_packets_with_malformed_response_json(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        bad_packet = json.dumps({"Response": "not-valid-json", "timestamp": 1234})
        good_packet = _rows_packet({"id": "good"})
        mock_client = _make_stream_client([
            _make_streaming_response([bad_packet, good_packet]),
        ])
        conn._client = mock_client

        rows = await _collect_vql(conn, "SELECT * FROM scope()")
        # Bad packet skipped; good packet still returned
        assert len(rows) == 1
        assert rows[0]["id"] == "good"

    async def test_yields_rows_from_multiple_packets(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        packet1 = _rows_packet({"id": "1"}, {"id": "2"})
        packet2 = _rows_packet({"id": "3"})
        mock_client = _make_stream_client([
            _make_streaming_response([packet1, packet2]),
        ])
        conn._client = mock_client

        rows = await _collect_vql(conn, "SELECT * FROM scope()")
        assert len(rows) == 3
        assert [r["id"] for r in rows] == ["1", "2", "3"]


# ── _fetch_events() ────────────────────────────────────────────────────────────


class TestVelociraptorFetchEvents:
    async def test_yields_nothing_when_client_is_none(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        events = await _collect(conn)
        assert events == []

    async def test_uses_default_vql_when_artifacts_and_vql_empty(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response([_rows_packet({"flow_id": "F.001"})]),
        ])
        conn._client = mock_client

        events = await _collect(conn)
        assert len(events) == 1

        # Verify it called stream with the default VQL template content
        call_kwargs = mock_client.stream.call_args[1]
        vql_sent = call_kwargs["json"]["query"][0]["vql"]
        assert "flows()" in vql_sent

    async def test_uses_artifact_vql_when_artifacts_configured(self) -> None:
        conn = VelociraptorConnector(
            _make_config(artifacts=["Windows.System.Pslist"]),
            InMemoryQueue(),
        )
        mock_client = _make_stream_client([
            _make_streaming_response([_rows_packet({"Pid": 1234, "Name": "cmd.exe"})]),
        ])
        conn._client = mock_client

        events = await _collect(conn)
        assert len(events) == 1

        call_kwargs = mock_client.stream.call_args[1]
        vql_sent = call_kwargs["json"]["query"][0]["vql"]
        assert "Windows.System.Pslist" in vql_sent

    async def test_uses_custom_vql_when_vql_configured(self) -> None:
        custom = "SELECT * FROM pslist() WHERE Name =~ 'cmd'"
        conn = VelociraptorConnector(
            _make_config(vql=custom, artifacts=["Windows.System.Pslist"]),
            InMemoryQueue(),
        )
        mock_client = _make_stream_client([
            _make_streaming_response([_rows_packet({"Name": "cmd.exe"})]),
        ])
        conn._client = mock_client

        await _collect(conn)

        # Custom VQL overrides artifacts
        call_kwargs = mock_client.stream.call_args[1]
        vql_sent = call_kwargs["json"]["query"][0]["vql"]
        assert vql_sent == custom

    async def test_since_epoch_from_last_fetched_at_in_vql(self) -> None:
        ts = datetime(2024, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        conn = VelociraptorConnector(
            _make_config(), InMemoryQueue(), initial_last_fetched_at=ts
        )
        mock_client = _make_stream_client([
            _make_streaming_response([]),
        ])
        conn._client = mock_client

        await _collect(conn)

        call_kwargs = mock_client.stream.call_args[1]
        vql_sent = call_kwargs["json"]["query"][0]["vql"]
        assert str(int(ts.timestamp())) in vql_sent

    async def test_page_size_appears_in_vql(self) -> None:
        conn = VelociraptorConnector(
            _make_config(page_size=500), InMemoryQueue()
        )
        mock_client = _make_stream_client([
            _make_streaming_response([]),
        ])
        conn._client = mock_client

        await _collect(conn)

        call_kwargs = mock_client.stream.call_args[1]
        vql_sent = call_kwargs["json"]["query"][0]["vql"]
        assert "500" in vql_sent

    async def test_yields_events_from_multiple_artifacts(self) -> None:
        conn = VelociraptorConnector(
            _make_config(artifacts=["ArtifactA", "ArtifactB"]),
            InMemoryQueue(),
        )
        # Two stream calls — one per artifact
        mock_client = _make_stream_client([
            _make_streaming_response([_rows_packet({"_artifact_name": "ArtifactA", "id": "1"})]),
            _make_streaming_response([_rows_packet({"_artifact_name": "ArtifactB", "id": "2"})]),
        ])
        conn._client = mock_client

        events = await _collect(conn)
        assert len(events) == 2
        assert events[0]["id"] == "1"
        assert events[1]["id"] == "2"
        assert mock_client.stream.call_count == 2

    async def test_advances_last_fetched_at_after_successful_fetch(self) -> None:
        ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        conn = VelociraptorConnector(
            _make_config(), InMemoryQueue(), initial_last_fetched_at=ts
        )
        mock_client = _make_stream_client([
            _make_streaming_response([]),
        ])
        conn._client = mock_client

        before = datetime.now(timezone.utc)
        await _collect(conn)
        after = datetime.now(timezone.utc)

        assert conn._last_fetched_at > ts
        assert before <= conn._last_fetched_at <= after

    async def test_calls_checkpoint_callback_with_updated_timestamp(self) -> None:
        ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        checkpoint_cb = AsyncMock()
        conn = VelociraptorConnector(
            _make_config(),
            InMemoryQueue(),
            initial_last_fetched_at=ts,
            checkpoint_callback=checkpoint_cb,
        )
        mock_client = _make_stream_client([
            _make_streaming_response([]),
        ])
        conn._client = mock_client

        await _collect(conn)

        checkpoint_cb.assert_called_once()
        called_ts = checkpoint_cb.call_args[0][0]
        assert called_ts > ts
        assert isinstance(called_ts, datetime)

    async def test_does_not_call_checkpoint_when_none(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = _make_stream_client([
            _make_streaming_response([]),
        ])
        conn._client = mock_client

        # Should not raise
        await _collect(conn)

    async def test_default_vql_contains_since_epoch(self) -> None:
        ts = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        since_epoch = int(ts.timestamp())
        vql = _DEFAULT_VQL_TEMPLATE.format(since_epoch=since_epoch, page_size=1000)
        assert str(since_epoch) in vql

    async def test_default_vql_contains_page_size(self) -> None:
        vql = _DEFAULT_VQL_TEMPLATE.format(since_epoch=0, page_size=500)
        assert "500" in vql

    async def test_artifact_vql_contains_artifact_name(self) -> None:
        vql = _ARTIFACT_VQL_TEMPLATE.format(
            artifact="Windows.System.Pslist", since_epoch=0, page_size=1000
        )
        assert "Windows.System.Pslist" in vql

    async def test_artifact_vql_contains_since_epoch(self) -> None:
        ts = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        since_epoch = int(ts.timestamp())
        vql = _ARTIFACT_VQL_TEMPLATE.format(
            artifact="SomeArtifact", since_epoch=since_epoch, page_size=1000
        )
        assert str(since_epoch) in vql


# ── Exponential backoff ────────────────────────────────────────────────────────


class TestVelociraptorBackoff:
    def test_backoff_base_is_1_second(self) -> None:
        assert BACKOFF_BASE == 1.0

    def test_backoff_max_is_60_seconds(self) -> None:
        assert BACKOFF_MAX == 60.0

    def test_backoff_delay_starts_at_base(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        assert conn._backoff_delay == BACKOFF_BASE

    async def test_fetch_error_doubles_backoff_delay(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("API unavailable")
            yield  # noqa: unreachable — makes this an async generator

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_BASE * 2

    async def test_doubling_beyond_max_is_capped(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = 32.0  # 32 * 2 = 64 > 60

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_MAX

    async def test_successful_cycle_resets_backoff_to_base(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = 32.0  # simulate elevated backoff

        async def _mock_fetch():
            conn._stop_event.set()
            return
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_BASE

    async def test_error_does_not_reset_backoff_to_base(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = 16.0

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay != BACKOFF_BASE

    async def test_at_max_backoff_another_error_stays_at_max(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = BACKOFF_MAX

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_MAX


# ── Poll loop integration ──────────────────────────────────────────────────────


class TestVelociraptorPollLoop:
    async def test_publishes_events_to_raw_velociraptor_topic(self) -> None:
        queue = InMemoryQueue()
        conn = VelociraptorConnector(_make_config(), queue)

        async def _mock_fetch():
            yield {"client_id": "C.abc123", "flow_id": "F.001"}
            conn._stop_event.set()

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        msg = await queue._queues[Topic.RAW_VELOCIRAPTOR].get()
        assert msg["client_id"] == "C.abc123"

    async def test_events_total_increments_per_event(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            yield {"id": "obj-1"}
            yield {"id": "obj-2"}
            conn._stop_event.set()

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn.health.events_total == 2

    async def test_last_event_at_updated_after_first_publish(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        assert conn.health.last_event_at is None

        async def _mock_fetch():
            yield {"id": "obj-1"}
            conn._stop_event.set()

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]

        before = datetime.now(timezone.utc)
        await conn._poll_loop()
        after = datetime.now(timezone.utc)

        assert conn.health.last_event_at is not None
        assert before <= conn.health.last_event_at <= after

    async def test_no_publish_when_fetch_yields_nothing(self) -> None:
        queue = InMemoryQueue()
        conn = VelociraptorConnector(_make_config(), queue)

        async def _mock_fetch():
            conn._stop_event.set()
            return
            yield

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn.health.events_total == 0
        assert queue._queues[Topic.RAW_VELOCIRAPTOR].empty()

    async def test_fetch_error_does_not_crash_loop(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("transient error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()  # must not raise

    async def test_fetch_error_increments_errors_total(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn.health.errors_total == 1

    async def test_fetch_error_stores_message_in_health(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("velociraptor server unreachable")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert "velociraptor server unreachable" in conn.health.error_message

    async def test_status_callback_called_with_active_on_success(self) -> None:
        status_cb = AsyncMock()
        conn = VelociraptorConnector(_make_config(), InMemoryQueue(), status_callback=status_cb)

        async def _mock_fetch():
            conn._stop_event.set()
            return
            yield

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        status_cb.assert_called_once_with(ConnectorStatus.ACTIVE.value, None)

    async def test_status_callback_called_with_error_on_failure(self) -> None:
        status_cb = AsyncMock()
        conn = VelociraptorConnector(_make_config(), InMemoryQueue(), status_callback=status_cb)

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("api error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        statuses = [c[0][0] for c in status_cb.call_args_list]
        assert ConnectorStatus.ERROR.value in statuses


# ── stop() ────────────────────────────────────────────────────────────────────


class TestVelociraptorStop:
    async def test_stop_closes_http_client(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client

        await conn.stop()

        mock_client.aclose.assert_called_once()

    async def test_stop_clears_client_reference(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client

        await conn.stop()

        assert conn._client is None

    async def test_stop_is_safe_when_client_is_none(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        assert conn._client is None
        await conn.stop()  # must not raise

    async def test_stop_sets_health_status_to_inactive(self) -> None:
        conn = VelociraptorConnector(_make_config(), InMemoryQueue())
        conn.health.status = ConnectorStatus.ACTIVE

        await conn.stop()

        assert conn.health.status == ConnectorStatus.INACTIVE


# ── VelociraptorConnectorFactory ───────────────────────────────────────────────


class TestVelociraptorConnectorFactory:
    def test_creates_velociraptor_connector_instance(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://velociraptor.test:8889", "api_key": "test-key"},
            InMemoryQueue(),
        )
        assert isinstance(conn, VelociraptorConnector)

    def test_name_defaults_to_velociraptor(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.name == "velociraptor"

    def test_name_can_be_overridden(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"name": "my-velociraptor", "api_url": "https://v.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.name == "my-velociraptor"

    def test_poll_interval_defaults_to_300(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.poll_interval_seconds == 300

    def test_poll_interval_can_be_overridden(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k", "poll_interval_seconds": 60},
            InMemoryQueue(),
        )
        assert conn.config.poll_interval_seconds == 60

    def test_api_url_in_extra(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://velociraptor.test:8889", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["api_url"] == "https://velociraptor.test:8889"

    def test_api_key_in_extra(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "secret-key"},
            InMemoryQueue(),
        )
        assert conn.config.extra["api_key"] == "secret-key"

    def test_artifacts_defaults_to_empty_list(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["artifacts"] == []

    def test_artifacts_can_be_set(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {
                "api_url": "https://v.test",
                "api_key": "k",
                "artifacts": ["Windows.System.Pslist", "Linux.Sys.Pslist"],
            },
            InMemoryQueue(),
        )
        assert conn.config.extra["artifacts"] == ["Windows.System.Pslist", "Linux.Sys.Pslist"]

    def test_vql_defaults_to_empty_string(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["vql"] == ""

    def test_vql_can_be_set(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k", "vql": "SELECT 1 FROM scope()"},
            InMemoryQueue(),
        )
        assert conn.config.extra["vql"] == "SELECT 1 FROM scope()"

    def test_page_size_defaults_to_default_page_size(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["page_size"] == DEFAULT_PAGE_SIZE

    def test_page_size_can_be_overridden(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k", "page_size": 500},
            InMemoryQueue(),
        )
        assert conn.config.extra["page_size"] == 500

    def test_verify_ssl_defaults_to_true(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["verify_ssl"] is True

    def test_verify_ssl_can_be_disabled(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k", "verify_ssl": False},
            InMemoryQueue(),
        )
        assert conn.config.extra["verify_ssl"] is False

    def test_timeout_defaults_to_30(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["timeout"] == 30

    def test_timeout_can_be_overridden(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k", "timeout": 60},
            InMemoryQueue(),
        )
        assert conn.config.extra["timeout"] == 60

    def test_org_id_defaults_to_empty_string(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["org_id"] == ""

    def test_org_id_can_be_set(self) -> None:
        conn = VelociraptorConnectorFactory.from_dict(
            {"api_url": "https://v.test", "api_key": "k", "org_id": "acme"},
            InMemoryQueue(),
        )
        assert conn.config.extra["org_id"] == "acme"
