"""
Tests for OpenCTIConnector.

Feature 6.20 — OpenCTI connector — threat intelligence feed:

Initialization:
  - client is None on init
  - last_fetched_at defaults to ~1 hour ago when no initial timestamp given
  - initial_last_fetched_at is used when provided
  - topic is mxtac.raw.opencti
  - topic literal string is "mxtac.raw.opencti"
  - health status is INACTIVE on init
  - _backoff_delay starts at BACKOFF_BASE on init
  - checkpoint_callback defaults to None

_connect():
  - creates httpx AsyncClient on first connect
  - raises ConnectionError when api_url is missing
  - raises ConnectionError when api_token is missing
  - raises HTTPStatusError on non-2xx GraphQL response
  - raises ConnectionError when GraphQL response contains errors
  - reuses existing client on re-connect (no second instantiation)
  - sends Authorization Bearer header
  - sets base_url from config extra api_url

_fetch_events():
  - yields nothing when client is None
  - yields nodes from single page
  - paginates through multiple pages using cursor (hasNextPage + endCursor)
  - stops pagination when hasNextPage is False
  - stops pagination when edges list is empty
  - stops pagination when endCursor is None
  - includes updated_at gte filter using last_fetched_at
  - applies object_types filter when configured
  - no entity_type filter when object_types is empty
  - raises RuntimeError when GraphQL response contains errors
  - raises HTTPStatusError on non-2xx response
  - advances _last_fetched_at after successful fetch
  - calls checkpoint_callback with updated timestamp
  - does not call checkpoint_callback when it is None
  - skips edges with empty node

Exponential backoff (matching Prowler pattern):
  - _backoff_delay starts at BACKOFF_BASE (1.0 s)
  - BACKOFF_MAX is exactly 60.0 seconds
  - fetch error doubles _backoff_delay
  - doubling beyond BACKOFF_MAX is capped at BACKOFF_MAX
  - when at BACKOFF_MAX, another error keeps it at BACKOFF_MAX
  - successful cycle resets _backoff_delay to BACKOFF_BASE
  - error does NOT reset _backoff_delay to BACKOFF_BASE

Poll loop integration:
  - publishes each event to mxtac.raw.opencti topic
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

OpenCTIConnectorFactory:
  - creates OpenCTIConnector instance
  - name defaults to 'opencti'
  - poll_interval_seconds defaults to 300
  - required keys (api_url, api_token) are present in extra
  - optional keys have correct defaults (object_types=[], page_size=100)
  - verify_ssl defaults to True
  - timeout defaults to 30
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.connectors.base import ConnectorConfig, ConnectorStatus
from app.connectors.opencti import (
    BACKOFF_BASE,
    BACKOFF_MAX,
    DEFAULT_PAGE_SIZE,
    OpenCTIConnector,
    OpenCTIConnectorFactory,
)
from app.pipeline.queue import InMemoryQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_config(**extra_overrides) -> ConnectorConfig:
    return ConnectorConfig(
        name="opencti-test",
        connector_type="opencti",
        enabled=True,
        poll_interval_seconds=300,
        extra={
            "api_url": "https://opencti.test",
            "api_token": "test-api-token",
            "verify_ssl": False,
            **extra_overrides,
        },
    )


def _make_response(status_code: int, json_data: dict) -> MagicMock:
    """Mock httpx.Response with controllable status_code, json(), raise_for_status()."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


def _health_ok() -> MagicMock:
    return _make_response(200, {"data": {"about": {"version": "6.0.0"}}})


def _objects_resp(
    nodes: list,
    has_next_page: bool = False,
    end_cursor: str | None = None,
) -> MagicMock:
    return _make_response(
        200,
        {
            "data": {
                "stixCoreObjects": {
                    "pageInfo": {
                        "hasNextPage": has_next_page,
                        "endCursor": end_cursor,
                    },
                    "edges": [{"node": n} for n in nodes],
                }
            }
        },
    )


async def _collect(conn: OpenCTIConnector) -> list[dict]:
    results = []
    async for event in conn._fetch_events():
        results.append(event)
    return results


# ── Initialization ─────────────────────────────────────────────────────────────


class TestOpenCTIConnectorInit:
    def test_client_is_none_on_init(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        assert conn._client is None

    def test_last_fetched_at_defaults_to_approximately_1_hour_ago(self) -> None:
        before = datetime.now(timezone.utc)
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        after = datetime.now(timezone.utc)
        delta = before - conn._last_fetched_at
        assert 55 * 60 < delta.total_seconds() < 65 * 60
        assert conn._last_fetched_at < after

    def test_initial_last_fetched_at_used_when_provided(self) -> None:
        ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        conn = OpenCTIConnector(_make_config(), InMemoryQueue(), initial_last_fetched_at=ts)
        assert conn._last_fetched_at == ts

    def test_topic_is_raw_opencti(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        assert conn.topic == Topic.RAW_OPENCTI

    def test_topic_literal_string(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        assert conn.topic == "mxtac.raw.opencti"

    def test_health_status_is_inactive(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        assert conn.health.status == ConnectorStatus.INACTIVE

    def test_backoff_delay_starts_at_base(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        assert conn._backoff_delay == BACKOFF_BASE

    def test_checkpoint_callback_defaults_to_none(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        assert conn._checkpoint_callback is None


# ── _connect() ─────────────────────────────────────────────────────────────────


class TestOpenCTIConnectorConnect:
    async def test_connect_creates_http_client(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=_health_ok())

        with patch("httpx.AsyncClient", return_value=mock_client):
            await conn._connect()

        assert conn._client is not None

    async def test_connect_raises_when_api_url_missing(self) -> None:
        conn = OpenCTIConnector(_make_config(api_url=""), InMemoryQueue())
        with pytest.raises(ConnectionError, match="api_url"):
            await conn._connect()

    async def test_connect_raises_when_api_token_missing(self) -> None:
        conn = OpenCTIConnector(_make_config(api_token=""), InMemoryQueue())
        with pytest.raises(ConnectionError, match="api_token"):
            await conn._connect()

    async def test_connect_raises_on_non_2xx_response(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=_make_response(503, {}))
        conn._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            await conn._connect()

    async def test_connect_raises_when_graphql_returns_errors(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_make_response(200, {"errors": [{"message": "Unauthorized"}]})
        )
        conn._client = mock_client

        with pytest.raises(ConnectionError, match="GraphQL error"):
            await conn._connect()

    async def test_connect_reuses_existing_client(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        existing_client = MagicMock()
        existing_client.post = AsyncMock(return_value=_health_ok())
        conn._client = existing_client

        with patch("httpx.AsyncClient") as mock_cls:
            await conn._connect()
            mock_cls.assert_not_called()

        assert conn._client is existing_client

    async def test_connect_probes_graphql_health_endpoint(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=_health_ok())
        conn._client = mock_client

        await conn._connect()

        mock_client.post.assert_called_once_with(
            "/graphql",
            json={"query": "{ about { version } }"},
        )

    async def test_connect_strips_trailing_slash_from_api_url(self) -> None:
        conn = OpenCTIConnector(
            _make_config(api_url="https://opencti.test/"),
            InMemoryQueue(),
        )
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=_health_ok())
        conn._client = mock_client

        # Should not raise — trailing slash is stripped in _connect()
        await conn._connect()


# ── _fetch_events() ────────────────────────────────────────────────────────────


class TestOpenCTIFetchEvents:
    async def test_yields_nothing_when_client_is_none(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        events = await _collect(conn)
        assert events == []

    async def test_yields_nodes_from_single_page(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        nodes = [
            {"id": "indicator-1", "entity_type": "Indicator", "name": "evil.com"},
            {"id": "malware-1", "entity_type": "Malware", "name": "AgentTesla"},
        ]
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp(nodes, has_next_page=False)
        )
        conn._client = mock_client

        events = await _collect(conn)
        assert len(events) == 2
        assert events[0]["id"] == "indicator-1"
        assert events[1]["id"] == "malware-1"

    async def test_paginates_through_multiple_pages_using_cursor(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        page1 = [{"id": "obj-1", "entity_type": "Indicator"}]
        page2 = [{"id": "obj-2", "entity_type": "Malware"}]

        responses = [
            _objects_resp(page1, has_next_page=True, end_cursor="cursor-abc"),
            _objects_resp(page2, has_next_page=False, end_cursor=None),
        ]
        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=responses)
        conn._client = mock_client

        events = await _collect(conn)
        assert len(events) == 2
        assert events[0]["id"] == "obj-1"
        assert events[1]["id"] == "obj-2"
        assert mock_client.post.call_count == 2

    async def test_second_page_call_includes_cursor(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        page1 = [{"id": "obj-1"}]
        page2 = [{"id": "obj-2"}]

        responses = [
            _objects_resp(page1, has_next_page=True, end_cursor="cursor-xyz"),
            _objects_resp(page2, has_next_page=False),
        ]
        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=responses)
        conn._client = mock_client

        await _collect(conn)

        # Second call should include cursor in variables
        second_call_kwargs = mock_client.post.call_args_list[1][1]
        variables = second_call_kwargs["json"]["variables"]
        assert variables["after"] == "cursor-xyz"

    async def test_first_page_call_does_not_include_after(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp([], has_next_page=False)
        )
        conn._client = mock_client

        await _collect(conn)

        first_call_kwargs = mock_client.post.call_args[1]
        variables = first_call_kwargs["json"]["variables"]
        assert "after" not in variables

    async def test_stops_pagination_when_has_next_page_is_false(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp([{"id": "obj-1"}], has_next_page=False)
        )
        conn._client = mock_client

        await _collect(conn)
        assert mock_client.post.call_count == 1

    async def test_stops_pagination_when_edges_empty(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        # Claims has_next_page=True but returns no edges
        mock_client.post = AsyncMock(
            return_value=_objects_resp([], has_next_page=True, end_cursor="cursor-abc")
        )
        conn._client = mock_client

        events = await _collect(conn)
        assert events == []
        assert mock_client.post.call_count == 1

    async def test_stops_pagination_when_cursor_is_none(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        # Claims has_next_page=True but no cursor
        mock_client.post = AsyncMock(
            return_value=_objects_resp(
                [{"id": "obj-1"}], has_next_page=True, end_cursor=None
            )
        )
        conn._client = mock_client

        events = await _collect(conn)
        assert len(events) == 1
        assert mock_client.post.call_count == 1

    async def test_filter_includes_updated_at_gte_using_last_fetched_at(self) -> None:
        ts = datetime(2024, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        conn = OpenCTIConnector(
            _make_config(), InMemoryQueue(), initial_last_fetched_at=ts
        )
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp([], has_next_page=False)
        )
        conn._client = mock_client

        await _collect(conn)

        call_kwargs = mock_client.post.call_args[1]
        filters = call_kwargs["json"]["variables"]["filters"]
        ts_filters = [f for f in filters["filters"] if f["key"] == "updated_at"]
        assert len(ts_filters) == 1
        assert ts_filters[0]["operator"] == "gte"
        assert ts_filters[0]["values"] == ["2024-06-01T10:00:00.000Z"]

    async def test_applies_object_types_filter_when_configured(self) -> None:
        conn = OpenCTIConnector(
            _make_config(object_types=["Indicator", "Malware"]),
            InMemoryQueue(),
        )
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp([], has_next_page=False)
        )
        conn._client = mock_client

        await _collect(conn)

        call_kwargs = mock_client.post.call_args[1]
        filters = call_kwargs["json"]["variables"]["filters"]
        type_filters = [f for f in filters["filters"] if f["key"] == "entity_type"]
        assert len(type_filters) == 1
        assert type_filters[0]["operator"] == "eq"
        assert type_filters[0]["values"] == ["Indicator", "Malware"]

    async def test_no_entity_type_filter_when_object_types_empty(self) -> None:
        conn = OpenCTIConnector(_make_config(object_types=[]), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp([], has_next_page=False)
        )
        conn._client = mock_client

        await _collect(conn)

        call_kwargs = mock_client.post.call_args[1]
        filters = call_kwargs["json"]["variables"]["filters"]
        type_filters = [f for f in filters["filters"] if f["key"] == "entity_type"]
        assert len(type_filters) == 0

    async def test_raises_runtime_error_when_graphql_response_has_errors(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_make_response(200, {"errors": [{"message": "some error"}]})
        )
        conn._client = mock_client

        with pytest.raises(RuntimeError, match="GraphQL error"):
            await _collect(conn)

    async def test_raises_on_non_2xx_api_response(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=_make_response(500, {}))
        conn._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            await _collect(conn)

    async def test_advances_last_fetched_at_after_successful_fetch(self) -> None:
        ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        conn = OpenCTIConnector(
            _make_config(), InMemoryQueue(), initial_last_fetched_at=ts
        )
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp([], has_next_page=False)
        )
        conn._client = mock_client

        before = datetime.now(timezone.utc)
        await _collect(conn)
        after = datetime.now(timezone.utc)

        assert conn._last_fetched_at > ts
        assert before <= conn._last_fetched_at <= after

    async def test_calls_checkpoint_callback_with_updated_timestamp(self) -> None:
        ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        checkpoint_cb = AsyncMock()
        conn = OpenCTIConnector(
            _make_config(),
            InMemoryQueue(),
            initial_last_fetched_at=ts,
            checkpoint_callback=checkpoint_cb,
        )
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp([], has_next_page=False)
        )
        conn._client = mock_client

        await _collect(conn)

        checkpoint_cb.assert_called_once()
        called_ts = checkpoint_cb.call_args[0][0]
        assert called_ts > ts
        assert isinstance(called_ts, datetime)

    async def test_does_not_call_checkpoint_when_none(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp([], has_next_page=False)
        )
        conn._client = mock_client

        # Should not raise
        await _collect(conn)

    async def test_skips_empty_node_in_edges(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        # One valid node and one empty node
        mock_client.post = AsyncMock(
            return_value=_make_response(
                200,
                {
                    "data": {
                        "stixCoreObjects": {
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "edges": [
                                {"node": {"id": "obj-1", "entity_type": "Indicator"}},
                                {"node": {}},
                            ],
                        }
                    }
                },
            )
        )
        conn._client = mock_client

        events = await _collect(conn)
        # Empty node ({}) is falsy, so it is skipped
        assert len(events) == 1
        assert events[0]["id"] == "obj-1"

    async def test_page_size_passed_to_graphql_variables(self) -> None:
        conn = OpenCTIConnector(_make_config(page_size=50), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            return_value=_objects_resp([], has_next_page=False)
        )
        conn._client = mock_client

        await _collect(conn)

        call_kwargs = mock_client.post.call_args[1]
        variables = call_kwargs["json"]["variables"]
        assert variables["first"] == 50


# ── Exponential backoff ────────────────────────────────────────────────────────


class TestOpenCTIBackoff:
    def test_backoff_base_is_1_second(self) -> None:
        assert BACKOFF_BASE == 1.0

    def test_backoff_max_is_60_seconds(self) -> None:
        assert BACKOFF_MAX == 60.0

    def test_backoff_delay_starts_at_base(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        assert conn._backoff_delay == BACKOFF_BASE

    async def test_fetch_error_doubles_backoff_delay(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("API unavailable")
            yield  # noqa: unreachable — makes this an async generator

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]

        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_BASE * 2

    async def test_doubling_beyond_max_is_capped(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = 32.0  # 32 * 2 = 64 > 60

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_MAX

    async def test_successful_cycle_resets_backoff_to_base(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = 32.0  # simulate elevated backoff

        async def _mock_fetch():
            conn._stop_event.set()
            return
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_BASE

    async def test_error_does_not_reset_backoff_to_base(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = 16.0

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay != BACKOFF_BASE

    async def test_at_max_backoff_another_error_stays_at_max(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = BACKOFF_MAX

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_MAX


# ── Poll loop integration ──────────────────────────────────────────────────────


class TestOpenCTIPollLoop:
    async def test_publishes_events_to_raw_opencti_topic(self) -> None:
        queue = InMemoryQueue()
        conn = OpenCTIConnector(_make_config(), queue)

        async def _mock_fetch():
            yield {"id": "indicator-1", "entity_type": "Indicator"}
            conn._stop_event.set()

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        msg = await queue._queues[Topic.RAW_OPENCTI].get()
        assert msg["id"] == "indicator-1"

    async def test_events_total_increments_per_event(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            yield {"id": "obj-1"}
            yield {"id": "obj-2"}
            conn._stop_event.set()

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn.health.events_total == 2

    async def test_last_event_at_updated_after_first_publish(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
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
        conn = OpenCTIConnector(_make_config(), queue)

        async def _mock_fetch():
            conn._stop_event.set()
            return
            yield

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn.health.events_total == 0
        assert queue._queues[Topic.RAW_OPENCTI].empty()

    async def test_fetch_error_does_not_crash_loop(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("transient error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()  # must not raise

    async def test_fetch_error_increments_errors_total(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn.health.errors_total == 1

    async def test_fetch_error_stores_message_in_health(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("opencti unreachable")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert "opencti unreachable" in conn.health.error_message

    async def test_status_callback_called_with_active_on_success(self) -> None:
        status_cb = AsyncMock()
        conn = OpenCTIConnector(_make_config(), InMemoryQueue(), status_callback=status_cb)

        async def _mock_fetch():
            conn._stop_event.set()
            return
            yield

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        status_cb.assert_called_once_with(ConnectorStatus.ACTIVE.value, None)

    async def test_status_callback_called_with_error_on_failure(self) -> None:
        status_cb = AsyncMock()
        conn = OpenCTIConnector(_make_config(), InMemoryQueue(), status_callback=status_cb)

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("api error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        statuses = [c[0][0] for c in status_cb.call_args_list]
        assert ConnectorStatus.ERROR.value in statuses


# ── stop() ────────────────────────────────────────────────────────────────────


class TestOpenCTIStop:
    async def test_stop_closes_http_client(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client

        await conn.stop()

        mock_client.aclose.assert_called_once()

    async def test_stop_clears_client_reference(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client

        await conn.stop()

        assert conn._client is None

    async def test_stop_is_safe_when_client_is_none(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        assert conn._client is None
        await conn.stop()  # must not raise

    async def test_stop_sets_health_status_to_inactive(self) -> None:
        conn = OpenCTIConnector(_make_config(), InMemoryQueue())
        conn.health.status = ConnectorStatus.ACTIVE

        await conn.stop()

        assert conn.health.status == ConnectorStatus.INACTIVE


# ── OpenCTIConnectorFactory ────────────────────────────────────────────────────


class TestOpenCTIConnectorFactory:
    def test_creates_opencti_connector_instance(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://opencti.test", "api_token": "token123"},
            InMemoryQueue(),
        )
        assert isinstance(conn, OpenCTIConnector)

    def test_name_defaults_to_opencti(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://opencti.test", "api_token": "token123"},
            InMemoryQueue(),
        )
        assert conn.config.name == "opencti"

    def test_name_can_be_overridden(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"name": "my-opencti", "api_url": "https://o.test", "api_token": "t"},
            InMemoryQueue(),
        )
        assert conn.config.name == "my-opencti"

    def test_poll_interval_defaults_to_300(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://opencti.test", "api_token": "token123"},
            InMemoryQueue(),
        )
        assert conn.config.poll_interval_seconds == 300

    def test_poll_interval_can_be_overridden(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://o.test", "api_token": "t", "poll_interval_seconds": 600},
            InMemoryQueue(),
        )
        assert conn.config.poll_interval_seconds == 600

    def test_api_url_in_extra(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://opencti.test", "api_token": "token123"},
            InMemoryQueue(),
        )
        assert conn.config.extra["api_url"] == "https://opencti.test"

    def test_api_token_in_extra(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://opencti.test", "api_token": "token123"},
            InMemoryQueue(),
        )
        assert conn.config.extra["api_token"] == "token123"

    def test_object_types_defaults_to_empty_list(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://o.test", "api_token": "t"},
            InMemoryQueue(),
        )
        assert conn.config.extra["object_types"] == []

    def test_object_types_can_be_set(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {
                "api_url": "https://o.test",
                "api_token": "t",
                "object_types": ["Indicator", "Malware"],
            },
            InMemoryQueue(),
        )
        assert conn.config.extra["object_types"] == ["Indicator", "Malware"]

    def test_page_size_defaults_to_100(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://o.test", "api_token": "t"},
            InMemoryQueue(),
        )
        assert conn.config.extra["page_size"] == DEFAULT_PAGE_SIZE

    def test_page_size_can_be_overridden(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://o.test", "api_token": "t", "page_size": 50},
            InMemoryQueue(),
        )
        assert conn.config.extra["page_size"] == 50

    def test_verify_ssl_defaults_to_true(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://o.test", "api_token": "t"},
            InMemoryQueue(),
        )
        assert conn.config.extra["verify_ssl"] is True

    def test_verify_ssl_can_be_disabled(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://o.test", "api_token": "t", "verify_ssl": False},
            InMemoryQueue(),
        )
        assert conn.config.extra["verify_ssl"] is False

    def test_timeout_defaults_to_30(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://o.test", "api_token": "t"},
            InMemoryQueue(),
        )
        assert conn.config.extra["timeout"] == 30

    def test_timeout_can_be_overridden(self) -> None:
        conn = OpenCTIConnectorFactory.from_dict(
            {"api_url": "https://o.test", "api_token": "t", "timeout": 60},
            InMemoryQueue(),
        )
        assert conn.config.extra["timeout"] == 60
