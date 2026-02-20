"""
Tests for WazuhConnector.

Feature 6.1 — Authenticate to Wazuh API (Basic → JWT):
  - _connect(): creates httpx client, basic-auth call, stores JWT, reuses client on
    re-auth, raises on non-2xx, respects verify_ssl, strips trailing slash

Feature 6.2 — Poll /alerts endpoint — paginated:
  - _fetch_events(): empty when not connected, yields alerts from single/multi pages,
    bearer token header, correct query params (q/sort/limit/offset), pagination with
    correct per-page offsets, updates last_fetched_at after all pages, re-auths on 401
    and retries, raises on non-401 errors, empty results handled correctly

Feature 6.3 — Track last-seen timestamp:
  - initial_last_fetched_at: used when provided, falls back to 5-min-ago when None
  - checkpoint_callback: called after each fetch cycle with the new timestamp,
    not called when None, receives the updated _last_fetched_at value

Common:
  - Initialisation: client/token None, last_fetched_at ~5 min ago, topic, health status
  - stop(): closes httpx client, clears _client and _token refs, safe when no client
  - WazuhConnectorFactory: creates WazuhConnector, name/poll_interval defaults,
    credentials in extra, verify_ssl default/override
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.connectors.base import ConnectorConfig, ConnectorStatus
from app.connectors.wazuh import WazuhConnector, WazuhConnectorFactory
from app.pipeline.queue import InMemoryQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_config(**extra_overrides) -> ConnectorConfig:
    return ConnectorConfig(
        name="wazuh-test",
        connector_type="wazuh",
        enabled=True,
        poll_interval_seconds=60,
        extra={
            "url": "https://wazuh.test:55000",
            "username": "wazuh-wui",
            "password": "testpass",
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


def _auth_resp(token: str = "jwt-test-token") -> MagicMock:
    return _make_response(200, {"data": {"token": token}})


def _alerts_resp(alerts: list, total: int) -> MagicMock:
    return _make_response(200, {"data": {"affected_items": alerts, "total_affected_items": total}})


# ── Initialisation ─────────────────────────────────────────────────────────────


class TestWazuhConnectorInit:
    def test_client_is_none_on_init(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        assert conn._client is None

    def test_token_is_none_on_init(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        assert conn._token is None

    def test_last_fetched_at_is_approximately_5_min_ago(self) -> None:
        before = datetime.now(timezone.utc)
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        after = datetime.now(timezone.utc)
        delta = before - conn._last_fetched_at
        assert 4 * 60 < delta.total_seconds() < 6 * 60
        assert conn._last_fetched_at < after

    def test_topic_is_raw_wazuh(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        assert conn.topic == Topic.RAW_WAZUH

    def test_health_status_is_inactive(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        assert conn.health.status == ConnectorStatus.INACTIVE


# ── _connect() ─────────────────────────────────────────────────────────────────


class TestWazuhConnectorConnect:
    async def test_connect_creates_http_client(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_auth_resp())

        with patch("app.connectors.wazuh.httpx.AsyncClient", return_value=mock_client):
            await conn._connect()

        assert conn._client is mock_client

    async def test_connect_calls_auth_endpoint_with_basic_auth(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_auth_resp("tok"))

        with patch("app.connectors.wazuh.httpx.AsyncClient", return_value=mock_client):
            await conn._connect()

        mock_client.get.assert_called_once_with(
            "/security/user/authenticate",
            auth=("wazuh-wui", "testpass"),
        )

    async def test_connect_stores_jwt_token(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_auth_resp("my-jwt"))

        with patch("app.connectors.wazuh.httpx.AsyncClient", return_value=mock_client):
            await conn._connect()

        assert conn._token == "my-jwt"

    async def test_connect_reuses_existing_client_on_reauth(self) -> None:
        """Re-auth call must not create a new httpx.AsyncClient."""
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_auth_resp("refreshed-token"))
        conn._client = mock_client  # already connected

        with patch("app.connectors.wazuh.httpx.AsyncClient") as mock_cls:
            await conn._connect()
            mock_cls.assert_not_called()

        assert conn._client is mock_client
        assert conn._token == "refreshed-token"

    async def test_connect_raises_on_auth_failure(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_make_response(401, {"error": "Unauthorized"}))

        with patch("app.connectors.wazuh.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                await conn._connect()

    async def test_connect_respects_verify_ssl_false(self) -> None:
        conn = WazuhConnector(_make_config(verify_ssl=False), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_auth_resp())

        with patch("app.connectors.wazuh.httpx.AsyncClient", return_value=mock_client) as mock_cls:
            await conn._connect()

        assert mock_cls.call_args.kwargs["verify"] is False

    async def test_connect_strips_trailing_slash_from_url(self) -> None:
        conn = WazuhConnector(_make_config(url="https://wazuh.test:55000/"), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_auth_resp())

        with patch("app.connectors.wazuh.httpx.AsyncClient", return_value=mock_client) as mock_cls:
            await conn._connect()

        assert mock_cls.call_args.kwargs["base_url"] == "https://wazuh.test:55000"


# ── _fetch_events() ────────────────────────────────────────────────────────────


class TestWazuhConnectorFetchEvents:
    async def test_yields_nothing_when_client_is_none(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        events = [e async for e in conn._fetch_events()]
        assert events == []

    async def test_yields_nothing_when_token_is_none(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        conn._client = MagicMock()
        conn._token = None
        events = [e async for e in conn._fetch_events()]
        assert events == []

    async def test_yields_alerts_from_single_page(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        alerts = [{"id": "1"}, {"id": "2"}]
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp(alerts, total=2))
        conn._client = mock_client
        conn._token = "tok"

        received = [e async for e in conn._fetch_events()]
        assert received == alerts

    async def test_uses_bearer_token_in_header(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "bearer-xyz"

        [e async for e in conn._fetch_events()]

        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["headers"] == {"Authorization": "Bearer bearer-xyz"}

    async def test_paginates_across_multiple_pages(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        page1 = [{"id": str(i)} for i in range(100)]
        page2 = [{"id": str(i)} for i in range(100, 150)]
        mock_client = MagicMock()
        mock_client.get = AsyncMock(
            side_effect=[
                _alerts_resp(page1, total=150),
                _alerts_resp(page2, total=150),
            ]
        )
        conn._client = mock_client
        conn._token = "tok"

        received = [e async for e in conn._fetch_events()]
        assert len(received) == 150
        assert mock_client.get.call_count == 2

    async def test_updates_last_fetched_at_after_fetch(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        old_time = conn._last_fetched_at
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        assert conn._last_fetched_at > old_time

    async def test_reauthenticates_and_retries_on_401(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        alert = {"id": "abc"}
        mock_client = MagicMock()
        mock_client.get = AsyncMock(
            side_effect=[
                _make_response(401, {}),      # first /alerts → expired token
                _auth_resp("new-token"),       # /security/user/authenticate
                _alerts_resp([alert], total=1),  # retry /alerts
            ]
        )
        conn._client = mock_client
        conn._token = "old-token"

        received = [e async for e in conn._fetch_events()]

        assert received == [alert]
        assert conn._token == "new-token"

    async def test_raises_on_non_401_http_error(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_make_response(500, {"error": "server error"}))
        conn._client = mock_client
        conn._token = "tok"

        with pytest.raises(httpx.HTTPStatusError):
            [e async for e in conn._fetch_events()]

    async def test_single_page_when_total_less_than_page_size(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        alerts = [{"id": str(i)} for i in range(5)]
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp(alerts, total=5))
        conn._client = mock_client
        conn._token = "tok"

        received = [e async for e in conn._fetch_events()]
        assert len(received) == 5
        assert mock_client.get.call_count == 1

    async def test_empty_result_does_not_update_last_fetched_at_before_loop_end(self) -> None:
        """last_fetched_at is updated at the end of the generator, even for zero results."""
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        old_time = conn._last_fetched_at
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        events = [e async for e in conn._fetch_events()]
        assert events == []
        assert conn._last_fetched_at > old_time

    async def test_first_page_uses_offset_zero(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["params"]["offset"] == 0

    async def test_first_page_uses_default_page_size_limit(self) -> None:
        from app.connectors.wazuh import DEFAULT_PAGE_SIZE

        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["params"]["limit"] == DEFAULT_PAGE_SIZE

    async def test_query_param_filters_by_timestamp_since(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        since_before = conn._last_fetched_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        [e async for e in conn._fetch_events()]

        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["params"]["q"] == f"timestamp>{since_before}"

    async def test_query_param_sorts_by_timestamp_ascending(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["params"]["sort"] == "+timestamp"

    async def test_second_page_offset_increments_by_page_size(self) -> None:
        from app.connectors.wazuh import DEFAULT_PAGE_SIZE

        conn = WazuhConnector(_make_config(), InMemoryQueue())
        page1 = [{"id": str(i)} for i in range(DEFAULT_PAGE_SIZE)]
        page2 = [{"id": str(i)} for i in range(DEFAULT_PAGE_SIZE, DEFAULT_PAGE_SIZE + 10)]
        mock_client = MagicMock()
        mock_client.get = AsyncMock(
            side_effect=[
                _alerts_resp(page1, total=DEFAULT_PAGE_SIZE + 10),
                _alerts_resp(page2, total=DEFAULT_PAGE_SIZE + 10),
            ]
        )
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        # First call: offset=0, second call: offset=DEFAULT_PAGE_SIZE
        first_call_offset = mock_client.get.call_args_list[0][1]["params"]["offset"]
        second_call_offset = mock_client.get.call_args_list[1][1]["params"]["offset"]
        assert first_call_offset == 0
        assert second_call_offset == DEFAULT_PAGE_SIZE

    async def test_fetches_alerts_endpoint(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        call_args = mock_client.get.call_args[0]
        assert call_args[0] == "/alerts"


# ── stop() ─────────────────────────────────────────────────────────────────────


class TestWazuhConnectorStop:
    async def test_stop_closes_http_client(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client
        conn._token = "tok"

        await conn.stop()

        mock_client.aclose.assert_called_once()

    async def test_stop_sets_client_to_none(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client

        await conn.stop()

        assert conn._client is None

    async def test_stop_clears_token(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client
        conn._token = "tok"

        await conn.stop()

        assert conn._token is None

    async def test_stop_with_no_client_does_not_raise(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        await conn.stop()  # _client is None — must not raise

    async def test_stop_sets_status_to_inactive(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client

        await conn.stop()

        assert conn.health.status == ConnectorStatus.INACTIVE


# ── WazuhConnectorFactory ──────────────────────────────────────────────────────


class TestWazuhConnectorFactory:
    def test_from_dict_returns_wazuh_connector_instance(self) -> None:
        conn = WazuhConnectorFactory.from_dict(
            {"name": "prod", "url": "https://h:55000", "username": "u", "password": "p"},
            InMemoryQueue(),
        )
        assert isinstance(conn, WazuhConnector)

    def test_from_dict_sets_name(self) -> None:
        conn = WazuhConnectorFactory.from_dict(
            {"name": "my-wazuh", "url": "https://h:55000", "username": "u", "password": "p"},
            InMemoryQueue(),
        )
        assert conn.config.name == "my-wazuh"

    def test_from_dict_defaults_name_to_wazuh(self) -> None:
        conn = WazuhConnectorFactory.from_dict(
            {"url": "https://h:55000", "username": "u", "password": "p"},
            InMemoryQueue(),
        )
        assert conn.config.name == "wazuh"

    def test_from_dict_sets_poll_interval_seconds(self) -> None:
        conn = WazuhConnectorFactory.from_dict(
            {"url": "https://h:55000", "username": "u", "password": "p", "poll_interval_seconds": 30},
            InMemoryQueue(),
        )
        assert conn.config.poll_interval_seconds == 30

    def test_from_dict_default_poll_interval_is_60(self) -> None:
        conn = WazuhConnectorFactory.from_dict(
            {"url": "https://h:55000", "username": "u", "password": "p"},
            InMemoryQueue(),
        )
        assert conn.config.poll_interval_seconds == 60

    def test_from_dict_passes_credentials_in_extra(self) -> None:
        conn = WazuhConnectorFactory.from_dict(
            {"url": "https://h:55000", "username": "wui", "password": "pass123"},
            InMemoryQueue(),
        )
        assert conn.config.extra["url"] == "https://h:55000"
        assert conn.config.extra["username"] == "wui"
        assert conn.config.extra["password"] == "pass123"

    def test_from_dict_default_verify_ssl_is_true(self) -> None:
        conn = WazuhConnectorFactory.from_dict(
            {"url": "https://h:55000", "username": "u", "password": "p"},
            InMemoryQueue(),
        )
        assert conn.config.extra["verify_ssl"] is True

    def test_from_dict_respects_verify_ssl_false(self) -> None:
        conn = WazuhConnectorFactory.from_dict(
            {"url": "https://h:55000", "username": "u", "password": "p", "verify_ssl": False},
            InMemoryQueue(),
        )
        assert conn.config.extra["verify_ssl"] is False

    def test_from_dict_connector_type_is_wazuh(self) -> None:
        conn = WazuhConnectorFactory.from_dict(
            {"url": "https://h:55000", "username": "u", "password": "p"},
            InMemoryQueue(),
        )
        assert conn.config.connector_type == "wazuh"


# ── Feature 6.3 — Track last-seen timestamp ────────────────────────────────────


class TestWazuhConnectorCheckpoint:
    def test_initial_last_fetched_at_used_when_provided(self) -> None:
        fixed = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        conn = WazuhConnector(_make_config(), InMemoryQueue(), initial_last_fetched_at=fixed)
        assert conn._last_fetched_at == fixed

    def test_initial_last_fetched_at_none_falls_back_to_5_min_ago(self) -> None:
        before = datetime.now(timezone.utc)
        conn = WazuhConnector(_make_config(), InMemoryQueue(), initial_last_fetched_at=None)
        delta = before - conn._last_fetched_at
        assert 4 * 60 < delta.total_seconds() < 6 * 60

    def test_checkpoint_callback_none_by_default(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue())
        assert conn._checkpoint_callback is None

    async def test_checkpoint_callback_called_after_fetch(self) -> None:
        captured: list[datetime] = []

        async def _cb(ts: datetime) -> None:
            captured.append(ts)

        conn = WazuhConnector(_make_config(), InMemoryQueue(), checkpoint_callback=_cb)
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        assert len(captured) == 1

    async def test_checkpoint_callback_receives_updated_timestamp(self) -> None:
        captured: list[datetime] = []

        async def _cb(ts: datetime) -> None:
            captured.append(ts)

        conn = WazuhConnector(_make_config(), InMemoryQueue(), checkpoint_callback=_cb)
        old_time = conn._last_fetched_at
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        assert captured[0] == conn._last_fetched_at
        assert captured[0] > old_time

    async def test_checkpoint_callback_not_called_when_none(self) -> None:
        conn = WazuhConnector(_make_config(), InMemoryQueue(), checkpoint_callback=None)
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        # Must not raise
        [e async for e in conn._fetch_events()]

    async def test_checkpoint_callback_called_once_per_fetch_cycle(self) -> None:
        """Callback fires once per _fetch_events() call, even across multiple pages."""
        call_count = 0

        async def _cb(ts: datetime) -> None:
            nonlocal call_count
            call_count += 1

        conn = WazuhConnector(_make_config(), InMemoryQueue(), checkpoint_callback=_cb)
        page1 = [{"id": str(i)} for i in range(100)]
        page2 = [{"id": str(i)} for i in range(100, 110)]
        mock_client = MagicMock()
        mock_client.get = AsyncMock(
            side_effect=[
                _alerts_resp(page1, total=110),
                _alerts_resp(page2, total=110),
            ]
        )
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        assert call_count == 1

    async def test_fetch_query_uses_initial_last_fetched_at(self) -> None:
        fixed = datetime(2025, 6, 1, 8, 0, 0, tzinfo=timezone.utc)
        conn = WazuhConnector(
            _make_config(), InMemoryQueue(), initial_last_fetched_at=fixed
        )
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_alerts_resp([], total=0))
        conn._client = mock_client
        conn._token = "tok"

        [e async for e in conn._fetch_events()]

        call_kwargs = mock_client.get.call_args[1]
        assert call_kwargs["params"]["q"] == "timestamp>2025-06-01T08:00:00Z"
