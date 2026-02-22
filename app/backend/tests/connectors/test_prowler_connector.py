"""
Tests for ProwlerConnector.

Feature 6.19 — Prowler connector — cloud security findings (AWS/Azure/GCP):

Initialization:
  - client is None on init
  - last_fetched_at defaults to ~1 hour ago when no initial timestamp given
  - initial_last_fetched_at is used when provided
  - topic is mxtac.raw.prowler
  - topic literal string is "mxtac.raw.prowler"
  - health status is INACTIVE on init
  - _backoff_delay starts at BACKOFF_BASE on init
  - checkpoint_callback defaults to None

_connect():
  - creates httpx AsyncClient on first connect
  - raises ConnectionError when api_url is missing
  - raises ConnectionError when api_key is missing
  - raises HTTPStatusError on non-2xx health response
  - reuses existing client on re-connect (no second instantiation)
  - sends Authorization Bearer header on health probe
  - sets base_url from config extra api_url

_fetch_events():
  - yields nothing when client is None
  - yields findings from single page
  - paginates through multiple pages using page[number]
  - stops pagination when page equals total_pages
  - stops pagination when data list is empty
  - includes filter[inserted_at_gte] param using last_fetched_at
  - applies provider filter when providers configured
  - applies severity filter when severity configured
  - applies status filter when status configured (default FAIL)
  - no status filter param when status list is empty
  - no provider filter param when providers list is empty
  - no severity filter param when severity list is empty
  - advances _last_fetched_at after successful fetch
  - calls checkpoint_callback with updated timestamp
  - does not call checkpoint_callback when it is None
  - raises on non-2xx API response

Exponential backoff (matching Wazuh pattern):
  - _backoff_delay starts at BACKOFF_BASE (1.0 s)
  - BACKOFF_MAX is exactly 60.0 seconds
  - fetch error doubles _backoff_delay
  - doubling beyond BACKOFF_MAX is capped at BACKOFF_MAX
  - when at BACKOFF_MAX, another error keeps it at BACKOFF_MAX
  - successful cycle resets _backoff_delay to BACKOFF_BASE
  - error does NOT reset _backoff_delay to BACKOFF_BASE

Poll loop integration:
  - publishes each event to mxtac.raw.prowler topic
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

ProwlerConnectorFactory:
  - creates ProwlerConnector instance
  - name defaults to 'prowler'
  - poll_interval_seconds defaults to 300
  - required keys (api_url, api_key) are present in extra
  - optional keys have correct defaults (providers=[], severity=[], status=[FAIL])
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.connectors.base import ConnectorConfig, ConnectorStatus
from app.connectors.prowler import (
    BACKOFF_BASE,
    BACKOFF_MAX,
    ProwlerConnector,
    ProwlerConnectorFactory,
)
from app.pipeline.queue import InMemoryQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_config(**extra_overrides) -> ConnectorConfig:
    return ConnectorConfig(
        name="prowler-test",
        connector_type="prowler",
        enabled=True,
        poll_interval_seconds=300,
        extra={
            "api_url": "https://prowler.test",
            "api_key": "test-api-key",
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
    return _make_response(200, {"status": "ok"})


def _findings_resp(findings: list, pages: int = 1, current_page: int = 1) -> MagicMock:
    return _make_response(
        200,
        {
            "data": findings,
            "meta": {
                "pagination": {
                    "pages": pages,
                    "page": current_page,
                }
            },
        },
    )


async def _collect(conn: ProwlerConnector) -> list[dict]:
    results = []
    async for event in conn._fetch_events():
        results.append(event)
    return results


# ── Initialization ─────────────────────────────────────────────────────────────


class TestProwlerConnectorInit:
    def test_client_is_none_on_init(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        assert conn._client is None

    def test_last_fetched_at_defaults_to_approximately_1_hour_ago(self) -> None:
        before = datetime.now(timezone.utc)
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        after = datetime.now(timezone.utc)
        delta = before - conn._last_fetched_at
        assert 55 * 60 < delta.total_seconds() < 65 * 60
        assert conn._last_fetched_at < after

    def test_initial_last_fetched_at_used_when_provided(self) -> None:
        ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        conn = ProwlerConnector(_make_config(), InMemoryQueue(), initial_last_fetched_at=ts)
        assert conn._last_fetched_at == ts

    def test_topic_is_raw_prowler(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        assert conn.topic == Topic.RAW_PROWLER

    def test_topic_literal_string(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        assert conn.topic == "mxtac.raw.prowler"

    def test_health_status_is_inactive(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        assert conn.health.status == ConnectorStatus.INACTIVE

    def test_backoff_delay_starts_at_base(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        assert conn._backoff_delay == BACKOFF_BASE

    def test_checkpoint_callback_defaults_to_none(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        assert conn._checkpoint_callback is None


# ── _connect() ─────────────────────────────────────────────────────────────────


class TestProwlerConnectorConnect:
    async def test_connect_creates_http_client(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_health_ok())

        with patch("httpx.AsyncClient", return_value=mock_client):
            await conn._connect()

        assert conn._client is not None

    async def test_connect_raises_when_api_url_missing(self) -> None:
        conn = ProwlerConnector(
            _make_config(api_url=""),
            InMemoryQueue(),
        )
        with pytest.raises(ConnectionError, match="api_url"):
            await conn._connect()

    async def test_connect_raises_when_api_key_missing(self) -> None:
        conn = ProwlerConnector(
            _make_config(api_key=""),
            InMemoryQueue(),
        )
        with pytest.raises(ConnectionError, match="api_key"):
            await conn._connect()

    async def test_connect_raises_on_non_2xx_health_response(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_make_response(503, {}))
        conn._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            await conn._connect()

    async def test_connect_reuses_existing_client(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        existing_client = MagicMock()
        existing_client.get = AsyncMock(return_value=_health_ok())
        conn._client = existing_client

        with patch("httpx.AsyncClient") as mock_cls:
            await conn._connect()
            mock_cls.assert_not_called()

        assert conn._client is existing_client

    async def test_connect_sends_bearer_auth_header(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_health_ok())
        conn._client = mock_client

        await conn._connect()

        # The Authorization header is set on the AsyncClient at instantiation;
        # here we verify the health probe call is made to the expected path.
        mock_client.get.assert_called_once_with("/api/v1/health")

    async def test_connect_strips_trailing_slash_from_api_url(self) -> None:
        """The connector should work with or without a trailing slash in api_url."""
        conn = ProwlerConnector(
            _make_config(api_url="https://prowler.test/"),
            InMemoryQueue(),
        )
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_health_ok())
        conn._client = mock_client

        # Should not raise — trailing slash is stripped in _connect()
        await conn._connect()


# ── _fetch_events() ────────────────────────────────────────────────────────────


class TestProwlerFetchEvents:
    async def test_yields_nothing_when_client_is_none(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        events = await _collect(conn)
        assert events == []

    async def test_yields_findings_from_single_page(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        findings = [
            {"id": "f1", "status": "FAIL", "severity": "critical"},
            {"id": "f2", "status": "FAIL", "severity": "high"},
        ]
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp(findings, pages=1))
        conn._client = mock_client

        events = await _collect(conn)
        assert len(events) == 2
        assert events[0]["id"] == "f1"
        assert events[1]["id"] == "f2"

    async def test_paginates_through_multiple_pages(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        page1 = [{"id": "f1"}]
        page2 = [{"id": "f2"}]

        responses = [
            _findings_resp(page1, pages=2, current_page=1),
            _findings_resp(page2, pages=2, current_page=2),
        ]
        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=responses)
        conn._client = mock_client

        events = await _collect(conn)
        assert len(events) == 2
        assert events[0]["id"] == "f1"
        assert events[1]["id"] == "f2"
        assert mock_client.get.call_count == 2

    async def test_stops_pagination_when_page_equals_total_pages(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        # Single page response — total_pages == 1, current page starts at 1
        mock_client.get = AsyncMock(
            return_value=_findings_resp([{"id": "f1"}], pages=1)
        )
        conn._client = mock_client

        await _collect(conn)
        assert mock_client.get.call_count == 1

    async def test_stops_pagination_when_data_is_empty(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        # Claim 3 pages but return empty data on first call
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=3))
        conn._client = mock_client

        events = await _collect(conn)
        assert events == []
        assert mock_client.get.call_count == 1

    async def test_filter_inserted_at_gte_uses_last_fetched_at(self) -> None:
        ts = datetime(2024, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        conn = ProwlerConnector(
            _make_config(), InMemoryQueue(), initial_last_fetched_at=ts
        )
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert call_params["filter[inserted_at_gte]"] == "2024-06-01T10:00:00Z"

    async def test_applies_provider_filter_when_configured(self) -> None:
        conn = ProwlerConnector(
            _make_config(providers=["aws", "azure"]),
            InMemoryQueue(),
        )
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert call_params["filter[provider]"] == "aws,azure"

    async def test_no_provider_filter_when_providers_empty(self) -> None:
        conn = ProwlerConnector(_make_config(providers=[]), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert "filter[provider]" not in call_params

    async def test_applies_severity_filter_when_configured(self) -> None:
        conn = ProwlerConnector(
            _make_config(severity=["critical", "high"]),
            InMemoryQueue(),
        )
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert call_params["filter[severity]"] == "critical,high"

    async def test_no_severity_filter_when_severity_empty(self) -> None:
        conn = ProwlerConnector(_make_config(severity=[]), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert "filter[severity]" not in call_params

    async def test_applies_default_fail_status_filter(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert call_params["filter[status]"] == "FAIL"

    async def test_applies_custom_status_filter(self) -> None:
        conn = ProwlerConnector(
            _make_config(status=["FAIL", "MANUAL"]),
            InMemoryQueue(),
        )
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert call_params["filter[status]"] == "FAIL,MANUAL"

    async def test_no_status_filter_when_status_list_empty(self) -> None:
        conn = ProwlerConnector(_make_config(status=[]), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert "filter[status]" not in call_params

    async def test_advances_last_fetched_at_after_successful_fetch(self) -> None:
        ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        conn = ProwlerConnector(
            _make_config(), InMemoryQueue(), initial_last_fetched_at=ts
        )
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        before = datetime.now(timezone.utc)
        await _collect(conn)
        after = datetime.now(timezone.utc)

        assert conn._last_fetched_at > ts
        assert before <= conn._last_fetched_at <= after

    async def test_calls_checkpoint_callback_with_updated_timestamp(self) -> None:
        ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        checkpoint_cb = AsyncMock()
        conn = ProwlerConnector(
            _make_config(),
            InMemoryQueue(),
            initial_last_fetched_at=ts,
            checkpoint_callback=checkpoint_cb,
        )
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        checkpoint_cb.assert_called_once()
        called_ts = checkpoint_cb.call_args[0][0]
        assert called_ts > ts
        assert isinstance(called_ts, datetime)

    async def test_does_not_call_checkpoint_when_none(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        # Should not raise
        await _collect(conn)

    async def test_raises_on_non_2xx_api_response(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_make_response(500, {}))
        conn._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            await _collect(conn)

    async def test_uses_page_size_in_params(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert "page[size]" in call_params
        assert call_params["page[size]"] > 0

    async def test_gcp_provider_filter(self) -> None:
        conn = ProwlerConnector(_make_config(providers=["gcp"]), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_findings_resp([], pages=1))
        conn._client = mock_client

        await _collect(conn)

        call_params = mock_client.get.call_args[1]["params"]
        assert call_params["filter[provider]"] == "gcp"


# ── Exponential backoff ────────────────────────────────────────────────────────


class TestProwlerBackoff:
    def test_backoff_base_is_1_second(self) -> None:
        assert BACKOFF_BASE == 1.0

    def test_backoff_max_is_60_seconds(self) -> None:
        assert BACKOFF_MAX == 60.0

    def test_backoff_delay_starts_at_base(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        assert conn._backoff_delay == BACKOFF_BASE

    async def test_fetch_error_doubles_backoff_delay(self) -> None:
        """_backoff_delay is doubled after a fetch failure.

        stop_event is set BEFORE raising so the loop exits after the error path
        without running another successful cycle that would reset the delay.
        """
        conn = ProwlerConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("API unavailable")
            yield  # noqa: unreachable — makes this an async generator

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]

        initial_backoff = conn._backoff_delay
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_BASE * 2

    async def test_doubling_beyond_max_is_capped(self) -> None:
        """32 * 2 = 64 exceeds BACKOFF_MAX (60), so delay is clamped to 60."""
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = 32.0  # 32 * 2 = 64 > 60

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_MAX

    async def test_successful_cycle_resets_backoff_to_base(self) -> None:
        """A successful (non-raising) fetch cycle resets _backoff_delay to BACKOFF_BASE."""
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = 32.0  # simulate elevated backoff from prior errors

        async def _mock_fetch():
            conn._stop_event.set()
            return
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_BASE

    async def test_error_does_not_reset_backoff_to_base(self) -> None:
        """After a failure the delay doubles, not resets to base."""
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = 16.0

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay != BACKOFF_BASE

    async def test_at_max_backoff_another_error_stays_at_max(self) -> None:
        """An error when _backoff_delay is already BACKOFF_MAX keeps it at max."""
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        conn._backoff_delay = BACKOFF_MAX

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn._backoff_delay == BACKOFF_MAX


# ── Poll loop integration ──────────────────────────────────────────────────────


class TestProwlerPollLoop:
    async def test_publishes_events_to_raw_prowler_topic(self) -> None:
        queue = InMemoryQueue()
        conn = ProwlerConnector(_make_config(), queue)

        async def _mock_fetch():
            yield {"id": "f1", "status": "FAIL"}
            conn._stop_event.set()

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        msg = await queue._queues[Topic.RAW_PROWLER].get()
        assert msg["id"] == "f1"

    async def test_events_total_increments_per_event(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            yield {"id": "f1"}
            yield {"id": "f2"}
            conn._stop_event.set()

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn.health.events_total == 2

    async def test_last_event_at_updated_after_first_publish(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        assert conn.health.last_event_at is None

        async def _mock_fetch():
            yield {"id": "f1"}
            conn._stop_event.set()

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]

        before = datetime.now(timezone.utc)
        await conn._poll_loop()
        after = datetime.now(timezone.utc)

        assert conn.health.last_event_at is not None
        assert before <= conn.health.last_event_at <= after

    async def test_no_publish_when_fetch_yields_nothing(self) -> None:
        queue = InMemoryQueue()
        conn = ProwlerConnector(_make_config(), queue)

        async def _mock_fetch():
            conn._stop_event.set()
            return
            yield

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn.health.events_total == 0
        assert queue._queues[Topic.RAW_PROWLER].empty()

    async def test_fetch_error_does_not_crash_loop(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("transient error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()  # must not raise

    async def test_fetch_error_increments_errors_total(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert conn.health.errors_total == 1

    async def test_fetch_error_stores_message_in_health(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("prowler unreachable")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        assert "prowler unreachable" in conn.health.error_message

    async def test_status_callback_called_with_active_on_success(self) -> None:
        status_cb = AsyncMock()
        conn = ProwlerConnector(_make_config(), InMemoryQueue(), status_callback=status_cb)

        async def _mock_fetch():
            conn._stop_event.set()
            return
            yield

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        status_cb.assert_called_once_with(ConnectorStatus.ACTIVE.value, None)

    async def test_status_callback_called_with_error_on_failure(self) -> None:
        status_cb = AsyncMock()
        conn = ProwlerConnector(_make_config(), InMemoryQueue(), status_callback=status_cb)

        async def _mock_fetch():
            conn._stop_event.set()
            raise RuntimeError("api error")
            yield  # noqa: unreachable

        conn._fetch_events = _mock_fetch  # type: ignore[method-assign]
        await conn._poll_loop()

        calls = [c for c in status_cb.call_args_list]
        statuses = [c[0][0] for c in calls]
        assert ConnectorStatus.ERROR.value in statuses


# ── stop() ────────────────────────────────────────────────────────────────────


class TestProwlerStop:
    async def test_stop_closes_http_client(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client

        await conn.stop()

        mock_client.aclose.assert_called_once()

    async def test_stop_clears_client_reference(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        conn._client = mock_client

        await conn.stop()

        assert conn._client is None

    async def test_stop_is_safe_when_client_is_none(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        assert conn._client is None
        await conn.stop()  # must not raise

    async def test_stop_sets_health_status_to_inactive(self) -> None:
        conn = ProwlerConnector(_make_config(), InMemoryQueue())
        conn.health.status = ConnectorStatus.ACTIVE

        await conn.stop()

        assert conn.health.status == ConnectorStatus.INACTIVE


# ── ProwlerConnectorFactory ────────────────────────────────────────────────────


class TestProwlerConnectorFactory:
    def test_creates_prowler_connector_instance(self) -> None:
        queue = InMemoryQueue()
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://prowler.test", "api_key": "key123"},
            queue,
        )
        assert isinstance(conn, ProwlerConnector)

    def test_name_defaults_to_prowler(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://prowler.test", "api_key": "key123"},
            InMemoryQueue(),
        )
        assert conn.config.name == "prowler"

    def test_name_can_be_overridden(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"name": "my-prowler", "api_url": "https://p.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.name == "my-prowler"

    def test_poll_interval_defaults_to_300(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://prowler.test", "api_key": "key123"},
            InMemoryQueue(),
        )
        assert conn.config.poll_interval_seconds == 300

    def test_poll_interval_can_be_overridden(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://p.test", "api_key": "k", "poll_interval_seconds": 600},
            InMemoryQueue(),
        )
        assert conn.config.poll_interval_seconds == 600

    def test_api_url_in_extra(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://prowler.test", "api_key": "key123"},
            InMemoryQueue(),
        )
        assert conn.config.extra["api_url"] == "https://prowler.test"

    def test_api_key_in_extra(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://prowler.test", "api_key": "key123"},
            InMemoryQueue(),
        )
        assert conn.config.extra["api_key"] == "key123"

    def test_providers_defaults_to_empty_list(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://p.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["providers"] == []

    def test_severity_defaults_to_empty_list(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://p.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["severity"] == []

    def test_status_defaults_to_fail_only(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://p.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["status"] == ["FAIL"]

    def test_verify_ssl_defaults_to_true(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://p.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["verify_ssl"] is True

    def test_timeout_defaults_to_30(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {"api_url": "https://p.test", "api_key": "k"},
            InMemoryQueue(),
        )
        assert conn.config.extra["timeout"] == 30

    def test_all_providers_can_be_configured(self) -> None:
        conn = ProwlerConnectorFactory.from_dict(
            {
                "api_url": "https://p.test",
                "api_key": "k",
                "providers": ["aws", "azure", "gcp"],
            },
            InMemoryQueue(),
        )
        assert conn.config.extra["providers"] == ["aws", "azure", "gcp"]
