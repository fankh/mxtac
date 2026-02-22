"""Tests for POST /api/v1/ingest — feature 35.3 generic webhook receiver.

Coverage:
  - POST /ingest: missing X-MxTac-Source header → 422
  - POST /ingest: missing X-MxTac-Token header → 422
  - POST /ingest: unknown source (no matching connector) → 401
  - POST /ingest: source connector has wrong type (not "generic") → 401
  - POST /ingest: correct source but wrong token → 401
  - POST /ingest: no webhook_token configured in connector → 401
  - POST /ingest: valid single JSON object → 202, accepted=1, rejected=0
  - POST /ingest: valid JSON array → 202, accepted=N, rejected=0
  - POST /ingest: empty array → 202, accepted=0, rejected=0
  - POST /ingest: mixed array (dicts + non-dicts) → accepted + rejected split
  - POST /ingest: non-object/array JSON (bare string) → 400
  - POST /ingest: invalid JSON body → 400
  - POST /ingest: body exceeds 5 MB → 413
  - POST /ingest: rate limit exceeded → 429
  - POST /ingest: rate limit fail-open when Valkey is unavailable
  - POST /ingest: events published to mxtac.raw.{source_name} topic
  - POST /ingest: _webhook_source and _received_at metadata injected
  - POST /ingest: batch shares single _received_at timestamp
  - POST /ingest/test: valid credentials → 200 {"status": "ok"}
  - POST /ingest/test: wrong token → 401
  - POST /ingest/test: missing source header → 422

Uses in-memory SQLite via the ``db_session`` fixture (get_db overridden).
Queue is mocked to capture published events without external side effects.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import get_db
from app.main import app
from app.pipeline.queue import get_queue
from app.repositories.connector_repo import ConnectorRepo

BASE = "/api/v1/ingest"

_SOURCE = "my-webhook"
_TOKEN = "super-secret-token"
_GOOD_HEADERS = {
    "X-MxTac-Source": _SOURCE,
    "X-MxTac-Token": _TOKEN,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_queue() -> MagicMock:
    """Mock MessageQueue that captures publish calls."""
    q = MagicMock()
    q.publish = AsyncMock()
    return q


@pytest.fixture
async def ingest_client(
    db_session,
    mock_queue: MagicMock,
) -> AsyncGenerator[AsyncClient, None]:
    """AsyncClient with get_db and get_queue both overridden."""

    async def _override_get_db() -> AsyncGenerator:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_queue] = lambda: mock_queue

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
async def generic_connector(db_session):
    """Registered generic connector with a known webhook_token."""
    return await ConnectorRepo.create(
        db_session,
        name=_SOURCE,
        connector_type="generic",
        config_json=json.dumps({"webhook_token": _TOKEN}),
    )


@pytest.fixture
async def wazuh_connector(db_session):
    """Registered wazuh connector (not generic) for type-validation tests."""
    return await ConnectorRepo.create(
        db_session,
        name="wazuh-src",
        connector_type="wazuh",
        config_json=json.dumps({"webhook_token": _TOKEN}),
    )


# ---------------------------------------------------------------------------
# Header validation — required headers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_source_header(ingest_client: AsyncClient) -> None:
    """Missing X-MxTac-Source → 422 Unprocessable Entity."""
    resp = await ingest_client.post(
        BASE,
        headers={"X-MxTac-Token": _TOKEN},
        json={"event": "data"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_missing_token_header(ingest_client: AsyncClient) -> None:
    """Missing X-MxTac-Token → 422 Unprocessable Entity."""
    resp = await ingest_client.post(
        BASE,
        headers={"X-MxTac-Source": _SOURCE},
        json={"event": "data"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Connector / token validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_source(ingest_client: AsyncClient) -> None:
    """Source not registered in DB → 401."""
    resp = await ingest_client.post(BASE, headers=_GOOD_HEADERS, json={"x": 1})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_wrong_connector_type(
    ingest_client: AsyncClient,
    wazuh_connector,
) -> None:
    """Source exists but connector_type is not 'generic' → 401."""
    resp = await ingest_client.post(
        BASE,
        headers={"X-MxTac-Source": "wazuh-src", "X-MxTac-Token": _TOKEN},
        json={"x": 1},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_wrong_token(
    ingest_client: AsyncClient,
    generic_connector,
) -> None:
    """Correct source, mismatched token → 401."""
    resp = await ingest_client.post(
        BASE,
        headers={"X-MxTac-Source": _SOURCE, "X-MxTac-Token": "wrong-token"},
        json={"x": 1},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_no_webhook_token_configured(
    ingest_client: AsyncClient,
    db_session,
) -> None:
    """Connector config_json missing webhook_token → 401 (empty token never matches)."""
    await ConnectorRepo.create(
        db_session,
        name="no-token-src",
        connector_type="generic",
        config_json=json.dumps({}),
    )
    resp = await ingest_client.post(
        BASE,
        headers={"X-MxTac-Source": "no-token-src", "X-MxTac-Token": "anything"},
        json={"x": 1},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Happy path — single object
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_single_object(
    ingest_client: AsyncClient,
    generic_connector,
    mock_queue: MagicMock,
) -> None:
    """Valid single JSON object → 202, accepted=1, rejected=0, published once."""
    resp = await ingest_client.post(
        BASE,
        headers=_GOOD_HEADERS,
        json={"host": "server1", "event_type": "login"},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] == 1
    assert body["rejected"] == 0
    mock_queue.publish.assert_awaited_once()


# ---------------------------------------------------------------------------
# Happy path — array of objects
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_array(
    ingest_client: AsyncClient,
    generic_connector,
    mock_queue: MagicMock,
) -> None:
    """Valid array of 5 objects → 202, accepted=5, rejected=0."""
    events = [{"id": i} for i in range(5)]
    resp = await ingest_client.post(BASE, headers=_GOOD_HEADERS, json=events)
    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] == 5
    assert body["rejected"] == 0
    assert mock_queue.publish.await_count == 5


@pytest.mark.asyncio
async def test_empty_array(
    ingest_client: AsyncClient,
    generic_connector,
    mock_queue: MagicMock,
) -> None:
    """Empty JSON array → 202, accepted=0, rejected=0 (no error)."""
    resp = await ingest_client.post(BASE, headers=_GOOD_HEADERS, json=[])
    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] == 0
    assert body["rejected"] == 0
    mock_queue.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_mixed_array_rejected_count(
    ingest_client: AsyncClient,
    generic_connector,
    mock_queue: MagicMock,
) -> None:
    """Array with dicts and non-dicts → correct accepted/rejected split."""
    events: list = [{"ok": True}, "bad", {"also": "ok"}, 42, None]
    resp = await ingest_client.post(BASE, headers=_GOOD_HEADERS, json=events)
    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] == 2
    assert body["rejected"] == 3
    assert mock_queue.publish.await_count == 2


# ---------------------------------------------------------------------------
# Published message validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_published_to_correct_topic(
    ingest_client: AsyncClient,
    generic_connector,
    mock_queue: MagicMock,
) -> None:
    """Events are published to mxtac.raw.{source_name}."""
    await ingest_client.post(BASE, headers=_GOOD_HEADERS, json={"x": 1})
    topic, _payload = mock_queue.publish.call_args.args
    assert topic == f"mxtac.raw.{_SOURCE}"


@pytest.mark.asyncio
async def test_metadata_injected(
    ingest_client: AsyncClient,
    generic_connector,
    mock_queue: MagicMock,
) -> None:
    """_webhook_source and _received_at are injected; original fields preserved."""
    await ingest_client.post(
        BASE,
        headers=_GOOD_HEADERS,
        json={"host": "srv1"},
    )
    _topic, payload = mock_queue.publish.call_args.args
    assert payload["_webhook_source"] == _SOURCE
    assert "_received_at" in payload
    datetime.fromisoformat(payload["_received_at"])  # must be valid ISO 8601
    assert payload["host"] == "srv1"


@pytest.mark.asyncio
async def test_batch_shares_received_at(
    ingest_client: AsyncClient,
    generic_connector,
    mock_queue: MagicMock,
) -> None:
    """All events in a batch share the same _received_at timestamp."""
    await ingest_client.post(
        BASE,
        headers=_GOOD_HEADERS,
        json=[{"i": 0}, {"i": 1}, {"i": 2}],
    )
    timestamps = {call.args[1]["_received_at"] for call in mock_queue.publish.await_args_list}
    assert len(timestamps) == 1, "All batch events must share one _received_at"


# ---------------------------------------------------------------------------
# Body validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_json_body(
    ingest_client: AsyncClient,
    generic_connector,
) -> None:
    """Non-JSON body → 400."""
    resp = await ingest_client.post(
        BASE,
        headers={**_GOOD_HEADERS, "Content-Type": "application/json"},
        content=b"not-json{{{",
    )
    assert resp.status_code == 400
    assert "valid JSON" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_non_object_non_array_json(
    ingest_client: AsyncClient,
    generic_connector,
) -> None:
    """JSON body that is a bare string → 400."""
    resp = await ingest_client.post(
        BASE,
        headers={**_GOOD_HEADERS, "Content-Type": "application/json"},
        content=b'"just a string"',
    )
    assert resp.status_code == 400
    assert "object or an array" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_body_too_large(
    ingest_client: AsyncClient,
    generic_connector,
) -> None:
    """Body exceeding 5 MB → 413 Request Entity Too Large."""
    # 5 MB + overhead to exceed the limit
    large_body = b'{"x":"' + b"a" * (5 * 1024 * 1024) + b'"}'
    resp = await ingest_client.post(
        BASE,
        headers={**_GOOD_HEADERS, "Content-Type": "application/json"},
        content=large_body,
    )
    assert resp.status_code == 413


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limit_exceeded(
    ingest_client: AsyncClient,
    generic_connector,
) -> None:
    """When rate limiter returns False → 429 Too Many Requests."""
    with patch(
        "app.api.v1.endpoints.webhook_ingest.check_webhook_source_rate_limit",
        new=AsyncMock(return_value=False),
    ):
        resp = await ingest_client.post(
            BASE,
            headers=_GOOD_HEADERS,
            json={"event": "data"},
        )
    assert resp.status_code == 429
    assert "Rate limit" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_rate_limit_fail_open(
    ingest_client: AsyncClient,
    generic_connector,
    mock_queue: MagicMock,
) -> None:
    """When Valkey is unreachable, requests are allowed (fail-open)."""
    with patch(
        "app.core.valkey.get_valkey_client",
        new=AsyncMock(side_effect=Exception("connection refused")),
    ):
        resp = await ingest_client.post(
            BASE,
            headers=_GOOD_HEADERS,
            json={"event": "login"},
        )
    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# Connectivity probe — POST /ingest/test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_valid_credentials(
    ingest_client: AsyncClient,
    generic_connector,
) -> None:
    """POST /ingest/test with valid source + token → 200 {"status": "ok"}."""
    resp = await ingest_client.post(f"{BASE}/test", headers=_GOOD_HEADERS)
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_probe_wrong_token(
    ingest_client: AsyncClient,
    generic_connector,
) -> None:
    """POST /ingest/test with wrong token → 401."""
    resp = await ingest_client.post(
        f"{BASE}/test",
        headers={"X-MxTac-Source": _SOURCE, "X-MxTac-Token": "wrong"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_probe_missing_source(ingest_client: AsyncClient) -> None:
    """POST /ingest/test without X-MxTac-Source → 422."""
    resp = await ingest_client.post(
        f"{BASE}/test",
        headers={"X-MxTac-Token": _TOKEN},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_probe_unknown_source(ingest_client: AsyncClient) -> None:
    """POST /ingest/test for source not in DB → 401."""
    resp = await ingest_client.post(f"{BASE}/test", headers=_GOOD_HEADERS)
    assert resp.status_code == 401
