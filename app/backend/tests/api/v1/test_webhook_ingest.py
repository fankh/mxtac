"""Tests for POST /api/v1/ingest — generic webhook receiver (Feature 6.21).

Coverage:
  - POST /ingest/test: connectivity probe (401/403 on bad key, 200 on valid key)
  - 401 when X-API-Key header is absent
  - 403 when key is unknown / invalid
  - 400 when body is not valid JSON
  - 400 when body is not an object or array of objects (e.g. a bare string/number)
  - 400 when an array element is not a JSON object
  - 422 when array is empty
  - 422 when array exceeds 1,000 items
  - 202 with a single JSON object — published once with _webhook_source injected
  - 202 with an array of objects — published N times
  - 202 with X-Webhook-Source header — source label embedded in published events
  - 202 without X-Webhook-Source — defaults to "generic"
  - Exactly 1,000 events accepted (boundary value)
  - _received_at metadata injected into every published event
  - 429 when rate limit is exceeded (Valkey reports counter > limit)
  - Rate limit fail-open when Valkey is unreachable
"""

from __future__ import annotations

import secrets
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.pipeline.queue import Topic, get_queue
from app.repositories.api_key_repo import APIKeyRepo

BASE = "/api/v1/ingest"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_key(db: AsyncSession, label: str = "webhook-test") -> str:
    """Insert an active API key and return the raw (plaintext) key string."""
    raw = f"mxtac_{secrets.token_hex(16)}"
    await APIKeyRepo.create(db, raw_key=raw, label=label)
    return raw


def _make_queue() -> MagicMock:
    """Return a mock queue that captures publish calls."""
    mock = MagicMock()
    mock.publish = AsyncMock()
    return mock


def _valkey_allow() -> AsyncMock:
    """Mock Valkey client that allows requests (counter within limit)."""
    mock = AsyncMock()
    mock.eval = AsyncMock(return_value=1)
    return mock


def _valkey_deny() -> AsyncMock:
    """Mock Valkey client that denies requests (counter exceeds limit)."""
    mock = AsyncMock()
    mock.eval = AsyncMock(return_value=10_001)
    return mock


# ---------------------------------------------------------------------------
# Auth checks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_no_key(client: AsyncClient) -> None:
    """Missing X-API-Key → 401."""
    resp = await client.post(BASE, json={"alert": "test"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_invalid_key(client: AsyncClient) -> None:
    """Unknown X-API-Key → 403."""
    resp = await client.post(
        BASE,
        headers={"X-API-Key": "mxtac_doesnotexist"},
        json={"alert": "test"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Body validation — bad JSON / wrong types
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_invalid_json(client: AsyncClient, db_session: AsyncSession) -> None:
    """Non-JSON body → 400."""
    raw = await _create_key(db_session)
    resp = await client.post(
        BASE,
        headers={"X-API-Key": raw, "Content-Type": "application/json"},
        content=b"not-json!!!",
    )
    assert resp.status_code == 400
    assert "valid JSON" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_bare_string(client: AsyncClient, db_session: AsyncSession) -> None:
    """JSON body that is a bare string → 400."""
    raw = await _create_key(db_session)
    resp = await client.post(
        BASE,
        headers={"X-API-Key": raw, "Content-Type": "application/json"},
        content=b'"just a string"',
    )
    assert resp.status_code == 400
    assert "object or an array" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_bare_number(client: AsyncClient, db_session: AsyncSession) -> None:
    """JSON body that is a bare number → 400."""
    raw = await _create_key(db_session)
    resp = await client.post(
        BASE,
        headers={"X-API-Key": raw, "Content-Type": "application/json"},
        content=b"42",
    )
    assert resp.status_code == 400
    assert "object or an array" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_array_with_non_object_element(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Array containing a non-object element → 400."""
    raw = await _create_key(db_session)
    resp = await client.post(
        BASE,
        headers={"X-API-Key": raw},
        json=[{"ok": True}, "not-an-object"],
    )
    assert resp.status_code == 400
    assert "index 1" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Batch size validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_empty_array(client: AsyncClient, db_session: AsyncSession) -> None:
    """Empty array → 422."""
    raw = await _create_key(db_session)
    resp = await client.post(BASE, headers={"X-API-Key": raw}, json=[])
    assert resp.status_code == 422
    assert "at least one event" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_array_too_large(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Array of 1,001 objects → 422."""
    raw = await _create_key(db_session)
    batch = [{"i": i} for i in range(1001)]
    resp = await client.post(BASE, headers={"X-API-Key": raw}, json=batch)
    assert resp.status_code == 422
    assert "1000" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_array_exactly_1000(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Array of exactly 1,000 objects is accepted (boundary value)."""
    raw = await _create_key(db_session)
    mock_q = _make_queue()
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        batch = [{"i": i} for i in range(1000)]
        resp = await client.post(BASE, headers={"X-API-Key": raw}, json=batch)
        assert resp.status_code == 202
        body = resp.json()
        assert body["accepted"] == 1000
        assert mock_q.publish.call_count == 1000
    finally:
        app.dependency_overrides.pop(get_queue, None)


# ---------------------------------------------------------------------------
# Happy path — single object
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_single_object(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Single JSON object → 202, published once."""
    raw = await _create_key(db_session)
    mock_q = _make_queue()
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        resp = await client.post(
            BASE,
            headers={"X-API-Key": raw},
            json={"event_type": "login", "user": "alice"},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert body["accepted"] == 1
        assert body["topic"] == Topic.RAW_WEBHOOK
        assert body["status"] == "queued"
        assert mock_q.publish.call_count == 1
    finally:
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_single_object_published_to_raw_webhook(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Single object is published to the mxtac.raw.webhook topic."""
    raw = await _create_key(db_session)

    published: list[tuple[str, dict]] = []

    async def _capture(topic: str, message: dict) -> None:
        published.append((topic, message))

    mock_q = MagicMock()
    mock_q.publish = _capture
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        resp = await client.post(
            BASE,
            headers={"X-API-Key": raw},
            json={"event_type": "process_create", "pid": 1234},
        )
        assert resp.status_code == 202
        assert len(published) == 1
        topic, msg = published[0]
        assert topic == "mxtac.raw.webhook"
        assert msg["event_type"] == "process_create"
        assert msg["pid"] == 1234
    finally:
        app.dependency_overrides.pop(get_queue, None)


# ---------------------------------------------------------------------------
# Happy path — array of objects
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_array_of_objects(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Array of 3 objects → 202, accepted=3, published 3 times."""
    raw = await _create_key(db_session)
    mock_q = _make_queue()
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        batch = [{"seq": i, "action": "click"} for i in range(3)]
        resp = await client.post(BASE, headers={"X-API-Key": raw}, json=batch)
        assert resp.status_code == 202
        body = resp.json()
        assert body["accepted"] == 3
        assert mock_q.publish.call_count == 3
    finally:
        app.dependency_overrides.pop(get_queue, None)


# ---------------------------------------------------------------------------
# Source tagging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_source_header_embedded(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """X-Webhook-Source header value is injected as _webhook_source in published event."""
    raw = await _create_key(db_session)

    published: list[tuple[str, dict]] = []

    async def _capture(topic: str, message: dict) -> None:
        published.append((topic, message))

    mock_q = MagicMock()
    mock_q.publish = _capture
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        resp = await client.post(
            BASE,
            headers={"X-API-Key": raw, "X-Webhook-Source": "github"},
            json={"action": "push", "repo": "mxtac"},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert body["source"] == "github"
        topic, msg = published[0]
        assert msg["_webhook_source"] == "github"
        assert msg["action"] == "push"
    finally:
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_default_source_generic(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """When X-Webhook-Source is absent, _webhook_source defaults to 'generic'."""
    raw = await _create_key(db_session)

    published: list[tuple[str, dict]] = []

    async def _capture(topic: str, message: dict) -> None:
        published.append((topic, message))

    mock_q = MagicMock()
    mock_q.publish = _capture
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        resp = await client.post(
            BASE,
            headers={"X-API-Key": raw},
            json={"data": "anything"},
        )
        assert resp.status_code == 202
        assert resp.json()["source"] == "generic"
        _, msg = published[0]
        assert msg["_webhook_source"] == "generic"
    finally:
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_source_not_overwrite_existing_key(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """_webhook_source is prepended; existing event keys are preserved."""
    raw = await _create_key(db_session)

    published: list[tuple[str, dict]] = []

    async def _capture(topic: str, message: dict) -> None:
        published.append((topic, message))

    mock_q = MagicMock()
    mock_q.publish = _capture
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        await client.post(
            BASE,
            headers={"X-API-Key": raw, "X-Webhook-Source": "custom"},
            json={"severity": "high", "host": "srv-01"},
        )
        _, msg = published[0]
        assert msg["_webhook_source"] == "custom"
        assert msg["severity"] == "high"
        assert msg["host"] == "srv-01"
    finally:
        app.dependency_overrides.pop(get_queue, None)


# ---------------------------------------------------------------------------
# Connectivity probe — POST /ingest/test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_test_no_key(client: AsyncClient) -> None:
    """Missing X-API-Key → 401."""
    resp = await client.post(BASE + "/test")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_test_invalid_key(client: AsyncClient) -> None:
    """Unknown X-API-Key → 403."""
    resp = await client.post(
        BASE + "/test",
        headers={"X-API-Key": "mxtac_doesnotexist"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_ingest_test_valid_key(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Valid X-API-Key → 200 with status ok."""
    raw = await _create_key(db_session)
    resp = await client.post(BASE + "/test", headers={"X-API-Key": raw})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# _received_at metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_received_at_injected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Every published event contains a _received_at ISO 8601 timestamp."""
    raw = await _create_key(db_session)

    published: list[tuple[str, dict]] = []

    async def _capture(topic: str, message: dict) -> None:
        published.append((topic, message))

    mock_q = MagicMock()
    mock_q.publish = _capture
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        resp = await client.post(
            BASE,
            headers={"X-API-Key": raw},
            json={"event": "login"},
        )
        assert resp.status_code == 202
        assert len(published) == 1
        _, msg = published[0]
        assert "_received_at" in msg
        # Must be parseable as an ISO 8601 datetime
        from datetime import datetime
        datetime.fromisoformat(msg["_received_at"])
    finally:
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_batch_all_events_share_received_at(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """All events in a batch share the same _received_at timestamp."""
    raw = await _create_key(db_session)

    published: list[tuple[str, dict]] = []

    async def _capture(topic: str, message: dict) -> None:
        published.append((topic, message))

    mock_q = MagicMock()
    mock_q.publish = _capture
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        resp = await client.post(
            BASE,
            headers={"X-API-Key": raw},
            json=[{"i": 0}, {"i": 1}, {"i": 2}],
        )
        assert resp.status_code == 202
        timestamps = {msg["_received_at"] for _, msg in published}
        assert len(timestamps) == 1, "All events in a batch must share the same _received_at"
    finally:
        app.dependency_overrides.pop(get_queue, None)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_rate_limit_exceeded(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """When Valkey reports counter above the limit → 429."""
    raw = await _create_key(db_session)

    with patch(
        "app.core.valkey.get_valkey_client",
        new=AsyncMock(return_value=_valkey_deny()),
    ):
        resp = await client.post(
            BASE,
            headers={"X-API-Key": raw},
            json={"event": "login"},
        )
    assert resp.status_code == 429
    assert "Rate limit" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_rate_limit_fail_open(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """When Valkey is unreachable, requests are allowed (fail-open)."""
    raw = await _create_key(db_session)

    mock_q = _make_queue()
    app.dependency_overrides[get_queue] = lambda: mock_q

    try:
        with patch(
            "app.core.valkey.get_valkey_client",
            new=AsyncMock(side_effect=Exception("connection refused")),
        ):
            resp = await client.post(
                BASE,
                headers={"X-API-Key": raw},
                json={"event": "login"},
            )
        assert resp.status_code == 202
    finally:
        app.dependency_overrides.pop(get_queue, None)
