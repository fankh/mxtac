"""Tests for the OCSF event ingest endpoints.

Coverage:
  - POST /ingest/test: auth (401 with missing/invalid key, 200 with valid key)
  - POST /ingest:
      - 401 when X-API-Key header is absent
      - 401 when key is unknown
      - 422 when batch size exceeds 1,000 events
      - 429 when rate limit is exceeded
      - 202 when batch is valid; events published to queue
"""

from __future__ import annotations

import secrets
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import app.api.v1.endpoints.events as events_module
from app.main import app
from app.pipeline.queue import Topic, get_queue
from app.repositories.api_key_repo import APIKeyRepo

BASE = "/api/v1/events"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_key(db: AsyncSession, label: str = "test-agent") -> str:
    """Insert an active API key and return the raw (plaintext) key string."""
    raw = f"mxtac_{secrets.token_hex(16)}"
    await APIKeyRepo.create(db, raw_key=raw, label=label)
    return raw


def _ocsf_event(**kwargs: Any) -> dict:
    return {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "severity_id": 1,
        "metadata_product": "mxguard",
        **kwargs,
    }


# ---------------------------------------------------------------------------
# Fixture: reset rate-limiter state between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    events_module._rate_counters.clear()
    yield
    events_module._rate_counters.clear()


# ---------------------------------------------------------------------------
# POST /ingest/test — connectivity probe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_test_no_key(client: AsyncClient) -> None:
    """Missing X-API-Key → 401."""
    resp = await client.post(BASE + "/ingest/test")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_test_invalid_key(client: AsyncClient) -> None:
    """Unknown X-API-Key → 401."""
    resp = await client.post(
        BASE + "/ingest/test",
        headers={"X-API-Key": "mxtac_doesnotexist"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_test_valid_key(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Valid X-API-Key → 200 with status ok."""
    raw = await _create_key(db_session)
    resp = await client.post(
        BASE + "/ingest/test",
        headers={"X-API-Key": raw},
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /ingest — auth checks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_no_key(client: AsyncClient) -> None:
    """Missing X-API-Key → 401."""
    resp = await client.post(BASE + "/ingest", json={"events": [_ocsf_event()]})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_invalid_key(client: AsyncClient) -> None:
    """Unknown X-API-Key → 401."""
    resp = await client.post(
        BASE + "/ingest",
        headers={"X-API-Key": "mxtac_badkey"},
        json={"events": [_ocsf_event()]},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /ingest — batch size validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_batch_too_large(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Batch of 1,001 events → 422 Unprocessable Entity."""
    raw = await _create_key(db_session)
    oversized = [_ocsf_event() for _ in range(1001)]
    resp = await client.post(
        BASE + "/ingest",
        headers={"X-API-Key": raw},
        json={"events": oversized},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ingest_batch_exactly_1000(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Batch of exactly 1,000 events is accepted (boundary value)."""
    raw = await _create_key(db_session)

    mock_queue = MagicMock()
    mock_queue.publish = AsyncMock()
    app.dependency_overrides[get_queue] = lambda: mock_queue

    try:
        batch = [_ocsf_event() for _ in range(1000)]
        resp = await client.post(
            BASE + "/ingest",
            headers={"X-API-Key": raw},
            json={"events": batch},
        )
        assert resp.status_code == 202
        assert resp.json()["accepted"] == 1000
    finally:
        app.dependency_overrides.pop(get_queue, None)


# ---------------------------------------------------------------------------
# POST /ingest — rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_rate_limit_exceeded(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """When the rate counter is already at the limit, a new request → 429."""
    raw = await _create_key(db_session)

    # Look up the stored key's id so we can pre-seed the counter
    from app.repositories.api_key_repo import APIKeyRepo as Repo
    from app.models.api_key import hash_api_key
    from sqlalchemy import select
    from app.models.api_key import APIKey

    result = await db_session.execute(
        select(APIKey).where(APIKey.key_hash == hash_api_key(raw))
    )
    stored_key = result.scalar_one()

    # Pre-fill the counter to exactly at-limit
    import time
    events_module._rate_counters[stored_key.id] = (10_000, time.monotonic())

    resp = await client.post(
        BASE + "/ingest",
        headers={"X-API-Key": raw},
        json={"events": [_ocsf_event()]},
    )
    assert resp.status_code == 429
    assert "Rate limit" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# POST /ingest — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Valid key + batch → 202, correct accepted count, events published."""
    raw = await _create_key(db_session)

    mock_queue = MagicMock()
    mock_queue.publish = AsyncMock()
    app.dependency_overrides[get_queue] = lambda: mock_queue

    try:
        batch = [_ocsf_event(severity_id=i % 5 + 1) for i in range(5)]
        resp = await client.post(
            BASE + "/ingest",
            headers={"X-API-Key": raw},
            json={"events": batch},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert body["accepted"] == 5
        assert body["status"] == "queued"
        assert mock_queue.publish.call_count == 5
    finally:
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_publishes_to_normalized_topic(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Events are published to the mxtac.normalized topic."""
    raw = await _create_key(db_session)

    published: list[tuple[str, dict]] = []

    async def _capture_publish(topic: str, message: dict) -> None:
        published.append((topic, message))

    mock_queue = MagicMock()
    mock_queue.publish = _capture_publish
    app.dependency_overrides[get_queue] = lambda: mock_queue

    try:
        event = _ocsf_event(class_uid=1007, class_name="Process Activity")
        resp = await client.post(
            BASE + "/ingest",
            headers={"X-API-Key": raw},
            json={"events": [event]},
        )
        assert resp.status_code == 202
        assert len(published) == 1
        topic, msg = published[0]
        assert topic == Topic.NORMALIZED
        assert msg["class_uid"] == 1007
    finally:
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_single_event_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A single-event batch returns accepted=1."""
    raw = await _create_key(db_session)

    mock_queue = MagicMock()
    mock_queue.publish = AsyncMock()
    app.dependency_overrides[get_queue] = lambda: mock_queue

    try:
        resp = await client.post(
            BASE + "/ingest",
            headers={"X-API-Key": raw},
            json={"events": [_ocsf_event()]},
        )
        assert resp.status_code == 202
        assert resp.json()["accepted"] == 1
    finally:
        app.dependency_overrides.pop(get_queue, None)


@pytest.mark.asyncio
async def test_ingest_rate_limit_window_resets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """After the window expires, the rate counter resets and requests succeed."""
    from app.models.api_key import APIKey, hash_api_key
    from sqlalchemy import select

    raw = await _create_key(db_session)

    result = await db_session.execute(
        select(APIKey).where(APIKey.key_hash == hash_api_key(raw))
    )
    stored_key = result.scalar_one()

    # Seed counter with an old window (61 seconds ago) — should reset on next call
    import time
    events_module._rate_counters[stored_key.id] = (10_000, time.monotonic() - 61)

    mock_queue = MagicMock()
    mock_queue.publish = AsyncMock()
    app.dependency_overrides[get_queue] = lambda: mock_queue

    try:
        resp = await client.post(
            BASE + "/ingest",
            headers={"X-API-Key": raw},
            json={"events": [_ocsf_event()]},
        )
        # Window expired → counter reset → request succeeds
        assert resp.status_code == 202
    finally:
        app.dependency_overrides.pop(get_queue, None)
