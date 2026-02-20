"""Tests for /api/v1/events endpoints.

Coverage:
  - POST /search: unauthenticated → 401; hunter+ required; mock OpenSearch response
  - GET /{id}: 404 when OpenSearch returns None
  - POST /aggregate: returns mock data when OpenSearch not connected
  - GET /entity/{type}/{value}: returns structured response (mocked OS)

All tests mock ``get_opensearch`` to avoid requiring a live OpenSearch cluster.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

BASE_URL = "/api/v1/events"
MOCK_OS = "app.api.v1.endpoints.events.get_opensearch"


def _mock_os_empty():
    """Return a mock OpenSearch client that returns empty results."""
    os = MagicMock()
    os._client = MagicMock()  # Not None → real OS path taken
    os.search_events = AsyncMock(
        return_value={"hits": {"total": {"value": 0}, "hits": []}}
    )
    os.get_event = AsyncMock(return_value=None)
    return os


def _mock_os_with_event():
    """Return a mock OpenSearch client that returns one event."""
    event = {
        "event_uid": "EVT-001",
        "time": "2026-02-19T14:21:07Z",
        "severity_id": 5,
        "class_name": "Process Activity",
    }
    os = MagicMock()
    os._client = MagicMock()
    os.search_events = AsyncMock(
        return_value={"hits": {"total": {"value": 1}, "hits": [{"_source": event}]}}
    )
    os.get_event = AsyncMock(return_value=event)
    return os


# ---------------------------------------------------------------------------
# Auth / access control
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_events_unauthenticated(client: AsyncClient) -> None:
    """POST /events/search without auth → 401 or 403."""
    resp = await client.post(BASE_URL + "/search", json={})
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_search_events_analyst_forbidden(client: AsyncClient, analyst_headers: dict) -> None:
    """POST /events/search with analyst role → 403 (events:search requires hunter+)."""
    resp = await client.post(BASE_URL + "/search", headers=analyst_headers, json={})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /search
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_events_empty_result(client: AsyncClient, hunter_headers: dict) -> None:
    """POST /events/search returns total=0 and items=[] when OS is empty."""
    with patch(MOCK_OS, return_value=_mock_os_empty()):
        resp = await client.post(
            BASE_URL + "/search",
            headers=hunter_headers,
            json={"query": "mimikatz"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_search_events_with_filter(client: AsyncClient, hunter_headers: dict) -> None:
    """POST /events/search with filters list returns structured response."""
    with patch(MOCK_OS, return_value=_mock_os_with_event()):
        resp = await client.post(
            BASE_URL + "/search",
            headers=hunter_headers,
            json={
                "query": "lsass",
                "filters": [{"field": "severity_id", "operator": "gte", "value": 4}],
                "time_from": "now-24h",
                "size": 50,
            },
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)


# ---------------------------------------------------------------------------
# GET /{id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_event_not_found(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /events/{id} when OS returns None → 404."""
    with patch(MOCK_OS, return_value=_mock_os_empty()):
        resp = await client.get(f"{BASE_URL}/EVT-MISSING", headers=hunter_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Event not found"


# ---------------------------------------------------------------------------
# POST /aggregate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aggregate_events_no_opensearch(client: AsyncClient, hunter_headers: dict) -> None:
    """POST /events/aggregate returns mock data when OS client is None."""
    no_os = MagicMock()
    no_os._client = None  # Triggers the mock-data path in the endpoint
    with patch(MOCK_OS, return_value=no_os):
        resp = await client.post(
            BASE_URL + "/aggregate",
            headers=hunter_headers,
            json={"field": "severity_id"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert "field" in data
    assert "buckets" in data
    assert isinstance(data["buckets"], list)
    assert len(data["buckets"]) > 0


# ---------------------------------------------------------------------------
# GET /entity/{type}/{value}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entity_timeline_host(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /events/entity/host/{hostname} returns entity timeline structure."""
    with patch(MOCK_OS, return_value=_mock_os_empty()):
        resp = await client.get(
            f"{BASE_URL}/entity/host/DC-PROD-01",
            headers=hunter_headers,
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_type"] == "host"
    assert data["entity_value"] == "DC-PROD-01"
    assert "total" in data
    assert "events" in data


@pytest.mark.asyncio
async def test_entity_timeline_user(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /events/entity/user/{username} returns entity timeline structure."""
    with patch(MOCK_OS, return_value=_mock_os_empty()):
        resp = await client.get(
            f"{BASE_URL}/entity/user/CORP%5Cadmin",
            headers=hunter_headers,
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_type"] == "user"
    assert "events" in data
