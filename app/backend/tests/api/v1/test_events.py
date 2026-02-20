"""Tests for /api/v1/events endpoints — PostgreSQL-backed implementation.

Coverage:
  - POST /search: auth (401 / 403), full-text query, structured filters, time range
  - GET /{id}: found (200) and missing (404)
  - POST /aggregate: returns term counts per field
  - GET /entity/{type}/{value}: entity timeline by IP, host, user
  - POST /search (OpenSearch path): delegates to OS client when available
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models.event import Event
from app.services.opensearch_client import get_opensearch_dep

BASE_URL = "/api/v1/events"

_NOW = datetime.now(timezone.utc)


def _make_event(**kwargs) -> dict:
    """Return kwargs for EventRepo.create / Event(**) with sensible defaults."""
    defaults = {
        "time":     _NOW - timedelta(minutes=30),  # well inside a 1-hour window
        "class_name": "Process Activity",
        "severity_id": 3,
        "hostname": "host-01",
        "username": "CORP\\user01",
        "src_ip":   "10.0.0.1",
        "dst_ip":   "10.0.0.2",
        "summary":  "lsass memory read detected",
        "source":   "wazuh",
    }
    defaults.update(kwargs)
    return defaults


async def _seed(db: AsyncSession, *overrides) -> list[Event]:
    """Insert Event rows directly and flush."""
    events = []
    for kw in overrides:
        evt = Event(**_make_event(**kw))
        db.add(evt)
        events.append(evt)
    await db.flush()
    return events


# ---------------------------------------------------------------------------
# Auth / access control
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_unauthenticated(client: AsyncClient) -> None:
    """POST /events/search without auth → 401 or 403."""
    resp = await client.post(BASE_URL + "/search", json={})
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_search_analyst_denied(client: AsyncClient, analyst_headers: dict) -> None:
    """POST /events/search with analyst role → 403 (events:search requires hunter+)."""
    resp = await client.post(BASE_URL + "/search", headers=analyst_headers, json={})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /search — basic structure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_empty_db(client: AsyncClient, hunter_headers: dict) -> None:
    """POST /events/search on empty DB → total=0 and items=[]."""
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
async def test_search_returns_seeded_event(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Events inserted in DB are returned by search."""
    await _seed(db_session, {"summary": "mimikatz credential dump", "hostname": "dc-01"})

    resp = await client.post(
        BASE_URL + "/search",
        headers=hunter_headers,
        json={"time_from": "now-1h", "time_to": "now"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["hostname"] == "dc-01"


# ---------------------------------------------------------------------------
# POST /search — full-text query
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_fulltext_match(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Query string matches event summary text."""
    await _seed(
        db_session,
        {"summary": "mimikatz credential dump"},
        {"summary": "benign network connection"},
    )

    resp = await client.post(
        BASE_URL + "/search",
        headers=hunter_headers,
        json={"query": "mimikatz", "time_from": "now-1h"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert "mimikatz" in data["items"][0]["summary"]


@pytest.mark.asyncio
async def test_search_fulltext_no_match(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Query that matches nothing returns total=0."""
    await _seed(db_session, {"summary": "normal event"})

    resp = await client.post(
        BASE_URL + "/search",
        headers=hunter_headers,
        json={"query": "ransomware", "time_from": "now-1h"},
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


# ---------------------------------------------------------------------------
# POST /search — structured filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_filter_severity_gte(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Filter by severity_id gte returns only matching events."""
    await _seed(
        db_session,
        {"severity_id": 5, "summary": "critical event"},
        {"severity_id": 2, "summary": "low event"},
    )

    resp = await client.post(
        BASE_URL + "/search",
        headers=hunter_headers,
        json={
            "filters": [{"field": "severity_id", "operator": "gte", "value": 4}],
            "time_from": "now-1h",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["severity_id"] == 5


@pytest.mark.asyncio
async def test_search_filter_hostname_eq(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Filter by hostname eq returns exact match only."""
    await _seed(
        db_session,
        {"hostname": "dc-prod-01"},
        {"hostname": "workstation-42"},
    )

    resp = await client.post(
        BASE_URL + "/search",
        headers=hunter_headers,
        json={
            "filters": [{"field": "hostname", "operator": "eq", "value": "dc-prod-01"}],
            "time_from": "now-1h",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["hostname"] == "dc-prod-01"


@pytest.mark.asyncio
async def test_search_filter_class_name_contains(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Filter operator 'contains' performs case-insensitive substring match."""
    await _seed(
        db_session,
        {"class_name": "Process Activity"},
        {"class_name": "Network Activity"},
    )

    resp = await client.post(
        BASE_URL + "/search",
        headers=hunter_headers,
        json={
            "filters": [{"field": "class_name", "operator": "contains", "value": "process"}],
            "time_from": "now-1h",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert "Process" in data["items"][0]["class_name"]


# ---------------------------------------------------------------------------
# POST /search — time range
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_time_range_excludes_old_events(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Events outside the time range are not returned."""
    # One recent event, one old event
    await _seed(
        db_session,
        {"time": _NOW - timedelta(hours=2), "summary": "old event"},
        {"time": _NOW - timedelta(minutes=30), "summary": "recent event"},
    )

    resp = await client.post(
        BASE_URL + "/search",
        headers=hunter_headers,
        json={"time_from": "now-1h", "time_to": "now"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert "recent" in data["items"][0]["summary"]


# ---------------------------------------------------------------------------
# POST /search — pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_pagination(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """size and from_ parameters are honoured."""
    for i in range(5):
        evt = Event(**_make_event(summary=f"event {i}"))
        db_session.add(evt)
    await db_session.flush()

    resp = await client.post(
        BASE_URL + "/search",
        headers=hunter_headers,
        json={"time_from": "now-1h", "size": 2, "from_": 0},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["items"]) == 2
    assert data["size"] == 2


# ---------------------------------------------------------------------------
# GET /{event_id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_event_found(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """GET /events/{id} returns the event when it exists."""
    (evt,) = await _seed(db_session, {"summary": "specific event"})

    resp = await client.get(f"{BASE_URL}/{evt.id}", headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == evt.id
    assert data["summary"] == "specific event"


@pytest.mark.asyncio
async def test_get_event_not_found(client: AsyncClient, hunter_headers: dict) -> None:
    """GET /events/{id} with unknown ID → 404."""
    resp = await client.get(f"{BASE_URL}/nonexistent-id", headers=hunter_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Event not found"


# ---------------------------------------------------------------------------
# POST /aggregate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aggregate_empty_db(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """POST /events/aggregate on empty DB returns empty buckets list."""
    resp = await client.post(
        BASE_URL + "/aggregate",
        headers=hunter_headers,
        json={"field": "severity_id"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["field"] == "severity_id"
    assert isinstance(data["buckets"], list)
    assert len(data["buckets"]) == 0


@pytest.mark.asyncio
async def test_aggregate_with_data(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """POST /events/aggregate returns correct term counts."""
    await _seed(
        db_session,
        {"severity_id": 5},
        {"severity_id": 5},
        {"severity_id": 3},
    )

    resp = await client.post(
        BASE_URL + "/aggregate",
        headers=hunter_headers,
        json={"field": "severity_id", "time_from": "now-1h"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["field"] == "severity_id"
    buckets = {b["key"]: b["count"] for b in data["buckets"]}
    assert buckets.get("5") == 2
    assert buckets.get("3") == 1


# ---------------------------------------------------------------------------
# GET /entity/{type}/{value}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entity_timeline_host(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """GET /events/entity/host/{hostname} returns matching events."""
    await _seed(
        db_session,
        {"hostname": "DC-PROD-01"},
        {"hostname": "workstation-99"},
    )

    resp = await client.get(
        f"{BASE_URL}/entity/host/DC-PROD-01",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_type"] == "host"
    assert data["entity_value"] == "DC-PROD-01"
    assert data["total"] == 1
    assert data["events"][0]["hostname"] == "DC-PROD-01"


@pytest.mark.asyncio
async def test_entity_timeline_ip(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """GET /events/entity/ip/{ip} matches both src_ip and dst_ip."""
    await _seed(
        db_session,
        {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"},
        {"src_ip": "10.0.0.5", "dst_ip": "192.168.1.100"},
        {"src_ip": "172.16.0.1", "dst_ip": "172.16.0.2"},
    )

    resp = await client.get(
        f"{BASE_URL}/entity/ip/192.168.1.100",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2


@pytest.mark.asyncio
async def test_entity_timeline_user(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """GET /events/entity/user/{username} returns user-related events."""
    await _seed(
        db_session,
        {"username": "CORP\\admin"},
        {"username": "CORP\\jdoe"},
    )

    resp = await client.get(
        f"{BASE_URL}/entity/user/CORP%5Cadmin",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1


@pytest.mark.asyncio
async def test_entity_timeline_no_results(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """Entity timeline for unknown value returns total=0."""
    resp = await client.get(
        f"{BASE_URL}/entity/host/UNKNOWN-HOST",
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["events"] == []


# ---------------------------------------------------------------------------
# POST /search — OpenSearch-backed path
# ---------------------------------------------------------------------------

def _make_os_client(hits: list[dict], total: int) -> MagicMock:
    """Build a mock OpenSearchService that returns the given hits."""
    mock = MagicMock()
    mock.is_available = True
    mock.search_events = AsyncMock(return_value={
        "hits": {
            "total": {"value": total},
            "hits": hits,
        }
    })
    return mock


@pytest.mark.asyncio
async def test_search_opensearch_path_used_when_available(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """When OpenSearch is available, search_events is delegated to the OS client."""
    os_mock = _make_os_client(
        hits=[{"_id": "os-doc-1", "_source": {"class_name": "Process Activity", "severity_id": 4}}],
        total=1,
    )

    app.dependency_overrides[get_opensearch_dep] = lambda: os_mock
    try:
        resp = await client.post(
            BASE_URL + "/search",
            headers=hunter_headers,
            json={"query": "mimikatz", "time_from": "now-1h"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["backend"] == "opensearch"
        assert len(data["items"]) == 1
        assert data["items"][0]["class_name"] == "Process Activity"
        os_mock.search_events.assert_called_once()
    finally:
        app.dependency_overrides.pop(get_opensearch_dep, None)


@pytest.mark.asyncio
async def test_search_opensearch_filters_converted_to_dsl(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """Structured EventFilter objects are converted to OS DSL before delegation."""
    os_mock = _make_os_client(hits=[], total=0)

    app.dependency_overrides[get_opensearch_dep] = lambda: os_mock
    try:
        await client.post(
            BASE_URL + "/search",
            headers=hunter_headers,
            json={
                "filters": [{"field": "severity_id", "operator": "gte", "value": 4}],
                "time_from": "now-1h",
            },
        )
        call_kwargs = os_mock.search_events.call_args.kwargs
        # The filters kwarg should contain the converted DSL clause
        filters_passed = call_kwargs.get("filters") or []
        assert any("range" in f for f in filters_passed)
    finally:
        app.dependency_overrides.pop(get_opensearch_dep, None)


@pytest.mark.asyncio
async def test_search_opensearch_unknown_filter_field_skipped(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """Unknown filter fields are silently skipped (no DSL clause sent to OS)."""
    os_mock = _make_os_client(hits=[], total=0)

    app.dependency_overrides[get_opensearch_dep] = lambda: os_mock
    try:
        resp = await client.post(
            BASE_URL + "/search",
            headers=hunter_headers,
            json={
                "filters": [{"field": "unknown_field", "operator": "eq", "value": "x"}],
                "time_from": "now-1h",
            },
        )
        assert resp.status_code == 200
        call_kwargs = os_mock.search_events.call_args.kwargs
        # filters kwarg should be None when all filter clauses are skipped
        assert call_kwargs.get("filters") is None
    finally:
        app.dependency_overrides.pop(get_opensearch_dep, None)


@pytest.mark.asyncio
async def test_search_falls_back_to_postgres_when_os_unavailable(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """When OpenSearch is unavailable, search falls back to PostgreSQL."""
    os_mock = MagicMock()
    os_mock.is_available = False  # simulate no OS connection

    # Seed a record so we can verify PG is actually used
    evt = Event(**_make_event(summary="postgres fallback event"))
    db_session.add(evt)
    await db_session.flush()

    app.dependency_overrides[get_opensearch_dep] = lambda: os_mock
    try:
        resp = await client.post(
            BASE_URL + "/search",
            headers=hunter_headers,
            json={"time_from": "now-1h"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["backend"] == "postgres"
        assert data["total"] == 1
        assert "postgres fallback" in data["items"][0]["summary"]
    finally:
        app.dependency_overrides.pop(get_opensearch_dep, None)


@pytest.mark.asyncio
async def test_search_opensearch_hit_id_from_source(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """When _source contains 'id', it is returned as the item id."""
    os_mock = _make_os_client(
        hits=[{"_id": "os-doc-2", "_source": {"id": "pg-uuid-99", "class_name": "Authentication"}}],
        total=1,
    )

    app.dependency_overrides[get_opensearch_dep] = lambda: os_mock
    try:
        resp = await client.post(BASE_URL + "/search", headers=hunter_headers, json={})
        assert resp.status_code == 200
        data = resp.json()
        # The PG UUID from _source should be used, not the OS _id
        assert data["items"][0]["id"] == "pg-uuid-99"
    finally:
        app.dependency_overrides.pop(get_opensearch_dep, None)


@pytest.mark.asyncio
async def test_search_opensearch_hit_id_falls_back_to_doc_id(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """When _source has no 'id', the OpenSearch _id is used."""
    os_mock = _make_os_client(
        hits=[{"_id": "auto-gen-id", "_source": {"class_name": "Network Activity"}}],
        total=1,
    )

    app.dependency_overrides[get_opensearch_dep] = lambda: os_mock
    try:
        resp = await client.post(BASE_URL + "/search", headers=hunter_headers, json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"][0]["id"] == "auto-gen-id"
    finally:
        app.dependency_overrides.pop(get_opensearch_dep, None)
