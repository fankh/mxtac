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


@pytest.mark.asyncio
async def test_get_event_unauthenticated(client: AsyncClient) -> None:
    """GET /events/{id} without auth → 401 or 403."""
    resp = await client.get(f"{BASE_URL}/some-event-id")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_get_event_viewer_denied(client: AsyncClient, viewer_headers: dict) -> None:
    """GET /events/{id} with viewer role → 403 (events:search requires hunter+)."""
    resp = await client.get(f"{BASE_URL}/some-event-id", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_event_analyst_denied(client: AsyncClient, analyst_headers: dict) -> None:
    """GET /events/{id} with analyst role → 403 (events:search requires hunter+)."""
    resp = await client.get(f"{BASE_URL}/some-event-id", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_event_engineer_allowed(
    client: AsyncClient,
    engineer_headers: dict,
    db_session: AsyncSession,
) -> None:
    """GET /events/{id} with engineer role → 200."""
    (evt,) = await _seed(db_session, {"summary": "engineer test event"})
    resp = await client.get(f"{BASE_URL}/{evt.id}", headers=engineer_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_get_event_admin_allowed(
    client: AsyncClient,
    admin_headers: dict,
    db_session: AsyncSession,
) -> None:
    """GET /events/{id} with admin role → 200."""
    (evt,) = await _seed(db_session, {"summary": "admin test event"})
    resp = await client.get(f"{BASE_URL}/{evt.id}", headers=admin_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_get_event_response_contains_all_base_fields(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """GET /events/{id} response includes all base serialized fields."""
    (evt,) = await _seed(db_session, {
        "event_uid": "uid-001",
        "class_name": "Process Activity",
        "class_uid": 4007,
        "severity_id": 4,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "hostname": "ws-01",
        "username": "CORP\\jdoe",
        "process_hash": "abc123",
        "source": "wazuh",
        "summary": "test event",
    })
    resp = await client.get(f"{BASE_URL}/{evt.id}", headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    for field in (
        "id", "event_uid", "time", "class_name", "class_uid", "severity_id",
        "src_ip", "dst_ip", "hostname", "username", "process_hash", "source", "summary",
    ):
        assert field in data, f"Expected field '{field}' in response"
    assert data["event_uid"] == "uid-001"
    assert data["class_name"] == "Process Activity"
    assert data["class_uid"] == 4007
    assert data["severity_id"] == 4
    assert data["src_ip"] == "10.0.0.1"
    assert data["dst_ip"] == "10.0.0.2"
    assert data["hostname"] == "ws-01"
    assert data["username"] == "CORP\\jdoe"
    assert data["process_hash"] == "abc123"
    assert data["source"] == "wazuh"


@pytest.mark.asyncio
async def test_get_event_raw_payload_merged_into_response(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """When the event has a raw OCSF payload, its fields are merged into the response."""
    raw = {
        "actor_user": {"name": "jdoe", "domain": "CORP"},
        "process": {"pid": 1234, "name": "powershell.exe"},
    }
    (evt,) = await _seed(db_session, {"summary": "raw event", "raw": raw})
    resp = await client.get(f"{BASE_URL}/{evt.id}", headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"] == "raw event"
    assert data["actor_user"]["name"] == "jdoe"
    assert data["process"]["pid"] == 1234


@pytest.mark.asyncio
async def test_get_event_raw_overrides_base_field(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Raw payload fields with the same key overwrite the corresponding base fields."""
    raw = {"summary": "raw-overridden-summary"}
    (evt,) = await _seed(db_session, {"summary": "original summary", "raw": raw})
    resp = await client.get(f"{BASE_URL}/{evt.id}", headers=hunter_headers)
    assert resp.status_code == 200
    # raw["summary"] must overwrite the ORM-extracted summary
    assert resp.json()["summary"] == "raw-overridden-summary"


@pytest.mark.asyncio
async def test_get_event_no_raw_payload(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """When the event has no raw payload, the response contains only the base fields."""
    (evt,) = await _seed(db_session, {"summary": "no raw", "raw": None})
    resp = await client.get(f"{BASE_URL}/{evt.id}", headers=hunter_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == evt.id
    assert data["summary"] == "no raw"
    # No extra OCSF-nested keys that would only come from a raw payload
    assert "actor_user" not in data
    assert "process" not in data


@pytest.mark.asyncio
async def test_get_event_id_in_response_matches_path(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """The 'id' field in the response matches the UUID used in the URL path."""
    (evt,) = await _seed(db_session, {"summary": "id check"})
    resp = await client.get(f"{BASE_URL}/{evt.id}", headers=hunter_headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == evt.id


@pytest.mark.asyncio
async def test_get_event_time_serialized_as_isoformat(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """The 'time' field is returned as an ISO-8601 string."""
    (evt,) = await _seed(db_session, {"summary": "time check"})
    resp = await client.get(f"{BASE_URL}/{evt.id}", headers=hunter_headers)
    assert resp.status_code == 200
    time_val = resp.json()["time"]
    assert isinstance(time_val, str)
    # Must be parseable as ISO 8601
    datetime.fromisoformat(time_val.replace("Z", "+00:00"))


@pytest.mark.asyncio
async def test_get_event_not_found_uuid_format(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """GET /events/{id} with a well-formed UUID that does not exist → 404."""
    resp = await client.get(
        f"{BASE_URL}/00000000-0000-0000-0000-000000000000",
        headers=hunter_headers,
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Event not found"


@pytest.mark.asyncio
async def test_get_event_different_events_return_different_data(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Each event ID returns its own data — no cross-contamination between events."""
    evt_a, evt_b = await _seed(
        db_session,
        {"summary": "event-alpha", "hostname": "host-alpha"},
        {"summary": "event-beta", "hostname": "host-beta"},
    )
    resp_a = await client.get(f"{BASE_URL}/{evt_a.id}", headers=hunter_headers)
    resp_b = await client.get(f"{BASE_URL}/{evt_b.id}", headers=hunter_headers)
    assert resp_a.json()["summary"] == "event-alpha"
    assert resp_b.json()["summary"] == "event-beta"
    assert resp_a.json()["hostname"] == "host-alpha"
    assert resp_b.json()["hostname"] == "host-beta"


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


@pytest.mark.asyncio
async def test_aggregate_date_histogram_empty_db(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """POST /events/aggregate with date_histogram on empty DB returns empty buckets."""
    resp = await client.post(
        BASE_URL + "/aggregate",
        headers=hunter_headers,
        json={"agg_type": "date_histogram", "interval": "1h"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["agg_type"] == "date_histogram"
    assert data["interval"] == "1h"
    assert isinstance(data["buckets"], list)
    assert len(data["buckets"]) == 0


@pytest.mark.asyncio
async def test_aggregate_date_histogram_with_data(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """date_histogram groups events into correct hour buckets."""
    base_hour = _NOW.replace(minute=0, second=0, microsecond=0)
    # 2 events in hour N, 1 event in hour N-1
    await _seed(
        db_session,
        {"time": base_hour - timedelta(minutes=10)},
        {"time": base_hour - timedelta(minutes=20)},
        {"time": base_hour - timedelta(hours=1, minutes=5)},
    )

    resp = await client.post(
        BASE_URL + "/aggregate",
        headers=hunter_headers,
        json={"agg_type": "date_histogram", "interval": "1h", "time_from": "now-3h"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["agg_type"] == "date_histogram"
    assert data["interval"] == "1h"
    buckets = data["buckets"]
    assert len(buckets) == 2  # two distinct hour buckets
    counts = {b["key"][:13]: b["count"] for b in buckets}  # compare up to "YYYY-MM-DDTHH"
    # Most-recent bucket has 2 events; previous bucket has 1
    assert 2 in counts.values()
    assert 1 in counts.values()
    # Verify buckets are sorted oldest-first (ascending)
    assert buckets[0]["key"] < buckets[1]["key"]


@pytest.mark.asyncio
async def test_aggregate_date_histogram_day_interval(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """date_histogram with 1d interval merges events from the same calendar day."""
    today = _NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    await _seed(
        db_session,
        {"time": today + timedelta(hours=2)},
        {"time": today + timedelta(hours=14)},
    )

    resp = await client.post(
        BASE_URL + "/aggregate",
        headers=hunter_headers,
        json={"agg_type": "date_histogram", "interval": "1d", "time_from": "now-3d"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["buckets"]) == 1
    assert data["buckets"][0]["count"] == 2


@pytest.mark.asyncio
async def test_aggregate_unknown_agg_type_returns_422(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """POST /events/aggregate with unsupported agg_type → 422."""
    resp = await client.post(
        BASE_URL + "/aggregate",
        headers=hunter_headers,
        json={"agg_type": "percentiles", "field": "severity_id"},
    )
    assert resp.status_code == 422
    assert "agg_type" in resp.json()["detail"].lower() or "unsupported" in resp.json()["detail"].lower()


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


# ---------------------------------------------------------------------------
# POST /query-dsl — Lucene DSL builder (feature 11.6)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_dsl_unauthenticated(client: AsyncClient) -> None:
    """POST /events/query-dsl without auth → 401 or 403."""
    resp = await client.post(BASE_URL + "/query-dsl", json={})
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_query_dsl_analyst_denied(client: AsyncClient, analyst_headers: dict) -> None:
    """POST /events/query-dsl with analyst role → 403 (requires hunter+)."""
    resp = await client.post(BASE_URL + "/query-dsl", headers=analyst_headers, json={})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_query_dsl_empty_request_returns_time_range(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """Empty body → Lucene string with only the default time range."""
    resp = await client.post(
        BASE_URL + "/query-dsl",
        headers=hunter_headers,
        json={},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "lucene" in data
    assert "time:[now-7d TO now]" in data["lucene"]


@pytest.mark.asyncio
async def test_query_dsl_text_query_only(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """Text query with no filters → query prepended to time range."""
    resp = await client.post(
        BASE_URL + "/query-dsl",
        headers=hunter_headers,
        json={"query": "mimikatz", "time_from": "now-1h", "time_to": "now"},
    )
    assert resp.status_code == 200
    lucene = resp.json()["lucene"]
    assert lucene.startswith("mimikatz")
    assert "time:[now-1h TO now]" in lucene


@pytest.mark.asyncio
async def test_query_dsl_single_filter(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """Single filter generates correct Lucene clause."""
    resp = await client.post(
        BASE_URL + "/query-dsl",
        headers=hunter_headers,
        json={
            "filters": [{"field": "severity_id", "operator": "gte", "value": 4}],
            "time_from": "now-7d",
            "time_to": "now",
        },
    )
    assert resp.status_code == 200
    lucene = resp.json()["lucene"]
    assert "severity_id:[4 TO *]" in lucene
    assert "time:[now-7d TO now]" in lucene


@pytest.mark.asyncio
async def test_query_dsl_multiple_filters(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """Multiple filters are ANDed together in the Lucene string."""
    resp = await client.post(
        BASE_URL + "/query-dsl",
        headers=hunter_headers,
        json={
            "filters": [
                {"field": "severity_id", "operator": "gte", "value": 4},
                {"field": "hostname", "operator": "contains", "value": "dc-"},
            ],
            "time_from": "now-24h",
            "time_to": "now",
        },
    )
    assert resp.status_code == 200
    lucene = resp.json()["lucene"]
    assert "severity_id:[4 TO *]" in lucene
    assert "src_endpoint.hostname:*dc-*" in lucene
    assert " AND " in lucene


@pytest.mark.asyncio
async def test_query_dsl_full_hunt_query(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """Text + filters + custom time range → correct combined Lucene query."""
    resp = await client.post(
        BASE_URL + "/query-dsl",
        headers=hunter_headers,
        json={
            "query": "lsass",
            "filters": [
                {"field": "severity_id", "operator": "gte", "value": 4},
                {"field": "class_name", "operator": "eq", "value": "Process Activity"},
            ],
            "time_from": "now-12h",
            "time_to": "now",
        },
    )
    assert resp.status_code == 200
    lucene = resp.json()["lucene"]
    assert lucene.startswith("lsass")
    assert "severity_id:[4 TO *]" in lucene
    assert 'class_name:"Process Activity"' in lucene
    assert "time:[now-12h TO now]" in lucene


@pytest.mark.asyncio
async def test_query_dsl_unknown_filter_field_skipped(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """Filters on unknown fields are silently dropped; response is still 200."""
    resp = await client.post(
        BASE_URL + "/query-dsl",
        headers=hunter_headers,
        json={
            "filters": [{"field": "nonexistent", "operator": "eq", "value": "x"}],
            "time_from": "now-7d",
            "time_to": "now",
        },
    )
    assert resp.status_code == 200
    lucene = resp.json()["lucene"]
    # Unknown field should not appear; time range should still be present
    assert "nonexistent" not in lucene
    assert "time:[now-7d TO now]" in lucene


@pytest.mark.asyncio
async def test_query_dsl_no_db_call(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """/query-dsl is a pure translation — no OpenSearch dependency needed."""
    # Override OpenSearch to confirm it is never called
    os_mock = MagicMock()
    os_mock.is_available = True
    os_mock.search_events = AsyncMock(side_effect=AssertionError("OS should not be called"))

    app.dependency_overrides[get_opensearch_dep] = lambda: os_mock
    try:
        resp = await client.post(
            BASE_URL + "/query-dsl",
            headers=hunter_headers,
            json={"query": "test"},
        )
        assert resp.status_code == 200
    finally:
        app.dependency_overrides.pop(get_opensearch_dep, None)
