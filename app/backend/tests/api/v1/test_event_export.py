"""Tests for POST /api/v1/events/export — Feature 31.3.

Coverage:
  - 200 with CSV content-type and Content-Disposition header
  - CSV header row matches expected columns
  - Data rows from PostgreSQL fallback (seeded DB)
  - Empty result → header row only
  - Max 10,000 rows enforced (size cap)
  - Auth: unauthenticated → 401/403; analyst → 403; hunter → 200
  - OpenSearch path: delegates to OS client when available
"""

from __future__ import annotations

import csv
import io
from datetime import timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, MagicMock

from app.models.event import Event
from app.services.opensearch_client import get_opensearch_dep

BASE_URL = "/api/v1/events/export"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event_kwargs(**kwargs) -> dict:
    from datetime import datetime, timezone, timedelta
    defaults = {
        "time": datetime.now(timezone.utc) - timedelta(minutes=30),
        "class_name": "Process Activity",
        "severity_id": 3,
        "hostname": "host-01",
        "username": "CORP\\user01",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "summary": "test event",
        "source": "wazuh",
    }
    defaults.update(kwargs)
    return defaults


async def _seed(db: AsyncSession, *overrides) -> list[Event]:
    events = []
    for kw in overrides:
        evt = Event(**_make_event_kwargs(**kw))
        db.add(evt)
        events.append(evt)
    await db.flush()
    return events


def _parse_csv(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_unauthenticated(client: AsyncClient) -> None:
    """POST /events/export without auth → 401 or 403."""
    resp = await client.post(BASE_URL, json={})
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_export_analyst_denied(client: AsyncClient, analyst_headers: dict) -> None:
    """Analyst role lacks events:search → 403."""
    resp = await client.post(BASE_URL, headers=analyst_headers, json={})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_export_hunter_allowed(client: AsyncClient, hunter_headers: dict) -> None:
    """Hunter role (events:search) can access the export endpoint."""
    resp = await client.post(BASE_URL, headers=hunter_headers, json={})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Response format
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_content_type(client: AsyncClient, hunter_headers: dict) -> None:
    """Response has text/csv content-type."""
    resp = await client.post(BASE_URL, headers=hunter_headers, json={})
    assert "text/csv" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_export_content_disposition(client: AsyncClient, hunter_headers: dict) -> None:
    """Response has Content-Disposition: attachment with a .csv filename."""
    resp = await client.post(BASE_URL, headers=hunter_headers, json={})
    cd = resp.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert ".csv" in cd


@pytest.mark.asyncio
async def test_export_csv_header_row(client: AsyncClient, hunter_headers: dict) -> None:
    """First CSV row contains the expected column names."""
    resp = await client.post(BASE_URL, headers=hunter_headers, json={})
    rows = _parse_csv(resp.text)
    expected = ["id", "time", "class_name", "severity_id", "src_ip", "dst_ip", "hostname", "username", "source", "summary"]
    assert rows[0] == expected


# ---------------------------------------------------------------------------
# Empty DB
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_empty_db(client: AsyncClient, hunter_headers: dict) -> None:
    """Empty DB → CSV contains header row only."""
    resp = await client.post(BASE_URL, headers=hunter_headers, json={})
    rows = _parse_csv(resp.text)
    assert len(rows) == 1  # header only


# ---------------------------------------------------------------------------
# Data rows (PostgreSQL fallback)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_single_event(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Single seeded event → header + 1 data row."""
    await _seed(db_session, {"hostname": "export-host", "summary": "export test"})

    resp = await client.post(
        BASE_URL,
        headers=hunter_headers,
        json={"time_from": "now-1h", "time_to": "now"},
    )
    assert resp.status_code == 200
    rows = _parse_csv(resp.text)
    assert len(rows) == 2
    # hostname is column index 6
    assert rows[1][6] == "export-host"


@pytest.mark.asyncio
async def test_export_multiple_events(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Multiple seeded events → header + N data rows."""
    await _seed(
        db_session,
        {"hostname": "host-A"},
        {"hostname": "host-B"},
        {"hostname": "host-C"},
    )

    resp = await client.post(
        BASE_URL,
        headers=hunter_headers,
        json={"time_from": "now-1h", "time_to": "now"},
    )
    assert resp.status_code == 200
    rows = _parse_csv(resp.text)
    assert len(rows) == 4  # 1 header + 3 data rows


@pytest.mark.asyncio
async def test_export_filter_applied(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Filters in body are applied — only matching events appear in export."""
    await _seed(
        db_session,
        {"hostname": "target-host", "severity_id": 5},
        {"hostname": "other-host", "severity_id": 2},
    )

    resp = await client.post(
        BASE_URL,
        headers=hunter_headers,
        json={
            "time_from": "now-1h",
            "filters": [{"field": "severity_id", "operator": "eq", "value": 5}],
        },
    )
    assert resp.status_code == 200
    rows = _parse_csv(resp.text)
    assert len(rows) == 2  # header + 1 matching row
    assert rows[1][6] == "target-host"


@pytest.mark.asyncio
async def test_export_query_filter(
    client: AsyncClient,
    hunter_headers: dict,
    db_session: AsyncSession,
) -> None:
    """Full-text query in body filters events."""
    await _seed(
        db_session,
        {"summary": "mimikatz credential dump"},
        {"summary": "benign network event"},
    )

    resp = await client.post(
        BASE_URL,
        headers=hunter_headers,
        json={"query": "mimikatz", "time_from": "now-1h"},
    )
    assert resp.status_code == 200
    rows = _parse_csv(resp.text)
    assert len(rows) == 2  # header + 1 matching row
    # summary is last column (index 9)
    assert "mimikatz" in rows[1][9]


# ---------------------------------------------------------------------------
# OpenSearch path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_opensearch_path(
    client: AsyncClient,
    hunter_headers: dict,
) -> None:
    """When OpenSearch is available, export delegates to it."""
    mock_os = MagicMock()
    mock_os.is_available = True
    mock_os.search_events = AsyncMock(return_value={
        "hits": {
            "total": {"value": 1},
            "hits": [
                {
                    "_id": "os-evt-1",
                    "_source": {
                        "id": "os-evt-1",
                        "time": "2026-02-19T10:00:00Z",
                        "class_name": "Network Activity",
                        "severity_id": 4,
                        "src_ip": "192.168.1.1",
                        "dst_ip": "8.8.8.8",
                        "hostname": "os-host",
                        "username": "user",
                        "source": "zeek",
                        "summary": "DNS query",
                    },
                }
            ],
        }
    })

    app_ref = __import__("app.main", fromlist=["app"]).app
    app_ref.dependency_overrides[get_opensearch_dep] = lambda: mock_os

    try:
        resp = await client.post(BASE_URL, headers=hunter_headers, json={})
    finally:
        app_ref.dependency_overrides.pop(get_opensearch_dep, None)

    assert resp.status_code == 200
    rows = _parse_csv(resp.text)
    assert len(rows) == 2
    assert rows[1][0] == "os-evt-1"
    assert rows[1][6] == "os-host"

    # Confirm export used 10,000 row cap, not body's size
    call_kwargs = mock_os.search_events.call_args.kwargs
    assert call_kwargs["size"] == 10_000
    assert call_kwargs["from_"] == 0
