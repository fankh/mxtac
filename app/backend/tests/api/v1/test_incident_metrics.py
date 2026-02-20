"""Tests for GET /api/v1/incidents/metrics — Feature 26.9 Incident SLA tracking.

Verifies:
- Empty DB returns zeros and nulls
- Status counts (total_incidents by status) are accurate
- incidents_by_severity groups correctly
- mttr_seconds is computed from closed incidents
- mttd_seconds is None when no ttd_seconds data exists
- incidents_this_week and incidents_this_month count recent incidents
- from_date / to_date params filter incidents correctly
- Viewer+ role can access (incidents:read); unauthenticated gets 401
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_INCIDENT = {
    "title": "SLA Test Incident",
    "severity": "high",
    "detection_ids": [],
}


async def _create_incident(client: AsyncClient, headers: dict, **overrides) -> int:
    body = {**_BASE_INCIDENT, **overrides}
    resp = await client.post("/api/v1/incidents", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _close_incident(client: AsyncClient, incident_id: int, headers: dict) -> None:
    """Advance incident through all statuses to 'closed', triggering auto ttr_seconds."""
    for status in ("investigating", "contained", "resolved", "closed"):
        resp = await client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": status},
            headers=headers,
        )
        assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# Structure and auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated requests receive 401."""
    resp = await client.get("/api/v1/incidents/metrics")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_metrics_viewer_can_access(client: AsyncClient, viewer_headers: dict) -> None:
    """Viewer role (incidents:read) can access the metrics endpoint."""
    resp = await client.get("/api/v1/incidents/metrics", headers=viewer_headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Empty DB
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_empty_db(client: AsyncClient, viewer_headers: dict) -> None:
    """Empty database returns all-zero counts and null averages."""
    resp = await client.get("/api/v1/incidents/metrics", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()

    total = data["total_incidents"]
    assert total["new"] == 0
    assert total["investigating"] == 0
    assert total["contained"] == 0
    assert total["resolved"] == 0
    assert total["closed"] == 0

    assert data["mttr_seconds"] is None
    assert data["mttd_seconds"] is None
    assert data["open_incidents_count"] == 0
    assert data["incidents_this_week"] == 0
    assert data["incidents_this_month"] == 0

    sev = data["incidents_by_severity"]
    assert sev["critical"] == 0
    assert sev["high"] == 0
    assert sev["medium"] == 0
    assert sev["low"] == 0

    assert "from_date" in data
    assert "to_date" in data


# ---------------------------------------------------------------------------
# Status counts and open_incidents_count
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_status_counts(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """total_incidents counts by status and open_incidents_count match reality."""
    # Two open incidents
    await _create_incident(client, analyst_headers, severity="critical")
    await _create_incident(client, analyst_headers, severity="medium")
    # One closed incident
    inc_id = await _create_incident(client, analyst_headers, severity="low")
    await _close_incident(client, inc_id, analyst_headers)

    resp = await client.get("/api/v1/incidents/metrics", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()

    total = data["total_incidents"]
    assert total["new"] == 2
    assert total["closed"] == 1
    assert total["investigating"] == 0
    assert data["open_incidents_count"] == 2


# ---------------------------------------------------------------------------
# Severity breakdown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_severity_breakdown(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """incidents_by_severity groups incidents by severity level."""
    await _create_incident(client, analyst_headers, severity="critical")
    await _create_incident(client, analyst_headers, severity="critical")
    await _create_incident(client, analyst_headers, severity="high")

    resp = await client.get("/api/v1/incidents/metrics", headers=viewer_headers)
    data = resp.json()

    assert data["incidents_by_severity"]["critical"] == 2
    assert data["incidents_by_severity"]["high"] == 1
    assert data["incidents_by_severity"]["medium"] == 0
    assert data["incidents_by_severity"]["low"] == 0


# ---------------------------------------------------------------------------
# MTTR
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_mttr_none_with_no_closed_incidents(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """mttr_seconds is None when no closed incidents exist in the range."""
    await _create_incident(client, analyst_headers)  # stays open

    resp = await client.get("/api/v1/incidents/metrics", headers=viewer_headers)
    assert resp.json()["mttr_seconds"] is None


@pytest.mark.asyncio
async def test_metrics_mttr_from_closed_incident(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """mttr_seconds is a non-negative float once a closed incident exists."""
    inc_id = await _create_incident(client, analyst_headers)
    await _close_incident(client, inc_id, analyst_headers)

    resp = await client.get("/api/v1/incidents/metrics", headers=viewer_headers)
    data = resp.json()

    assert data["mttr_seconds"] is not None
    assert isinstance(data["mttr_seconds"], float)
    assert data["mttr_seconds"] >= 0.0
    assert data["total_incidents"]["closed"] == 1


# ---------------------------------------------------------------------------
# MTTD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_mttd_null_without_ttd_data(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """mttd_seconds is None when no incidents have ttd_seconds set.

    ttd_seconds is an ingest-time field not writable via the PATCH API,
    so in a test environment it will always be null unless set at DB level.
    """
    await _create_incident(client, analyst_headers)

    resp = await client.get("/api/v1/incidents/metrics", headers=viewer_headers)
    assert resp.json()["mttd_seconds"] is None


# ---------------------------------------------------------------------------
# Week / month counters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_this_week_and_month(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """incidents created right now are counted for this week and this month."""
    await _create_incident(client, analyst_headers)
    await _create_incident(client, analyst_headers)

    resp = await client.get("/api/v1/incidents/metrics", headers=viewer_headers)
    data = resp.json()

    assert data["incidents_this_week"] == 2
    assert data["incidents_this_month"] == 2


# ---------------------------------------------------------------------------
# Date range filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_date_range_excludes_incidents_outside_range(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Incidents created now are excluded when the query range is entirely in the past."""
    await _create_incident(client, analyst_headers)
    await _create_incident(client, analyst_headers)

    resp = await client.get(
        "/api/v1/incidents/metrics",
        params={"from_date": "2000-01-01T00:00:00Z", "to_date": "2000-12-31T23:59:59Z"},
        headers=viewer_headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    total = data["total_incidents"]
    assert sum(total.values()) == 0
    assert data["open_incidents_count"] == 0


@pytest.mark.asyncio
async def test_metrics_returns_requested_date_range_in_response(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """from_date and to_date in the response reflect the requested range."""
    resp = await client.get(
        "/api/v1/incidents/metrics",
        params={"from_date": "2026-01-01T00:00:00Z", "to_date": "2026-01-31T23:59:59Z"},
        headers=viewer_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["from_date"].startswith("2026-01-01")
    assert data["to_date"].startswith("2026-01-31")
