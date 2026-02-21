"""Tests for GET /api/v1/coverage/trend endpoint (Feature 16.6).

Coverage trend returns daily snapshots stored in coverage_snapshots table.
The endpoint auto-captures today's snapshot when enabled rules exist.
"""

from __future__ import annotations

import json
from datetime import date, timedelta

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_trend_requires_auth(client: AsyncClient) -> None:
    """Endpoint rejects unauthenticated requests."""
    resp = await client.get("/api/v1/coverage/trend")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_trend_empty_db_returns_empty_points(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Empty DB (no rules, no snapshots) returns empty points list."""
    resp = await client.get("/api/v1/coverage/trend", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "points" in data
    assert "days" in data
    assert isinstance(data["points"], list)
    assert len(data["points"]) == 0
    assert data["days"] == 30  # default


@pytest.mark.asyncio
async def test_trend_captures_today_when_rules_exist(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """When enabled rules exist, hitting the trend endpoint auto-captures today's snapshot."""
    from app.models.rule import Rule

    rule = Rule(
        title="Cred Dump",
        content="title: Cred Dump\n",
        level="critical",
        enabled=True,
        technique_ids=json.dumps(["T1003.001", "T1003.002"]),
    )
    db_session.add(rule)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/trend", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert len(data["points"]) == 1
    point = data["points"][0]
    assert point["date"] == date.today().isoformat()
    assert point["covered_count"] == 2
    assert point["total_count"] == 105
    assert point["coverage_pct"] == round(2 / 105 * 100, 1)


@pytest.mark.asyncio
async def test_trend_returns_stored_snapshots_ascending(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Stored snapshots are returned ordered ascending by date."""
    from app.models.coverage_snapshot import CoverageSnapshot
    from app.models.base import new_uuid

    today = date.today()
    snapshots = [
        CoverageSnapshot(
            id=new_uuid(),
            snapshot_date=today - timedelta(days=2),
            coverage_pct=40.0,
            covered_count=42,
            total_count=105,
        ),
        CoverageSnapshot(
            id=new_uuid(),
            snapshot_date=today - timedelta(days=1),
            coverage_pct=45.0,
            covered_count=47,
            total_count=105,
        ),
        CoverageSnapshot(
            id=new_uuid(),
            snapshot_date=today,
            coverage_pct=50.0,
            covered_count=52,
            total_count=105,
        ),
    ]
    db_session.add_all(snapshots)
    await db_session.flush()

    resp = await client.get(
        "/api/v1/coverage/trend", params={"days": 7}, headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()

    points = data["points"]
    assert len(points) == 3

    # Verify ascending date order
    dates = [p["date"] for p in points]
    assert dates == sorted(dates)

    # Verify oldest is first
    assert points[0]["coverage_pct"] == 40.0
    assert points[2]["coverage_pct"] == 50.0


@pytest.mark.asyncio
async def test_trend_days_parameter_filters_window(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Only snapshots within the requested `days` window are returned."""
    from app.models.coverage_snapshot import CoverageSnapshot
    from app.models.base import new_uuid

    today = date.today()
    old_snapshot = CoverageSnapshot(
        id=new_uuid(),
        snapshot_date=today - timedelta(days=60),
        coverage_pct=30.0,
        covered_count=31,
        total_count=105,
    )
    recent_snapshot = CoverageSnapshot(
        id=new_uuid(),
        snapshot_date=today - timedelta(days=5),
        coverage_pct=55.0,
        covered_count=57,
        total_count=105,
    )
    db_session.add_all([old_snapshot, recent_snapshot])
    await db_session.flush()

    # Request only 30 days — the 60-day-old snapshot should be excluded
    resp = await client.get(
        "/api/v1/coverage/trend", params={"days": 30}, headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["days"] == 30
    points = data["points"]
    assert len(points) == 1
    assert points[0]["coverage_pct"] == 55.0


@pytest.mark.asyncio
async def test_trend_days_default_is_30(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Default days parameter is 30."""
    resp = await client.get("/api/v1/coverage/trend", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["days"] == 30


@pytest.mark.asyncio
async def test_trend_days_max_is_365(
    client: AsyncClient, auth_headers: dict
) -> None:
    """days parameter above 365 is rejected."""
    resp = await client.get(
        "/api/v1/coverage/trend", params={"days": 400}, headers=auth_headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_trend_days_min_is_1(
    client: AsyncClient, auth_headers: dict
) -> None:
    """days parameter below 1 is rejected."""
    resp = await client.get(
        "/api/v1/coverage/trend", params={"days": 0}, headers=auth_headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_trend_upserts_today_on_repeated_calls(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Calling the endpoint twice on the same day updates, not duplicates, the snapshot."""
    from app.models.rule import Rule

    rule = Rule(
        title="Exec Rule",
        content="title: Exec Rule\n",
        level="high",
        enabled=True,
        technique_ids=json.dumps(["T1059.001"]),
    )
    db_session.add(rule)
    await db_session.flush()

    # First call — creates snapshot
    resp1 = await client.get("/api/v1/coverage/trend", headers=auth_headers)
    assert resp1.status_code == 200
    points1 = resp1.json()["points"]

    # Second call — should upsert, not duplicate
    resp2 = await client.get("/api/v1/coverage/trend", headers=auth_headers)
    assert resp2.status_code == 200
    points2 = resp2.json()["points"]

    # Still only one point for today
    today_str = date.today().isoformat()
    today_points = [p for p in points2 if p["date"] == today_str]
    assert len(today_points) == 1
    assert len(points2) == len(points1)


@pytest.mark.asyncio
async def test_trend_point_schema(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Each trend point has the correct schema fields and types."""
    from app.models.rule import Rule

    rule = Rule(
        title="Schema Test Rule",
        content="title: Schema Test Rule\n",
        level="medium",
        enabled=True,
        technique_ids=json.dumps(["T1078.002", "T1078.003"]),
    )
    db_session.add(rule)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/trend", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["points"]) >= 1

    point = data["points"][-1]
    assert isinstance(point["date"], str)
    assert isinstance(point["coverage_pct"], float)
    assert isinstance(point["covered_count"], int)
    assert isinstance(point["total_count"], int)
    assert 0.0 <= point["coverage_pct"] <= 100.0
    assert point["total_count"] == 105
