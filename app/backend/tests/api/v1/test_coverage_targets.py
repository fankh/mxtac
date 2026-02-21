"""Tests for coverage target endpoints (Feature 16.7).

GET  /api/v1/coverage/target  — read current target + alert status
PUT  /api/v1/coverage/target  — create or update the target threshold
"""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# GET /coverage/target
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_target_requires_auth(client: AsyncClient) -> None:
    """Endpoint rejects unauthenticated requests."""
    resp = await client.get("/api/v1/coverage/target")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_target_no_target_configured_returns_default(
    client: AsyncClient, auth_headers: dict
) -> None:
    """When no target is set, returns a disabled default at 80 %."""
    resp = await client.get("/api/v1/coverage/target", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["target_pct"] == 80.0
    assert data["enabled"] is False
    assert data["label"] is None
    assert data["is_below_threshold"] is False  # disabled → never alerts
    assert "current_pct" in data
    assert isinstance(data["current_pct"], float)


@pytest.mark.asyncio
async def test_get_target_schema_fields(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Response always contains all required schema fields."""
    resp = await client.get("/api/v1/coverage/target", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    required = {"target_pct", "enabled", "label", "current_pct", "is_below_threshold"}
    assert required <= set(data.keys())


# ---------------------------------------------------------------------------
# PUT /coverage/target
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_target_requires_auth(client: AsyncClient) -> None:
    """PUT is rejected without authentication."""
    resp = await client.put(
        "/api/v1/coverage/target", json={"target_pct": 75.0}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_put_target_viewer_is_forbidden(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Viewer role cannot set coverage targets (requires detections:write)."""
    resp = await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": 75.0},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_put_target_analyst_can_set(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Analyst role has detections:write and can set the target."""
    resp = await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": 60.0, "enabled": True, "label": "Q1 Goal"},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_pct"] == 60.0
    assert data["enabled"] is True
    assert data["label"] == "Q1 Goal"


@pytest.mark.asyncio
async def test_put_target_creates_and_get_returns_it(
    client: AsyncClient, auth_headers: dict, analyst_headers: dict
) -> None:
    """After PUT, GET reflects the stored target."""
    await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": 70.0, "enabled": True},
        headers=analyst_headers,
    )

    resp = await client.get("/api/v1/coverage/target", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_pct"] == 70.0
    assert data["enabled"] is True


@pytest.mark.asyncio
async def test_put_target_updates_existing(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """A second PUT updates (not duplicates) the singleton target."""
    await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": 50.0},
        headers=analyst_headers,
    )
    resp = await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": 90.0, "label": "Year-end"},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_pct"] == 90.0
    assert data["label"] == "Year-end"


@pytest.mark.asyncio
async def test_put_target_clamps_above_100(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Values above 100 are clamped to 100.0 server-side."""
    resp = await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": 150.0},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["target_pct"] == 100.0


@pytest.mark.asyncio
async def test_put_target_clamps_below_zero(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Values below 0 are clamped to 0.0 server-side."""
    resp = await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": -10.0},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["target_pct"] == 0.0


# ---------------------------------------------------------------------------
# Alert status — is_below_threshold logic
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_below_threshold_true_when_coverage_low(
    client: AsyncClient, db_session, analyst_headers: dict, auth_headers: dict
) -> None:
    """is_below_threshold is True when enabled and current coverage < target."""
    # With no enabled rules current_pct comes from mock data (COVERAGE_SUMMARY).
    # Set target above that value so the alert fires.
    from app.services.mock_data import COVERAGE_SUMMARY

    high_target = COVERAGE_SUMMARY.coverage_pct + 10.0
    await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": high_target, "enabled": True},
        headers=analyst_headers,
    )

    resp = await client.get("/api/v1/coverage/target", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_below_threshold"] is True


@pytest.mark.asyncio
async def test_is_below_threshold_false_when_coverage_meets_target(
    client: AsyncClient, db_session, analyst_headers: dict, auth_headers: dict
) -> None:
    """is_below_threshold is False when current coverage >= target."""
    from app.services.mock_data import COVERAGE_SUMMARY

    low_target = max(0.0, COVERAGE_SUMMARY.coverage_pct - 10.0)
    await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": low_target, "enabled": True},
        headers=analyst_headers,
    )

    resp = await client.get("/api/v1/coverage/target", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_below_threshold"] is False


@pytest.mark.asyncio
async def test_is_below_threshold_false_when_disabled(
    client: AsyncClient, db_session, analyst_headers: dict, auth_headers: dict
) -> None:
    """is_below_threshold is always False when enabled=False."""
    from app.services.mock_data import COVERAGE_SUMMARY

    high_target = COVERAGE_SUMMARY.coverage_pct + 50.0
    await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": high_target, "enabled": False},
        headers=analyst_headers,
    )

    resp = await client.get("/api/v1/coverage/target", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_below_threshold"] is False


@pytest.mark.asyncio
async def test_is_below_threshold_uses_live_rules(
    client: AsyncClient, db_session, analyst_headers: dict, auth_headers: dict
) -> None:
    """When enabled rules exist, current_pct is derived from live DB state."""
    from app.models.rule import Rule

    rule = Rule(
        title="Threshold Rule",
        content="title: Threshold Rule\n",
        level="high",
        enabled=True,
        technique_ids=json.dumps(["T1059.001", "T1059.002"]),  # 2 techniques
    )
    db_session.add(rule)
    await db_session.flush()

    live_pct = round(2 / 105 * 100, 1)  # ~1.9 %

    # Target set above live coverage → should alert
    await client.put(
        "/api/v1/coverage/target",
        json={"target_pct": live_pct + 5.0, "enabled": True},
        headers=analyst_headers,
    )

    resp = await client.get("/api/v1/coverage/target", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["current_pct"] == live_pct
    assert data["is_below_threshold"] is True
