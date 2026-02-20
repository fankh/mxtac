"""Tests for GET /api/v1/coverage endpoint.

Coverage is calculated from active (enabled) Sigma rules, not from detections.
"""

import json

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_coverage_empty_db_returns_mock(client: AsyncClient, auth_headers: dict) -> None:
    """Empty DB (no rules) falls back to mock data with valid shape."""
    resp = await client.get("/api/v1/coverage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "coverage_pct" in data
    assert "covered_count" in data
    assert "total_count" in data
    assert isinstance(data["coverage_pct"], float)
    assert isinstance(data["covered_count"], int)
    assert isinstance(data["total_count"], int)
    assert data["total_count"] > 0
    assert 0.0 <= data["coverage_pct"] <= 100.0


@pytest.mark.asyncio
async def test_coverage_requires_auth(client: AsyncClient) -> None:
    """Endpoint rejects unauthenticated requests."""
    resp = await client.get("/api/v1/coverage")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_coverage_from_enabled_rules(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Coverage counts distinct technique_ids from enabled rules."""
    from app.models.rule import Rule

    rules = [
        Rule(
            title="PowerShell Exec",
            content="title: PowerShell Exec\n",
            level="high",
            enabled=True,
            technique_ids=json.dumps(["T1059.001", "T1059.003"]),
        ),
        Rule(
            title="Valid Accounts Abuse",
            content="title: Valid Accounts Abuse\n",
            level="medium",
            enabled=True,
            technique_ids=json.dumps(["T1078.002"]),
        ),
        # Duplicate technique — should only be counted once
        Rule(
            title="PowerShell Again",
            content="title: PowerShell Again\n",
            level="medium",
            enabled=True,
            technique_ids=json.dumps(["T1059.001"]),
        ),
    ]
    db_session.add_all(rules)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # 3 distinct technique IDs: T1059.001, T1059.003, T1078.002
    assert data["covered_count"] == 3
    assert data["total_count"] == 105
    assert data["coverage_pct"] == round(3 / 105 * 100, 1)


@pytest.mark.asyncio
async def test_coverage_disabled_rules_excluded(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Disabled rules do not contribute to coverage."""
    from app.models.rule import Rule

    rules = [
        Rule(
            title="Enabled Rule",
            content="title: Enabled Rule\n",
            level="high",
            enabled=True,
            technique_ids=json.dumps(["T1059.001"]),
        ),
        Rule(
            title="Disabled Rule",
            content="title: Disabled Rule\n",
            level="high",
            enabled=False,
            technique_ids=json.dumps(["T1003.001", "T1021.002"]),
        ),
    ]
    db_session.add_all(rules)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # Only the enabled rule's technique counts
    assert data["covered_count"] == 1
    assert data["coverage_pct"] == round(1 / 105 * 100, 1)


@pytest.mark.asyncio
async def test_coverage_rules_without_techniques_ignored(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Enabled rules with no technique_ids do not contribute."""
    from app.models.rule import Rule

    rules = [
        Rule(
            title="Rule With Techniques",
            content="title: Rule With Techniques\n",
            level="high",
            enabled=True,
            technique_ids=json.dumps(["T1059.001"]),
        ),
        Rule(
            title="Rule Without Techniques",
            content="title: Rule Without Techniques\n",
            level="medium",
            enabled=True,
            technique_ids=None,
        ),
    ]
    db_session.add_all(rules)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["covered_count"] == 1


@pytest.mark.asyncio
async def test_coverage_pct_is_capped_at_100(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """coverage_pct never exceeds 100.0 even if distinct techniques exceed total_count."""
    from app.models.rule import Rule

    # Create rules with 200 unique technique IDs to exceed total_count (105)
    rules = [
        Rule(
            title=f"Rule {i}",
            content=f"title: Rule {i}\n",
            level="medium",
            enabled=True,
            technique_ids=json.dumps([f"T9999.{i:03d}"]),
        )
        for i in range(200)
    ]
    db_session.add_all(rules)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["coverage_pct"] == 100.0
    assert data["covered_count"] == data["total_count"]
