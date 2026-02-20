"""Tests for GET /api/v1/coverage endpoint."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_coverage_empty_db_returns_mock(client: AsyncClient, auth_headers: dict) -> None:
    """Empty DB falls back to mock data with valid shape."""
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
async def test_coverage_from_db(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """When detections exist, endpoint returns real coverage counts."""
    from datetime import datetime, timezone
    from app.models.detection import Detection as DetectionModel

    now = datetime.now(timezone.utc)
    rows = [
        DetectionModel(
            score=9.0,
            severity="critical",
            technique_id="T1059.001",
            technique_name="PowerShell",
            name="PowerShell Exec",
            host="host-a",
            tactic="Execution",
            tactic_id="TA0002",
            status="active",
            time=now,
            description="test",
            user="root",
            process="pwsh",
            rule_name="rule1",
            log_source="syslog",
            event_id="evt1",
            occurrence_count=1,
            cvss_v3=9.0,
            confidence=90,
            assigned_to=None,
            priority="P1",
        ),
        DetectionModel(
            score=8.0,
            severity="high",
            technique_id="T1078.002",
            technique_name="Valid Accounts: Domain Accounts",
            name="Domain Account Abuse",
            host="host-b",
            tactic="Credential Access",
            tactic_id="TA0006",
            status="active",
            time=now,
            description="test",
            user="user1",
            process="lsass.exe",
            rule_name="rule2",
            log_source="syslog",
            event_id="evt2",
            occurrence_count=1,
            cvss_v3=8.0,
            confidence=85,
            assigned_to=None,
            priority="P2",
        ),
        # Duplicate technique_id — should only be counted once
        DetectionModel(
            score=7.0,
            severity="high",
            technique_id="T1059.001",
            technique_name="PowerShell",
            name="PowerShell Again",
            host="host-c",
            tactic="Execution",
            tactic_id="TA0002",
            status="active",
            time=now,
            description="test",
            user="user2",
            process="pwsh.exe",
            rule_name="rule3",
            log_source="syslog",
            event_id="evt3",
            occurrence_count=2,
            cvss_v3=7.0,
            confidence=80,
            assigned_to=None,
            priority="P2",
        ),
    ]
    db_session.add_all(rows)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # 2 distinct technique IDs: T1059.001 and T1078.002
    assert data["covered_count"] == 2
    assert data["total_count"] == 105  # sum of _TACTIC_TOTALS
    assert data["coverage_pct"] == round(2 / 105 * 100, 1)


@pytest.mark.asyncio
async def test_coverage_pct_is_capped_at_100(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """coverage_pct never exceeds 100.0 even if covered_count > total_count."""
    from datetime import datetime, timezone
    from app.models.detection import Detection as DetectionModel

    now = datetime.now(timezone.utc)
    # Insert 200 detections with unique technique IDs to exceed total_count (105)
    rows = [
        DetectionModel(
            score=5.0,
            severity="medium",
            technique_id=f"T9999.{i:03d}",
            technique_name=f"Technique {i}",
            name=f"Detection {i}",
            host="host-x",
            tactic="Execution",
            tactic_id="TA0002",
            status="active",
            time=now,
            description="test",
            user="root",
            process="bash",
            rule_name=f"rule{i}",
            log_source="syslog",
            event_id=f"evt{i}",
            occurrence_count=1,
            cvss_v3=5.0,
            confidence=70,
            assigned_to=None,
            priority="P3",
        )
        for i in range(200)
    ]
    db_session.add_all(rows)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["coverage_pct"] == 100.0
    assert data["covered_count"] == data["total_count"]
