"""Tests for GET /api/v1/hunting/suggestions (Feature 11.8).

ATT&CK-guided hunt suggestions derived from:
  - Recent detection telemetry (trending techniques)
  - Coverage gap analysis (disabled-rule techniques)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Auth / structure tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_suggestions_requires_auth(client: AsyncClient) -> None:
    """Endpoint rejects unauthenticated requests."""
    resp = await client.get("/api/v1/hunting/suggestions")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_suggestions_empty_db(client: AsyncClient, auth_headers: dict) -> None:
    """Empty DB returns a valid response with an empty suggestions list."""
    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "suggestions" in data
    assert "generated_at" in data
    assert "window_hours" in data
    assert isinstance(data["suggestions"], list)
    assert data["window_hours"] == 24


@pytest.mark.asyncio
async def test_suggestions_default_params(client: AsyncClient, auth_headers: dict) -> None:
    """Default parameters (hours=24, limit=10) are respected."""
    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["window_hours"] == 24
    assert len(data["suggestions"]) <= 10


@pytest.mark.asyncio
async def test_suggestions_custom_params(client: AsyncClient, auth_headers: dict) -> None:
    """Custom hours and limit params are accepted and reflected."""
    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"hours": 48, "limit": 5},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["window_hours"] == 48
    assert len(data["suggestions"]) <= 5


@pytest.mark.asyncio
async def test_suggestions_param_validation(client: AsyncClient, auth_headers: dict) -> None:
    """Invalid parameter values return 422."""
    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"hours": 0},   # ge=1 violated
    )
    assert resp.status_code == 422

    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"limit": 0},   # ge=1 violated
    )
    assert resp.status_code == 422

    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"hours": 721},  # le=720 violated
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Trending detection tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_suggestions_surfaces_trending_technique(
    client: AsyncClient,
    db_session,
    auth_headers: dict,
) -> None:
    """A technique with recent detections appears as a suggestion."""
    from app.models.detection import Detection

    now = _utcnow()
    detections = [
        Detection(
            score=0.9,
            severity="high",
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            tactic_id="TA0002",
            name="PowerShell Suspicious Activity",
            host="workstation-01",
            time=now - timedelta(hours=1),
            status="active",
        )
        for _ in range(5)
    ]
    db_session.add_all(detections)
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    technique_ids = [s["technique_id"] for s in data["suggestions"]]
    assert "T1059.001" in technique_ids


@pytest.mark.asyncio
async def test_suggestion_has_required_fields(
    client: AsyncClient,
    db_session,
    auth_headers: dict,
) -> None:
    """Each suggestion contains all required schema fields."""
    from app.models.detection import Detection

    now = _utcnow()
    db_session.add(
        Detection(
            score=0.8,
            severity="critical",
            technique_id="T1003.006",
            technique_name="DCSync",
            tactic="Credential Access",
            tactic_id="TA0006",
            name="DCSync Detected",
            host="dc-01",
            time=now - timedelta(hours=2),
            status="active",
        )
    )
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]
    assert len(suggestions) >= 1

    s = next(x for x in suggestions if x["technique_id"] == "T1003.006")
    assert isinstance(s["technique_id"], str)
    assert isinstance(s["technique_name"], str)
    assert isinstance(s["tactic"], str)
    assert isinstance(s["tactic_id"], str)
    assert isinstance(s["reason"], str)
    assert s["priority"] in ("high", "medium", "low")
    assert isinstance(s["detection_count"], int)
    assert isinstance(s["rule_count"], int)
    assert isinstance(s["suggested_queries"], list)
    assert len(s["suggested_queries"]) >= 1


@pytest.mark.asyncio
async def test_critical_detection_yields_high_priority(
    client: AsyncClient,
    db_session,
    auth_headers: dict,
) -> None:
    """A technique with critical-severity detections gets priority='high'."""
    from app.models.detection import Detection

    now = _utcnow()
    db_session.add(
        Detection(
            score=0.99,
            severity="critical",
            technique_id="T1078.001",
            technique_name="Default Accounts",
            tactic="Initial Access",
            tactic_id="TA0001",
            name="Admin Login via Default Account",
            host="server-01",
            time=now - timedelta(hours=1),
            status="active",
        )
    )
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]
    s = next((x for x in suggestions if x["technique_id"] == "T1078.001"), None)
    assert s is not None
    assert s["priority"] == "high"


@pytest.mark.asyncio
async def test_old_detections_excluded_from_window(
    client: AsyncClient,
    db_session,
    auth_headers: dict,
) -> None:
    """Detections older than the requested window are not included."""
    from app.models.detection import Detection

    now = _utcnow()
    # Detection is 48 hours old — outside a 24-hour window
    db_session.add(
        Detection(
            score=0.7,
            severity="high",
            technique_id="T1021.002",
            technique_name="SMB/Windows Admin Shares",
            tactic="Lateral Movement",
            tactic_id="TA0008",
            name="SMB Lateral Movement",
            host="host-02",
            time=now - timedelta(hours=48),
            status="active",
        )
    )
    await db_session.flush()

    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"hours": 24},
    )
    assert resp.status_code == 200
    technique_ids = [s["technique_id"] for s in resp.json()["suggestions"]]
    # The old detection should NOT appear as a trending suggestion
    # (it may appear as a gap if a disabled rule covers it, but detection_count must be 0)
    for s in resp.json()["suggestions"]:
        if s["technique_id"] == "T1021.002":
            assert s["detection_count"] == 0


@pytest.mark.asyncio
async def test_limit_respected(
    client: AsyncClient,
    db_session,
    auth_headers: dict,
) -> None:
    """The limit parameter caps the number of returned suggestions."""
    from app.models.detection import Detection

    now = _utcnow()
    # Add detections for 8 distinct techniques
    techniques = [
        ("T1059.001", "PowerShell", "Execution", "TA0002"),
        ("T1059.003", "Windows Command Shell", "Execution", "TA0002"),
        ("T1003.001", "LSASS Memory", "Credential Access", "TA0006"),
        ("T1003.006", "DCSync", "Credential Access", "TA0006"),
        ("T1021.001", "RDP", "Lateral Movement", "TA0008"),
        ("T1021.002", "SMB", "Lateral Movement", "TA0008"),
        ("T1078.001", "Default Accounts", "Initial Access", "TA0001"),
        ("T1055.001", "DLL Injection", "Defense Evasion", "TA0005"),
    ]
    for tid, tname, tactic, tactic_id in techniques:
        db_session.add(
            Detection(
                score=0.8,
                severity="high",
                technique_id=tid,
                technique_name=tname,
                tactic=tactic,
                tactic_id=tactic_id,
                name=f"Alert {tid}",
                host="host-01",
                time=now - timedelta(hours=1),
                status="active",
            )
        )
    await db_session.flush()

    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"limit": 3},
    )
    assert resp.status_code == 200
    assert len(resp.json()["suggestions"]) <= 3


# ---------------------------------------------------------------------------
# Coverage gap tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_coverage_gap_technique_surfaced(
    client: AsyncClient,
    db_session,
    auth_headers: dict,
) -> None:
    """A disabled-rule technique with no enabled rule coverage appears as a gap suggestion."""
    from app.models.rule import Rule

    # Disabled rule covering T1547.001 — this creates a coverage gap
    db_session.add(
        Rule(
            title="Boot Autostart Persistence",
            content="title: Boot Autostart\n",
            level="high",
            enabled=False,
            technique_ids=json.dumps(["T1547.001"]),
        )
    )
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]
    technique_ids = [s["technique_id"] for s in suggestions]
    # Gap technique T1547.001 should appear
    assert "T1547.001" in technique_ids

    gap = next(x for x in suggestions if x["technique_id"] == "T1547.001")
    assert gap["detection_count"] == 0
    assert gap["rule_count"] == 0
    # Gap suggestions should have at least one query
    assert len(gap["suggested_queries"]) >= 1


@pytest.mark.asyncio
async def test_enabled_rule_technique_gets_rule_count(
    client: AsyncClient,
    db_session,
    auth_headers: dict,
) -> None:
    """rule_count reflects the number of enabled Sigma rules covering the technique."""
    from app.models.detection import Detection
    from app.models.rule import Rule

    now = _utcnow()
    # Add detection for T1059.001
    db_session.add(
        Detection(
            score=0.8,
            severity="high",
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            tactic_id="TA0002",
            name="PowerShell Exec",
            host="ws-01",
            time=now - timedelta(hours=1),
            status="active",
        )
    )
    # Two enabled rules covering T1059.001
    for i in range(2):
        db_session.add(
            Rule(
                title=f"PowerShell Rule {i}",
                content=f"title: PowerShell Rule {i}\n",
                level="high",
                enabled=True,
                technique_ids=json.dumps(["T1059.001"]),
            )
        )
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]
    s = next((x for x in suggestions if x["technique_id"] == "T1059.001"), None)
    assert s is not None
    assert s["rule_count"] == 2


# ---------------------------------------------------------------------------
# Suggested queries structure tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_suggested_queries_have_required_fields(
    client: AsyncClient,
    db_session,
    auth_headers: dict,
) -> None:
    """Each suggested_query has label, query, and time_from fields."""
    from app.models.detection import Detection

    now = _utcnow()
    db_session.add(
        Detection(
            score=0.7,
            severity="medium",
            technique_id="T1055.001",
            technique_name="DLL Injection",
            tactic="Defense Evasion",
            tactic_id="TA0005",
            name="DLL Injection Alert",
            host="host-01",
            time=now - timedelta(hours=1),
            status="active",
        )
    )
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]
    s = next((x for x in suggestions if x["technique_id"] == "T1055.001"), None)
    assert s is not None

    for q in s["suggested_queries"]:
        assert "label" in q
        assert "query" in q
        assert "time_from" in q
        assert isinstance(q["label"], str)
        assert isinstance(q["query"], str)
        assert isinstance(q["time_from"], str)


# ---------------------------------------------------------------------------
# RBAC tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_viewer_can_access_suggestions(client: AsyncClient, viewer_headers: dict) -> None:
    """Viewers with detections:read permission can access hunt suggestions."""
    resp = await client.get("/api/v1/hunting/suggestions", headers=viewer_headers)
    # Viewer has detections:read → 200 OK
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_hunter_can_access_suggestions(client: AsyncClient, hunter_headers: dict) -> None:
    """Hunters can access hunt suggestions."""
    resp = await client.get("/api/v1/hunting/suggestions", headers=hunter_headers)
    assert resp.status_code == 200
