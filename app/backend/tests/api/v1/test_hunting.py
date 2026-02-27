"""Additional tests for GET /api/v1/hunting/suggestions (Feature 11.8).

Covers scenarios not addressed in test_hunting_suggestions.py:
  - limit=51 query-param validation (le=50 violated)
  - High-severity (non-critical) detection → priority="medium"
  - Trending technique with no enabled rule coverage → priority="high"
  - Sort ordering: high before medium before low
  - generated_at ISO-8601 UTC format
  - Admin and engineer RBAC access
  - Deduplication: technique in both trending and gap appears only once
  - Multiple coverage-gap techniques (up to _GAP_LIMIT = 5)
  - Gap technique with associated detections surfaces correct reason/priority
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Query-parameter validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_limit_too_large_returns_422(
    client: AsyncClient, auth_headers: dict
) -> None:
    """limit > 50 violates le=50 constraint and must return 422."""
    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"limit": 51},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_hours_boundary_720_is_valid(
    client: AsyncClient, auth_headers: dict
) -> None:
    """hours=720 (maximum) must be accepted."""
    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"hours": 720},
    )
    assert resp.status_code == 200
    assert resp.json()["window_hours"] == 720


@pytest.mark.asyncio
async def test_limit_boundary_50_is_valid(
    client: AsyncClient, auth_headers: dict
) -> None:
    """limit=50 (maximum) must be accepted."""
    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"limit": 50},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Priority assignment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_high_severity_detection_yields_medium_priority(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_headers: dict,
) -> None:
    """A technique with only high-severity detections (no critical) gets priority='medium'."""
    from app.models.detection import Detection

    now = _utcnow()
    db_session.add(
        Detection(
            score=0.8,
            severity="high",
            technique_id="T1566.001",
            technique_name="Spearphishing Attachment",
            tactic="Initial Access",
            tactic_id="TA0001",
            name="Phishing Email Alert",
            host="mail-01",
            time=now - timedelta(hours=1),
            status="active",
        )
    )
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]
    s = next((x for x in suggestions if x["technique_id"] == "T1566.001"), None)
    assert s is not None
    assert s["priority"] == "medium"


@pytest.mark.asyncio
async def test_trending_technique_with_no_rule_yields_high_priority(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_headers: dict,
) -> None:
    """A trending technique (detections present) with no enabled rules gets priority='high'."""
    from app.models.detection import Detection

    now = _utcnow()
    # Use medium-severity only so critical/high counts stay zero
    db_session.add(
        Detection(
            score=0.5,
            severity="medium",
            technique_id="T1070.004",
            technique_name="File Deletion",
            tactic="Defense Evasion",
            tactic_id="TA0005",
            name="Suspicious File Deletion",
            host="host-01",
            time=now - timedelta(hours=2),
            status="active",
        )
    )
    await db_session.flush()

    # No Sigma rules cover T1070.004 → rule_count=0

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]
    s = next((x for x in suggestions if x["technique_id"] == "T1070.004"), None)
    assert s is not None
    assert s["priority"] == "high", (
        "count > 0 and rule_count == 0 should yield high priority"
    )
    assert s["rule_count"] == 0


@pytest.mark.asyncio
async def test_coverage_gap_with_no_detections_yields_low_priority(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_headers: dict,
) -> None:
    """A pure coverage-gap technique (disabled rule, no detections) gets priority='low'."""
    from app.models.rule import Rule

    db_session.add(
        Rule(
            title="Scheduled Task Persistence",
            content="title: Scheduled Task\n",
            level="medium",
            enabled=False,
            technique_ids=json.dumps(["T1053.005"]),
        )
    )
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]
    s = next((x for x in suggestions if x["technique_id"] == "T1053.005"), None)
    assert s is not None
    assert s["priority"] == "low"
    assert s["detection_count"] == 0


# ---------------------------------------------------------------------------
# Sort ordering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_suggestions_sorted_high_before_medium_before_low(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_headers: dict,
) -> None:
    """Suggestions are returned in descending priority order: high → medium → low."""
    from app.models.detection import Detection
    from app.models.rule import Rule

    now = _utcnow()

    # Technique A: medium priority (high-severity detection + enabled rule)
    db_session.add(
        Detection(
            score=0.7,
            severity="high",
            technique_id="T1059.003",
            technique_name="Windows Command Shell",
            tactic="Execution",
            tactic_id="TA0002",
            name="CMD Shell Activity",
            host="ws-01",
            time=now - timedelta(hours=1),
            status="active",
        )
    )
    db_session.add(
        Rule(
            title="CMD Rule",
            content="title: CMD Rule\n",
            level="high",
            enabled=True,
            technique_ids=json.dumps(["T1059.003"]),
        )
    )

    # Technique B: high priority (critical-severity detection)
    db_session.add(
        Detection(
            score=0.99,
            severity="critical",
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            tactic="Credential Access",
            tactic_id="TA0006",
            name="LSASS Dump Detected",
            host="dc-01",
            time=now - timedelta(hours=1),
            status="active",
        )
    )

    # Technique C: low priority (disabled rule, no detections)
    db_session.add(
        Rule(
            title="Token Impersonation",
            content="title: Token Impersonation\n",
            level="low",
            enabled=False,
            technique_ids=json.dumps(["T1134.001"]),
        )
    )

    await db_session.flush()

    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"limit": 10},
    )
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]

    _priority_order = {"high": 0, "medium": 1, "low": 2}
    priorities = [s["priority"] for s in suggestions]
    assert priorities == sorted(priorities, key=lambda p: _priority_order.get(p, 3)), (
        f"Suggestions not in priority order: {priorities}"
    )


# ---------------------------------------------------------------------------
# generated_at format
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generated_at_is_iso8601_utc(
    client: AsyncClient, auth_headers: dict
) -> None:
    """generated_at must be a valid ISO-8601 UTC timestamp ending in 'Z'."""
    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    generated_at = resp.json()["generated_at"]
    assert isinstance(generated_at, str)
    # Format: YYYY-MM-DDTHH:MM:SSZ
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", generated_at), (
        f"generated_at '{generated_at}' does not match ISO-8601 UTC format"
    )
    # Must parse as a valid datetime
    dt = datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ")
    assert dt.year >= 2024


# ---------------------------------------------------------------------------
# RBAC — admin and engineer access
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_can_access_hunting_suggestions(
    client: AsyncClient, admin_headers: dict
) -> None:
    """Admin role (has detections:read) can access hunt suggestions."""
    resp = await client.get("/api/v1/hunting/suggestions", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "suggestions" in data
    assert "generated_at" in data
    assert "window_hours" in data


@pytest.mark.asyncio
async def test_engineer_can_access_hunting_suggestions(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Engineer role (has detections:read) can access hunt suggestions."""
    resp = await client.get("/api/v1/hunting/suggestions", headers=engineer_headers)
    assert resp.status_code == 200
    assert "suggestions" in resp.json()


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_technique_in_trending_and_gap_not_duplicated(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_headers: dict,
) -> None:
    """A technique that is both trending and a coverage gap appears only once."""
    from app.models.detection import Detection
    from app.models.rule import Rule

    now = _utcnow()
    # Detection for T1036.003
    db_session.add(
        Detection(
            score=0.7,
            severity="high",
            technique_id="T1036.003",
            technique_name="Rename System Utilities",
            tactic="Defense Evasion",
            tactic_id="TA0005",
            name="System Utility Renamed",
            host="ws-02",
            time=now - timedelta(hours=1),
            status="active",
        )
    )
    # Disabled rule for T1036.003 → makes it a coverage gap
    db_session.add(
        Rule(
            title="Rename Utility Rule",
            content="title: Rename Utility\n",
            level="medium",
            enabled=False,
            technique_ids=json.dumps(["T1036.003"]),
        )
    )
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    technique_ids = [s["technique_id"] for s in resp.json()["suggestions"]]
    count = technique_ids.count("T1036.003")
    assert count == 1, f"T1036.003 appeared {count} times (expected 1)"


# ---------------------------------------------------------------------------
# Multiple coverage-gap techniques
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multiple_gap_techniques_surfaced(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_headers: dict,
) -> None:
    """Multiple disabled-rule techniques all surface as gap suggestions."""
    from app.models.rule import Rule

    gap_techniques = [
        "T1547.001",
        "T1547.002",
        "T1547.003",
        "T1547.004",
        "T1547.005",
    ]
    for i, tid in enumerate(gap_techniques):
        db_session.add(
            Rule(
                title=f"Gap Rule {i}",
                content=f"title: Gap Rule {i}\n",
                level="medium",
                enabled=False,
                technique_ids=json.dumps([tid]),
            )
        )
    await db_session.flush()

    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"limit": 50},
    )
    assert resp.status_code == 200
    surfaced_ids = {s["technique_id"] for s in resp.json()["suggestions"]}
    for tid in gap_techniques:
        assert tid in surfaced_ids, f"{tid} not surfaced as gap suggestion"


@pytest.mark.asyncio
async def test_gap_limit_caps_at_five(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_headers: dict,
) -> None:
    """At most 5 pure coverage-gap techniques are surfaced (internal _GAP_LIMIT)."""
    from app.models.rule import Rule

    # Add 8 disabled rules → only 5 gaps should surface
    for i in range(8):
        db_session.add(
            Rule(
                title=f"Excess Gap Rule {i}",
                content=f"title: Excess Gap Rule {i}\n",
                level="low",
                enabled=False,
                technique_ids=json.dumps([f"T9999.{i:03d}"]),
            )
        )
    await db_session.flush()

    resp = await client.get(
        "/api/v1/hunting/suggestions",
        headers=auth_headers,
        params={"limit": 50},
    )
    assert resp.status_code == 200
    gap_suggestions = [
        s for s in resp.json()["suggestions"]
        if s["technique_id"].startswith("T9999.")
    ]
    assert len(gap_suggestions) <= 5, (
        f"Expected ≤5 pure gap suggestions, got {len(gap_suggestions)}"
    )


# ---------------------------------------------------------------------------
# Gap technique with associated detections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gap_technique_with_detections_has_high_priority(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_headers: dict,
) -> None:
    """A trending technique with no active rule coverage gets priority='high'.

    Scenario: T1112 has detections AND only a disabled rule (gap).
    The detection path classifies it as high because count > 0 and rule_count == 0.
    """
    from app.models.detection import Detection
    from app.models.rule import Rule

    now = _utcnow()
    db_session.add(
        Detection(
            score=0.65,
            severity="medium",
            technique_id="T1112",
            technique_name="Modify Registry",
            tactic="Defense Evasion",
            tactic_id="TA0005",
            name="Registry Modification",
            host="workstation-03",
            time=now - timedelta(hours=3),
            status="active",
        )
    )
    # Disabled rule makes it a gap
    db_session.add(
        Rule(
            title="Registry Mod Rule",
            content="title: Registry Mod\n",
            level="medium",
            enabled=False,
            technique_ids=json.dumps(["T1112"]),
        )
    )
    await db_session.flush()

    resp = await client.get("/api/v1/hunting/suggestions", headers=auth_headers)
    assert resp.status_code == 200
    suggestions = resp.json()["suggestions"]
    s = next((x for x in suggestions if x["technique_id"] == "T1112"), None)
    assert s is not None
    # count > 0, rule_count == 0 → high priority regardless of severity
    assert s["priority"] == "high"
    assert s["detection_count"] >= 1
    assert s["rule_count"] == 0


# ---------------------------------------------------------------------------
# detection_count accuracy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detection_count_reflects_window(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_headers: dict,
) -> None:
    """detection_count equals the number of detections within the requested window."""
    from app.models.detection import Detection

    now = _utcnow()
    # 3 detections inside a 24-hour window
    for _ in range(3):
        db_session.add(
            Detection(
                score=0.6,
                severity="medium",
                technique_id="T1027",
                technique_name="Obfuscated Files or Information",
                tactic="Defense Evasion",
                tactic_id="TA0005",
                name="Obfuscation Alert",
                host="host-01",
                time=now - timedelta(hours=2),
                status="active",
            )
        )
    # 1 detection outside the window (should be excluded)
    db_session.add(
        Detection(
            score=0.6,
            severity="medium",
            technique_id="T1027",
            technique_name="Obfuscated Files or Information",
            tactic="Defense Evasion",
            tactic_id="TA0005",
            name="Old Obfuscation Alert",
            host="host-01",
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
    suggestions = resp.json()["suggestions"]
    s = next((x for x in suggestions if x["technique_id"] == "T1027"), None)
    assert s is not None
    assert s["detection_count"] == 3
