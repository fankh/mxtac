"""Tests for GET /api/v1/coverage/gaps — techniques with no enabled rule.

The endpoint returns:
  - covered_count          — distinct technique IDs in enabled rules
  - total_count            — 105 (ATT&CK v14 fixed scope)
  - gap_count              — 105 - covered_count
  - coverage_pct           — covered_count / 105 * 100
  - uncovered_techniques   — technique IDs in ANY rule but NOT in any enabled rule
"""

import json

import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_rule(**kwargs):
    """Return a minimal Rule ORM instance."""
    from app.models.rule import Rule

    defaults = dict(
        title="Test Rule",
        content="title: Test Rule\n",
        level="medium",
        enabled=True,
        technique_ids=None,
    )
    defaults.update(kwargs)
    return Rule(**defaults)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gaps_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/v1/coverage/gaps")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_gaps_viewer_role_allowed(client: AsyncClient, viewer_headers: dict) -> None:
    """The viewer role (lowest privilege) can access the gaps endpoint."""
    resp = await client.get("/api/v1/coverage/gaps", headers=viewer_headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gaps_response_shape(client: AsyncClient, auth_headers: dict) -> None:
    """Response always contains the required fields with correct types."""
    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "covered_count" in data
    assert "total_count" in data
    assert "gap_count" in data
    assert "coverage_pct" in data
    assert "uncovered_techniques" in data
    assert isinstance(data["covered_count"], int)
    assert isinstance(data["total_count"], int)
    assert isinstance(data["gap_count"], int)
    assert isinstance(data["coverage_pct"], float)
    assert isinstance(data["uncovered_techniques"], list)


@pytest.mark.asyncio
async def test_gaps_empty_db_zero_coverage(client: AsyncClient, auth_headers: dict) -> None:
    """Empty DB → covered_count=0, gap_count=105, uncovered_techniques=[]."""
    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["covered_count"] == 0
    assert data["total_count"] == 105
    assert data["gap_count"] == 105
    assert data["coverage_pct"] == 0.0
    assert data["uncovered_techniques"] == []


# ---------------------------------------------------------------------------
# Gap + covered_count invariants
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gaps_count_invariant(client: AsyncClient, auth_headers: dict) -> None:
    """gap_count + covered_count always equals total_count."""
    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    data = resp.json()
    assert data["gap_count"] + data["covered_count"] == data["total_count"]


@pytest.mark.asyncio
async def test_gaps_coverage_pct_in_range(client: AsyncClient, auth_headers: dict) -> None:
    """coverage_pct is always in [0.0, 100.0]."""
    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    data = resp.json()
    assert 0.0 <= data["coverage_pct"] <= 100.0


# ---------------------------------------------------------------------------
# Enabled vs disabled rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gaps_enabled_rules_reduce_gap(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Enabled rules with technique_ids reduce covered_count and gap_count."""
    db_session.add_all([
        _make_rule(
            title="Rule A",
            enabled=True,
            technique_ids=json.dumps(["T1059.001", "T1059.003"]),
        ),
        _make_rule(
            title="Rule B",
            enabled=True,
            technique_ids=json.dumps(["T1078.002"]),
        ),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["covered_count"] == 3
    assert data["gap_count"] == 105 - 3
    assert data["total_count"] == 105
    assert data["coverage_pct"] == round(3 / 105 * 100, 1)


@pytest.mark.asyncio
async def test_gaps_disabled_rules_appear_in_uncovered(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Technique IDs from disabled-only rules appear in uncovered_techniques."""
    db_session.add_all([
        _make_rule(
            title="Enabled",
            enabled=True,
            technique_ids=json.dumps(["T1059.001"]),
        ),
        _make_rule(
            title="Disabled",
            enabled=False,
            technique_ids=json.dumps(["T1003.001", "T1021.002"]),
        ),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    data = resp.json()

    # covered_count: only 1 from the enabled rule
    assert data["covered_count"] == 1
    # uncovered: T1003.001 and T1021.002 are in disabled rules but not in enabled rules
    uncovered = set(data["uncovered_techniques"])
    assert "T1003.001" in uncovered
    assert "T1021.002" in uncovered
    # T1059.001 is covered so should NOT appear in uncovered
    assert "T1059.001" not in uncovered


@pytest.mark.asyncio
async def test_gaps_technique_covered_by_both_not_in_uncovered(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """A technique covered by both enabled AND disabled rules is NOT in uncovered_techniques."""
    db_session.add_all([
        _make_rule(
            title="Enabled",
            enabled=True,
            technique_ids=json.dumps(["T1059.001"]),
        ),
        _make_rule(
            title="Disabled for same technique",
            enabled=False,
            technique_ids=json.dumps(["T1059.001", "T1059.003"]),
        ),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    data = resp.json()

    # T1059.001 is in an enabled rule → covered, not a gap
    assert "T1059.001" not in data["uncovered_techniques"]
    # T1059.003 is only in a disabled rule → gap
    assert "T1059.003" in data["uncovered_techniques"]


@pytest.mark.asyncio
async def test_gaps_no_technique_ids_no_contribution(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with null technique_ids don't affect covered or uncovered counts."""
    db_session.add_all([
        _make_rule(title="No Techniques Enabled", enabled=True, technique_ids=None),
        _make_rule(title="No Techniques Disabled", enabled=False, technique_ids=None),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    data = resp.json()

    assert data["covered_count"] == 0
    assert data["uncovered_techniques"] == []


@pytest.mark.asyncio
async def test_gaps_duplicate_technique_ids_counted_once(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Duplicate technique IDs across multiple enabled rules count as one."""
    db_session.add_all([
        _make_rule(
            title="Rule 1",
            enabled=True,
            technique_ids=json.dumps(["T1059.001"]),
        ),
        _make_rule(
            title="Rule 2",
            enabled=True,
            technique_ids=json.dumps(["T1059.001", "T1059.003"]),
        ),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    data = resp.json()

    # T1059.001 appears twice but counts once
    assert data["covered_count"] == 2  # T1059.001 + T1059.003


@pytest.mark.asyncio
async def test_gaps_uncovered_techniques_sorted(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """uncovered_techniques list is returned in sorted order."""
    db_session.add(_make_rule(
        title="Disabled with multiple",
        enabled=False,
        technique_ids=json.dumps(["T1078.002", "T1003.001", "T1059.001"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    data = resp.json()

    uncovered = data["uncovered_techniques"]
    assert uncovered == sorted(uncovered), "uncovered_techniques must be sorted"


@pytest.mark.asyncio
async def test_gaps_coverage_pct_capped_at_100(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """coverage_pct never exceeds 100.0 even with more techniques than total_count."""
    rules = [
        _make_rule(
            title=f"Rule {i}",
            enabled=True,
            technique_ids=json.dumps([f"T9999.{i:03d}"]),
        )
        for i in range(200)
    ]
    db_session.add_all(rules)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    data = resp.json()

    assert data["coverage_pct"] == 100.0
    assert data["covered_count"] == data["total_count"]
    assert data["gap_count"] == 0


@pytest.mark.asyncio
async def test_gaps_all_enabled_no_uncovered(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """When all rules are enabled, uncovered_techniques is empty."""
    db_session.add_all([
        _make_rule(title="A", enabled=True, technique_ids=json.dumps(["T1059.001"])),
        _make_rule(title="B", enabled=True, technique_ids=json.dumps(["T1003.001"])),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/gaps", headers=auth_headers)
    data = resp.json()

    assert data["uncovered_techniques"] == []
    assert data["covered_count"] == 2
