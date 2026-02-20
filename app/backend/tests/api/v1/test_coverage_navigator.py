"""Tests for GET /api/v1/coverage/navigator — ATT&CK Navigator JSON export.

The endpoint returns a Navigator v4.5 layer JSON where:
  - Each technique in the layer comes from at least one enabled rule
  - score = number of enabled rules covering that technique
  - Disabled rules are excluded entirely
  - The layer contains required Navigator envelope fields
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
async def test_navigator_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/v1/coverage/navigator")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_navigator_viewer_role_allowed(client: AsyncClient, viewer_headers: dict) -> None:
    """The viewer role (lowest privilege) can access the navigator endpoint."""
    resp = await client.get("/api/v1/coverage/navigator", headers=viewer_headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Response envelope shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_navigator_envelope_fields(client: AsyncClient, auth_headers: dict) -> None:
    """Response contains all required ATT&CK Navigator layer envelope fields."""
    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # Required top-level fields
    assert "name" in data
    assert "versions" in data
    assert "domain" in data
    assert "description" in data
    assert "techniques" in data
    assert "gradient" in data

    # versions sub-fields
    assert "attack" in data["versions"]
    assert "navigator" in data["versions"]
    assert "layer" in data["versions"]

    # Fixed values
    assert data["domain"] == "enterprise-attack"
    assert data["versions"]["layer"] == "4.5"
    assert data["versions"]["attack"] == "14"

    # techniques is always a list
    assert isinstance(data["techniques"], list)


@pytest.mark.asyncio
async def test_navigator_empty_db_returns_empty_techniques(
    client: AsyncClient, auth_headers: dict
) -> None:
    """Empty DB → techniques list is empty, envelope is still valid."""
    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["techniques"] == []
    # gradient maxValue defaults to 1 (not 0) to avoid division-by-zero in Navigator
    assert data["gradient"]["maxValue"] == 1


# ---------------------------------------------------------------------------
# Technique entries
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_navigator_technique_entry_shape(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Each technique entry has the required Navigator fields."""
    db_session.add(_make_rule(
        title="Rule A",
        enabled=True,
        technique_ids=json.dumps(["T1059.001"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert len(data["techniques"]) == 1
    tech = data["techniques"][0]

    assert "techniqueID" in tech
    assert "score" in tech
    assert "color" in tech
    assert "comment" in tech
    assert "enabled" in tech
    assert "metadata" in tech
    assert "links" in tech
    assert "showSubtechniques" in tech


@pytest.mark.asyncio
async def test_navigator_score_equals_enabled_rule_count(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Score for each technique equals the count of enabled rules covering it."""
    db_session.add_all([
        _make_rule(title="Rule 1", enabled=True, technique_ids=json.dumps(["T1059.001"])),
        _make_rule(title="Rule 2", enabled=True, technique_ids=json.dumps(["T1059.001", "T1078.002"])),
        _make_rule(title="Rule 3", enabled=True, technique_ids=json.dumps(["T1078.002"])),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    by_id = {t["techniqueID"]: t for t in data["techniques"]}
    assert "T1059.001" in by_id
    assert "T1078.002" in by_id

    # T1059.001 covered by Rule 1 and Rule 2 → score 2
    assert by_id["T1059.001"]["score"] == 2
    # T1078.002 covered by Rule 2 and Rule 3 → score 2
    assert by_id["T1078.002"]["score"] == 2


@pytest.mark.asyncio
async def test_navigator_disabled_rules_excluded(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Disabled rules do not appear in the Navigator layer techniques."""
    db_session.add_all([
        _make_rule(title="Enabled", enabled=True, technique_ids=json.dumps(["T1059.001"])),
        _make_rule(title="Disabled", enabled=False, technique_ids=json.dumps(["T1003.001"])),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    ids = {t["techniqueID"] for t in data["techniques"]}
    assert "T1059.001" in ids
    assert "T1003.001" not in ids


@pytest.mark.asyncio
async def test_navigator_all_disabled_no_techniques(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """When all rules are disabled, techniques list is empty."""
    db_session.add_all([
        _make_rule(title="Disabled A", enabled=False, technique_ids=json.dumps(["T1059.001"])),
        _make_rule(title="Disabled B", enabled=False, technique_ids=json.dumps(["T1078.002"])),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["techniques"] == []


@pytest.mark.asyncio
async def test_navigator_no_technique_ids_rules_excluded(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Enabled rules with null technique_ids do not appear in techniques list."""
    db_session.add_all([
        _make_rule(title="No Techs", enabled=True, technique_ids=None),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["techniques"] == []


@pytest.mark.asyncio
async def test_navigator_techniques_sorted(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Technique entries are returned sorted by techniqueID."""
    db_session.add(_make_rule(
        title="Multi",
        enabled=True,
        technique_ids=json.dumps(["T1078.002", "T1003.001", "T1059.001"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    ids = [t["techniqueID"] for t in data["techniques"]]
    assert ids == sorted(ids)


@pytest.mark.asyncio
async def test_navigator_gradient_max_reflects_max_score(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """gradient.maxValue equals the highest score across all techniques."""
    db_session.add_all([
        _make_rule(title="R1", enabled=True, technique_ids=json.dumps(["T1059.001"])),
        _make_rule(title="R2", enabled=True, technique_ids=json.dumps(["T1059.001"])),
        _make_rule(title="R3", enabled=True, technique_ids=json.dumps(["T1059.001"])),
        _make_rule(title="R4", enabled=True, technique_ids=json.dumps(["T1078.002"])),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # T1059.001 has score 3 (highest), T1078.002 has score 1
    assert data["gradient"]["maxValue"] == 3
    assert data["gradient"]["minValue"] == 0


@pytest.mark.asyncio
async def test_navigator_comment_singular_plural(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Comment uses 'rule' (singular) vs 'rules' (plural) based on score."""
    db_session.add_all([
        _make_rule(title="Single", enabled=True, technique_ids=json.dumps(["T1059.001"])),
        _make_rule(title="Multi1", enabled=True, technique_ids=json.dumps(["T1078.002"])),
        _make_rule(title="Multi2", enabled=True, technique_ids=json.dumps(["T1078.002"])),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/navigator", headers=auth_headers)
    data = resp.json()

    by_id = {t["techniqueID"]: t for t in data["techniques"]}
    assert "1 rule covering" in by_id["T1059.001"]["comment"]
    assert "2 rules covering" in by_id["T1078.002"]["comment"]
