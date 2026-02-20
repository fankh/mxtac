"""Tests for feature 13.10 — SigmaEngine hot-reload on demand.

POST /rules/reload clears the in-process engine and reloads every rule from
the database.  This is the "hot reload" mechanism: no server restart required.

Coverage:
  - POST /rules/reload: rules present in DB are loaded into a fresh engine
  - POST /rules/reload: stale engine rules (not in DB) are evicted
  - POST /rules/reload: engine index is rebuilt from DB rules
  - POST /rules/reload: disabled rules loaded with enabled=False
  - POST /rules/reload: returns {"reloaded": N, "total_rules": N}
  - POST /rules/reload: 503 when sigma_engine is not initialized
  - RBAC: engineer can reload (rules:write)
  - RBAC: admin can reload (rules:write)
  - RBAC: hunter is rejected (403, rules:read only)
  - RBAC: viewer is rejected (403, rules:read only)
  - SigmaEngine.reload_from_db: clears existing state before reload
  - SigmaEngine.reload_from_db: returns count of successfully loaded rules
"""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient

from app.engine.sigma_engine import SigmaEngine
from app.main import app
from app.repositories.rule_repo import RuleRepo

BASE_URL = "/api/v1/rules"

_SIGMA_YAML_A = """\
title: Reload Test Rule A
id: reload-test-rule-A
status: experimental
description: Hot reload test rule A
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: evil.exe
  condition: selection
level: high
tags:
  - attack.t1059
"""

_SIGMA_YAML_B = """\
title: Reload Test Rule B
id: reload-test-rule-B
status: experimental
description: Hot reload test rule B
logsource:
  category: network_connection
  product: linux
detection:
  selection:
    dst_port: 9001
  condition: selection
level: medium
"""

_SIGMA_YAML_C = """\
title: Reload Test Rule C (disabled)
id: reload-test-rule-C
status: experimental
description: Hot reload test rule C — disabled
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: backdoor
  condition: selection
level: critical
"""


# ---------------------------------------------------------------------------
# Fixture: fresh SigmaEngine mounted on app.state
# ---------------------------------------------------------------------------


@pytest.fixture
def sigma_engine():
    """Mount a fresh SigmaEngine on app.state and clean up after the test."""
    engine = SigmaEngine()
    app.state.sigma_engine = engine
    yield engine
    try:
        delattr(app.state, "sigma_engine")
    except (AttributeError, KeyError):
        pass


# ---------------------------------------------------------------------------
# Helper: create a rule directly in DB (bypasses engine sync)
# ---------------------------------------------------------------------------


async def _create_db_rule(db_session, rule_id: str, yaml_text: str, enabled: bool = True):
    engine = SigmaEngine()
    sigma_rule = engine.load_rule_yaml(yaml_text)
    logsource = sigma_rule.logsource if sigma_rule else {}
    return await RuleRepo.create(
        db_session,
        id=rule_id,
        title=sigma_rule.title if sigma_rule else rule_id,
        description=sigma_rule.description if sigma_rule else "",
        content=yaml_text,
        status=sigma_rule.status if sigma_rule else "experimental",
        level=sigma_rule.level if sigma_rule else "medium",
        enabled=enabled,
        logsource_product=logsource.get("product"),
        logsource_category=logsource.get("category"),
        logsource_service=logsource.get("service"),
        technique_ids=json.dumps(sigma_rule.technique_ids if sigma_rule else []),
        tactic_ids=json.dumps(sigma_rule.tactic_ids if sigma_rule else []),
        source="custom",
        rule_type="sigma",
    )


# ---------------------------------------------------------------------------
# POST /rules/reload — core behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reload_loads_db_rules_into_engine(
    client: AsyncClient,
    db_session,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """POST /rules/reload populates the engine with rules currently in DB."""
    await _create_db_rule(db_session, "reload-test-rule-A", _SIGMA_YAML_A)
    await _create_db_rule(db_session, "reload-test-rule-B", _SIGMA_YAML_B)

    resp = await client.post(f"{BASE_URL}/reload", headers=engineer_headers)
    assert resp.status_code == 200
    assert "reload-test-rule-A" in sigma_engine._rules
    assert "reload-test-rule-B" in sigma_engine._rules


@pytest.mark.asyncio
async def test_reload_returns_correct_counts(
    client: AsyncClient,
    db_session,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """POST /rules/reload returns reloaded and total_rules counts."""
    await _create_db_rule(db_session, "reload-test-rule-A", _SIGMA_YAML_A)
    await _create_db_rule(db_session, "reload-test-rule-B", _SIGMA_YAML_B)

    resp = await client.post(f"{BASE_URL}/reload", headers=engineer_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["reloaded"] == 2
    assert body["total_rules"] == 2


@pytest.mark.asyncio
async def test_reload_evicts_stale_engine_rules(
    client: AsyncClient,
    db_session,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """POST /rules/reload removes rules in engine that no longer exist in DB."""
    # Load a rule into the engine that is NOT in the DB
    stale_rule = sigma_engine.load_rule_yaml(_SIGMA_YAML_A)
    sigma_engine.add_rule(stale_rule)
    assert "reload-test-rule-A" in sigma_engine._rules

    # DB has only rule B
    await _create_db_rule(db_session, "reload-test-rule-B", _SIGMA_YAML_B)

    resp = await client.post(f"{BASE_URL}/reload", headers=engineer_headers)
    assert resp.status_code == 200
    # Stale rule A was evicted; only rule B remains
    assert "reload-test-rule-A" not in sigma_engine._rules
    assert "reload-test-rule-B" in sigma_engine._rules


@pytest.mark.asyncio
async def test_reload_rebuilds_index(
    client: AsyncClient,
    db_session,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """POST /rules/reload rebuilds the logsource index from DB state."""
    # Pre-load stale rule A (process_creation/windows) into engine
    stale = sigma_engine.load_rule_yaml(_SIGMA_YAML_A)
    sigma_engine.add_rule(stale)
    assert any("reload-test-rule-A" in [r.id for r in lst]
               for lst in sigma_engine._index.values())

    # DB has only rule B (network_connection/linux)
    await _create_db_rule(db_session, "reload-test-rule-B", _SIGMA_YAML_B)

    await client.post(f"{BASE_URL}/reload", headers=engineer_headers)

    # Stale A's index entry (product:windows / category:process_creation) must be gone
    all_indexed_ids = {r.id for lst in sigma_engine._index.values() for r in lst}
    assert "reload-test-rule-A" not in all_indexed_ids
    assert "reload-test-rule-B" in all_indexed_ids


@pytest.mark.asyncio
async def test_reload_respects_disabled_flag(
    client: AsyncClient,
    db_session,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """POST /rules/reload preserves enabled=False for rules stored as disabled."""
    await _create_db_rule(db_session, "reload-test-rule-C", _SIGMA_YAML_C, enabled=False)

    resp = await client.post(f"{BASE_URL}/reload", headers=engineer_headers)
    assert resp.status_code == 200
    assert sigma_engine._rules["reload-test-rule-C"].enabled is False


@pytest.mark.asyncio
async def test_reload_respects_enabled_true(
    client: AsyncClient,
    db_session,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """POST /rules/reload marks rules enabled=True when stored as enabled."""
    await _create_db_rule(db_session, "reload-test-rule-A", _SIGMA_YAML_A, enabled=True)

    resp = await client.post(f"{BASE_URL}/reload", headers=engineer_headers)
    assert resp.status_code == 200
    assert sigma_engine._rules["reload-test-rule-A"].enabled is True


@pytest.mark.asyncio
async def test_reload_empty_db_clears_engine(
    client: AsyncClient,
    db_session,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """POST /rules/reload with an empty DB results in an empty engine."""
    # Pre-load some rules into the engine
    rule_a = sigma_engine.load_rule_yaml(_SIGMA_YAML_A)
    sigma_engine.add_rule(rule_a)
    assert sigma_engine.rule_count == 1

    # DB is empty — reload should clear the engine
    resp = await client.post(f"{BASE_URL}/reload", headers=engineer_headers)
    assert resp.status_code == 200
    assert resp.json()["reloaded"] == 0
    assert sigma_engine.rule_count == 0


# ---------------------------------------------------------------------------
# POST /rules/reload — 503 when engine is absent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reload_returns_503_when_engine_absent(
    client: AsyncClient,
    engineer_headers: dict,
) -> None:
    """POST /rules/reload returns 503 when app.state.sigma_engine is not set."""
    try:
        delattr(app.state, "sigma_engine")
    except (AttributeError, KeyError):
        pass

    resp = await client.post(f"{BASE_URL}/reload", headers=engineer_headers)
    assert resp.status_code == 503
    assert "not initialized" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reload_allowed_for_engineer(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """Engineer role (rules:write) can trigger a hot reload."""
    resp = await client.post(f"{BASE_URL}/reload", headers=engineer_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_reload_allowed_for_admin(
    client: AsyncClient,
    admin_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """Admin role (rules:write) can trigger a hot reload."""
    resp = await client.post(f"{BASE_URL}/reload", headers=admin_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_reload_forbidden_for_hunter(
    client: AsyncClient,
    hunter_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """Hunter role (rules:read only) cannot trigger a hot reload."""
    resp = await client.post(f"{BASE_URL}/reload", headers=hunter_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_reload_forbidden_for_viewer(
    client: AsyncClient,
    viewer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """Viewer role cannot trigger a hot reload."""
    resp = await client.post(f"{BASE_URL}/reload", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_reload_unauthenticated(
    client: AsyncClient,
    sigma_engine: SigmaEngine,
) -> None:
    """Unauthenticated request to /rules/reload is rejected."""
    resp = await client.post(f"{BASE_URL}/reload")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# SigmaEngine.reload_from_db — unit tests (no HTTP layer)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reload_from_db_clears_existing_rules(
    db_session,
) -> None:
    """reload_from_db() clears pre-loaded rules before repopulating from DB."""
    engine = SigmaEngine()

    # Pre-load a rule into the engine (not in DB)
    stale = engine.load_rule_yaml(_SIGMA_YAML_A)
    engine.add_rule(stale)
    assert "reload-test-rule-A" in engine._rules

    # DB has only rule B
    await _create_db_rule(db_session, "reload-test-rule-B", _SIGMA_YAML_B)

    await engine.reload_from_db(db_session)

    assert "reload-test-rule-A" not in engine._rules
    assert "reload-test-rule-B" in engine._rules


@pytest.mark.asyncio
async def test_reload_from_db_clears_index(
    db_session,
) -> None:
    """reload_from_db() clears the logsource index before repopulating."""
    engine = SigmaEngine()

    # Pre-load rule A (product:windows)
    stale = engine.load_rule_yaml(_SIGMA_YAML_A)
    engine.add_rule(stale)
    assert engine._index.get("product:windows")

    # DB has only rule B (product:linux)
    await _create_db_rule(db_session, "reload-test-rule-B", _SIGMA_YAML_B)

    await engine.reload_from_db(db_session)

    # product:windows index must be empty (stale cleared, not repopulated)
    windows_ids = [r.id for r in engine._index.get("product:windows", [])]
    assert "reload-test-rule-A" not in windows_ids

    linux_ids = [r.id for r in engine._index.get("product:linux", [])]
    assert "reload-test-rule-B" in linux_ids


@pytest.mark.asyncio
async def test_reload_from_db_returns_count(
    db_session,
) -> None:
    """reload_from_db() returns the number of rules successfully loaded."""
    await _create_db_rule(db_session, "reload-test-rule-A", _SIGMA_YAML_A)
    await _create_db_rule(db_session, "reload-test-rule-B", _SIGMA_YAML_B)

    engine = SigmaEngine()
    count = await engine.reload_from_db(db_session)

    assert count == 2


@pytest.mark.asyncio
async def test_reload_from_db_empty_db_returns_zero(
    db_session,
) -> None:
    """reload_from_db() on empty DB returns 0 and leaves engine empty."""
    engine = SigmaEngine()
    # Pre-load a rule
    r = engine.load_rule_yaml(_SIGMA_YAML_A)
    engine.add_rule(r)

    count = await engine.reload_from_db(db_session)

    assert count == 0
    assert engine.rule_count == 0
    assert not engine._index
