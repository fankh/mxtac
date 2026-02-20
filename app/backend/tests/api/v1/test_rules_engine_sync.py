"""Tests for feature 13.9 — DB persistence for all rule operations.

Verifies that the in-process SigmaEngine (app.state.sigma_engine) is kept
in sync with the database for every mutating rule operation.

Coverage:
  - POST /rules: created rule is added to the engine
  - POST /rules (enabled=False): rule added to engine with enabled=False
  - POST /rules/import: bulk-imported rules appear in the engine
  - PATCH /rules/{id} (enabled=False): engine rule is disabled
  - PATCH /rules/{id} (enabled=True): engine rule is re-enabled
  - PATCH /rules/{id} (content): engine rule is replaced with new content
  - PATCH /rules/{id} (content + enabled): both changes applied to engine
  - DELETE /rules/{id}: rule removed from engine
  - DELETE /rules/{id} (already absent from engine): safe, no error
  - Engine absent (None): CRUD endpoints still return correct HTTP responses
  - Startup: load_rules_from_db populates engine from DB records
  - Startup: load_rules_from_db respects enabled flag from DB
  - Startup: load_rules_from_db uses upsert (overrides disk rule with same ID)
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.engine.sigma_engine import SigmaEngine
from app.main import app

BASE_URL = "/api/v1/rules"

_SIGMA_YAML = """\
title: Test Mimikatz Detection
id: test-rule-sync-001
status: experimental
description: Detects mimikatz execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1003
"""

_SIGMA_YAML_UPDATED = """\
title: Test Mimikatz Detection (Updated)
id: test-rule-sync-001
status: experimental
description: Detects mimikatz execution (updated)
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: mimikatz
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003
"""

_SIGMA_YAML_2 = """\
title: Second Test Rule
id: test-rule-sync-002
status: experimental
description: Second test rule
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    dst_port: 4444
  condition: selection
level: medium
"""


# ---------------------------------------------------------------------------
# Fixture: mount a real SigmaEngine on app.state for the duration of the test
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
# POST /rules — engine sync on create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_rule_adds_to_engine(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """Creating a rule via POST /rules adds it to the Sigma engine."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    assert resp.status_code == 201
    assert "test-rule-sync-001" in sigma_engine._rules


@pytest.mark.asyncio
async def test_create_rule_engine_rule_is_enabled_by_default(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """Rule added to engine has enabled=True when created without specifying enabled."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    assert sigma_engine._rules["test-rule-sync-001"].enabled is True


@pytest.mark.asyncio
async def test_create_disabled_rule_engine_rule_is_disabled(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """Creating a rule with enabled=False adds it to engine with enabled=False."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML, "enabled": False},
    )
    assert sigma_engine._rules["test-rule-sync-001"].enabled is False


@pytest.mark.asyncio
async def test_create_rule_engine_indexed_by_logsource(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """Rule is indexed by logsource so the engine can find it for evaluation."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    # Should appear in product:windows or category:process_creation index
    indexed_ids = {
        r.id
        for lst in sigma_engine._index.values()
        for r in lst
    }
    assert "test-rule-sync-001" in indexed_ids


# ---------------------------------------------------------------------------
# POST /rules/import — engine sync on bulk import
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_rules_adds_to_engine(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """Bulk importing rules adds each valid rule to the engine."""
    multi_doc = _SIGMA_YAML + "---\n" + _SIGMA_YAML_2
    resp = await client.post(
        f"{BASE_URL}/import",
        headers=engineer_headers,
        json={"yaml_content": multi_doc},
    )
    assert resp.status_code == 200
    assert resp.json()["imported"] == 2
    assert "test-rule-sync-001" in sigma_engine._rules
    assert "test-rule-sync-002" in sigma_engine._rules


# ---------------------------------------------------------------------------
# PATCH /rules/{id} — engine sync on update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_disable_syncs_engine(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """PATCH enabled=False disables the rule in the engine."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    assert sigma_engine._rules["test-rule-sync-001"].enabled is True

    await client.patch(
        f"{BASE_URL}/test-rule-sync-001",
        headers=engineer_headers,
        json={"enabled": False},
    )
    assert sigma_engine._rules["test-rule-sync-001"].enabled is False


@pytest.mark.asyncio
async def test_patch_enable_syncs_engine(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """PATCH enabled=True re-enables a disabled rule in the engine."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML, "enabled": False},
    )
    assert sigma_engine._rules["test-rule-sync-001"].enabled is False

    await client.patch(
        f"{BASE_URL}/test-rule-sync-001",
        headers=engineer_headers,
        json={"enabled": True},
    )
    assert sigma_engine._rules["test-rule-sync-001"].enabled is True


@pytest.mark.asyncio
async def test_patch_content_replaces_engine_rule(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """PATCH with new content replaces the engine rule (title, level, logsource updated)."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    assert sigma_engine._rules["test-rule-sync-001"].level == "high"

    await client.patch(
        f"{BASE_URL}/test-rule-sync-001",
        headers=engineer_headers,
        json={"content": _SIGMA_YAML_UPDATED},
    )
    rule = sigma_engine._rules["test-rule-sync-001"]
    assert rule.level == "critical"
    assert rule.title == "Test Mimikatz Detection (Updated)"


@pytest.mark.asyncio
async def test_patch_content_updates_engine_index(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """PATCH with new content updates the logsource index (old entries removed)."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    # Original rule is indexed under product:windows
    windows_rules = [r.id for r in sigma_engine._index.get("product:windows", [])]
    assert "test-rule-sync-001" in windows_rules

    # Updated rule moves to product:linux
    await client.patch(
        f"{BASE_URL}/test-rule-sync-001",
        headers=engineer_headers,
        json={"content": _SIGMA_YAML_UPDATED},
    )
    windows_rules_after = [r.id for r in sigma_engine._index.get("product:windows", [])]
    linux_rules_after = [r.id for r in sigma_engine._index.get("product:linux", [])]
    assert "test-rule-sync-001" not in windows_rules_after
    assert "test-rule-sync-001" in linux_rules_after


@pytest.mark.asyncio
async def test_patch_content_and_enabled_both_applied_to_engine(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """PATCH with both content and enabled applies both changes to engine rule."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )

    await client.patch(
        f"{BASE_URL}/test-rule-sync-001",
        headers=engineer_headers,
        json={"content": _SIGMA_YAML_UPDATED, "enabled": False},
    )
    rule = sigma_engine._rules["test-rule-sync-001"]
    assert rule.level == "critical"
    assert rule.enabled is False


# ---------------------------------------------------------------------------
# DELETE /rules/{id} — engine sync on delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_rule_removes_from_engine(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """DELETE /rules/{id} removes the rule from the engine."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    assert "test-rule-sync-001" in sigma_engine._rules

    resp = await client.delete(
        f"{BASE_URL}/test-rule-sync-001",
        headers=engineer_headers,
    )
    assert resp.status_code == 204
    assert "test-rule-sync-001" not in sigma_engine._rules


@pytest.mark.asyncio
async def test_delete_rule_removes_from_engine_index(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """DELETE /rules/{id} removes the rule from all logsource index entries."""
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    await client.delete(f"{BASE_URL}/test-rule-sync-001", headers=engineer_headers)

    indexed_ids = {
        r.id
        for lst in sigma_engine._index.values()
        for r in lst
    }
    assert "test-rule-sync-001" not in indexed_ids


@pytest.mark.asyncio
async def test_delete_rule_not_in_engine_is_safe(
    client: AsyncClient,
    engineer_headers: dict,
    sigma_engine: SigmaEngine,
) -> None:
    """DELETE /rules/{id} is safe even if the rule was never in the engine."""
    # Create via repo (bypasses engine sync) then delete via API
    from app.repositories.rule_repo import RuleRepo
    from app.core.database import get_db as real_get_db

    # Create rule in DB but not in engine by directly using the db fixture session
    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    # Manually remove from engine to simulate "not in engine" scenario
    sigma_engine.remove_rule("test-rule-sync-001")
    assert "test-rule-sync-001" not in sigma_engine._rules

    # Deleting should work without error (remove_rule on missing ID is safe)
    resp = await client.delete(
        f"{BASE_URL}/test-rule-sync-001",
        headers=engineer_headers,
    )
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Engine absent — CRUD still works
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_rule_works_without_engine(
    client: AsyncClient,
    engineer_headers: dict,
) -> None:
    """POST /rules works correctly even when app.state.sigma_engine is not set."""
    # Ensure engine is not set (no sigma_engine fixture)
    try:
        delattr(app.state, "sigma_engine")
    except (AttributeError, KeyError):
        pass

    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    assert resp.status_code == 201
    assert resp.json()["id"] == "test-rule-sync-001"


@pytest.mark.asyncio
async def test_patch_rule_works_without_engine(
    client: AsyncClient,
    engineer_headers: dict,
) -> None:
    """PATCH /rules/{id} works correctly even when app.state.sigma_engine is not set."""
    try:
        delattr(app.state, "sigma_engine")
    except (AttributeError, KeyError):
        pass

    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.patch(
        f"{BASE_URL}/test-rule-sync-001",
        headers=engineer_headers,
        json={"enabled": False},
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_delete_rule_works_without_engine(
    client: AsyncClient,
    engineer_headers: dict,
) -> None:
    """DELETE /rules/{id} works correctly even when app.state.sigma_engine is not set."""
    try:
        delattr(app.state, "sigma_engine")
    except (AttributeError, KeyError):
        pass

    await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"title": "Mimikatz", "content": _SIGMA_YAML},
    )
    resp = await client.delete(
        f"{BASE_URL}/test-rule-sync-001",
        headers=engineer_headers,
    )
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# SigmaEngine.load_rules_from_db — unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_load_rules_from_db_populates_engine(
    db_session,
) -> None:
    """load_rules_from_db adds DB-persisted rules to a fresh engine."""
    from app.repositories.rule_repo import RuleRepo
    import json

    await RuleRepo.create(
        db_session,
        id="db-load-test-001",
        title="DB Load Test Rule",
        content=_SIGMA_YAML.replace("test-rule-sync-001", "db-load-test-001"),
        level="high",
        status="experimental",
        rule_type="sigma",
        enabled=True,
        technique_ids=json.dumps(["T1003"]),
        tactic_ids=json.dumps([]),
        source="custom",
    )

    engine = SigmaEngine()
    count = await engine.load_rules_from_db(db_session)

    assert count == 1
    assert "db-load-test-001" in engine._rules


@pytest.mark.asyncio
async def test_load_rules_from_db_respects_enabled_false(
    db_session,
) -> None:
    """load_rules_from_db marks engine rules disabled when DB enabled=False."""
    from app.repositories.rule_repo import RuleRepo
    import json

    await RuleRepo.create(
        db_session,
        id="db-load-test-002",
        title="Disabled DB Rule",
        content=_SIGMA_YAML.replace("test-rule-sync-001", "db-load-test-002"),
        level="medium",
        status="experimental",
        rule_type="sigma",
        enabled=False,
        technique_ids=json.dumps([]),
        tactic_ids=json.dumps([]),
        source="custom",
    )

    engine = SigmaEngine()
    await engine.load_rules_from_db(db_session)

    assert engine._rules["db-load-test-002"].enabled is False


@pytest.mark.asyncio
async def test_load_rules_from_db_overrides_disk_rule(
    db_session,
) -> None:
    """load_rules_from_db uses upsert: DB version replaces a disk-loaded rule with same ID."""
    from app.repositories.rule_repo import RuleRepo
    import json

    rule_id = "disk-vs-db-rule"
    disk_yaml = f"""\
title: Disk Rule
id: {rule_id}
status: stable
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: test
  condition: selection
level: low
"""
    db_yaml = f"""\
title: DB Rule (overrides disk)
id: {rule_id}
status: experimental
logsource:
  product: linux
detection:
  selection:
    CommandLine|contains: test
  condition: selection
level: critical
"""

    engine = SigmaEngine()
    # Simulate disk-loaded rule
    disk_rule = engine.load_rule_yaml(disk_yaml)
    engine.add_rule(disk_rule)
    assert engine._rules[rule_id].level == "low"

    # Store the DB version (different level, enabled=False)
    await RuleRepo.create(
        db_session,
        id=rule_id,
        title="DB Rule",
        content=db_yaml,
        level="critical",
        status="experimental",
        rule_type="sigma",
        enabled=False,
        technique_ids=json.dumps([]),
        tactic_ids=json.dumps([]),
        source="custom",
    )

    await engine.load_rules_from_db(db_session)

    # DB version should override disk version
    rule = engine._rules[rule_id]
    assert rule.level == "critical"
    assert rule.enabled is False
    assert rule.title == "DB Rule (overrides disk)"

    # Old disk logsource index entry (product:windows) should be gone
    windows_ids = [r.id for r in engine._index.get("product:windows", [])]
    linux_ids = [r.id for r in engine._index.get("product:linux", [])]
    assert rule_id not in windows_ids
    assert rule_id in linux_ids


@pytest.mark.asyncio
async def test_load_rules_from_db_skips_empty_content(
    db_session,
) -> None:
    """load_rules_from_db skips DB rules with no content."""
    from app.repositories.rule_repo import RuleRepo
    import json

    # Create a rule with empty content (shouldn't be possible normally, but defensive)
    # We patch content after creation to simulate this edge case
    rule = await RuleRepo.create(
        db_session,
        id="empty-content-rule",
        title="Empty Content",
        content="placeholder",
        level="low",
        status="experimental",
        rule_type="sigma",
        enabled=True,
        technique_ids=json.dumps([]),
        tactic_ids=json.dumps([]),
        source="custom",
    )
    # Overwrite with empty content
    rule.content = ""
    await db_session.flush()

    engine = SigmaEngine()
    count = await engine.load_rules_from_db(db_session)
    # Should skip the empty-content rule
    assert count == 0
    assert "empty-content-rule" not in engine._rules
