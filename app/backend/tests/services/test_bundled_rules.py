"""Bundled Sigma rules are imported into the rules table (single source of truth)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.sigma_engine import SigmaEngine
from app.main import app
from app.repositories.rule_repo import RuleRepo
from app.services.bundled_rules import BUNDLED_RULES_DIR, BUNDLED_SOURCE, import_bundled_rules

BUNDLED_COUNT = len(list(BUNDLED_RULES_DIR.glob("*.yml")))
SSH_ROOT_RULE_ID = "b67d5827-73fd-46a2-a8fd-d15594ac491e"

RULE_TEMPLATE = """\
title: {title}
id: {rule_id}
level: low
logsource:
  product: linux
detection:
  selection:
    message|contains: '{needle}'
  condition: selection
tags:
  - attack.discovery
  - attack.t1082
"""


def _write_rule(directory: Path, rule_id: str, *, title: str = "Temp rule", needle: str = "x") -> None:
    (directory / f"{rule_id}.yml").write_text(
        RULE_TEMPLATE.format(title=title, rule_id=rule_id, needle=needle), encoding="utf-8"
    )


# ── Import ───────────────────────────────────────────────────────────────────


async def test_import_inserts_every_bundled_rule(db_session: AsyncSession) -> None:
    imported = await import_bundled_rules(db_session)

    assert imported == BUNDLED_COUNT >= 15
    rules = await RuleRepo.list(db_session)
    assert len(rules) == BUNDLED_COUNT
    assert {rule.source for rule in rules} == {BUNDLED_SOURCE}
    assert all(rule.enabled for rule in rules)


async def test_imported_row_carries_rule_metadata(db_session: AsyncSession) -> None:
    await import_bundled_rules(db_session)

    rule = await RuleRepo.get_by_id(db_session, SSH_ROOT_RULE_ID)
    assert rule.title == "SSH Failed Password for Root"
    assert rule.level == "medium"
    assert rule.logsource_product == "linux"
    assert rule.logsource_service == "sshd"
    assert json.loads(rule.technique_ids) == ["T1110.001"]
    assert json.loads(rule.tactic_ids) == ["TA0006"]
    assert "Failed password for root from" in rule.content


async def test_import_is_idempotent(db_session: AsyncSession) -> None:
    await import_bundled_rules(db_session)

    assert await import_bundled_rules(db_session) == 0
    assert await RuleRepo.count(db_session) == BUNDLED_COUNT


async def test_import_does_not_overwrite_edited_or_disabled_rule(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    rule_id = "7e0e5f0a-5a7b-4d55-8a55-0e7c2f3d9b11"
    _write_rule(tmp_path, rule_id, title="Shipped title", needle="shipped")
    await import_bundled_rules(db_session, tmp_path)

    await RuleRepo.update(
        db_session, rule_id, title="Edited by user", content="edited: true", enabled=False
    )
    await db_session.commit()

    assert await import_bundled_rules(db_session, tmp_path) == 0
    rule = await RuleRepo.get_by_id(db_session, rule_id)
    assert rule.title == "Edited by user"
    assert rule.content == "edited: true"
    assert rule.enabled is False


async def test_import_adds_only_new_rule_files(db_session: AsyncSession, tmp_path: Path) -> None:
    first, second = "0f6a1f43-5f0c-4f3f-8d0e-3b1e4c1f7a01", "c1b7a3f2-93c5-4b8e-a2c3-5d2f6e8a9b02"
    _write_rule(tmp_path, first)
    assert await import_bundled_rules(db_session, tmp_path) == 1

    _write_rule(tmp_path, second)
    assert await import_bundled_rules(db_session, tmp_path) == 1
    assert {rule.id for rule in await RuleRepo.list(db_session)} == {first, second}


async def test_import_skips_invalid_unsupported_and_id_less_files(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    good = "5b2f8e0c-7d4a-4a39-9c1f-6e0d3a2b1c03"
    _write_rule(tmp_path, good)
    (tmp_path / "broken.yml").write_text("title: [unclosed", encoding="utf-8")
    (tmp_path / "aggregation.yml").write_text(
        "title: Agg\nid: 9a1d2c3b-4e5f-4a6b-8c7d-0e1f2a3b4c04\n"
        "detection:\n  selection: {a: b}\n  condition: selection | count() > 5\n",
        encoding="utf-8",
    )
    (tmp_path / "no_id.yml").write_text(
        "title: No id\ndetection:\n  selection: {a: b}\n  condition: selection\n", encoding="utf-8"
    )

    assert await import_bundled_rules(db_session, tmp_path) == 1
    assert [rule.id for rule in await RuleRepo.list(db_session)] == [good]


async def test_import_with_missing_directory_is_a_no_op(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    assert await import_bundled_rules(db_session, tmp_path / "absent") == 0


# ── Engine is loaded from the table only; reload is stable ───────────────────


async def test_engine_loads_bundled_rules_from_table_and_reload_is_stable(
    db_session: AsyncSession,
) -> None:
    await import_bundled_rules(db_session)
    engine = SigmaEngine()

    assert await engine.load_rules_from_db(db_session) == BUNDLED_COUNT
    rule_ids = set(engine._rules)

    assert await engine.reload_from_db(db_session) == BUNDLED_COUNT
    assert set(engine._rules) == rule_ids
    assert await engine.reload_from_db(db_session) == BUNDLED_COUNT


async def test_disabled_bundled_rule_stays_disabled_after_restart(db_session: AsyncSession) -> None:
    await import_bundled_rules(db_session)
    await RuleRepo.disable(db_session, SSH_ROOT_RULE_ID)
    await db_session.commit()

    # "Restart": import again, then load a fresh engine.
    await import_bundled_rules(db_session)
    engine = SigmaEngine()
    await engine.load_rules_from_db(db_session)

    assert engine._rules[SSH_ROOT_RULE_ID].enabled is False


async def test_engine_uses_table_id_for_rule_without_yaml_id(db_session: AsyncSession) -> None:
    """Hit counters are keyed by the table id, also when the YAML has no id."""
    await RuleRepo.create(
        db_session,
        id="2d6b9f1e-8c3a-4f5d-9e7b-1a2c3d4e5f05",
        title="No id in YAML",
        content="title: No id in YAML\ndetection:\n  selection: {a: b}\n  condition: selection\n",
    )
    engine = SigmaEngine()
    await engine.load_rules_from_db(db_session)

    assert list(engine._rules) == ["2d6b9f1e-8c3a-4f5d-9e7b-1a2c3d4e5f05"]


# ── Visible through the API: list, coverage, reload ──────────────────────────


@pytest.fixture
def sigma_engine():
    engine = SigmaEngine()
    app.state.sigma_engine = engine
    yield engine
    app.state.sigma_engine = None


async def test_bundled_rules_are_listed_and_counted_in_coverage(
    client: AsyncClient, db_session: AsyncSession, engineer_headers: dict
) -> None:
    await import_bundled_rules(db_session)

    listed = await client.get("/api/v1/rules", headers=engineer_headers)
    assert listed.status_code == 200
    assert len(listed.json()) == BUNDLED_COUNT

    detail = await client.get(f"/api/v1/rules/{SSH_ROOT_RULE_ID}", headers=engineer_headers)
    assert detail.json()["source"] == BUNDLED_SOURCE

    coverage = await RuleRepo.get_coverage_summary(db_session)
    assert coverage["covered_count"] >= 15
    assert coverage["coverage_pct"] > 0


async def test_reload_endpoint_keeps_bundled_rules(
    client: AsyncClient, db_session: AsyncSession, engineer_headers: dict, sigma_engine: SigmaEngine
) -> None:
    await import_bundled_rules(db_session)
    await sigma_engine.load_rules_from_db(db_session)

    for _ in range(2):
        resp = await client.post("/api/v1/rules/reload", headers=engineer_headers)
        assert resp.status_code == 200
        assert resp.json() == {"reloaded": BUNDLED_COUNT, "total_rules": BUNDLED_COUNT}
        assert sigma_engine.rule_count == BUNDLED_COUNT
