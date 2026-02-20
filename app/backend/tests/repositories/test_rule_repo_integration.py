"""Integration tests for RuleRepo — real SQLite via the db_session fixture.

Feature 18.4 — Alembic migration 0002 (rules + connectors)

Approach:
  - Uses the ``db_session`` fixture from conftest.py (in-memory SQLite, fresh schema).
  - No mocks: every test exercises real SQL statements through SQLAlchemy.
  - Each test function receives an isolated session that is rolled back on teardown.

Coverage:
  - create(): ORM defaults applied; rule returned with correct attributes
  - create(): created rule persisted and retrievable via get_by_id
  - list(): empty table → empty list; non-empty → all rules returned
  - list(enabled=True/False): filter correctly selects rows
  - list(level=...): level filter selects only matching rows
  - list(enabled + level): both filters combined
  - list(): multiple rules returned in any order (ordering by created_at DESC)
  - get_by_id(): existing → returns Rule; nonexistent → None
  - update(): found → attributes mutated, flush reflected in subsequent read
  - update(): not found → returns None without error
  - update(): None kwarg values are skipped (no overwrite)
  - update(): False (bool) is applied, not skipped
  - enable(): sets enabled=True on existing rule
  - disable(): sets enabled=False on existing rule
  - enable() / disable(): return None for nonexistent id
  - delete(): found → True, rule no longer returned by get_by_id
  - delete(): not found → False
  - count(): returns 0 for empty table; exact count after inserts
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.rule_repo import RuleRepo

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_rule(session: AsyncSession, **kwargs) -> object:
    """Create a minimal rule, merging defaults with caller-supplied kwargs."""
    defaults = {
        "title": "Test Rule",
        "content": "detection:\n  condition: all of them",
        "level": "medium",
        "status": "experimental",
        "rule_type": "sigma",
    }
    defaults.update(kwargs)
    return await RuleRepo.create(session, **defaults)


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


class TestRuleRepoCreateIntegration:
    """RuleRepo.create() persists a rule with correct ORM defaults."""

    async def test_returns_rule_with_id(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        assert rule.id is not None
        assert len(rule.id) == 36  # UUID format

    async def test_returns_rule_with_correct_title(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, title="PowerShell Suspicious Download")
        assert rule.title == "PowerShell Suspicious Download"

    async def test_returns_rule_with_correct_level(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, level="high")
        assert rule.level == "high"

    async def test_default_status_is_experimental(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        assert rule.status == "experimental"

    async def test_default_rule_type_is_sigma(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        assert rule.rule_type == "sigma"

    async def test_default_enabled_is_true(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        assert rule.enabled is True

    async def test_default_hit_count_is_zero(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        assert rule.hit_count == 0

    async def test_default_fp_count_is_zero(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        assert rule.fp_count == 0

    async def test_rule_is_retrievable_after_create(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, title="Retrievable Rule")
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched is not None
        assert fetched.id == rule.id

    async def test_explicit_enabled_false_is_persisted(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, enabled=False)
        assert rule.enabled is False

    async def test_optional_fields_can_be_none(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, description=None, source=None, created_by=None)
        assert rule.description is None
        assert rule.source is None
        assert rule.created_by is None

    async def test_optional_fields_can_be_set(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(
            db_session,
            description="Detects credential dumping",
            source="sigmaHQ",
            created_by="analyst@mxtac.local",
        )
        assert rule.description == "Detects credential dumping"
        assert rule.source == "sigmaHQ"
        assert rule.created_by == "analyst@mxtac.local"


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


class TestRuleRepoListIntegration:
    """RuleRepo.list() returns rules from the database with optional filters."""

    async def test_empty_table_returns_empty_list(self, db_session: AsyncSession) -> None:
        result = await RuleRepo.list(db_session)
        assert result == []

    async def test_returns_all_rules(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, title="Rule A")
        await _create_rule(db_session, title="Rule B")
        result = await RuleRepo.list(db_session)
        assert len(result) == 2

    async def test_result_is_list_type(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session)
        result = await RuleRepo.list(db_session)
        assert isinstance(result, list)

    async def test_titles_in_result(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, title="Alpha Rule")
        await _create_rule(db_session, title="Beta Rule")
        titles = {r.title for r in await RuleRepo.list(db_session)}
        assert "Alpha Rule" in titles
        assert "Beta Rule" in titles

    async def test_filter_enabled_true_returns_only_enabled(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, title="Enabled", enabled=True)
        await _create_rule(db_session, title="Disabled", enabled=False)
        result = await RuleRepo.list(db_session, enabled=True)
        assert all(r.enabled is True for r in result)
        assert len(result) == 1
        assert result[0].title == "Enabled"

    async def test_filter_enabled_false_returns_only_disabled(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, title="Enabled", enabled=True)
        await _create_rule(db_session, title="Disabled", enabled=False)
        result = await RuleRepo.list(db_session, enabled=False)
        assert all(r.enabled is False for r in result)
        assert len(result) == 1
        assert result[0].title == "Disabled"

    async def test_filter_level_returns_only_matching(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, title="High Rule", level="high")
        await _create_rule(db_session, title="Low Rule", level="low")
        result = await RuleRepo.list(db_session, level="high")
        assert len(result) == 1
        assert result[0].level == "high"

    async def test_filter_enabled_and_level_combined(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, title="Match", enabled=True, level="critical")
        await _create_rule(db_session, title="Wrong Level", enabled=True, level="low")
        await _create_rule(db_session, title="Disabled", enabled=False, level="critical")
        result = await RuleRepo.list(db_session, enabled=True, level="critical")
        assert len(result) == 1
        assert result[0].title == "Match"

    async def test_no_filter_returns_all_regardless_of_enabled(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session, enabled=True)
        await _create_rule(db_session, enabled=False)
        result = await RuleRepo.list(db_session)
        assert len(result) == 2

    @pytest.mark.parametrize("level", ["low", "medium", "high", "critical"])
    async def test_all_valid_levels_filterable(self, db_session: AsyncSession, level: str) -> None:
        await _create_rule(db_session, level=level)
        result = await RuleRepo.list(db_session, level=level)
        assert len(result) == 1
        assert result[0].level == level


# ---------------------------------------------------------------------------
# get_by_id()
# ---------------------------------------------------------------------------


class TestRuleRepoGetByIdIntegration:
    """RuleRepo.get_by_id() queries the database for a rule by primary key."""

    async def test_returns_rule_when_found(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, title="Findable Rule")
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched is not None
        assert fetched.title == "Findable Rule"

    async def test_returns_none_when_not_found(self, db_session: AsyncSession) -> None:
        result = await RuleRepo.get_by_id(db_session, "nonexistent-uuid-0000-0000-000000000000")
        assert result is None

    async def test_returns_correct_rule_among_many(self, db_session: AsyncSession) -> None:
        rule1 = await _create_rule(db_session, title="First")
        rule2 = await _create_rule(db_session, title="Second")
        fetched = await RuleRepo.get_by_id(db_session, rule2.id)
        assert fetched is not None
        assert fetched.id == rule2.id
        assert fetched.title == "Second"

    async def test_returned_rule_has_all_fields(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(
            db_session,
            title="Full Rule",
            level="high",
            source="sigmaHQ",
            logsource_product="windows",
            logsource_category="process_creation",
        )
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched.level == "high"
        assert fetched.source == "sigmaHQ"
        assert fetched.logsource_product == "windows"
        assert fetched.logsource_category == "process_creation"


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestRuleRepoUpdateIntegration:
    """RuleRepo.update() modifies an existing rule in the database."""

    async def test_update_title(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, title="Old Title")
        updated = await RuleRepo.update(db_session, rule.id, title="New Title")
        assert updated is not None
        assert updated.title == "New Title"

    async def test_update_level(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, level="low")
        await RuleRepo.update(db_session, rule.id, level="critical")
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched.level == "critical"

    async def test_update_multiple_fields(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, title="Old", level="low")
        await RuleRepo.update(db_session, rule.id, title="New", level="high", source="custom")
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched.title == "New"
        assert fetched.level == "high"
        assert fetched.source == "custom"

    async def test_update_returns_none_for_nonexistent(self, db_session: AsyncSession) -> None:
        result = await RuleRepo.update(db_session, "nonexistent-id", title="Whatever")
        assert result is None

    async def test_none_kwarg_does_not_overwrite(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, title="Keep This Title", level="high")
        await RuleRepo.update(db_session, rule.id, title=None, level="low")
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched.title == "Keep This Title"  # None skipped
        assert fetched.level == "low"  # non-None applied

    async def test_false_value_is_applied(self, db_session: AsyncSession) -> None:
        """False must be applied, not skipped (only None is skipped)."""
        rule = await _create_rule(db_session, enabled=True)
        await RuleRepo.update(db_session, rule.id, enabled=False)
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched.enabled is False

    async def test_zero_hit_count_is_applied(self, db_session: AsyncSession) -> None:
        """Zero must be applied, not skipped."""
        rule = await _create_rule(db_session, hit_count=10)
        await RuleRepo.update(db_session, rule.id, hit_count=0)
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched.hit_count == 0


# ---------------------------------------------------------------------------
# enable() / disable()
# ---------------------------------------------------------------------------


class TestRuleRepoEnableDisableIntegration:
    """RuleRepo.enable() and disable() flip the enabled flag in the database."""

    async def test_enable_sets_enabled_true(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, enabled=False)
        assert rule.enabled is False
        result = await RuleRepo.enable(db_session, rule.id)
        assert result is not None
        assert result.enabled is True

    async def test_disable_sets_enabled_false(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, enabled=True)
        assert rule.enabled is True
        result = await RuleRepo.disable(db_session, rule.id)
        assert result is not None
        assert result.enabled is False

    async def test_enable_change_persists_to_db(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, enabled=False)
        await RuleRepo.enable(db_session, rule.id)
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched.enabled is True

    async def test_disable_change_persists_to_db(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, enabled=True)
        await RuleRepo.disable(db_session, rule.id)
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched.enabled is False

    async def test_enable_returns_none_for_nonexistent(self, db_session: AsyncSession) -> None:
        result = await RuleRepo.enable(db_session, "nonexistent-id")
        assert result is None

    async def test_disable_returns_none_for_nonexistent(self, db_session: AsyncSession) -> None:
        result = await RuleRepo.disable(db_session, "nonexistent-id")
        assert result is None

    async def test_enable_already_enabled_is_idempotent(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, enabled=True)
        result = await RuleRepo.enable(db_session, rule.id)
        assert result.enabled is True

    async def test_disable_already_disabled_is_idempotent(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session, enabled=False)
        result = await RuleRepo.disable(db_session, rule.id)
        assert result.enabled is False


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestRuleRepoDeleteIntegration:
    """RuleRepo.delete() removes the rule from the database."""

    async def test_returns_true_when_deleted(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        result = await RuleRepo.delete(db_session, rule.id)
        assert result is True

    async def test_rule_is_gone_after_delete(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        await RuleRepo.delete(db_session, rule.id)
        fetched = await RuleRepo.get_by_id(db_session, rule.id)
        assert fetched is None

    async def test_returns_false_for_nonexistent(self, db_session: AsyncSession) -> None:
        result = await RuleRepo.delete(db_session, "nonexistent-id")
        assert result is False

    async def test_other_rules_unaffected_by_delete(self, db_session: AsyncSession) -> None:
        rule1 = await _create_rule(db_session, title="Keep Me")
        rule2 = await _create_rule(db_session, title="Delete Me")
        await RuleRepo.delete(db_session, rule2.id)
        remaining = await RuleRepo.list(db_session)
        assert len(remaining) == 1
        assert remaining[0].id == rule1.id

    async def test_double_delete_returns_false(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        await RuleRepo.delete(db_session, rule.id)
        result = await RuleRepo.delete(db_session, rule.id)
        assert result is False


# ---------------------------------------------------------------------------
# count()
# ---------------------------------------------------------------------------


class TestRuleRepoCountIntegration:
    """RuleRepo.count() returns the exact number of rules in the database."""

    async def test_zero_when_empty(self, db_session: AsyncSession) -> None:
        result = await RuleRepo.count(db_session)
        assert result == 0

    async def test_one_after_create(self, db_session: AsyncSession) -> None:
        await _create_rule(db_session)
        result = await RuleRepo.count(db_session)
        assert result == 1

    async def test_count_matches_number_of_rules(self, db_session: AsyncSession) -> None:
        for i in range(5):
            await _create_rule(db_session, title=f"Rule {i}")
        result = await RuleRepo.count(db_session)
        assert result == 5

    async def test_count_decreases_after_delete(self, db_session: AsyncSession) -> None:
        rule = await _create_rule(db_session)
        await _create_rule(db_session, title="Rule 2")
        await RuleRepo.delete(db_session, rule.id)
        result = await RuleRepo.count(db_session)
        assert result == 1

    async def test_returns_integer(self, db_session: AsyncSession) -> None:
        result = await RuleRepo.count(db_session)
        assert isinstance(result, int)

    async def test_count_includes_disabled_rules(self, db_session: AsyncSession) -> None:
        """count() counts all rules regardless of enabled state."""
        await _create_rule(db_session, enabled=True)
        await _create_rule(db_session, enabled=False)
        result = await RuleRepo.count(db_session)
        assert result == 2
