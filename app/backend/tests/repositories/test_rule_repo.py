"""Tests for RuleRepo — async DB operations for the rules table.

Feature 18.4 — Alembic migration 0002 (rules + connectors)

Approach:
  - All session interactions are mocked (no live DB needed)
  - AsyncMock used for awaitable session methods (execute, flush, scalar)
  - MagicMock used for synchronous session methods (add)
  - get_by_id is patched internally for methods that call it (update, enable, disable, delete)

Coverage:
  - list(): returns all rules, session.execute called once
  - list(enabled=True/False): filter applied, result still returned correctly
  - list(level=...): level filter applied
  - list(enabled + level): both filters combined
  - list(): empty result returns empty list
  - get_by_id(): found → returns Rule; not found → returns None
  - create(): Rule added to session, flushed, returned
  - update(): found → sets attributes, flushes, returns Rule
  - update(): not found → returns None without flush
  - update(): None kwarg values are skipped
  - enable(): delegates to update with enabled=True
  - disable(): delegates to update with enabled=False
  - delete(): found → deletes, flushes, returns True
  - delete(): not found → returns False without delete/flush
  - count(): returns scalar result; None result → 0
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.repositories.rule_repo import RuleRepo


# ---------------------------------------------------------------------------
# Session factory helpers
# ---------------------------------------------------------------------------


def _make_session() -> MagicMock:
    """Sync MagicMock for the session with async methods patched."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.delete = AsyncMock()
    session.scalar = AsyncMock()
    return session


def _scalars_result(items: list) -> MagicMock:
    """Result mock whose .scalars().all() returns items."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    return result


def _scalar_one_result(item) -> MagicMock:
    """Result mock whose .scalar_one_or_none() returns item."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = item
    return result


def _make_rule(**kwargs) -> MagicMock:
    """Minimal Rule-like mock."""
    rule = MagicMock()
    rule.id = kwargs.get("id", "rule-abc")
    rule.title = kwargs.get("title", "Test Rule")
    rule.level = kwargs.get("level", "medium")
    rule.enabled = kwargs.get("enabled", True)
    rule.status = kwargs.get("status", "experimental")
    return rule


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


class TestRuleRepoList:
    """RuleRepo.list() returns rules from session.execute."""

    @pytest.mark.asyncio
    async def test_returns_all_rules_when_no_filter(self) -> None:
        rule1 = _make_rule(id="r1")
        rule2 = _make_rule(id="r2")
        session = _make_session()
        session.execute.return_value = _scalars_result([rule1, rule2])

        result = await RuleRepo.list(session)

        assert result == [rule1, rule2]

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        await RuleRepo.list(session)

        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_rules(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        result = await RuleRepo.list(session)

        assert result == []

    @pytest.mark.asyncio
    async def test_result_is_list_type(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([_make_rule()])

        result = await RuleRepo.list(session)

        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_list_with_enabled_true_calls_execute(self) -> None:
        rule = _make_rule(enabled=True)
        session = _make_session()
        session.execute.return_value = _scalars_result([rule])

        result = await RuleRepo.list(session, enabled=True)

        session.execute.assert_awaited_once()
        assert result == [rule]

    @pytest.mark.asyncio
    async def test_list_with_enabled_false_calls_execute(self) -> None:
        rule = _make_rule(enabled=False)
        session = _make_session()
        session.execute.return_value = _scalars_result([rule])

        result = await RuleRepo.list(session, enabled=False)

        session.execute.assert_awaited_once()
        assert result == [rule]

    @pytest.mark.asyncio
    async def test_list_with_level_filter_calls_execute(self) -> None:
        rule = _make_rule(level="high")
        session = _make_session()
        session.execute.return_value = _scalars_result([rule])

        result = await RuleRepo.list(session, level="high")

        session.execute.assert_awaited_once()
        assert result == [rule]

    @pytest.mark.asyncio
    async def test_list_with_enabled_and_level_calls_execute(self) -> None:
        rule = _make_rule(enabled=True, level="critical")
        session = _make_session()
        session.execute.return_value = _scalars_result([rule])

        result = await RuleRepo.list(session, enabled=True, level="critical")

        session.execute.assert_awaited_once()
        assert result == [rule]

    @pytest.mark.asyncio
    async def test_list_returns_multiple_rules(self) -> None:
        rules = [_make_rule(id=f"r{i}") for i in range(5)]
        session = _make_session()
        session.execute.return_value = _scalars_result(rules)

        result = await RuleRepo.list(session)

        assert len(result) == 5


# ---------------------------------------------------------------------------
# get_by_id()
# ---------------------------------------------------------------------------


class TestRuleRepoGetById:
    """RuleRepo.get_by_id() returns a Rule or None."""

    @pytest.mark.asyncio
    async def test_returns_rule_when_found(self) -> None:
        rule = _make_rule(id="rule-1")
        session = _make_session()
        session.execute.return_value = _scalar_one_result(rule)

        result = await RuleRepo.get_by_id(session, "rule-1")

        assert result is rule

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await RuleRepo.get_by_id(session, "nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await RuleRepo.get_by_id(session, "rule-1")

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


class TestRuleRepoCreate:
    """RuleRepo.create() constructs and persists a Rule."""

    @pytest.mark.asyncio
    async def test_returns_rule_instance(self) -> None:
        session = _make_session()

        result = await RuleRepo.create(
            session,
            id="rule-new",
            title="New Sigma Rule",
            content="detection:\n  condition: all of them",
            level="high",
        )

        assert result is not None

    @pytest.mark.asyncio
    async def test_calls_session_add(self) -> None:
        session = _make_session()

        await RuleRepo.create(session, title="Test Rule", content="yaml")

        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_calls_session_flush(self) -> None:
        session = _make_session()

        await RuleRepo.create(session, title="Test Rule", content="yaml")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_created_rule_has_correct_title(self) -> None:
        session = _make_session()

        result = await RuleRepo.create(
            session,
            title="PowerShell Suspicious Download",
            content="yaml",
            level="high",
        )

        assert result.title == "PowerShell Suspicious Download"

    @pytest.mark.asyncio
    async def test_created_rule_has_correct_level(self) -> None:
        session = _make_session()

        result = await RuleRepo.create(session, title="Rule", content="yaml", level="critical")

        assert result.level == "critical"

    @pytest.mark.asyncio
    async def test_created_rule_default_enabled_is_true(self) -> None:
        session = _make_session()

        result = await RuleRepo.create(session, title="Rule", content="yaml")

        # ORM default is True
        assert result.enabled is True

    @pytest.mark.asyncio
    async def test_add_receives_rule_object(self) -> None:
        from app.models.rule import Rule
        session = _make_session()

        await RuleRepo.create(session, title="Test", content="yaml")

        added = session.add.call_args[0][0]
        assert isinstance(added, Rule)


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestRuleRepoUpdate:
    """RuleRepo.update() modifies an existing Rule or returns None."""

    @pytest.mark.asyncio
    async def test_returns_updated_rule_when_found(self) -> None:
        rule = _make_rule(id="rule-1", title="Old Title")
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            result = await RuleRepo.update(session, "rule-1", title="New Title")

        assert result is rule

    @pytest.mark.asyncio
    async def test_sets_attribute_on_rule(self) -> None:
        rule = MagicMock()
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            await RuleRepo.update(session, "rule-1", title="Updated Title", level="high")

        assert rule.title == "Updated Title"
        assert rule.level == "high"

    @pytest.mark.asyncio
    async def test_skips_none_kwarg_values(self) -> None:
        rule = MagicMock()
        rule.title = "Original Title"
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            await RuleRepo.update(session, "rule-1", title=None, level="high")

        # None values must not overwrite the attribute
        assert rule.title == "Original Title"
        assert rule.level == "high"

    @pytest.mark.asyncio
    async def test_flushes_session_when_found(self) -> None:
        rule = _make_rule()
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            await RuleRepo.update(session, "rule-1", title="Updated")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await RuleRepo.update(session, "nonexistent", title="Whatever")

        assert result is None

    @pytest.mark.asyncio
    async def test_does_not_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await RuleRepo.update(session, "nonexistent", title="Whatever")

        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_false_value_is_not_skipped(self) -> None:
        """False is not None — it must be set, not skipped."""
        rule = MagicMock()
        rule.enabled = True
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            await RuleRepo.update(session, "rule-1", enabled=False)

        assert rule.enabled is False


# ---------------------------------------------------------------------------
# enable() / disable()
# ---------------------------------------------------------------------------


class TestRuleRepoEnableDisable:
    """RuleRepo.enable() and disable() delegate to update()."""

    @pytest.mark.asyncio
    async def test_enable_sets_enabled_true(self) -> None:
        rule = MagicMock()
        rule.enabled = False
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            result = await RuleRepo.enable(session, "rule-1")

        assert result is rule
        assert rule.enabled is True

    @pytest.mark.asyncio
    async def test_disable_sets_enabled_false(self) -> None:
        rule = MagicMock()
        rule.enabled = True
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            result = await RuleRepo.disable(session, "rule-1")

        assert result is rule
        assert rule.enabled is False

    @pytest.mark.asyncio
    async def test_enable_returns_none_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await RuleRepo.enable(session, "nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_disable_returns_none_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await RuleRepo.disable(session, "nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_enable_flushes_session(self) -> None:
        rule = _make_rule()
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            await RuleRepo.enable(session, "rule-1")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_disable_flushes_session(self) -> None:
        rule = _make_rule()
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            await RuleRepo.disable(session, "rule-1")

        session.flush.assert_awaited_once()


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestRuleRepoDelete:
    """RuleRepo.delete() removes an existing Rule or returns False."""

    @pytest.mark.asyncio
    async def test_returns_true_when_found(self) -> None:
        rule = _make_rule()
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            result = await RuleRepo.delete(session, "rule-1")

        assert result is True

    @pytest.mark.asyncio
    async def test_calls_session_delete_when_found(self) -> None:
        rule = _make_rule()
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            await RuleRepo.delete(session, "rule-1")

        session.delete.assert_awaited_once_with(rule)

    @pytest.mark.asyncio
    async def test_calls_session_flush_when_found(self) -> None:
        rule = _make_rule()
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=rule)):
            await RuleRepo.delete(session, "rule-1")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await RuleRepo.delete(session, "nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_no_session_delete_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await RuleRepo.delete(session, "nonexistent")

        session.delete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(RuleRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await RuleRepo.delete(session, "nonexistent")

        session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# count()
# ---------------------------------------------------------------------------


class TestRuleRepoCount:
    """RuleRepo.count() returns total rule count."""

    @pytest.mark.asyncio
    async def test_returns_count_from_scalar(self) -> None:
        session = _make_session()
        session.scalar.return_value = 42

        result = await RuleRepo.count(session)

        assert result == 42

    @pytest.mark.asyncio
    async def test_returns_zero_when_scalar_is_none(self) -> None:
        """None result from scalar (empty table) maps to 0."""
        session = _make_session()
        session.scalar.return_value = None

        result = await RuleRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_returns_zero_when_table_is_empty(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0

        result = await RuleRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_calls_session_scalar_once(self) -> None:
        session = _make_session()
        session.scalar.return_value = 5

        await RuleRepo.count(session)

        session.scalar.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_integer(self) -> None:
        session = _make_session()
        session.scalar.return_value = 7

        result = await RuleRepo.count(session)

        assert isinstance(result, int)

    @pytest.mark.parametrize("count_val", [0, 1, 100, 999])
    @pytest.mark.asyncio
    async def test_returns_exact_count(self, count_val: int) -> None:
        session = _make_session()
        session.scalar.return_value = count_val

        result = await RuleRepo.count(session)

        assert result == count_val
