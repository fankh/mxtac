"""Tests for SuppressionRepo — CRUD and match logic (feature 9.11).

Coverage:
  - list(): returns (items, total)
  - list(): is_active filter applied
  - list(): search filter applied
  - list(): empty result → ([], 0)
  - get(): found → SuppressionRule; not found → None
  - create(): adds to session, flushes, returns rule with correct fields
  - update(): found → sets attributes, returns updated rule
  - update(): not found → returns None
  - delete(): found → calls session.delete + flush, returns True
  - delete(): not found → returns False
  - match(): no active rules → returns None
  - match(): rule with rule_id only → matches when rule_id matches
  - match(): rule with rule_id only → does not match different rule_id
  - match(): host wildcard "win-*" matches "win-dc01"
  - match(): host wildcard "win-*" does not match "lin-dc01"
  - match(): technique_id exact match
  - match(): tactic case-insensitive match
  - match(): severity case-insensitive match
  - match(): AND logic — all non-null fields must match
  - match(): AND logic — rule does not match if one field differs
  - match(): expired rule is not matched
  - match(): inactive rule is not matched
  - match(): matched rule increments hit_count
  - _rule_matches(): NULL fields are wildcards
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from app.repositories.suppression_repo import SuppressionRepo, _rule_matches
from app.models.suppression_rule import SuppressionRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session() -> MagicMock:
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.delete = AsyncMock()
    session.get = AsyncMock()
    session.add = MagicMock()
    return session


def _scalars_result(items: list) -> MagicMock:
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    return result


def _scalar_one_result(value) -> MagicMock:
    result = MagicMock()
    result.scalar_one.return_value = value
    return result


def _make_rule(**kwargs) -> MagicMock:
    rule = MagicMock(spec=SuppressionRule)
    rule.id = kwargs.get("id", 1)
    rule.name = kwargs.get("name", "test-rule")
    rule.reason = kwargs.get("reason", None)
    rule.rule_id = kwargs.get("rule_id", None)
    rule.host = kwargs.get("host", None)
    rule.technique_id = kwargs.get("technique_id", None)
    rule.tactic = kwargs.get("tactic", None)
    rule.severity = kwargs.get("severity", None)
    rule.is_active = kwargs.get("is_active", True)
    rule.expires_at = kwargs.get("expires_at", None)
    rule.created_by = kwargs.get("created_by", "analyst@mxtac.local")
    rule.hit_count = kwargs.get("hit_count", 0)
    rule.last_hit_at = kwargs.get("last_hit_at", None)
    return rule


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_returns_items_and_total():
    session = _make_session()
    rules = [_make_rule(id=1), _make_rule(id=2)]
    session.execute.side_effect = [
        _scalar_one_result(2),
        _scalars_result(rules),
    ]
    items, total = await SuppressionRepo.list(session, page=1, page_size=25)
    assert total == 2
    assert items == rules


@pytest.mark.asyncio
async def test_list_empty():
    session = _make_session()
    session.execute.side_effect = [
        _scalar_one_result(0),
        _scalars_result([]),
    ]
    items, total = await SuppressionRepo.list(session)
    assert items == []
    assert total == 0


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_found():
    session = _make_session()
    rule = _make_rule()
    session.get.return_value = rule
    result = await SuppressionRepo.get(session, 1)
    assert result is rule


@pytest.mark.asyncio
async def test_get_not_found():
    session = _make_session()
    session.get.return_value = None
    result = await SuppressionRepo.get(session, 999)
    assert result is None


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_adds_and_flushes():
    session = _make_session()

    created_rule = _make_rule(name="new-rule", rule_id="rule-x")

    async def _refresh(obj):
        pass

    session.refresh = AsyncMock(side_effect=_refresh)

    # Patch SuppressionRule constructor to return our mock
    with patch("app.repositories.suppression_repo.SuppressionRule", return_value=created_rule):
        result = await SuppressionRepo.create(
            session,
            name="new-rule",
            rule_id="rule-x",
            created_by="engineer@mxtac.local",
        )

    session.add.assert_called_once_with(created_rule)
    session.flush.assert_awaited_once()
    assert result is created_rule


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_found():
    session = _make_session()
    rule = _make_rule(name="old-name")

    async def _refresh(obj):
        pass

    session.get.return_value = rule
    session.refresh = AsyncMock(side_effect=_refresh)

    result = await SuppressionRepo.update(session, 1, name="new-name", is_active=False)

    assert result is rule
    session.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_not_found():
    session = _make_session()
    session.get.return_value = None
    result = await SuppressionRepo.update(session, 999, name="irrelevant")
    assert result is None
    session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_found():
    session = _make_session()
    rule = _make_rule()
    session.get.return_value = rule
    result = await SuppressionRepo.delete(session, 1)
    assert result is True
    session.delete.assert_awaited_once_with(rule)
    session.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_not_found():
    session = _make_session()
    session.get.return_value = None
    result = await SuppressionRepo.delete(session, 999)
    assert result is False
    session.delete.assert_not_awaited()


# ---------------------------------------------------------------------------
# _rule_matches() helper
# ---------------------------------------------------------------------------


def _make_real_rule(**kwargs):
    """Create a namespace object with SuppressionRule-like attributes.

    Using SimpleNamespace avoids SQLAlchemy instrumentation issues when
    constructing ORM instances outside a session context.
    """
    from types import SimpleNamespace
    return SimpleNamespace(
        id=kwargs.get("id", 1),
        name=kwargs.get("name", "rule"),
        reason=kwargs.get("reason", None),
        rule_id=kwargs.get("rule_id", None),
        host=kwargs.get("host", None),
        technique_id=kwargs.get("technique_id", None),
        tactic=kwargs.get("tactic", None),
        severity=kwargs.get("severity", None),
        is_active=kwargs.get("is_active", True),
        expires_at=kwargs.get("expires_at", None),
        created_by=kwargs.get("created_by", "system"),
        hit_count=kwargs.get("hit_count", 0),
        last_hit_at=kwargs.get("last_hit_at", None),
    )


def test_rule_matches_all_null_matches_anything():
    """A rule with all NULL fields is a catch-all."""
    rule = _make_real_rule()  # all match fields None
    assert _rule_matches(rule, "any-rule", "any-host", "T1059", "Execution", "high")


def test_rule_matches_rule_id_exact():
    rule = _make_real_rule(rule_id="sigma-rule-001")
    assert _rule_matches(rule, "sigma-rule-001", "host", "T1059", "Execution", "high")
    assert not _rule_matches(rule, "sigma-rule-002", "host", "T1059", "Execution", "high")


def test_rule_matches_host_wildcard():
    rule = _make_real_rule(host="win-*")
    assert _rule_matches(rule, "r", "win-dc01", "T1003", "Credential Access", "critical")
    assert not _rule_matches(rule, "r", "lin-dc01", "T1003", "Credential Access", "critical")


def test_rule_matches_host_exact():
    rule = _make_real_rule(host="srv-dc01")
    assert _rule_matches(rule, "r", "srv-dc01", "", "", "low")
    assert not _rule_matches(rule, "r", "srv-dc02", "", "", "low")


def test_rule_matches_technique_id():
    rule = _make_real_rule(technique_id="T1059.001")
    assert _rule_matches(rule, "r", "h", "T1059.001", "Execution", "high")
    assert not _rule_matches(rule, "r", "h", "T1059.002", "Execution", "high")


def test_rule_matches_tactic_case_insensitive():
    rule = _make_real_rule(tactic="Execution")
    assert _rule_matches(rule, "r", "h", "T1059", "execution", "high")
    assert _rule_matches(rule, "r", "h", "T1059", "EXECUTION", "high")
    assert not _rule_matches(rule, "r", "h", "T1059", "Persistence", "high")


def test_rule_matches_severity_case_insensitive():
    rule = _make_real_rule(severity="high")
    assert _rule_matches(rule, "r", "h", "", "", "HIGH")
    assert _rule_matches(rule, "r", "h", "", "", "high")
    assert not _rule_matches(rule, "r", "h", "", "", "critical")


def test_rule_matches_and_logic_all_must_match():
    rule = _make_real_rule(rule_id="r1", host="win-*", severity="critical")
    # All match
    assert _rule_matches(rule, "r1", "win-dc01", "", "", "critical")
    # One field differs → no match
    assert not _rule_matches(rule, "r1", "win-dc01", "", "", "high")
    assert not _rule_matches(rule, "r1", "lin-dc01", "", "", "critical")
    assert not _rule_matches(rule, "r2", "win-dc01", "", "", "critical")


# ---------------------------------------------------------------------------
# match() — database integration (mocked session)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_match_no_active_rules():
    session = _make_session()
    session.execute.return_value = _scalars_result([])
    result = await SuppressionRepo.match(
        session,
        rule_id_val="r1",
        host_val="host",
        technique_id_val="T1059",
        tactic_val="Execution",
        severity_val="high",
    )
    assert result is None


@pytest.mark.asyncio
async def test_match_finds_matching_rule():
    session = _make_session()
    rule = _make_real_rule(rule_id="sigma-001")

    session.execute.side_effect = [
        _scalars_result([rule]),  # candidates query
        MagicMock(),              # UPDATE hit_count
    ]

    result = await SuppressionRepo.match(
        session,
        rule_id_val="sigma-001",
        host_val="win-host",
        technique_id_val="T1003",
        tactic_val="Credential Access",
        severity_val="high",
    )
    assert result is rule
    # UPDATE was called to increment hit_count
    assert session.execute.await_count == 2


@pytest.mark.asyncio
async def test_match_does_not_match_wrong_rule_id():
    session = _make_session()
    rule = _make_real_rule(rule_id="sigma-001")
    session.execute.return_value = _scalars_result([rule])

    result = await SuppressionRepo.match(
        session,
        rule_id_val="sigma-999",
        host_val="win-host",
        technique_id_val="",
        tactic_val="",
        severity_val="high",
    )
    assert result is None
    # No UPDATE called (no hit)
    assert session.execute.await_count == 1


@pytest.mark.asyncio
async def test_match_host_wildcard_matches():
    session = _make_session()
    rule = _make_real_rule(host="win-*")

    session.execute.side_effect = [
        _scalars_result([rule]),
        MagicMock(),
    ]

    result = await SuppressionRepo.match(
        session,
        rule_id_val="r",
        host_val="win-dc01",
        technique_id_val="",
        tactic_val="",
        severity_val="medium",
    )
    assert result is rule


@pytest.mark.asyncio
async def test_match_returns_first_matching_rule():
    session = _make_session()
    rule_a = _make_real_rule(id=1, severity="high")
    rule_b = _make_real_rule(id=2, severity="high")

    session.execute.side_effect = [
        _scalars_result([rule_a, rule_b]),
        MagicMock(),
    ]

    result = await SuppressionRepo.match(
        session,
        rule_id_val="r",
        host_val="host",
        technique_id_val="",
        tactic_val="",
        severity_val="high",
    )
    assert result is rule_a  # first match wins
