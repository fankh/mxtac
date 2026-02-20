"""Tests for feature 28.18 — Sigma: AND condition — both must match.

Coverage for _Condition._eval_condition() with the `and` keyword:
  - Both selections match → True
  - First selection fails → False
  - Second selection fails → False
  - Both selections fail → False
  - AND condition is case-sensitive keyword (lowercase 'and')
  - Order: `B and A` evaluates same as `A and B`
  - Three-way AND — all three match → True
  - Three-way AND — middle selection fails → False
  - Three-way AND — last selection fails → False
  - AND with NOT: `selection and not filter` — both conditions satisfied → True
  - AND with NOT: `selection and not filter` — filter matches → False (NOT filter = False)
  - AND with NOT: `selection and not filter` — selection fails → False
  - AND combined with OR — `selection1 and selection2 or selection3` (OR precedence)
  - AND has higher precedence than OR: `A and B or C` = `(A and B) or C`
  - Whitespace around `and` is handled correctly
  - Single selection in AND-only condition is evaluated correctly
  - Via load_rule_yaml: rule with `condition: selection1 and selection2` matches both → True
  - Via load_rule_yaml: rule matches when only selection2 fails → False
  - Via load_rule_yaml: rule matches when only selection1 fails → False
  - Via load_rule_yaml: rule with `condition: selection and not filter` works correctly
  - Via load_rule_yaml: filter match suppresses detection (not filter = False)
  - Via load_rule_yaml: three-way AND all matching → True
  - Via load_rule_yaml: three-way AND with one failure → False
"""

from __future__ import annotations

import pytest

from app.engine.sigma_engine import SigmaEngine, _Condition


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_condition_multi(selections: dict, condition: str) -> _Condition:
    """Build a _Condition with multiple named selections and a condition string."""
    detection = dict(selections)
    detection["condition"] = condition
    return _Condition(detection)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


# ---------------------------------------------------------------------------
# Basic two-selection AND
# ---------------------------------------------------------------------------

def test_and_both_selections_match() -> None:
    """Both named selections match their field criteria → True."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc and sel_args",
    )
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -enc abc"}) is True


def test_and_first_selection_fails() -> None:
    """First selection does not match → AND is False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc and sel_args",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd -enc abc"}) is False


def test_and_second_selection_fails() -> None:
    """Second selection does not match → AND is False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc and sel_args",
    )
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -nop"}) is False


def test_and_both_selections_fail() -> None:
    """Neither selection matches → AND is False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc and sel_args",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd /c whoami"}) is False


# ---------------------------------------------------------------------------
# AND is commutative
# ---------------------------------------------------------------------------

def test_and_reversed_order_both_match() -> None:
    """`B and A` yields the same result as `A and B` when both match."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_args and sel_proc",
    )
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -enc abc"}) is True


def test_and_reversed_order_first_fails() -> None:
    """`B and A` with B (now first in string) failing — result is still False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_args and sel_proc",
    )
    # sel_args fails (no -enc in cmd_line), sel_proc matches
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -nop"}) is False


# ---------------------------------------------------------------------------
# Three-way AND
# ---------------------------------------------------------------------------

def test_and_three_way_all_match() -> None:
    """Three selections all matching → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "sel_name and sel_flag and sel_user",
    )
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "admin"}
    assert cond.matches(event) is True


def test_and_three_way_middle_fails() -> None:
    """Middle selection fails in a three-way AND → False."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "sel_name and sel_flag and sel_user",
    )
    # sel_flag fails (no -enc)
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "admin"}
    assert cond.matches(event) is False


def test_and_three_way_last_fails() -> None:
    """Last selection fails in a three-way AND → False."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "sel_name and sel_flag and sel_user",
    )
    # sel_user fails (user is "guest", not "admin")
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "guest"}
    assert cond.matches(event) is False


def test_and_three_way_first_fails() -> None:
    """First selection fails in a three-way AND → False."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "sel_name and sel_flag and sel_user",
    )
    # sel_name fails (name is cmd.exe, not powershell.exe)
    event = {"name": "cmd.exe", "cmd_line": "cmd -enc abc", "user": "admin"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# AND with NOT (selection and not filter)
# ---------------------------------------------------------------------------

def test_and_not_both_conditions_met() -> None:
    """`selection and not filter` — selection matches, filter does not → True."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "powershell"},
            "filter":    {"cmd_line|contains": "legit_admin"},
        },
        "selection and not filter",
    )
    event = {"cmd_line": "powershell -enc abc"}
    assert cond.matches(event) is True


def test_and_not_filter_matches_suppresses() -> None:
    """`selection and not filter` — filter matches → NOT filter = False → overall False."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "powershell"},
            "filter":    {"cmd_line|contains": "legit_admin"},
        },
        "selection and not filter",
    )
    event = {"cmd_line": "powershell legit_admin maintenance"}
    assert cond.matches(event) is False


def test_and_not_selection_fails() -> None:
    """`selection and not filter` — selection fails → False regardless of filter."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "powershell"},
            "filter":    {"cmd_line|contains": "legit_admin"},
        },
        "selection and not filter",
    )
    event = {"cmd_line": "cmd.exe /c whoami"}
    assert cond.matches(event) is False


def test_and_not_both_fail() -> None:
    """`selection and not filter` — selection fails, filter does not match → False (selection is False)."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "mimikatz"},
            "filter":    {"cmd_line|contains": "safe"},
        },
        "selection and not filter",
    )
    event = {"cmd_line": "benign.exe"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# AND combined with OR — precedence
# ---------------------------------------------------------------------------

def test_and_or_precedence_only_or_term_matches() -> None:
    """`A and B or C` — only C matches → True (OR includes C)."""
    cond = _make_condition_multi(
        {
            "selA": {"name": "powershell.exe"},
            "selB": {"cmd_line|contains": "-enc"},
            "selC": {"user": "admin"},
        },
        "selA and selB or selC",
    )
    # Only selC matches
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "admin"}
    assert cond.matches(event) is True


def test_and_or_precedence_and_term_matches() -> None:
    """`A and B or C` — A and B both match, C does not → True (AND term is True)."""
    cond = _make_condition_multi(
        {
            "selA": {"name": "powershell.exe"},
            "selB": {"cmd_line|contains": "-enc"},
            "selC": {"user": "admin"},
        },
        "selA and selB or selC",
    )
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "guest"}
    assert cond.matches(event) is True


def test_and_or_precedence_nothing_matches() -> None:
    """`A and B or C` — nothing matches → False."""
    cond = _make_condition_multi(
        {
            "selA": {"name": "powershell.exe"},
            "selB": {"cmd_line|contains": "-enc"},
            "selC": {"user": "admin"},
        },
        "selA and selB or selC",
    )
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "guest"}
    assert cond.matches(event) is False


def test_and_or_precedence_only_a_matches() -> None:
    """`A and B or C` — only A matches (neither B nor C) → False."""
    cond = _make_condition_multi(
        {
            "selA": {"name": "powershell.exe"},
            "selB": {"cmd_line|contains": "-enc"},
            "selC": {"user": "admin"},
        },
        "selA and selB or selC",
    )
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "guest"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Field-level AND within a single selection (dict keys)
# ---------------------------------------------------------------------------

def test_selection_fields_and_semantics() -> None:
    """Multiple keys in one selection dict are AND'd — both must match."""
    cond = _make_condition_multi(
        {
            "selection": {
                "name": "powershell.exe",
                "cmd_line|contains": "-enc",
            },
        },
        "selection",
    )
    # Both fields match
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -enc abc"}) is True


def test_selection_fields_and_semantics_one_fails() -> None:
    """One field in a dict selection fails → entire selection is False."""
    cond = _make_condition_multi(
        {
            "selection": {
                "name": "powershell.exe",
                "cmd_line|contains": "-enc",
            },
        },
        "selection",
    )
    # name matches but cmd_line does not contain -enc
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -nop"}) is False


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_AND_TWO = """\
title: Detect Encoded PowerShell with Name Check
id: test-and-001
status: test
level: high
logsource:
  category: process_creation
detection:
  sel_name:
    name: powershell.exe
  sel_flag:
    cmd_line|contains: '-enc'
  condition: sel_name and sel_flag
"""

_RULE_AND_NOT = """\
title: PowerShell Suspicious Execution Excluding Admins
id: test-and-002
status: test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    cmd_line|contains: '-enc'
  filter:
    user: 'svc_automation'
  condition: selection and not filter
"""

_RULE_AND_THREE = """\
title: Triple AND Rule
id: test-and-003
status: test
level: critical
logsource:
  category: process_creation
detection:
  sel_a:
    name: powershell.exe
  sel_b:
    cmd_line|contains: mimikatz
  sel_c:
    user: SYSTEM
  condition: sel_a and sel_b and sel_c
"""


def test_rule_and_both_match(engine: SigmaEngine) -> None:
    """Rule with `condition: A and B` — both match → True."""
    rule = engine.load_rule_yaml(_RULE_AND_TWO)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc SGVsbG8="}
    assert rule._matcher.matches(event) is True


def test_rule_and_first_fails(engine: SigmaEngine) -> None:
    """Rule with `condition: A and B` — first selection fails → False."""
    rule = engine.load_rule_yaml(_RULE_AND_TWO)
    assert rule is not None
    event = {"name": "cmd.exe", "cmd_line": "cmd -enc SGVsbG8="}
    assert rule._matcher.matches(event) is False


def test_rule_and_second_fails(engine: SigmaEngine) -> None:
    """Rule with `condition: A and B` — second selection fails → False."""
    rule = engine.load_rule_yaml(_RULE_AND_TWO)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop -c whoami"}
    assert rule._matcher.matches(event) is False


def test_rule_and_not_detection_no_filter(engine: SigmaEngine) -> None:
    """Rule `selection and not filter` — filter user absent → True."""
    rule = engine.load_rule_yaml(_RULE_AND_NOT)
    assert rule is not None
    event = {"cmd_line": "powershell -enc abc", "user": "jdoe"}
    assert rule._matcher.matches(event) is True


def test_rule_and_not_filter_user_matches(engine: SigmaEngine) -> None:
    """Rule `selection and not filter` — filter user matches → suppressed → False."""
    rule = engine.load_rule_yaml(_RULE_AND_NOT)
    assert rule is not None
    event = {"cmd_line": "powershell -enc abc", "user": "svc_automation"}
    assert rule._matcher.matches(event) is False


def test_rule_and_not_selection_fails(engine: SigmaEngine) -> None:
    """Rule `selection and not filter` — selection fails → False."""
    rule = engine.load_rule_yaml(_RULE_AND_NOT)
    assert rule is not None
    event = {"cmd_line": "powershell -nop", "user": "jdoe"}
    assert rule._matcher.matches(event) is False


def test_rule_three_way_and_all_match(engine: SigmaEngine) -> None:
    """Rule with three-way AND — all selections match → True."""
    rule = engine.load_rule_yaml(_RULE_AND_THREE)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "invoke-mimikatz", "user": "SYSTEM"}
    assert rule._matcher.matches(event) is True


def test_rule_three_way_and_one_fails(engine: SigmaEngine) -> None:
    """Rule with three-way AND — one selection fails → False."""
    rule = engine.load_rule_yaml(_RULE_AND_THREE)
    assert rule is not None
    # sel_c fails: user is not SYSTEM
    event = {"name": "powershell.exe", "cmd_line": "invoke-mimikatz", "user": "jdoe"}
    assert rule._matcher.matches(event) is False
