"""Tests for feature 28.19 — Sigma: OR condition — either matches.

Coverage for _Condition._eval_condition() with the `or` keyword:
  - First selection matches, second does not → True
  - Second selection matches, first does not → True
  - Both selections match → True
  - Neither selection matches → False
  - OR condition is case-sensitive keyword (lowercase 'or')
  - Order: `B or A` evaluates same as `A or B`
  - Three-way OR — only first matches → True
  - Three-way OR — only middle matches → True
  - Three-way OR — only last matches → True
  - Three-way OR — all match → True
  - Three-way OR — none match → False
  - OR with NOT: `selection or not filter` — selection matches → True
  - OR with NOT: `selection or not filter` — filter absent (not filter = True) → True
  - OR with NOT: `selection or not filter` — selection fails AND filter matches → False
  - AND has higher precedence than OR: `A and B or C` = `(A and B) or C`
  - `A and B or C` — only C matches → True
  - `A and B or C` — A and B both match, C does not → True
  - `A and B or C` — nothing matches → False
  - `A or B and C` — only A matches → True (A or (B and C))
  - `A or B and C` — only B and C match → True
  - Via load_rule_yaml: rule with `condition: selection1 or selection2` — first matches → True
  - Via load_rule_yaml: rule with `condition: selection1 or selection2` — second matches → True
  - Via load_rule_yaml: rule with `condition: selection1 or selection2` — neither matches → False
  - Via load_rule_yaml: three-way OR — only one matches → True
  - Via load_rule_yaml: three-way OR — none match → False
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
# Basic two-selection OR
# ---------------------------------------------------------------------------

def test_or_first_matches_second_does_not() -> None:
    """First selection matches, second does not → OR is True."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc or sel_args",
    )
    # sel_proc matches (powershell.exe), sel_args does not (-nop not -enc)
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -nop"}) is True


def test_or_second_matches_first_does_not() -> None:
    """Second selection matches, first does not → OR is True."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc or sel_args",
    )
    # sel_proc does not match (cmd.exe), sel_args matches (-enc present)
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd -enc abc"}) is True


def test_or_both_selections_match() -> None:
    """Both selections match → OR is True."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc or sel_args",
    )
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -enc abc"}) is True


def test_or_neither_selection_matches() -> None:
    """Neither selection matches → OR is False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc or sel_args",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd /c whoami"}) is False


# ---------------------------------------------------------------------------
# OR is commutative
# ---------------------------------------------------------------------------

def test_or_reversed_order_first_matches() -> None:
    """`B or A` with B matching gives the same True result as `A or B`."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_args or sel_proc",
    )
    # sel_args is now listed first; sel_proc matches (powershell.exe), sel_args does not
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -nop"}) is True


def test_or_reversed_order_neither_matches() -> None:
    """`B or A` with neither matching → still False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_args or sel_proc",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd /c whoami"}) is False


# ---------------------------------------------------------------------------
# Three-way OR
# ---------------------------------------------------------------------------

def test_or_three_way_only_first_matches() -> None:
    """Only the first selection matches in a three-way OR → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "sel_name or sel_flag or sel_user",
    )
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "guest"}
    assert cond.matches(event) is True


def test_or_three_way_only_middle_matches() -> None:
    """Only the middle selection matches in a three-way OR → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "sel_name or sel_flag or sel_user",
    )
    event = {"name": "cmd.exe", "cmd_line": "run -enc abc", "user": "guest"}
    assert cond.matches(event) is True


def test_or_three_way_only_last_matches() -> None:
    """Only the last selection matches in a three-way OR → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "sel_name or sel_flag or sel_user",
    )
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "admin"}
    assert cond.matches(event) is True


def test_or_three_way_all_match() -> None:
    """All three selections match in a three-way OR → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "sel_name or sel_flag or sel_user",
    )
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "admin"}
    assert cond.matches(event) is True


def test_or_three_way_none_match() -> None:
    """None of the three selections match → False."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "sel_name or sel_flag or sel_user",
    )
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "guest"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# OR with NOT
# ---------------------------------------------------------------------------

def test_or_not_selection_matches() -> None:
    """`selection or not filter` — selection matches → True (OR short-circuits)."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "mimikatz"},
            "filter":    {"user": "svc_scanner"},
        },
        "selection or not filter",
    )
    # selection matches; filter does not match → not filter = True
    event = {"cmd_line": "invoke-mimikatz", "user": "jdoe"}
    assert cond.matches(event) is True


def test_or_not_filter_absent_gives_true() -> None:
    """`selection or not filter` — selection fails but filter does not match → not filter = True → True."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "mimikatz"},
            "filter":    {"user": "svc_scanner"},
        },
        "selection or not filter",
    )
    # selection does not match; filter does not match → not filter = True
    event = {"cmd_line": "benign.exe", "user": "jdoe"}
    assert cond.matches(event) is True


def test_or_not_selection_fails_and_filter_matches() -> None:
    """`selection or not filter` — selection fails, filter matches → not filter = False → False."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "mimikatz"},
            "filter":    {"user": "svc_scanner"},
        },
        "selection or not filter",
    )
    # selection does not match; filter matches → not filter = False; overall False
    event = {"cmd_line": "benign.exe", "user": "svc_scanner"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# AND higher precedence than OR: `A and B or C` = `(A and B) or C`
# ---------------------------------------------------------------------------

def test_or_and_precedence_only_c_matches() -> None:
    """`A and B or C` — only C matches → True (the OR includes C)."""
    cond = _make_condition_multi(
        {
            "selA": {"name": "powershell.exe"},
            "selB": {"cmd_line|contains": "-enc"},
            "selC": {"user": "admin"},
        },
        "selA and selB or selC",
    )
    # selA and selB both fail; selC matches
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "admin"}
    assert cond.matches(event) is True


def test_or_and_precedence_a_and_b_match() -> None:
    """`A and B or C` — A and B both match, C does not → True."""
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


def test_or_and_precedence_nothing_matches() -> None:
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


def test_or_and_precedence_only_a_matches() -> None:
    """`A and B or C` — only A matches (neither B nor C) → False."""
    cond = _make_condition_multi(
        {
            "selA": {"name": "powershell.exe"},
            "selB": {"cmd_line|contains": "-enc"},
            "selC": {"user": "admin"},
        },
        "selA and selB or selC",
    )
    # selA matches but selB does not; selC does not match
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "guest"}
    assert cond.matches(event) is False


def test_or_left_side_only_a_matches() -> None:
    """`A or B and C` — only A matches → True (A is OR'd with (B and C))."""
    cond = _make_condition_multi(
        {
            "selA": {"name": "powershell.exe"},
            "selB": {"cmd_line|contains": "-enc"},
            "selC": {"user": "admin"},
        },
        "selA or selB and selC",
    )
    # selA matches; selB and selC both fail
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "guest"}
    assert cond.matches(event) is True


def test_or_left_side_b_and_c_match() -> None:
    """`A or B and C` — only B and C match → True (B and C is True)."""
    cond = _make_condition_multi(
        {
            "selA": {"name": "powershell.exe"},
            "selB": {"cmd_line|contains": "-enc"},
            "selC": {"user": "admin"},
        },
        "selA or selB and selC",
    )
    # selA fails; selB and selC both match
    event = {"name": "cmd.exe", "cmd_line": "cmd -enc abc", "user": "admin"}
    assert cond.matches(event) is True


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_OR_TWO = """\
title: Detect PowerShell OR Encoded Flag
id: test-or-001
status: test
level: high
logsource:
  category: process_creation
detection:
  sel_name:
    name: powershell.exe
  sel_flag:
    cmd_line|contains: '-enc'
  condition: sel_name or sel_flag
"""

_RULE_OR_THREE = """\
title: Suspicious Process Trio
id: test-or-002
status: test
level: medium
logsource:
  category: process_creation
detection:
  sel_ps:
    name: powershell.exe
  sel_mimi:
    cmd_line|contains: mimikatz
  sel_sys:
    user: SYSTEM
  condition: sel_ps or sel_mimi or sel_sys
"""

_RULE_OR_NOT = """\
title: Suspicious Activity Unless Known Scanner
id: test-or-003
status: test
level: low
logsource:
  category: process_creation
detection:
  selection:
    cmd_line|startswith: 'nmap'
  filter:
    user: 'svc_netscan'
  condition: selection or not filter
"""


def test_rule_or_first_matches(engine: SigmaEngine) -> None:
    """Rule with `condition: A or B` — first selection matches → True."""
    rule = engine.load_rule_yaml(_RULE_OR_TWO)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop"}
    assert rule._matcher.matches(event) is True


def test_rule_or_second_matches(engine: SigmaEngine) -> None:
    """Rule with `condition: A or B` — second selection matches → True."""
    rule = engine.load_rule_yaml(_RULE_OR_TWO)
    assert rule is not None
    event = {"name": "cmd.exe", "cmd_line": "cmd -enc abc"}
    assert rule._matcher.matches(event) is True


def test_rule_or_both_match(engine: SigmaEngine) -> None:
    """Rule with `condition: A or B` — both match → True."""
    rule = engine.load_rule_yaml(_RULE_OR_TWO)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc"}
    assert rule._matcher.matches(event) is True


def test_rule_or_neither_matches(engine: SigmaEngine) -> None:
    """Rule with `condition: A or B` — neither matches → False."""
    rule = engine.load_rule_yaml(_RULE_OR_TWO)
    assert rule is not None
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami"}
    assert rule._matcher.matches(event) is False


def test_rule_three_way_or_one_matches(engine: SigmaEngine) -> None:
    """Three-way OR rule — only one selection matches → True."""
    rule = engine.load_rule_yaml(_RULE_OR_THREE)
    assert rule is not None
    # Only sel_sys matches (user is SYSTEM)
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "SYSTEM"}
    assert rule._matcher.matches(event) is True


def test_rule_three_way_or_none_match(engine: SigmaEngine) -> None:
    """Three-way OR rule — no selection matches → False."""
    rule = engine.load_rule_yaml(_RULE_OR_THREE)
    assert rule is not None
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "jdoe"}
    assert rule._matcher.matches(event) is False


def test_rule_or_not_selection_matches(engine: SigmaEngine) -> None:
    """Rule `selection or not filter` — selection matches, filter does not → True."""
    rule = engine.load_rule_yaml(_RULE_OR_NOT)
    assert rule is not None
    event = {"cmd_line": "nmap -sV 10.0.0.1", "user": "attacker"}
    assert rule._matcher.matches(event) is True


def test_rule_or_not_filter_absent(engine: SigmaEngine) -> None:
    """Rule `selection or not filter` — selection fails, filter does not match → not filter = True → True."""
    rule = engine.load_rule_yaml(_RULE_OR_NOT)
    assert rule is not None
    # selection fails; filter does not match → not filter = True
    event = {"cmd_line": "curl http://example.com", "user": "jdoe"}
    assert rule._matcher.matches(event) is True


def test_rule_or_not_filter_matches_suppresses(engine: SigmaEngine) -> None:
    """Rule `selection or not filter` — selection fails, filter matches → False."""
    rule = engine.load_rule_yaml(_RULE_OR_NOT)
    assert rule is not None
    # selection fails; filter matches → not filter = False → overall False
    event = {"cmd_line": "curl http://example.com", "user": "svc_netscan"}
    assert rule._matcher.matches(event) is False
