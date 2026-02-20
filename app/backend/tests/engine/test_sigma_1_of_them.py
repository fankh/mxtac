"""Tests for feature 28.21 — Sigma: `1 of them` across selections.

Coverage for _Condition._eval_condition() with the `1 of them` keyword:
  - `1 of them` — first selection matches, second does not → True
  - `1 of them` — second selection matches, first does not → True
  - `1 of them` — both selections match → True
  - `1 of them` — neither selection matches → False
  - `1 of them` — three selections, only one matches → True
  - `1 of them` — three selections, none match → False
  - `1 of them` — three selections, all match → True
  - `1 of them` — single selection matches → True
  - `1 of them` — single selection does not match → False
  - `1 of them` with field modifiers (contains): matching → True
  - `1 of them` with field modifiers (contains): not matching → False
  - `1 of selection*` wildcard — matching-pattern selection matches → True
  - `1 of selection*` wildcard — matching-pattern selection does not match → False
  - `1 of selection*` wildcard — non-matching selection name excluded from consideration → False
  - `1 of filter*` wildcard — only filter selections considered → True when one filter matches
  - `all of them` — all selections match → True
  - `all of them` — one selection fails → False
  - `all of them` — no selections match → False
  - `all of them` — single selection matches → True
  - `all of them` — single selection does not match → False
  - `all of selection*` wildcard — all pattern-matching selections match → True
  - `all of selection*` wildcard — one pattern-matching selection fails → False
  - `all of selection*` wildcard — non-matching-pattern selection excluded → True (only matching evaluated)
  - Via load_rule_yaml: `condition: 1 of them` — one selection matches → True
  - Via load_rule_yaml: `condition: 1 of them` — none match → False
  - Via load_rule_yaml: `condition: 1 of them` — all match → True
  - Via load_rule_yaml: `condition: 1 of selection*` — wildcard pattern, matching selection fires → True
  - Via load_rule_yaml: `condition: 1 of selection*` — none of the pattern selections match → False
  - Via load_rule_yaml: `condition: all of them` — all match → True
  - Via load_rule_yaml: `condition: all of them` — one fails → False
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
# `1 of them` — two selections
# ---------------------------------------------------------------------------

def test_1_of_them_first_matches_second_does_not() -> None:
    """`1 of them` — first selection matches, second does not → True."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "1 of them",
    )
    # sel_proc matches (powershell.exe present), sel_args does not (-nop, not -enc)
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -nop"}) is True


def test_1_of_them_second_matches_first_does_not() -> None:
    """`1 of them` — second selection matches, first does not → True."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "1 of them",
    )
    # sel_proc fails (cmd.exe), sel_args matches (-enc present)
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd -enc abc"}) is True


def test_1_of_them_both_selections_match() -> None:
    """`1 of them` — both selections match → True."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "1 of them",
    )
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -enc abc"}) is True


def test_1_of_them_neither_selection_matches() -> None:
    """`1 of them` — neither selection matches → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "1 of them",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd /c whoami"}) is False


# ---------------------------------------------------------------------------
# `1 of them` — three selections
# ---------------------------------------------------------------------------

def test_1_of_them_three_only_first_matches() -> None:
    """`1 of them` — three selections, only first matches → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "1 of them",
    )
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "guest"}
    assert cond.matches(event) is True


def test_1_of_them_three_only_middle_matches() -> None:
    """`1 of them` — three selections, only middle matches → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "1 of them",
    )
    event = {"name": "cmd.exe", "cmd_line": "run -enc abc", "user": "guest"}
    assert cond.matches(event) is True


def test_1_of_them_three_only_last_matches() -> None:
    """`1 of them` — three selections, only last matches → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "1 of them",
    )
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "admin"}
    assert cond.matches(event) is True


def test_1_of_them_three_none_match() -> None:
    """`1 of them` — three selections, none match → False."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "1 of them",
    )
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "guest"}
    assert cond.matches(event) is False


def test_1_of_them_three_all_match() -> None:
    """`1 of them` — three selections, all match → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "1 of them",
    )
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "admin"}
    assert cond.matches(event) is True


# ---------------------------------------------------------------------------
# `1 of them` — single selection
# ---------------------------------------------------------------------------

def test_1_of_them_single_selection_matches() -> None:
    """`1 of them` — single selection matches → True."""
    cond = _make_condition_multi(
        {"selection": {"name": "mimikatz.exe"}},
        "1 of them",
    )
    assert cond.matches({"name": "mimikatz.exe"}) is True


def test_1_of_them_single_selection_does_not_match() -> None:
    """`1 of them` — single selection does not match → False."""
    cond = _make_condition_multi(
        {"selection": {"name": "mimikatz.exe"}},
        "1 of them",
    )
    assert cond.matches({"name": "cmd.exe"}) is False


# ---------------------------------------------------------------------------
# `1 of them` with field modifiers
# ---------------------------------------------------------------------------

def test_1_of_them_contains_modifier_matches() -> None:
    """`1 of them` with `contains` modifier — matching selection → True."""
    cond = _make_condition_multi(
        {
            "sel_cmd": {"cmd_line|contains": "mimikatz"},
            "sel_net": {"dst_ip": "10.0.0.1"},
        },
        "1 of them",
    )
    # sel_cmd matches (mimikatz in cmd_line), sel_net does not
    assert cond.matches({"cmd_line": "invoke-mimikatz", "dst_ip": "192.168.1.1"}) is True


def test_1_of_them_contains_modifier_no_match() -> None:
    """`1 of them` with `contains` modifier — no selection matches → False."""
    cond = _make_condition_multi(
        {
            "sel_cmd": {"cmd_line|contains": "mimikatz"},
            "sel_net": {"dst_ip": "10.0.0.1"},
        },
        "1 of them",
    )
    assert cond.matches({"cmd_line": "benign.exe", "dst_ip": "192.168.1.1"}) is False


# ---------------------------------------------------------------------------
# `1 of selection*` — wildcard pattern
# ---------------------------------------------------------------------------

def test_1_of_pattern_matching_selection_fires() -> None:
    """`1 of selection*` — a selection whose name matches the pattern fires → True."""
    cond = _make_condition_multi(
        {
            "selection_proc": {"name": "powershell.exe"},
            "selection_flag": {"cmd_line|contains": "-enc"},
            "filter": {"user": "svc_av"},
        },
        "1 of selection*",
    )
    # selection_proc matches; filter is excluded by the pattern
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "svc_av"}
    assert cond.matches(event) is True


def test_1_of_pattern_no_matching_selection_fires() -> None:
    """`1 of selection*` — none of the pattern-matching selections fire → False."""
    cond = _make_condition_multi(
        {
            "selection_proc": {"name": "powershell.exe"},
            "selection_flag": {"cmd_line|contains": "-enc"},
            "filter": {"user": "svc_av"},
        },
        "1 of selection*",
    )
    # Neither selection_proc nor selection_flag match; filter is not considered
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "svc_av"}
    assert cond.matches(event) is False


def test_1_of_pattern_non_pattern_selection_excluded() -> None:
    """`1 of selection*` — filter selection excluded; only selection_* names are evaluated."""
    cond = _make_condition_multi(
        {
            "selection_main": {"name": "powershell.exe"},
            "filter": {"user": "svc_av"},
        },
        "1 of selection*",
    )
    # filter matches but is excluded from the pattern — only selection_main counts
    # selection_main does NOT match (name is cmd.exe) → False
    event = {"name": "cmd.exe", "user": "svc_av"}
    assert cond.matches(event) is False


def test_1_of_filter_pattern_matches_filter_selection() -> None:
    """`1 of filter*` — only filter* selections are evaluated → True when one fires."""
    cond = _make_condition_multi(
        {
            "selection": {"name": "powershell.exe"},
            "filter_user": {"user": "svc_av"},
            "filter_proc": {"name": "svchost.exe"},
        },
        "1 of filter*",
    )
    # filter_user matches (user = svc_av); selection is excluded from the pattern
    event = {"name": "powershell.exe", "user": "svc_av"}
    assert cond.matches(event) is True


# ---------------------------------------------------------------------------
# `all of them`
# ---------------------------------------------------------------------------

def test_all_of_them_both_selections_match() -> None:
    """`all of them` — both selections match → True."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "all of them",
    )
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -enc abc"}) is True


def test_all_of_them_first_selection_fails() -> None:
    """`all of them` — first selection fails → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "all of them",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd -enc abc"}) is False


def test_all_of_them_second_selection_fails() -> None:
    """`all of them` — second selection fails → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "all of them",
    )
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -nop"}) is False


def test_all_of_them_neither_matches() -> None:
    """`all of them` — neither selection matches → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "all of them",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd /c whoami"}) is False


def test_all_of_them_single_selection_matches() -> None:
    """`all of them` — single selection matches → True."""
    cond = _make_condition_multi(
        {"selection": {"name": "mimikatz.exe"}},
        "all of them",
    )
    assert cond.matches({"name": "mimikatz.exe"}) is True


def test_all_of_them_single_selection_fails() -> None:
    """`all of them` — single selection does not match → False."""
    cond = _make_condition_multi(
        {"selection": {"name": "mimikatz.exe"}},
        "all of them",
    )
    assert cond.matches({"name": "cmd.exe"}) is False


def test_all_of_them_three_all_match() -> None:
    """`all of them` — three selections all match → True."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "all of them",
    )
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "admin"}
    assert cond.matches(event) is True


def test_all_of_them_three_one_fails() -> None:
    """`all of them` — three selections, one fails → False."""
    cond = _make_condition_multi(
        {
            "sel_name": {"name": "powershell.exe"},
            "sel_flag": {"cmd_line|contains": "-enc"},
            "sel_user": {"user": "admin"},
        },
        "all of them",
    )
    # sel_flag fails: no -enc in cmd_line
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "admin"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# `all of selection*` — wildcard pattern
# ---------------------------------------------------------------------------

def test_all_of_pattern_all_matching_selections_match() -> None:
    """`all of selection*` — all selections whose names match the pattern match → True."""
    cond = _make_condition_multi(
        {
            "selection_proc": {"name": "powershell.exe"},
            "selection_flag": {"cmd_line|contains": "-enc"},
            "filter": {"user": "svc_av"},
        },
        "all of selection*",
    )
    # Both selection_proc and selection_flag match; filter is excluded
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "svc_av"}
    assert cond.matches(event) is True


def test_all_of_pattern_one_matching_selection_fails() -> None:
    """`all of selection*` — one pattern-matching selection fails → False."""
    cond = _make_condition_multi(
        {
            "selection_proc": {"name": "powershell.exe"},
            "selection_flag": {"cmd_line|contains": "-enc"},
            "filter": {"user": "svc_av"},
        },
        "all of selection*",
    )
    # selection_flag fails (-nop, not -enc); filter is excluded from pattern
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "svc_av"}
    assert cond.matches(event) is False


def test_all_of_pattern_non_pattern_excluded_from_evaluation() -> None:
    """`all of selection*` — selections not matching the pattern are excluded."""
    cond = _make_condition_multi(
        {
            "selection_main": {"name": "powershell.exe"},
            "filter": {"user": "svc_av"},
        },
        "all of selection*",
    )
    # Only selection_main is evaluated; filter is excluded
    # selection_main matches → True (filter's match is irrelevant)
    event = {"name": "powershell.exe", "user": "svc_av"}
    assert cond.matches(event) is True


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_1_OF_THEM = """\
title: Detect Credential Dumping Indicators
id: test-1ofth-001
status: test
level: high
logsource:
  category: process_creation
detection:
  sel_lsass:
    cmd_line|contains: lsass
  sel_mimi:
    cmd_line|contains: mimikatz
  sel_sekurlsa:
    cmd_line|contains: sekurlsa
  condition: 1 of them
"""

_RULE_1_OF_PATTERN = """\
title: Detect Any Suspicious Selection
id: test-1ofth-002
status: test
level: medium
logsource:
  category: process_creation
detection:
  selection_proc:
    name: powershell.exe
  selection_enc:
    cmd_line|contains: '-enc'
  filter_legit:
    user: 'svc_automation'
  condition: 1 of selection*
"""

_RULE_ALL_OF_THEM = """\
title: Detect Combined PowerShell Attack
id: test-1ofth-003
status: test
level: critical
logsource:
  category: process_creation
detection:
  sel_name:
    name: powershell.exe
  sel_encoded:
    cmd_line|contains: '-enc'
  sel_bypass:
    cmd_line|contains: bypass
  condition: all of them
"""


def test_rule_1_of_them_first_selection_matches(engine: SigmaEngine) -> None:
    """Rule with `condition: 1 of them` — first selection (lsass) fires → True."""
    rule = engine.load_rule_yaml(_RULE_1_OF_THEM)
    assert rule is not None
    event = {"cmd_line": "procdump -ma lsass.exe lsass.dmp"}
    assert rule._matcher.matches(event) is True


def test_rule_1_of_them_second_selection_matches(engine: SigmaEngine) -> None:
    """Rule with `condition: 1 of them` — second selection (mimikatz) fires → True."""
    rule = engine.load_rule_yaml(_RULE_1_OF_THEM)
    assert rule is not None
    event = {"cmd_line": "invoke-mimikatz -command sekurlsa::logonpasswords"}
    assert rule._matcher.matches(event) is True


def test_rule_1_of_them_last_selection_matches(engine: SigmaEngine) -> None:
    """Rule with `condition: 1 of them` — last selection (sekurlsa) fires → True."""
    rule = engine.load_rule_yaml(_RULE_1_OF_THEM)
    assert rule is not None
    event = {"cmd_line": "sekurlsa::logonpasswords"}
    assert rule._matcher.matches(event) is True


def test_rule_1_of_them_none_match(engine: SigmaEngine) -> None:
    """Rule with `condition: 1 of them` — no selection matches → False."""
    rule = engine.load_rule_yaml(_RULE_1_OF_THEM)
    assert rule is not None
    event = {"cmd_line": "whoami /priv"}
    assert rule._matcher.matches(event) is False


def test_rule_1_of_them_all_match(engine: SigmaEngine) -> None:
    """Rule with `condition: 1 of them` — all selections match → True."""
    rule = engine.load_rule_yaml(_RULE_1_OF_THEM)
    assert rule is not None
    # cmd_line contains all three keywords
    event = {"cmd_line": "invoke-mimikatz -command sekurlsa::logonpasswords lsass"}
    assert rule._matcher.matches(event) is True


def test_rule_1_of_pattern_proc_matches(engine: SigmaEngine) -> None:
    """Rule with `condition: 1 of selection*` — selection_proc matches → True."""
    rule = engine.load_rule_yaml(_RULE_1_OF_PATTERN)
    assert rule is not None
    # selection_proc matches (powershell.exe); filter_legit is excluded from pattern
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "svc_automation"}
    assert rule._matcher.matches(event) is True


def test_rule_1_of_pattern_enc_matches(engine: SigmaEngine) -> None:
    """Rule with `condition: 1 of selection*` — selection_enc matches → True."""
    rule = engine.load_rule_yaml(_RULE_1_OF_PATTERN)
    assert rule is not None
    # selection_enc matches (-enc in cmd_line); filter_legit is excluded from pattern
    event = {"name": "cmd.exe", "cmd_line": "cmd -enc abc", "user": "jdoe"}
    assert rule._matcher.matches(event) is True


def test_rule_1_of_pattern_none_match(engine: SigmaEngine) -> None:
    """Rule with `condition: 1 of selection*` — none of the selection_* match → False."""
    rule = engine.load_rule_yaml(_RULE_1_OF_PATTERN)
    assert rule is not None
    # Neither selection_proc nor selection_enc match; filter_legit is excluded
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami", "user": "svc_automation"}
    assert rule._matcher.matches(event) is False


def test_rule_all_of_them_all_match(engine: SigmaEngine) -> None:
    """Rule with `condition: all of them` — all selections match → True."""
    rule = engine.load_rule_yaml(_RULE_ALL_OF_THEM)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc -ExecutionPolicy bypass"}
    assert rule._matcher.matches(event) is True


def test_rule_all_of_them_one_fails(engine: SigmaEngine) -> None:
    """Rule with `condition: all of them` — one selection fails → False."""
    rule = engine.load_rule_yaml(_RULE_ALL_OF_THEM)
    assert rule is not None
    # sel_bypass fails: no 'bypass' in cmd_line
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc"}
    assert rule._matcher.matches(event) is False


def test_rule_all_of_them_none_match(engine: SigmaEngine) -> None:
    """Rule with `condition: all of them` — no selections match → False."""
    rule = engine.load_rule_yaml(_RULE_ALL_OF_THEM)
    assert rule is not None
    event = {"name": "cmd.exe", "cmd_line": "cmd /c whoami"}
    assert rule._matcher.matches(event) is False
