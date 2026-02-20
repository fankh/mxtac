"""Tests for feature 28.22 — Sigma: non-matching event yields no alert.

Coverage for _Condition.matches() returning False and engine.evaluate() yielding
no SigmaAlert when the event does not satisfy the rule's detection logic:

  - Simple selection, wrong field value → False
  - Simple selection, required field absent → False
  - AND condition, first selection fails → False
  - AND condition, second selection fails → False
  - AND condition, both selections fail → False
  - OR condition, neither selection matches → False
  - NOT-only condition, filter catches the event → False
  - `selection and not filter` — filter matches → False
  - contains modifier, substring absent → False
  - startswith modifier, prefix mismatch → False
  - Multiple values (OR semantics), none match → False
  - `1 of them`, neither selection matches → False
  - `all of them`, one selection fails → False
  - Via engine.evaluate(): rule loaded, event field wrong → no alerts
  - Via engine.evaluate(): AND rule, one part fails → no alerts
  - Via engine.evaluate(): OR rule, neither side matches → no alerts
  - Via engine.evaluate(): rule disabled → no alerts even when event matches
  - Via engine.evaluate(): no rules loaded → always empty
  - Via engine.evaluate(): event product mismatches rule logsource → no alerts
  - Via engine.evaluate(): multiple rules, none match event → no alerts
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.engine.sigma_engine import SigmaEngine, _Condition
from app.services.normalizers.ocsf import (
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_condition(selection: dict, condition: str = "selection") -> _Condition:
    """Build a _Condition with a single 'selection' block."""
    return _Condition({"selection": selection, "condition": condition})


def _make_condition_multi(selections: dict, condition: str) -> _Condition:
    """Build a _Condition with multiple named selections and a condition string."""
    detection = dict(selections)
    detection["condition"] = condition
    return _Condition(detection)


def _ocsf_process_event(**overrides: object) -> OCSFEvent:
    """Return a minimal OCSFEvent for a process-activity source."""
    kwargs: dict = dict(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        class_name="Process Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        time=datetime.now(timezone.utc),
        severity_id=1,
        metadata_product="windows",
        process=ProcessInfo(name="cmd.exe", cmd_line="cmd /c whoami"),
    )
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


# ---------------------------------------------------------------------------
# Simple selection — wrong field value
# ---------------------------------------------------------------------------

def test_simple_selection_wrong_value() -> None:
    """Single selection, field present but value wrong → False."""
    cond = _make_condition({"name": "powershell.exe"})
    assert cond.matches({"name": "cmd.exe"}) is False


def test_simple_selection_field_absent() -> None:
    """Single selection, required field not in event → False."""
    cond = _make_condition({"name": "powershell.exe"})
    assert cond.matches({"cmd_line": "powershell -enc abc"}) is False


def test_simple_selection_empty_event() -> None:
    """Single selection against an empty event dict → False."""
    cond = _make_condition({"name": "powershell.exe"})
    assert cond.matches({}) is False


# ---------------------------------------------------------------------------
# AND condition — partial failures
# ---------------------------------------------------------------------------

def test_and_first_selection_fails() -> None:
    """AND — first selection fails, second matches → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc and sel_args",
    )
    # sel_proc fails (cmd.exe, not powershell.exe); sel_args matches
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd -enc"}) is False


def test_and_second_selection_fails() -> None:
    """AND — first selection matches, second fails → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc and sel_args",
    )
    # sel_proc matches, sel_args fails (no -enc)
    assert cond.matches({"name": "powershell.exe", "cmd_line": "powershell -nop"}) is False


def test_and_both_selections_fail() -> None:
    """AND — both selections fail → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "sel_proc and sel_args",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd /c whoami"}) is False


def test_and_three_way_middle_fails() -> None:
    """Three-way AND — middle selection fails → False."""
    cond = _make_condition_multi(
        {
            "sel_a": {"name": "powershell.exe"},
            "sel_b": {"cmd_line|contains": "-enc"},
            "sel_c": {"user": "SYSTEM"},
        },
        "sel_a and sel_b and sel_c",
    )
    # sel_a OK, sel_b FAIL, sel_c OK
    assert cond.matches({"name": "powershell.exe", "cmd_line": "-nop", "user": "SYSTEM"}) is False


# ---------------------------------------------------------------------------
# OR condition — neither side matches
# ---------------------------------------------------------------------------

def test_or_neither_matches() -> None:
    """OR — both selections fail → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_script": {"name": "wscript.exe"},
        },
        "sel_proc or sel_script",
    )
    assert cond.matches({"name": "cmd.exe"}) is False


def test_or_three_way_none_match() -> None:
    """Three-way OR — no selection matches → False."""
    cond = _make_condition_multi(
        {
            "sel_a": {"name": "powershell.exe"},
            "sel_b": {"name": "wscript.exe"},
            "sel_c": {"name": "cscript.exe"},
        },
        "sel_a or sel_b or sel_c",
    )
    assert cond.matches({"name": "cmd.exe"}) is False


# ---------------------------------------------------------------------------
# NOT condition — filter catches the event
# ---------------------------------------------------------------------------

def test_not_filter_catches_event() -> None:
    """`not filter` — filter matches → overall condition is False."""
    cond = _make_condition_multi(
        {"filter": {"name": "svchost.exe"}},
        "not filter",
    )
    # The filter matches, so `not filter` → False
    assert cond.matches({"name": "svchost.exe"}) is False


def test_selection_and_not_filter_filter_fires() -> None:
    """`selection and not filter` — selection matches but filter fires → False."""
    cond = _make_condition_multi(
        {
            "selection": {"name": "powershell.exe"},
            "filter":    {"cmd_line|contains": "WindowsUpdate"},
        },
        "selection and not filter",
    )
    # Both selection AND filter match — the NOT filter suppresses the alert
    event = {"name": "powershell.exe", "cmd_line": "powershell WindowsUpdate.ps1"}
    assert cond.matches(event) is False


def test_selection_and_not_filter_selection_misses() -> None:
    """`selection and not filter` — selection itself fails → False regardless of filter."""
    cond = _make_condition_multi(
        {
            "selection": {"name": "powershell.exe"},
            "filter":    {"cmd_line|contains": "WindowsUpdate"},
        },
        "selection and not filter",
    )
    # selection fails (cmd.exe), filter irrelevant
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd /c dir"}) is False


# ---------------------------------------------------------------------------
# Field modifiers — negative cases
# ---------------------------------------------------------------------------

def test_contains_modifier_substring_absent() -> None:
    """`contains` modifier — substring not found in value → False."""
    cond = _make_condition({"cmd_line|contains": "-EncodedCommand"})
    assert cond.matches({"cmd_line": "powershell -NoProfile"}) is False


def test_contains_modifier_field_missing() -> None:
    """`contains` modifier — field not in event → False."""
    cond = _make_condition({"cmd_line|contains": "-enc"})
    assert cond.matches({"name": "powershell.exe"}) is False


def test_startswith_modifier_prefix_mismatch() -> None:
    """`startswith` modifier — value does not start with the pattern → False."""
    cond = _make_condition({"cmd_line|startswith": "powershell"})
    assert cond.matches({"cmd_line": "cmd.exe /c powershell"}) is False


def test_endswith_modifier_suffix_mismatch() -> None:
    """`endswith` modifier — value does not end with pattern → False."""
    cond = _make_condition({"name|endswith": ".exe"})
    assert cond.matches({"name": "powershell.ps1"}) is False


def test_multiple_values_or_semantics_none_match() -> None:
    """List values (OR semantics) — none of the values match → False."""
    cond = _make_condition({"name": ["powershell.exe", "wscript.exe", "cscript.exe"]})
    assert cond.matches({"name": "cmd.exe"}) is False


# ---------------------------------------------------------------------------
# `1 of them` / `all of them` — non-matching cases
# ---------------------------------------------------------------------------

def test_1_of_them_neither_matches() -> None:
    """`1 of them` — no selection matches → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "1 of them",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd /c whoami"}) is False


def test_all_of_them_one_fails() -> None:
    """`all of them` — one selection fails → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "all of them",
    )
    # sel_proc matches, sel_args does not
    assert cond.matches({"name": "powershell.exe", "cmd_line": "-nop"}) is False


def test_all_of_them_none_match() -> None:
    """`all of them` — no selections match → False."""
    cond = _make_condition_multi(
        {
            "sel_proc": {"name": "powershell.exe"},
            "sel_args": {"cmd_line|contains": "-enc"},
        },
        "all of them",
    )
    assert cond.matches({"name": "cmd.exe", "cmd_line": "cmd /c whoami"}) is False


# ---------------------------------------------------------------------------
# Via engine.evaluate() — full pipeline: no alerts yielded
# ---------------------------------------------------------------------------

_RULE_YAML_WRONG_FIELD = """\
title: Detect PowerShell
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: powershell.exe
    cmd_line|contains: -enc
  condition: selection
level: high
"""

_RULE_YAML_AND = """\
title: AND Rule
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  sel_proc:
    name: powershell.exe
  sel_args:
    cmd_line|contains: -enc
  condition: sel_proc and sel_args
level: medium
"""

_RULE_YAML_OR = """\
title: OR Rule
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  sel_proc:
    name: powershell.exe
  sel_script:
    name: wscript.exe
  condition: sel_proc or sel_script
level: low
"""


@pytest.mark.asyncio
async def test_evaluate_no_match_wrong_value(engine: SigmaEngine) -> None:
    """engine.evaluate() — rule loaded but event field value wrong → no alerts."""
    rule = engine.load_rule_yaml(_RULE_YAML_WRONG_FIELD)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event(
        process=ProcessInfo(name="cmd.exe", cmd_line="cmd /c whoami"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert alerts == []


@pytest.mark.asyncio
async def test_evaluate_no_match_and_partial(engine: SigmaEngine) -> None:
    """engine.evaluate() — AND rule, one part fails → no alerts."""
    rule = engine.load_rule_yaml(_RULE_YAML_AND)
    assert rule is not None
    engine.add_rule(rule)

    # sel_proc matches (powershell.exe), sel_args fails (no -enc)
    event = _ocsf_process_event(
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -NoProfile"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert alerts == []


@pytest.mark.asyncio
async def test_evaluate_no_match_or_neither(engine: SigmaEngine) -> None:
    """engine.evaluate() — OR rule, neither selection fires → no alerts."""
    rule = engine.load_rule_yaml(_RULE_YAML_OR)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event(
        process=ProcessInfo(name="cmd.exe", cmd_line="cmd /c dir"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert alerts == []


@pytest.mark.asyncio
async def test_evaluate_disabled_rule_no_alerts(engine: SigmaEngine) -> None:
    """engine.evaluate() — rule disabled → no alerts even if event matches rule logic."""
    rule = engine.load_rule_yaml(_RULE_YAML_WRONG_FIELD)
    assert rule is not None
    rule.enabled = False
    engine.add_rule(rule)

    # Event that WOULD match if the rule were enabled
    event = _ocsf_process_event(
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert alerts == []


@pytest.mark.asyncio
async def test_evaluate_no_rules_loaded_empty(engine: SigmaEngine) -> None:
    """engine.evaluate() — no rules loaded → always yields no alerts."""
    event = _ocsf_process_event(
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert alerts == []


_RULE_YAML_PRODUCT_ONLY = """\
title: Windows-Only Rule
status: experimental
logsource:
  product: windows
detection:
  selection:
    name: powershell.exe
  condition: selection
level: medium
"""


@pytest.mark.asyncio
async def test_evaluate_product_mismatch_no_alerts(engine: SigmaEngine) -> None:
    """engine.evaluate() — rule indexed by product:windows only, event product is 'linux' → no alerts.

    A rule with only `product: windows` (no category) is indexed solely under
    product:windows.  An event from a different product does not hit that index
    bucket and therefore yields no candidates, hence no alerts.
    """
    rule = engine.load_rule_yaml(_RULE_YAML_PRODUCT_ONLY)
    assert rule is not None
    engine.add_rule(rule)

    # Event with matching process name but wrong product — not a windows source
    event = _ocsf_process_event(
        metadata_product="linux",
        process=ProcessInfo(name="powershell.exe", cmd_line="pwsh -File script.ps1"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert alerts == []


@pytest.mark.asyncio
async def test_evaluate_multiple_rules_none_match(engine: SigmaEngine) -> None:
    """engine.evaluate() — multiple rules loaded, none match the event → no alerts."""
    for yaml_text in (_RULE_YAML_WRONG_FIELD, _RULE_YAML_AND, _RULE_YAML_OR):
        rule = engine.load_rule_yaml(yaml_text)
        assert rule is not None
        engine.add_rule(rule)

    # Event that doesn't match any rule
    event = _ocsf_process_event(
        process=ProcessInfo(name="notepad.exe", cmd_line="notepad.exe readme.txt"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert alerts == []
