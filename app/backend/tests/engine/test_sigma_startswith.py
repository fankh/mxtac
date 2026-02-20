"""Tests for feature 28.16 — Sigma: `startswith` modifier matches.

Coverage for _Condition._field_matches() with the `startswith` modifier:
  - Single value prefix match returns True
  - Single value no match when pattern is NOT at start returns False
  - Match is case-insensitive (search value uppercase, field lowercase)
  - Match is case-insensitive (search value lowercase, field uppercase)
  - Empty prefix always matches (empty string is a prefix of any string)
  - Full-string prefix match returns True (startswith entire field value)
  - List of values uses OR semantics — first value matches
  - List of values uses OR semantics — last value matches
  - List of values uses OR semantics — none match → False
  - List of values: pattern that appears mid-string does NOT match startswith
  - `startswith|all` with all prefixes present → True (nested prefixes)
  - `startswith|all` with one prefix absent → False
  - `startswith|all` with single-element list → True when it matches
  - Field not present in event → False
  - Field explicitly None → False
  - Nested field via dot notation → matches correctly
  - Nested field via dot notation → no match when pattern is not at start
  - Numeric field value is coerced to string before matching
  - Numeric field: no match when prefix not at start of string
  - `startswith` does NOT match substrings in the middle of the field
  - `startswith` does NOT match suffixes (patterns at the end only)
  - Two-field selection — both fields start with their patterns → True
  - Two-field selection — one field fails → False
  - Via load_rule_yaml: rule with single `startswith` value matches event
  - Via load_rule_yaml: rule with single `startswith` value does not match
  - Via load_rule_yaml: rule with list `startswith` value matches event (OR)
  - Via load_rule_yaml: rule with `startswith|all` matches when all prefixes present
  - Via load_rule_yaml: rule with `startswith|all` does not match when one prefix absent
  - Via load_rule_yaml: matching is case-insensitive through full load path
"""

from __future__ import annotations

import pytest

from app.engine.sigma_engine import SigmaEngine, _Condition


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_condition(field_expr: str, values: object, condition: str = "selection") -> _Condition:
    """Build a _Condition with a single selection using the given field expression."""
    detection = {
        "selection": {field_expr: values},
        "condition": condition,
    }
    return _Condition(detection)


def _matches(field_expr: str, values: object, event: dict) -> bool:
    return _make_condition(field_expr, values).matches(event)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


# ---------------------------------------------------------------------------
# Basic single-value `startswith` matching
# ---------------------------------------------------------------------------

def test_startswith_single_value_match() -> None:
    """Prefix present at start of field value → True."""
    assert _matches("name|startswith", "powershell", {"name": "powershell.exe"}) is True


def test_startswith_single_value_no_match_in_middle() -> None:
    """Pattern present only in the middle of field value — not a prefix → False."""
    assert _matches("name|startswith", "shell", {"name": "powershell.exe"}) is False


def test_startswith_single_value_no_match_at_end() -> None:
    """Pattern present only at the end of the field value → False."""
    assert _matches("cmd_line|startswith", ".exe", {"cmd_line": "powershell.exe"}) is False


def test_startswith_case_insensitive_upper_pattern() -> None:
    """Search value is uppercase, field is lowercase — still matches."""
    assert _matches("name|startswith", "POWERSHELL", {"name": "powershell.exe"}) is True


def test_startswith_case_insensitive_upper_field() -> None:
    """Field value is uppercase, search value is lowercase — still matches."""
    assert _matches("name|startswith", "powershell", {"name": "POWERSHELL.EXE"}) is True


def test_startswith_empty_prefix_always_matches() -> None:
    """Empty string is a prefix of any non-empty string."""
    assert _matches("cmd_line|startswith", "", {"cmd_line": "anything"}) is True


def test_startswith_full_string_match() -> None:
    """Prefix equal to the entire field value → True."""
    assert _matches("name|startswith", "cmd.exe", {"name": "cmd.exe"}) is True


def test_startswith_prefix_longer_than_field_no_match() -> None:
    """Prefix longer than field value → False."""
    assert _matches("name|startswith", "powershell.exe.extra", {"name": "powershell.exe"}) is False


# ---------------------------------------------------------------------------
# List of values — OR semantics
# ---------------------------------------------------------------------------

def test_startswith_list_first_value_matches() -> None:
    """OR semantics: first value is a prefix → True."""
    assert _matches(
        "cmd_line|startswith",
        ["powershell", "cmd.exe"],
        {"cmd_line": "powershell -enc abc"},
    ) is True


def test_startswith_list_last_value_matches() -> None:
    """OR semantics: only the last value is a prefix → still True."""
    assert _matches(
        "cmd_line|startswith",
        ["python", "cmd.exe"],
        {"cmd_line": "cmd.exe /c whoami"},
    ) is True


def test_startswith_list_no_value_matches() -> None:
    """OR semantics: no value is a prefix → False."""
    assert _matches(
        "cmd_line|startswith",
        ["powershell", "cmd.exe"],
        {"cmd_line": "wscript.exe evil.vbs"},
    ) is False


def test_startswith_list_mid_string_pattern_does_not_match() -> None:
    """OR list: pattern present mid-string but not at start → False for that value."""
    assert _matches(
        "cmd_line|startswith",
        ["-enc"],
        {"cmd_line": "powershell -enc base64"},
    ) is False


def test_startswith_list_multiple_values_match() -> None:
    """OR semantics: multiple values are prefixes — still True (short-circuits)."""
    assert _matches(
        "name|startswith",
        ["pow", "powershell"],
        {"name": "powershell.exe"},
    ) is True


# ---------------------------------------------------------------------------
# `startswith|all` — AND semantics
# ---------------------------------------------------------------------------

def test_startswith_all_nested_prefixes_match() -> None:
    """startswith|all: both values are prefixes (one is a prefix of the other) → True."""
    # "c:\\" is a prefix of "c:\\windows\\system32\\cmd.exe"
    # "c:\\windows" is also a prefix of that path
    assert _matches(
        "path|startswith|all",
        ["c:\\\\", "c:\\\\windows"],
        {"path": "c:\\\\windows\\\\system32\\\\cmd.exe"},
    ) is True


def test_startswith_all_one_prefix_absent() -> None:
    """startswith|all: one value is NOT a prefix → False."""
    assert _matches(
        "path|startswith|all",
        ["c:\\\\", "c:\\\\temp"],
        {"path": "c:\\\\windows\\\\cmd.exe"},
    ) is False


def test_startswith_all_none_are_prefixes() -> None:
    """startswith|all: no values are prefixes → False."""
    assert _matches(
        "cmd_line|startswith|all",
        ["-enc", "mimikatz"],
        {"cmd_line": "python benign.py"},
    ) is False


def test_startswith_all_single_value_matches() -> None:
    """startswith|all with single-element list and it matches → True."""
    assert _matches(
        "name|startswith|all",
        ["powershell"],
        {"name": "powershell.exe"},
    ) is True


def test_startswith_all_single_value_no_match() -> None:
    """startswith|all with single-element list and it doesn't match → False."""
    assert _matches(
        "name|startswith|all",
        ["cmd.exe"],
        {"name": "powershell.exe"},
    ) is False


# ---------------------------------------------------------------------------
# Field existence
# ---------------------------------------------------------------------------

def test_startswith_field_missing_returns_false() -> None:
    """Field key not present in event → False (not an error)."""
    assert _matches("cmd_line|startswith", "powershell", {"process_name": "explorer.exe"}) is False


def test_startswith_field_value_none_returns_false() -> None:
    """Field explicitly set to None → False."""
    assert _matches("cmd_line|startswith", "powershell", {"cmd_line": None}) is False


# ---------------------------------------------------------------------------
# Nested field (dot notation)
# ---------------------------------------------------------------------------

def test_startswith_nested_field_match() -> None:
    """Dot-notation field lookup works with startswith modifier."""
    event = {"process": {"name": "powershell.exe"}}
    assert _matches("process.name|startswith", "powershell", event) is True


def test_startswith_nested_field_no_match() -> None:
    """Dot-notation field value that doesn't start with pattern → False."""
    event = {"process": {"name": "powershell.exe"}}
    assert _matches("process.name|startswith", "cmd", event) is False


def test_startswith_nested_field_pattern_in_middle_no_match() -> None:
    """Dot-notation: pattern present in middle of value, not at start → False."""
    event = {"process": {"cmd_line": "c:\\windows\\powershell.exe -enc abc"}}
    assert _matches("process.cmd_line|startswith", "powershell", event) is False


def test_startswith_nested_field_missing() -> None:
    """Dot-notation where intermediate key is absent → False."""
    event = {"process": {}}  # no name key
    assert _matches("process.name|startswith", "powershell", event) is False


# ---------------------------------------------------------------------------
# Non-string field types
# ---------------------------------------------------------------------------

def test_startswith_numeric_field_coerced_to_string() -> None:
    """Numeric field values are coerced to string before matching."""
    # 12345 → "12345", startswith "123" → True
    assert _matches("pid|startswith", "123", {"pid": 12345}) is True


def test_startswith_numeric_field_no_match() -> None:
    """Coerced numeric value that doesn't start with search string → False."""
    # 12345 → "12345", startswith "45" → False (45 is at the end)
    assert _matches("pid|startswith", "45", {"pid": 12345}) is False


# ---------------------------------------------------------------------------
# Contrast: `startswith` vs `contains` semantics
# ---------------------------------------------------------------------------

def test_startswith_does_not_match_middle_substring() -> None:
    """`startswith` must not match a substring present only in the middle."""
    assert _matches("cmd_line|startswith", "-enc", {"cmd_line": "powershell -enc abc"}) is False


def test_startswith_does_not_match_suffix_only() -> None:
    """`startswith` must not match a substring present only at the end."""
    assert _matches("name|startswith", ".exe", {"name": "powershell.exe"}) is False


# ---------------------------------------------------------------------------
# Two-field selection — AND across fields
# ---------------------------------------------------------------------------

def test_startswith_two_field_selection_both_match() -> None:
    """When selection has two startswith fields both must start with their values."""
    detection = {
        "selection": {
            "cmd_line|startswith": "powershell",
            "name|startswith": "power",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"cmd_line": "powershell -enc abc", "name": "powershell.exe"}
    assert cond.matches(event) is True


def test_startswith_two_field_selection_one_fails() -> None:
    """When selection has two startswith fields and one doesn't match → False."""
    detection = {
        "selection": {
            "cmd_line|startswith": "powershell",
            "name|startswith": "cmd",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"cmd_line": "powershell -enc abc", "name": "powershell.exe"}
    assert cond.matches(event) is False


def test_startswith_two_field_selection_one_field_absent() -> None:
    """When one field is absent from the event → False."""
    detection = {
        "selection": {
            "cmd_line|startswith": "powershell",
            "name|startswith": "power",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    # name field is absent
    event = {"cmd_line": "powershell -enc abc"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_SINGLE_STARTSWITH = """\
title: Detect PowerShell Execution
id: test-startswith-001
status: test
level: high
logsource:
  category: process_creation
detection:
  selection:
    name|startswith: 'powershell'
  condition: selection
"""

_RULE_LIST_STARTSWITH = """\
title: Detect Common Shells
id: test-startswith-002
status: test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    name|startswith:
      - 'powershell'
      - 'cmd.exe'
      - 'wscript'
  condition: selection
"""

_RULE_ALL_STARTSWITH = """\
title: Detect System32 PowerShell
id: test-startswith-003
status: test
level: critical
logsource:
  category: process_creation
detection:
  selection:
    path|startswith|all:
      - 'c:\\windows'
      - 'c:\\windows\\system32'
  condition: selection
"""


def test_rule_single_startswith_matches(engine: SigmaEngine) -> None:
    """Rule with single `startswith` value matches an event whose field starts with it."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_STARTSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "powershell.exe"}) is True


def test_rule_single_startswith_no_match(engine: SigmaEngine) -> None:
    """Rule with single `startswith` value does not match when field starts with something else."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_STARTSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "cmd.exe"}) is False


def test_rule_single_startswith_no_match_mid_string(engine: SigmaEngine) -> None:
    """Rule with `startswith` does not match when pattern appears mid-string."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_STARTSWITH)
    assert rule is not None
    # 'powershell' is present but not at the start
    assert rule._matcher.matches({"name": "run_powershell_wrapper.exe"}) is False


def test_rule_list_startswith_first_value_matches(engine: SigmaEngine) -> None:
    """Rule list `startswith` matches event containing first list value as prefix."""
    rule = engine.load_rule_yaml(_RULE_LIST_STARTSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "powershell.exe"}) is True


def test_rule_list_startswith_second_value_matches(engine: SigmaEngine) -> None:
    """Rule list `startswith` matches event containing second list value as prefix."""
    rule = engine.load_rule_yaml(_RULE_LIST_STARTSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "cmd.exe /c whoami"}) is True


def test_rule_list_startswith_third_value_matches(engine: SigmaEngine) -> None:
    """Rule list `startswith` matches event containing third list value as prefix."""
    rule = engine.load_rule_yaml(_RULE_LIST_STARTSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "wscript.exe evil.vbs"}) is True


def test_rule_list_startswith_no_value_matches(engine: SigmaEngine) -> None:
    """Rule list `startswith` does not match when no listed value is a prefix."""
    rule = engine.load_rule_yaml(_RULE_LIST_STARTSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "python.exe benign.py"}) is False


def test_rule_startswith_all_both_prefixes_present(engine: SigmaEngine) -> None:
    """`startswith|all` rule matches when all values are prefixes of the field."""
    rule = engine.load_rule_yaml(_RULE_ALL_STARTSWITH)
    assert rule is not None
    # "c:\\windows\\system32\\cmd.exe" starts with both "c:\\windows" and "c:\\windows\\system32"
    assert rule._matcher.matches({"path": "c:\\windows\\system32\\cmd.exe"}) is True


def test_rule_startswith_all_one_prefix_absent(engine: SigmaEngine) -> None:
    """`startswith|all` rule does not match when one prefix is not present at start."""
    rule = engine.load_rule_yaml(_RULE_ALL_STARTSWITH)
    assert rule is not None
    # starts with "c:\\windows" but NOT with "c:\\windows\\system32"
    assert rule._matcher.matches({"path": "c:\\windows\\syswow64\\cmd.exe"}) is False


def test_rule_startswith_all_no_prefix_matches(engine: SigmaEngine) -> None:
    """`startswith|all` rule does not match when no prefixes match."""
    rule = engine.load_rule_yaml(_RULE_ALL_STARTSWITH)
    assert rule is not None
    assert rule._matcher.matches({"path": "d:\\tools\\cmd.exe"}) is False


def test_rule_startswith_case_insensitive_via_yaml(engine: SigmaEngine) -> None:
    """Matching through load_rule_yaml is case-insensitive."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_STARTSWITH)
    assert rule is not None
    # Field value in uppercase — must still match
    assert rule._matcher.matches({"name": "POWERSHELL.EXE"}) is True
