"""Tests for feature 8.8 — Sigma: `endswith` modifier matches.

Coverage for _Condition._precompile_field() with the `endswith` modifier:
  - Single value suffix match returns True
  - Single value no match when pattern is NOT at end returns False
  - Match is case-insensitive (search value uppercase, field lowercase)
  - Match is case-insensitive (search value lowercase, field uppercase)
  - Empty suffix always matches (empty string is a suffix of any string)
  - Full-string suffix match returns True (endswith entire field value)
  - Suffix longer than field → False
  - List of values uses OR semantics — first value matches
  - List of values uses OR semantics — last value matches
  - List of values uses OR semantics — none match → False
  - List of values: pattern that appears at start does NOT match endswith
  - `endswith|all` with all suffixes present → True (nested suffixes)
  - `endswith|all` with one suffix absent → False
  - `endswith|all` with single-element list → True when it matches
  - Field not present in event → False
  - Field explicitly None → False
  - Nested field via dot notation → matches correctly
  - Nested field via dot notation → no match when pattern is not at end
  - Numeric field value is coerced to string before matching
  - Numeric field: no match when suffix not at end of string
  - `endswith` does NOT match substrings in the middle of the field
  - `endswith` does NOT match prefixes (patterns at the start only)
  - Two-field selection — both fields end with their patterns → True
  - Two-field selection — one field fails → False
  - Via load_rule_yaml: rule with single `endswith` value matches event
  - Via load_rule_yaml: rule with single `endswith` value does not match
  - Via load_rule_yaml: rule with list `endswith` value matches event (OR)
  - Via load_rule_yaml: rule with `endswith|all` matches when all suffixes present
  - Via load_rule_yaml: rule with `endswith|all` does not match when one suffix absent
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
# Basic single-value `endswith` matching
# ---------------------------------------------------------------------------

def test_endswith_single_value_match() -> None:
    """Suffix present at end of field value → True."""
    assert _matches("name|endswith", ".exe", {"name": "powershell.exe"}) is True


def test_endswith_single_value_no_match_at_start() -> None:
    """Pattern present only at the start of field value — not a suffix → False."""
    assert _matches("name|endswith", "powershell", {"name": "powershell.exe"}) is False


def test_endswith_single_value_no_match_in_middle() -> None:
    """Pattern present only in the middle of field value → False."""
    assert _matches("cmd_line|endswith", "-enc", {"cmd_line": "powershell -enc base64data"}) is False


def test_endswith_case_insensitive_upper_pattern() -> None:
    """Search value is uppercase, field is lowercase — still matches."""
    assert _matches("name|endswith", ".EXE", {"name": "powershell.exe"}) is True


def test_endswith_case_insensitive_upper_field() -> None:
    """Field value is uppercase, search value is lowercase — still matches."""
    assert _matches("name|endswith", ".exe", {"name": "POWERSHELL.EXE"}) is True


def test_endswith_empty_suffix_always_matches() -> None:
    """Empty string is a suffix of any non-empty string."""
    assert _matches("cmd_line|endswith", "", {"cmd_line": "anything"}) is True


def test_endswith_full_string_match() -> None:
    """Suffix equal to the entire field value → True."""
    assert _matches("name|endswith", "cmd.exe", {"name": "cmd.exe"}) is True


def test_endswith_suffix_longer_than_field_no_match() -> None:
    """Suffix longer than field value → False."""
    assert _matches("name|endswith", "extra.powershell.exe", {"name": "powershell.exe"}) is False


# ---------------------------------------------------------------------------
# List of values — OR semantics
# ---------------------------------------------------------------------------

def test_endswith_list_first_value_matches() -> None:
    """OR semantics: first value is a suffix → True."""
    assert _matches(
        "name|endswith",
        [".exe", ".dll"],
        {"name": "powershell.exe"},
    ) is True


def test_endswith_list_last_value_matches() -> None:
    """OR semantics: only the last value is a suffix → still True."""
    assert _matches(
        "name|endswith",
        [".ps1", ".dll"],
        {"name": "malware.dll"},
    ) is True


def test_endswith_list_no_value_matches() -> None:
    """OR semantics: no value is a suffix → False."""
    assert _matches(
        "name|endswith",
        [".exe", ".dll"],
        {"name": "script.py"},
    ) is False


def test_endswith_list_start_pattern_does_not_match() -> None:
    """OR list: pattern present at start but not end → False for that value."""
    assert _matches(
        "name|endswith",
        ["powershell"],
        {"name": "powershell.exe"},
    ) is False


def test_endswith_list_multiple_values_match() -> None:
    """OR semantics: multiple values are suffixes — still True (short-circuits)."""
    assert _matches(
        "name|endswith",
        [".exe", "ell.exe"],
        {"name": "powershell.exe"},
    ) is True


# ---------------------------------------------------------------------------
# `endswith|all` — AND semantics
# ---------------------------------------------------------------------------

def test_endswith_all_nested_suffixes_match() -> None:
    """endswith|all: both values are suffixes (one is a suffix of the other) → True."""
    # ".exe" is a suffix of "system32\\cmd.exe"
    # "cmd.exe" is also a suffix of "system32\\cmd.exe"
    assert _matches(
        "path|endswith|all",
        [".exe", "cmd.exe"],
        {"path": "c:\\windows\\system32\\cmd.exe"},
    ) is True


def test_endswith_all_one_suffix_absent() -> None:
    """endswith|all: one value is NOT a suffix → False."""
    assert _matches(
        "path|endswith|all",
        [".exe", "notepad.exe"],
        {"path": "c:\\windows\\system32\\cmd.exe"},
    ) is False


def test_endswith_all_none_are_suffixes() -> None:
    """endswith|all: no values are suffixes → False."""
    assert _matches(
        "cmd_line|endswith|all",
        ["-enc", "mimikatz"],
        {"cmd_line": "python benign.py"},
    ) is False


def test_endswith_all_single_value_matches() -> None:
    """endswith|all with single-element list and it matches → True."""
    assert _matches(
        "name|endswith|all",
        [".exe"],
        {"name": "powershell.exe"},
    ) is True


def test_endswith_all_single_value_no_match() -> None:
    """endswith|all with single-element list and it doesn't match → False."""
    assert _matches(
        "name|endswith|all",
        [".dll"],
        {"name": "powershell.exe"},
    ) is False


# ---------------------------------------------------------------------------
# Field existence
# ---------------------------------------------------------------------------

def test_endswith_field_missing_returns_false() -> None:
    """Field key not present in event → False (not an error)."""
    assert _matches("name|endswith", ".exe", {"process_id": 1234}) is False


def test_endswith_field_value_none_returns_false() -> None:
    """Field explicitly set to None → False."""
    assert _matches("name|endswith", ".exe", {"name": None}) is False


# ---------------------------------------------------------------------------
# Nested field (dot notation)
# ---------------------------------------------------------------------------

def test_endswith_nested_field_match() -> None:
    """Dot-notation field lookup works with endswith modifier."""
    event = {"process": {"name": "powershell.exe"}}
    assert _matches("process.name|endswith", ".exe", event) is True


def test_endswith_nested_field_no_match() -> None:
    """Dot-notation field value that doesn't end with pattern → False."""
    event = {"process": {"name": "powershell.exe"}}
    assert _matches("process.name|endswith", ".dll", event) is False


def test_endswith_nested_field_pattern_at_start_no_match() -> None:
    """Dot-notation: pattern present at start of value, not at end → False."""
    event = {"process": {"cmd_line": "powershell -enc abc"}}
    assert _matches("process.cmd_line|endswith", "powershell", event) is False


def test_endswith_nested_field_missing() -> None:
    """Dot-notation where intermediate key is absent → False."""
    event = {"process": {}}  # no name key
    assert _matches("process.name|endswith", ".exe", event) is False


# ---------------------------------------------------------------------------
# Non-string field types
# ---------------------------------------------------------------------------

def test_endswith_numeric_field_coerced_to_string() -> None:
    """Numeric field values are coerced to string before matching."""
    # 12345 → "12345", endswith "45" → True
    assert _matches("pid|endswith", "45", {"pid": 12345}) is True


def test_endswith_numeric_field_no_match() -> None:
    """Coerced numeric value that doesn't end with search string → False."""
    # 12345 → "12345", endswith "123" → False (123 is at the start)
    assert _matches("pid|endswith", "123", {"pid": 12345}) is False


# ---------------------------------------------------------------------------
# Contrast: `endswith` vs `contains`/`startswith` semantics
# ---------------------------------------------------------------------------

def test_endswith_does_not_match_middle_substring() -> None:
    """`endswith` must not match a substring present only in the middle."""
    assert _matches("cmd_line|endswith", "-enc", {"cmd_line": "powershell -enc abc"}) is False


def test_endswith_does_not_match_prefix_only() -> None:
    """`endswith` must not match a substring present only at the start."""
    assert _matches("name|endswith", "powershell", {"name": "powershell.exe"}) is False


# ---------------------------------------------------------------------------
# Two-field selection — AND across fields
# ---------------------------------------------------------------------------

def test_endswith_two_field_selection_both_match() -> None:
    """When selection has two endswith fields both must end with their values."""
    detection = {
        "selection": {
            "name|endswith": ".exe",
            "path|endswith": "system32",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"name": "cmd.exe", "path": "c:\\windows\\system32"}
    assert cond.matches(event) is True


def test_endswith_two_field_selection_one_fails() -> None:
    """When selection has two endswith fields and one doesn't match → False."""
    detection = {
        "selection": {
            "name|endswith": ".exe",
            "path|endswith": "system32",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"name": "cmd.exe", "path": "c:\\windows\\syswow64"}
    assert cond.matches(event) is False


def test_endswith_two_field_selection_one_field_absent() -> None:
    """When one field is absent from the event → False."""
    detection = {
        "selection": {
            "name|endswith": ".exe",
            "path|endswith": "system32",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    # path field is absent
    event = {"name": "cmd.exe"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_SINGLE_ENDSWITH = """\
title: Detect Executable Files
id: test-endswith-001
status: test
level: high
logsource:
  category: process_creation
detection:
  selection:
    name|endswith: '.exe'
  condition: selection
"""

_RULE_LIST_ENDSWITH = """\
title: Detect Script Files
id: test-endswith-002
status: test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    name|endswith:
      - '.ps1'
      - '.vbs'
      - '.bat'
  condition: selection
"""

_RULE_ALL_ENDSWITH = """\
title: Detect System32 Executable
id: test-endswith-003
status: test
level: critical
logsource:
  category: process_creation
detection:
  selection:
    path|endswith|all:
      - '.exe'
      - 'cmd.exe'
  condition: selection
"""


def test_rule_single_endswith_matches(engine: SigmaEngine) -> None:
    """Rule with single `endswith` value matches an event whose field ends with it."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_ENDSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "powershell.exe"}) is True


def test_rule_single_endswith_no_match(engine: SigmaEngine) -> None:
    """Rule with single `endswith` value does not match when field ends with something else."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_ENDSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "script.ps1"}) is False


def test_rule_single_endswith_no_match_mid_string(engine: SigmaEngine) -> None:
    """Rule with `endswith` does not match when pattern appears mid-string."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_ENDSWITH)
    assert rule is not None
    # '.exe' is present but not at the end
    assert rule._matcher.matches({"name": "evil.exe.bak"}) is False


def test_rule_list_endswith_first_value_matches(engine: SigmaEngine) -> None:
    """Rule list `endswith` matches event containing first list value as suffix."""
    rule = engine.load_rule_yaml(_RULE_LIST_ENDSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "attack.ps1"}) is True


def test_rule_list_endswith_second_value_matches(engine: SigmaEngine) -> None:
    """Rule list `endswith` matches event containing second list value as suffix."""
    rule = engine.load_rule_yaml(_RULE_LIST_ENDSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "malware.vbs"}) is True


def test_rule_list_endswith_third_value_matches(engine: SigmaEngine) -> None:
    """Rule list `endswith` matches event containing third list value as suffix."""
    rule = engine.load_rule_yaml(_RULE_LIST_ENDSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "install.bat"}) is True


def test_rule_list_endswith_no_value_matches(engine: SigmaEngine) -> None:
    """Rule list `endswith` does not match when no listed value is a suffix."""
    rule = engine.load_rule_yaml(_RULE_LIST_ENDSWITH)
    assert rule is not None
    assert rule._matcher.matches({"name": "benign.exe"}) is False


def test_rule_endswith_all_both_suffixes_present(engine: SigmaEngine) -> None:
    """`endswith|all` rule matches when all values are suffixes of the field."""
    rule = engine.load_rule_yaml(_RULE_ALL_ENDSWITH)
    assert rule is not None
    # "c:\\windows\\system32\\cmd.exe" ends with both ".exe" and "cmd.exe"
    assert rule._matcher.matches({"path": "c:\\windows\\system32\\cmd.exe"}) is True


def test_rule_endswith_all_one_suffix_absent(engine: SigmaEngine) -> None:
    """`endswith|all` rule does not match when one suffix is not at end."""
    rule = engine.load_rule_yaml(_RULE_ALL_ENDSWITH)
    assert rule is not None
    # ends with ".exe" but NOT with "cmd.exe"
    assert rule._matcher.matches({"path": "c:\\windows\\system32\\notepad.exe"}) is False


def test_rule_endswith_all_no_suffix_matches(engine: SigmaEngine) -> None:
    """`endswith|all` rule does not match when no suffixes match."""
    rule = engine.load_rule_yaml(_RULE_ALL_ENDSWITH)
    assert rule is not None
    assert rule._matcher.matches({"path": "c:\\tools\\script.ps1"}) is False


def test_rule_endswith_case_insensitive_via_yaml(engine: SigmaEngine) -> None:
    """Matching through load_rule_yaml is case-insensitive."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_ENDSWITH)
    assert rule is not None
    # Field value in uppercase — must still match
    assert rule._matcher.matches({"name": "POWERSHELL.EXE"}) is True
