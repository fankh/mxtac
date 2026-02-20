"""Tests for feature 28.15 — Sigma: `contains` modifier matches.

Coverage for _Condition._field_matches() with the `contains` modifier:
  - Single value substring match returns True
  - Single value no match returns False
  - Match is case-insensitive (search value uppercase, field lowercase)
  - Match is case-insensitive (search value lowercase, field uppercase)
  - Substring at the start of the field value matches
  - Substring at the end of the field value matches
  - Substring in the middle of the field value matches
  - Empty search string always matches (empty string is a substring of any string)
  - List of values uses OR semantics — first value matches
  - List of values uses OR semantics — last value matches
  - List of values uses OR semantics — none match → False
  - `contains|all` with all values present → True
  - `contains|all` with one value absent → False
  - Field not present in event → False
  - Nested field via dot notation → matches correctly
  - Numeric field value is coerced to string before matching
  - `contains` does NOT match `startswith`-only patterns correctly (exact check)
  - Via load_rule_yaml: rule with single `contains` value matches event
  - Via load_rule_yaml: rule with single `contains` value does not match
  - Via load_rule_yaml: rule with list `contains` value matches event (OR)
  - Via load_rule_yaml: rule with `contains|all` matches when all present
  - Via load_rule_yaml: rule with `contains|all` does not match when one absent
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
# Basic single-value `contains` matching
# ---------------------------------------------------------------------------

def test_contains_single_value_match() -> None:
    """Substring present in field value → True."""
    assert _matches("cmd_line|contains", "evil", {"cmd_line": "run evil.exe now"}) is True


def test_contains_single_value_no_match() -> None:
    """Substring absent from field value → False."""
    assert _matches("cmd_line|contains", "evil", {"cmd_line": "benign process"}) is False


def test_contains_case_insensitive_upper_pattern() -> None:
    """Search value is uppercase, field is lowercase — still matches."""
    assert _matches("cmd_line|contains", "EVIL", {"cmd_line": "run evil.exe"}) is True


def test_contains_case_insensitive_upper_field() -> None:
    """Field value is uppercase, search value is lowercase — still matches."""
    assert _matches("cmd_line|contains", "evil", {"cmd_line": "RUN EVIL.EXE"}) is True


def test_contains_substring_at_start() -> None:
    """Substring at the beginning of the field value → True."""
    assert _matches("cmd_line|contains", "powershell", {"cmd_line": "powershell -enc abc"}) is True


def test_contains_substring_at_end() -> None:
    """Substring at the end of the field value → True."""
    assert _matches("cmd_line|contains", ".exe", {"cmd_line": "run evil.exe"}) is True


def test_contains_substring_in_middle() -> None:
    """Substring fully embedded inside field value → True."""
    assert _matches("cmd_line|contains", "-enc", {"cmd_line": "powershell -enc base64data"}) is True


def test_contains_empty_search_string_always_matches() -> None:
    """Empty string is a substring of any non-empty string."""
    assert _matches("cmd_line|contains", "", {"cmd_line": "anything"}) is True


# ---------------------------------------------------------------------------
# List of values — OR semantics
# ---------------------------------------------------------------------------

def test_contains_list_first_value_matches() -> None:
    """OR semantics: first value present in field → True."""
    assert _matches("cmd_line|contains", ["-enc", "-nop"], {"cmd_line": "powershell -enc abc"}) is True


def test_contains_list_last_value_matches() -> None:
    """OR semantics: only the last value is present → still True."""
    assert _matches("cmd_line|contains", ["-enc", "-nop"], {"cmd_line": "powershell -nop abc"}) is True


def test_contains_list_no_value_matches() -> None:
    """OR semantics: no value in list matches → False."""
    assert _matches("cmd_line|contains", ["-enc", "-nop"], {"cmd_line": "python script.py"}) is False


def test_contains_list_multiple_values_match() -> None:
    """OR semantics: multiple values match — still True (not exclusive)."""
    assert _matches("cmd_line|contains", ["-enc", "powershell"], {"cmd_line": "powershell -enc abc"}) is True


# ---------------------------------------------------------------------------
# `contains|all` — AND semantics
# ---------------------------------------------------------------------------

def test_contains_all_all_values_present() -> None:
    """contains|all: all listed values present in field → True."""
    assert _matches(
        "cmd_line|contains|all",
        ["-enc", "powershell"],
        {"cmd_line": "powershell -enc somedata"},
    ) is True


def test_contains_all_one_value_absent() -> None:
    """contains|all: one value absent → False."""
    assert _matches(
        "cmd_line|contains|all",
        ["-enc", "mimikatz"],
        {"cmd_line": "powershell -enc somedata"},
    ) is False


def test_contains_all_none_present() -> None:
    """contains|all: no values present → False."""
    assert _matches(
        "cmd_line|contains|all",
        ["-enc", "mimikatz"],
        {"cmd_line": "python benign.py"},
    ) is False


def test_contains_all_single_value_present() -> None:
    """contains|all with a single-element list and it matches → True."""
    assert _matches(
        "cmd_line|contains|all",
        ["mimikatz"],
        {"cmd_line": "invoke-mimikatz dump"},
    ) is True


# ---------------------------------------------------------------------------
# Field existence
# ---------------------------------------------------------------------------

def test_contains_field_missing_returns_false() -> None:
    """Field key not present in event → False (not an error)."""
    assert _matches("cmd_line|contains", "evil", {"process_name": "explorer.exe"}) is False


def test_contains_field_value_none_returns_false() -> None:
    """Field explicitly set to None → False."""
    assert _matches("cmd_line|contains", "evil", {"cmd_line": None}) is False


# ---------------------------------------------------------------------------
# Nested field (dot notation)
# ---------------------------------------------------------------------------

def test_contains_nested_field_match() -> None:
    """Dot-notation field lookup works with contains modifier."""
    event = {"process": {"cmd_line": "powershell -enc abc"}}
    assert _matches("process.cmd_line|contains", "-enc", event) is True


def test_contains_nested_field_no_match() -> None:
    """Dot-notation field that doesn't contain value → False."""
    event = {"process": {"cmd_line": "benign.exe"}}
    assert _matches("process.cmd_line|contains", "evil", event) is False


def test_contains_nested_field_missing() -> None:
    """Dot-notation where intermediate key is absent → False."""
    event = {"process": {}}  # no cmd_line key
    assert _matches("process.cmd_line|contains", "evil", event) is False


# ---------------------------------------------------------------------------
# Non-string field types
# ---------------------------------------------------------------------------

def test_contains_numeric_field_coerced_to_string() -> None:
    """Numeric field values are coerced to string before matching."""
    assert _matches("pid|contains", "123", {"pid": 12345}) is True


def test_contains_numeric_field_no_match() -> None:
    """Coerced numeric value that doesn't contain search string → False."""
    assert _matches("pid|contains", "999", {"pid": 12345}) is False


# ---------------------------------------------------------------------------
# Interaction with other conditions / AND across fields
# ---------------------------------------------------------------------------

def test_contains_two_field_selection_both_match() -> None:
    """When selection has two fields both must match (AND)."""
    detection = {
        "selection": {
            "cmd_line|contains": "-enc",
            "name|contains": "powershell",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"cmd_line": "powershell -enc abc", "name": "powershell.exe"}
    assert cond.matches(event) is True


def test_contains_two_field_selection_one_missing() -> None:
    """When selection has two fields and one doesn't match → False."""
    detection = {
        "selection": {
            "cmd_line|contains": "-enc",
            "name|contains": "powershell",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    # name field absent
    event = {"cmd_line": "powershell -enc abc"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_SINGLE_CONTAINS = """\
title: Detect Encoded Command
id: test-contains-001
status: test
level: high
logsource:
  category: process_creation
detection:
  selection:
    cmd_line|contains: '-enc'
  condition: selection
"""

_RULE_LIST_CONTAINS = """\
title: Detect Encoded or NoProfile
id: test-contains-002
status: test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    cmd_line|contains:
      - '-enc'
      - '-noprofile'
  condition: selection
"""

_RULE_ALL_CONTAINS = """\
title: Detect Mimikatz Invoke
id: test-contains-003
status: test
level: critical
logsource:
  category: process_creation
detection:
  selection:
    cmd_line|contains|all:
      - 'invoke'
      - 'mimikatz'
  condition: selection
"""


def test_rule_single_contains_matches(engine: SigmaEngine) -> None:
    """Rule with single `contains` value matches an event whose field contains it."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_CONTAINS)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "powershell -enc somebase64"}) is True


def test_rule_single_contains_no_match(engine: SigmaEngine) -> None:
    """Rule with single `contains` value does not match when absent."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_CONTAINS)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "python benign_script.py"}) is False


def test_rule_list_contains_first_value_matches(engine: SigmaEngine) -> None:
    """Rule list `contains` matches event containing first list value."""
    rule = engine.load_rule_yaml(_RULE_LIST_CONTAINS)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "powershell -enc abc"}) is True


def test_rule_list_contains_second_value_matches(engine: SigmaEngine) -> None:
    """Rule list `contains` matches event containing second list value."""
    rule = engine.load_rule_yaml(_RULE_LIST_CONTAINS)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "powershell -noprofile -c whoami"}) is True


def test_rule_list_contains_no_value_matches(engine: SigmaEngine) -> None:
    """Rule list `contains` does not match when no listed value is present."""
    rule = engine.load_rule_yaml(_RULE_LIST_CONTAINS)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "python benign.py"}) is False


def test_rule_contains_all_both_present(engine: SigmaEngine) -> None:
    """`contains|all` rule matches when all values are present in the field."""
    rule = engine.load_rule_yaml(_RULE_ALL_CONTAINS)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "invoke-mimikatz -DumpCreds"}) is True


def test_rule_contains_all_one_absent(engine: SigmaEngine) -> None:
    """`contains|all` rule does not match when one value is absent."""
    rule = engine.load_rule_yaml(_RULE_ALL_CONTAINS)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "invoke-expression -DumpCreds"}) is False


def test_rule_contains_all_none_present(engine: SigmaEngine) -> None:
    """`contains|all` rule does not match when no values are present."""
    rule = engine.load_rule_yaml(_RULE_ALL_CONTAINS)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "python benign.py"}) is False


def test_rule_contains_case_insensitive_via_yaml(engine: SigmaEngine) -> None:
    """Matching through load_rule_yaml is case-insensitive."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_CONTAINS)
    assert rule is not None
    # Field value in uppercase — must still match
    assert rule._matcher.matches({"cmd_line": "POWERSHELL -ENC SOMEBASE64"}) is True
