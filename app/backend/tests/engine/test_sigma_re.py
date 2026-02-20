"""Tests for feature 28.17 — Sigma: `re` modifier matches regex.

Coverage for _Condition._field_matches() with the `re` modifier:
  - Single regex pattern match returns True
  - Single regex pattern no match returns False
  - Match is case-insensitive (pattern uppercase, field lowercase)
  - Match is case-insensitive (pattern lowercase, field uppercase)
  - Pattern anchored at start (^) matches when field starts with pattern
  - Pattern anchored at start (^) does NOT match when field does not start with pattern
  - Pattern anchored at end ($) matches when field ends with pattern
  - Pattern anchored at end ($) does NOT match when field does not end with pattern
  - Pattern matches anywhere in the field value (re.search semantics)
  - Regex character classes (\\d+) match correctly
  - Regex alternation (a|b) within a single pattern matches correctly
  - Invalid regex pattern returns False (no exception raised)
  - Empty pattern matches any non-empty field value
  - List of patterns uses OR semantics — first pattern matches
  - List of patterns uses OR semantics — last pattern matches
  - List of patterns uses OR semantics — none match → False
  - `re|all` with all patterns matching → True
  - `re|all` with one pattern not matching → False
  - Field not present in event → False
  - Field explicitly None → False
  - Nested field via dot notation → matches correctly
  - Numeric field value is coerced to string before matching
  - Dot metacharacter matches any character
  - Quantifier `+` matches one-or-more occurrences
  - Quantifier `*` matches zero-or-more occurrences
  - Word boundary assertion (\\b) works correctly
  - Via load_rule_yaml: rule with single `re` value matches event
  - Via load_rule_yaml: rule with single `re` value does not match
  - Via load_rule_yaml: rule with list `re` values matches event (OR)
  - Via load_rule_yaml: anchored pattern (`^`) matches correctly
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
# Basic single-pattern `re` matching
# ---------------------------------------------------------------------------

def test_re_single_pattern_match() -> None:
    """Simple literal pattern found in field value → True."""
    assert _matches("cmd_line|re", "powershell", {"cmd_line": "powershell.exe -enc abc"}) is True


def test_re_single_pattern_no_match() -> None:
    """Pattern not present in field value → False."""
    assert _matches("cmd_line|re", "mimikatz", {"cmd_line": "powershell.exe"}) is False


def test_re_case_insensitive_upper_pattern() -> None:
    """Pattern in uppercase, field in lowercase — still matches (re.IGNORECASE)."""
    assert _matches("name|re", "POWERSHELL", {"name": "powershell.exe"}) is True


def test_re_case_insensitive_upper_field() -> None:
    """Field value in uppercase, pattern in lowercase — still matches (re.IGNORECASE)."""
    assert _matches("name|re", "powershell", {"name": "POWERSHELL.EXE"}) is True


# ---------------------------------------------------------------------------
# Anchored patterns
# ---------------------------------------------------------------------------

def test_re_anchor_start_match() -> None:
    """Pattern anchored at start (^) matches field that starts with it."""
    assert _matches("cmd_line|re", "^powershell", {"cmd_line": "powershell -enc abc"}) is True


def test_re_anchor_start_no_match() -> None:
    """Pattern anchored at start (^) does NOT match when field begins with something else."""
    assert _matches("cmd_line|re", "^powershell", {"cmd_line": "run powershell -enc"}) is False


def test_re_anchor_end_match() -> None:
    """Pattern anchored at end ($) matches field that ends with it."""
    assert _matches("name|re", r"\.exe$", {"name": "powershell.exe"}) is True


def test_re_anchor_end_no_match() -> None:
    """Pattern anchored at end ($) does NOT match when field doesn't end with it."""
    assert _matches("name|re", r"\.exe$", {"name": "powershell.exe.bak"}) is False


def test_re_full_anchor_match() -> None:
    """Pattern anchored at both ends (^...$) requires exact full-string match."""
    assert _matches("name|re", "^cmd\\.exe$", {"name": "cmd.exe"}) is True


def test_re_full_anchor_no_match_longer_string() -> None:
    """Pattern anchored at both ends does NOT match a longer string."""
    assert _matches("name|re", "^cmd\\.exe$", {"name": "cmd.exe.bak"}) is False


# ---------------------------------------------------------------------------
# re.search semantics — matches anywhere in the string
# ---------------------------------------------------------------------------

def test_re_matches_in_middle_of_field() -> None:
    """Pattern present in the middle of field value → True (re.search, not re.match)."""
    assert _matches("cmd_line|re", "mimikatz", {"cmd_line": "invoke-mimikatz.ps1"}) is True


def test_re_matches_at_end_of_field() -> None:
    """Pattern present at the end of field value → True."""
    assert _matches("cmd_line|re", "lsass", {"cmd_line": "dump-lsass"}) is True


# ---------------------------------------------------------------------------
# Regex metacharacters and features
# ---------------------------------------------------------------------------

def test_re_character_class_digits() -> None:
    r"""\\d+ matches a sequence of digits in the field."""
    assert _matches("pid|re", r"\d+", {"pid": "4567"}) is True


def test_re_character_class_digits_no_match() -> None:
    r"""\\d+ does not match a purely alphabetic field."""
    assert _matches("name|re", r"^\d+$", {"name": "abc"}) is False


def test_re_alternation_first_branch_matches() -> None:
    """Alternation (a|b) — first branch matches → True."""
    assert _matches("name|re", "powershell|cmd", {"name": "powershell.exe"}) is True


def test_re_alternation_second_branch_matches() -> None:
    """Alternation (a|b) — second branch matches → True."""
    assert _matches("name|re", "powershell|cmd", {"name": "cmd.exe"}) is True


def test_re_alternation_no_branch_matches() -> None:
    """Alternation (a|b) — neither branch matches → False."""
    assert _matches("name|re", "powershell|cmd", {"name": "wscript.exe"}) is False


def test_re_dot_metacharacter_matches_any_char() -> None:
    """Dot (.) metacharacter matches any single character."""
    assert _matches("name|re", "p.wershell", {"name": "powershell.exe"}) is True


def test_re_quantifier_plus_one_or_more() -> None:
    """Quantifier + requires one or more of the preceding element."""
    assert _matches("cmd_line|re", r"evil+\.exe", {"cmd_line": "evilll.exe /run"}) is True


def test_re_quantifier_star_zero_or_more() -> None:
    """Quantifier * allows zero or more of the preceding element."""
    assert _matches("cmd_line|re", r"evil*\.exe", {"cmd_line": "evi.exe"}) is True


def test_re_word_boundary_match() -> None:
    r"""\\b word boundary correctly isolates a whole-word match."""
    assert _matches("cmd_line|re", r"\bcmd\b", {"cmd_line": "run cmd /c whoami"}) is True


def test_re_word_boundary_no_match_substring() -> None:
    r"""\\b word boundary does NOT match when pattern is a substring of a word."""
    assert _matches("cmd_line|re", r"\bcmd\b", {"cmd_line": "xcmd /run"}) is False


# ---------------------------------------------------------------------------
# Invalid regex
# ---------------------------------------------------------------------------

def test_re_invalid_pattern_returns_false() -> None:
    """Invalid regex pattern raises re.error internally — should return False, not raise."""
    assert _matches("name|re", "[invalid(", {"name": "anything"}) is False


def test_re_empty_pattern_matches_any() -> None:
    """Empty regex pattern matches any non-empty field value."""
    assert _matches("name|re", "", {"name": "powershell.exe"}) is True


# ---------------------------------------------------------------------------
# List of patterns — OR semantics
# ---------------------------------------------------------------------------

def test_re_list_first_pattern_matches() -> None:
    """OR semantics: first pattern matches → True."""
    assert _matches(
        "cmd_line|re",
        [r"^powershell", r"mimikatz"],
        {"cmd_line": "powershell -enc abc"},
    ) is True


def test_re_list_last_pattern_matches() -> None:
    """OR semantics: only the last pattern matches → still True."""
    assert _matches(
        "cmd_line|re",
        [r"^python", r"mimikatz"],
        {"cmd_line": "invoke-mimikatz.ps1"},
    ) is True


def test_re_list_no_pattern_matches() -> None:
    """OR semantics: no pattern matches → False."""
    assert _matches(
        "cmd_line|re",
        [r"^python", r"mimikatz"],
        {"cmd_line": "benign.exe"},
    ) is False


# ---------------------------------------------------------------------------
# `re|all` — AND semantics
# ---------------------------------------------------------------------------

def test_re_all_both_patterns_match() -> None:
    """re|all: all patterns match → True."""
    assert _matches(
        "cmd_line|re|all",
        [r"powershell", r"-enc"],
        {"cmd_line": "powershell -enc base64abc"},
    ) is True


def test_re_all_one_pattern_does_not_match() -> None:
    """re|all: one pattern does not match → False."""
    assert _matches(
        "cmd_line|re|all",
        [r"powershell", r"mimikatz"],
        {"cmd_line": "powershell -enc base64abc"},
    ) is False


def test_re_all_no_pattern_matches() -> None:
    """re|all: no patterns match → False."""
    assert _matches(
        "cmd_line|re|all",
        [r"mimikatz", r"lsass"],
        {"cmd_line": "benign.exe"},
    ) is False


def test_re_all_single_pattern_matches() -> None:
    """re|all with single pattern that matches → True."""
    assert _matches(
        "name|re|all",
        [r"^powershell"],
        {"name": "powershell.exe"},
    ) is True


def test_re_all_single_pattern_no_match() -> None:
    """re|all with single pattern that does not match → False."""
    assert _matches(
        "name|re|all",
        [r"^cmd"],
        {"name": "powershell.exe"},
    ) is False


# ---------------------------------------------------------------------------
# Field existence
# ---------------------------------------------------------------------------

def test_re_field_missing_returns_false() -> None:
    """Field key not present in event → False (not an error)."""
    assert _matches("cmd_line|re", "powershell", {"process_name": "explorer.exe"}) is False


def test_re_field_value_none_returns_false() -> None:
    """Field explicitly set to None → False."""
    assert _matches("cmd_line|re", "powershell", {"cmd_line": None}) is False


# ---------------------------------------------------------------------------
# Nested field (dot notation)
# ---------------------------------------------------------------------------

def test_re_nested_field_match() -> None:
    """Dot-notation field lookup works with re modifier."""
    event = {"process": {"cmd_line": "powershell -enc abc"}}
    assert _matches("process.cmd_line|re", r"^powershell", event) is True


def test_re_nested_field_no_match() -> None:
    """Dot-notation field value that doesn't match pattern → False."""
    event = {"process": {"cmd_line": "cmd.exe /c whoami"}}
    assert _matches("process.cmd_line|re", r"^powershell", event) is False


def test_re_nested_field_missing() -> None:
    """Dot-notation where intermediate key is absent → False."""
    event = {"process": {}}
    assert _matches("process.cmd_line|re", "powershell", event) is False


# ---------------------------------------------------------------------------
# Non-string field types
# ---------------------------------------------------------------------------

def test_re_numeric_field_coerced_to_string() -> None:
    r"""Numeric field values are coerced to string before matching."""
    # 4321 → "4321", regex \\d+ matches
    assert _matches("pid|re", r"^\d{4}$", {"pid": 4321}) is True


def test_re_numeric_field_pattern_no_match() -> None:
    """Coerced numeric value that doesn't match pattern → False."""
    # 42 → "42", regex ^\\d{4}$ requires exactly 4 digits
    assert _matches("pid|re", r"^\d{4}$", {"pid": 42}) is False


# ---------------------------------------------------------------------------
# Two-field selection — AND across fields
# ---------------------------------------------------------------------------

def test_re_two_field_selection_both_match() -> None:
    """When selection has two re fields both must match their patterns."""
    detection = {
        "selection": {
            "cmd_line|re": r"^powershell",
            "name|re": r"\.exe$",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"cmd_line": "powershell -enc abc", "name": "powershell.exe"}
    assert cond.matches(event) is True


def test_re_two_field_selection_one_fails() -> None:
    """When selection has two re fields and one doesn't match → False."""
    detection = {
        "selection": {
            "cmd_line|re": r"^powershell",
            "name|re": r"^cmd",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"cmd_line": "powershell -enc abc", "name": "powershell.exe"}
    assert cond.matches(event) is False


def test_re_two_field_selection_one_field_absent() -> None:
    """When one field is absent from the event → False."""
    detection = {
        "selection": {
            "cmd_line|re": r"^powershell",
            "name|re": r"\.exe$",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"cmd_line": "powershell -enc abc"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_SINGLE_RE = """\
title: Detect Encoded PowerShell
id: test-re-001
status: test
level: high
logsource:
  category: process_creation
detection:
  selection:
    cmd_line|re: '^powershell.*-enc'
  condition: selection
"""

_RULE_LIST_RE = """\
title: Detect Suspicious Processes
id: test-re-002
status: test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    name|re:
      - '^powershell'
      - '^cmd\\.exe'
      - 'mimikatz'
  condition: selection
"""

_RULE_ANCHORED_RE = """\
title: Detect Exact Executable Name
id: test-re-003
status: test
level: critical
logsource:
  category: process_creation
detection:
  selection:
    name|re: '^cmd\\.exe$'
  condition: selection
"""


def test_rule_single_re_matches(engine: SigmaEngine) -> None:
    """Rule with single `re` value matches an event whose field satisfies the regex."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_RE)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "powershell -enc SGVsbG8="}) is True


def test_rule_single_re_no_match(engine: SigmaEngine) -> None:
    """Rule with single `re` value does not match when field doesn't satisfy the regex."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_RE)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "powershell -nop -c whoami"}) is False


def test_rule_single_re_no_match_wrong_prefix(engine: SigmaEngine) -> None:
    """Rule anchored with ^ does not match when the field starts with something else."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_RE)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "cmd.exe /c powershell -enc test"}) is False


def test_rule_list_re_first_pattern_matches(engine: SigmaEngine) -> None:
    """Rule list `re` matches event satisfying the first pattern."""
    rule = engine.load_rule_yaml(_RULE_LIST_RE)
    assert rule is not None
    assert rule._matcher.matches({"name": "powershell.exe"}) is True


def test_rule_list_re_second_pattern_matches(engine: SigmaEngine) -> None:
    """Rule list `re` matches event satisfying the second pattern."""
    rule = engine.load_rule_yaml(_RULE_LIST_RE)
    assert rule is not None
    assert rule._matcher.matches({"name": "cmd.exe"}) is True


def test_rule_list_re_third_pattern_matches(engine: SigmaEngine) -> None:
    """Rule list `re` matches event satisfying the third (unanchored) pattern."""
    rule = engine.load_rule_yaml(_RULE_LIST_RE)
    assert rule is not None
    assert rule._matcher.matches({"name": "invoke-mimikatz.ps1"}) is True


def test_rule_list_re_no_pattern_matches(engine: SigmaEngine) -> None:
    """Rule list `re` does not match when no pattern is satisfied."""
    rule = engine.load_rule_yaml(_RULE_LIST_RE)
    assert rule is not None
    assert rule._matcher.matches({"name": "benign.exe"}) is False


def test_rule_anchored_re_exact_match(engine: SigmaEngine) -> None:
    """Rule with fully anchored regex (^...$) matches exact string."""
    rule = engine.load_rule_yaml(_RULE_ANCHORED_RE)
    assert rule is not None
    assert rule._matcher.matches({"name": "cmd.exe"}) is True


def test_rule_anchored_re_no_match_longer_string(engine: SigmaEngine) -> None:
    """Rule with fully anchored regex does not match a longer/different string."""
    rule = engine.load_rule_yaml(_RULE_ANCHORED_RE)
    assert rule is not None
    assert rule._matcher.matches({"name": "cmd.exe.bak"}) is False


def test_rule_re_case_insensitive_via_yaml(engine: SigmaEngine) -> None:
    """Matching through load_rule_yaml is case-insensitive for `re` modifier."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_RE)
    assert rule is not None
    # Field value uppercase — must still match because re.IGNORECASE is set
    assert rule._matcher.matches({"cmd_line": "POWERSHELL -ENC SGVsbG8="}) is True
