"""Tests for feature 8.12 — Sigma: `all` modifier (AND for list values).

The `|all` modifier changes the default OR semantics of a value list to AND:
every value in the list must satisfy the condition for the field.

Coverage:
  - `contains|all`: all substrings must appear in the field → True
  - `contains|all`: any substring absent → False
  - `startswith|all`: field must begin with ALL listed prefixes → True only
    when every prefix is a prefix of the field (nested prefixes work)
  - `startswith|all`: one prefix absent → False
  - `endswith|all`: field must end with ALL listed suffixes → True only
    when every suffix is a suffix of the field (nested suffixes work)
  - `endswith|all`: one suffix absent → False
  - `re|all`: field must match ALL listed regex patterns → True
  - `re|all`: one pattern unmatched → False
  - `|all` with a single-element list behaves identically to OR semantics
  - `|all` vs `|` (default OR) on same data confirms semantic difference
  - Field not in event → False for all `|all` combinations
  - Field explicitly None → False for all `|all` combinations
  - `|all` on nested field via dot notation → correct AND evaluation
  - Numeric field coerced to string before `|all` matching
  - `contains|all` inside a two-field selection — both AND'd at selection level
  - Via load_rule_yaml: `contains|all` matches when all values present
  - Via load_rule_yaml: `contains|all` does not match when one value absent
  - Via load_rule_yaml: `startswith|all` matches when all prefixes present
  - Via load_rule_yaml: `startswith|all` does not match when one prefix absent
  - Via load_rule_yaml: `endswith|all` matches when all suffixes present
  - Via load_rule_yaml: `endswith|all` does not match when one suffix absent
  - Via load_rule_yaml: `re|all` matches when all patterns match
  - Via load_rule_yaml: `re|all` does not match when one pattern fails
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


@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


# ---------------------------------------------------------------------------
# contains|all
# ---------------------------------------------------------------------------

def test_contains_all_all_values_present() -> None:
    """`contains|all`: all listed substrings found in field → True."""
    assert _matches(
        "cmd_line|contains|all",
        ["-enc", "powershell"],
        {"cmd_line": "powershell -enc somedata"},
    ) is True


def test_contains_all_one_value_absent() -> None:
    """`contains|all`: one value absent from field → False."""
    assert _matches(
        "cmd_line|contains|all",
        ["-enc", "mimikatz"],
        {"cmd_line": "powershell -enc somedata"},
    ) is False


def test_contains_all_no_values_present() -> None:
    """`contains|all`: none of the values found → False."""
    assert _matches(
        "cmd_line|contains|all",
        ["-enc", "mimikatz"],
        {"cmd_line": "python benign.py"},
    ) is False


def test_contains_all_single_element_list() -> None:
    """`contains|all` with a single-element list: identical to OR semantics."""
    # OR would also be True here; |all with one element is the same
    assert _matches(
        "cmd_line|contains|all",
        ["mimikatz"],
        {"cmd_line": "invoke-mimikatz -DumpCreds"},
    ) is True


def test_contains_all_vs_or_semantic_difference() -> None:
    """`contains|all` requires ALL present; `contains` (OR) only needs one."""
    event = {"cmd_line": "powershell -enc somedata"}
    # OR semantics: True because '-enc' is present
    assert _matches("cmd_line|contains", ["-enc", "mimikatz"], event) is True
    # AND semantics: False because 'mimikatz' is absent
    assert _matches("cmd_line|contains|all", ["-enc", "mimikatz"], event) is False


def test_contains_all_field_missing() -> None:
    """`contains|all`: field absent from event → False."""
    assert _matches(
        "cmd_line|contains|all",
        ["-enc", "powershell"],
        {"process_name": "explorer.exe"},
    ) is False


def test_contains_all_field_none() -> None:
    """`contains|all`: field value is None → False."""
    assert _matches(
        "cmd_line|contains|all",
        ["-enc", "powershell"],
        {"cmd_line": None},
    ) is False


def test_contains_all_nested_field() -> None:
    """`contains|all` on dot-notation nested field: AND semantics apply."""
    event = {"process": {"cmd_line": "powershell -enc somedata"}}
    assert _matches("process.cmd_line|contains|all", ["-enc", "powershell"], event) is True


def test_contains_all_nested_field_one_absent() -> None:
    """`contains|all` on nested field: one value absent → False."""
    event = {"process": {"cmd_line": "powershell -enc somedata"}}
    assert _matches("process.cmd_line|contains|all", ["-enc", "mimikatz"], event) is False


def test_contains_all_case_insensitive() -> None:
    """`contains|all` matching is case-insensitive."""
    assert _matches(
        "cmd_line|contains|all",
        ["POWERSHELL", "-ENC"],
        {"cmd_line": "powershell -enc base64"},
    ) is True


def test_contains_all_numeric_field_coerced() -> None:
    """`contains|all`: numeric field is coerced to string before matching."""
    # pid=12345 → "12345" contains "123" and "45"
    assert _matches("pid|contains|all", ["123", "45"], {"pid": 12345}) is True


def test_contains_all_numeric_field_missing_substring() -> None:
    """`contains|all`: numeric coercion, one substring absent → False."""
    assert _matches("pid|contains|all", ["123", "999"], {"pid": 12345}) is False


# ---------------------------------------------------------------------------
# startswith|all
# ---------------------------------------------------------------------------

def test_startswith_all_nested_prefixes_match() -> None:
    """`startswith|all`: field starts with all listed prefixes → True.

    'powershell' starts with 'power' AND 'powershell' (itself).
    """
    assert _matches(
        "name|startswith|all",
        ["power", "powershell"],
        {"name": "powershell.exe"},
    ) is True


def test_startswith_all_one_prefix_absent() -> None:
    """`startswith|all`: one prefix not a prefix of field → False."""
    assert _matches(
        "name|startswith|all",
        ["power", "cmd"],
        {"name": "powershell.exe"},
    ) is False


def test_startswith_all_single_element() -> None:
    """`startswith|all` with single element behaves like OR."""
    assert _matches(
        "name|startswith|all",
        ["power"],
        {"name": "powershell.exe"},
    ) is True


def test_startswith_all_field_missing() -> None:
    """`startswith|all`: field absent → False."""
    assert _matches(
        "name|startswith|all",
        ["power", "powershell"],
        {"cmd_line": "powershell.exe"},
    ) is False


def test_startswith_all_field_none() -> None:
    """`startswith|all`: field value is None → False."""
    assert _matches(
        "name|startswith|all",
        ["power"],
        {"name": None},
    ) is False


def test_startswith_all_nested_field() -> None:
    """`startswith|all` on dot-notation field."""
    event = {"process": {"name": "powershell.exe"}}
    assert _matches("process.name|startswith|all", ["power", "powershell"], event) is True


def test_startswith_all_vs_or_difference() -> None:
    """`startswith|all` vs `startswith` (OR) on same data."""
    event = {"name": "powershell.exe"}
    # OR: True because 'power' is a prefix
    assert _matches("name|startswith", ["power", "cmd"], event) is True
    # AND: False because 'cmd' is NOT a prefix
    assert _matches("name|startswith|all", ["power", "cmd"], event) is False


# ---------------------------------------------------------------------------
# endswith|all
# ---------------------------------------------------------------------------

def test_endswith_all_nested_suffixes_match() -> None:
    """`endswith|all`: field ends with all listed suffixes → True.

    'powershell.exe' ends with '.exe' AND 'shell.exe'.
    """
    assert _matches(
        "name|endswith|all",
        [".exe", "shell.exe"],
        {"name": "powershell.exe"},
    ) is True


def test_endswith_all_one_suffix_absent() -> None:
    """`endswith|all`: one suffix not a suffix of field → False."""
    assert _matches(
        "name|endswith|all",
        [".exe", ".dll"],
        {"name": "powershell.exe"},
    ) is False


def test_endswith_all_single_element() -> None:
    """`endswith|all` with single element behaves like OR."""
    assert _matches(
        "name|endswith|all",
        [".exe"],
        {"name": "powershell.exe"},
    ) is True


def test_endswith_all_field_missing() -> None:
    """`endswith|all`: field absent → False."""
    assert _matches(
        "name|endswith|all",
        [".exe", ".dll"],
        {"cmd_line": "powershell.exe"},
    ) is False


def test_endswith_all_field_none() -> None:
    """`endswith|all`: field value is None → False."""
    assert _matches(
        "name|endswith|all",
        [".exe"],
        {"name": None},
    ) is False


def test_endswith_all_nested_field() -> None:
    """`endswith|all` on dot-notation field."""
    event = {"process": {"name": "powershell.exe"}}
    assert _matches("process.name|endswith|all", [".exe", "shell.exe"], event) is True


def test_endswith_all_vs_or_difference() -> None:
    """`endswith|all` vs `endswith` (OR) on same data."""
    event = {"name": "powershell.exe"}
    # OR: True because '.exe' is a suffix
    assert _matches("name|endswith", [".exe", ".dll"], event) is True
    # AND: False because '.dll' is NOT a suffix
    assert _matches("name|endswith|all", [".exe", ".dll"], event) is False


# ---------------------------------------------------------------------------
# re|all
# ---------------------------------------------------------------------------

def test_re_all_all_patterns_match() -> None:
    """`re|all`: field matches all listed regex patterns → True."""
    assert _matches(
        "cmd_line|re|all",
        [r"powershell", r"-enc\s+\w+"],
        {"cmd_line": "powershell -enc abc123"},
    ) is True


def test_re_all_one_pattern_fails() -> None:
    """`re|all`: one pattern does not match → False."""
    assert _matches(
        "cmd_line|re|all",
        [r"powershell", r"mimikatz"],
        {"cmd_line": "powershell -enc abc123"},
    ) is False


def test_re_all_no_patterns_match() -> None:
    """`re|all`: no patterns match → False."""
    assert _matches(
        "cmd_line|re|all",
        [r"powershell", r"mimikatz"],
        {"cmd_line": "python benign.py"},
    ) is False


def test_re_all_single_pattern() -> None:
    """`re|all` with a single-element pattern list → same as OR."""
    assert _matches(
        "cmd_line|re|all",
        [r"^powershell"],
        {"cmd_line": "powershell -enc abc"},
    ) is True


def test_re_all_anchored_patterns() -> None:
    """`re|all` with anchored patterns: ^ start and $ end must both match."""
    # "cmd.exe" starts with "cmd" AND ends with ".exe"
    assert _matches(
        "name|re|all",
        [r"^cmd", r"\.exe$"],
        {"name": "cmd.exe"},
    ) is True


def test_re_all_anchored_one_fails() -> None:
    """`re|all` with anchored patterns: one anchor mismatch → False."""
    # "powershell.exe" does NOT start with "cmd"
    assert _matches(
        "name|re|all",
        [r"^cmd", r"\.exe$"],
        {"name": "powershell.exe"},
    ) is False


def test_re_all_field_missing() -> None:
    """`re|all`: field absent → False."""
    assert _matches(
        "cmd_line|re|all",
        [r"powershell", r"-enc"],
        {"process_name": "powershell.exe"},
    ) is False


def test_re_all_field_none() -> None:
    """`re|all`: field value is None → False."""
    assert _matches(
        "cmd_line|re|all",
        [r"powershell"],
        {"cmd_line": None},
    ) is False


def test_re_all_nested_field() -> None:
    """`re|all` on dot-notation nested field."""
    event = {"process": {"cmd_line": "powershell -enc abc123"}}
    assert _matches(
        "process.cmd_line|re|all",
        [r"powershell", r"-enc"],
        event,
    ) is True


def test_re_all_case_insensitive() -> None:
    """`re|all` matching is case-insensitive."""
    assert _matches(
        "cmd_line|re|all",
        [r"POWERSHELL", r"-ENC"],
        {"cmd_line": "powershell -enc somedata"},
    ) is True


def test_re_all_vs_or_difference() -> None:
    """`re|all` vs `re` (OR) on same data confirms semantic difference."""
    event = {"cmd_line": "powershell -enc abc"}
    # OR: True because 'powershell' matches
    assert _matches("cmd_line|re", [r"powershell", r"mimikatz"], event) is True
    # AND: False because 'mimikatz' does not match
    assert _matches("cmd_line|re|all", [r"powershell", r"mimikatz"], event) is False


# ---------------------------------------------------------------------------
# |all inside a two-field selection (selection-level AND)
# ---------------------------------------------------------------------------

def test_contains_all_in_two_field_selection_both_pass() -> None:
    """`contains|all` in multi-field selection: both fields must satisfy their own |all."""
    detection = {
        "selection": {
            "cmd_line|contains|all": ["-enc", "powershell"],
            "name|contains|all": ["shell", ".exe"],
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"cmd_line": "powershell -enc abc", "name": "powershell.exe"}
    assert cond.matches(event) is True


def test_contains_all_in_two_field_selection_one_field_fails() -> None:
    """`contains|all` in multi-field selection: one field fails → overall False."""
    detection = {
        "selection": {
            "cmd_line|contains|all": ["-enc", "powershell"],
            "name|contains|all": ["shell", ".exe"],
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    # name field is missing the ".exe" suffix content
    event = {"cmd_line": "powershell -enc abc", "name": "cmd.exe"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_CONTAINS_ALL = """\
title: Detect Mimikatz Invoke
id: test-all-001
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

_RULE_STARTSWITH_ALL = """\
title: Detect Nested PowerShell Prefix
id: test-all-002
status: test
level: high
logsource:
  category: process_creation
detection:
  selection:
    name|startswith|all:
      - 'power'
      - 'powershell'
  condition: selection
"""

_RULE_ENDSWITH_ALL = """\
title: Detect EXE with Shell Suffix
id: test-all-003
status: test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    name|endswith|all:
      - '.exe'
      - 'shell.exe'
  condition: selection
"""

_RULE_RE_ALL = """\
title: Detect CMD EXE Pattern
id: test-all-004
status: test
level: high
logsource:
  category: process_creation
detection:
  selection:
    name|re|all:
      - '^cmd'
      - '\\.exe$'
  condition: selection
"""


def test_yaml_contains_all_matches(engine: SigmaEngine) -> None:
    """`contains|all` via load_rule_yaml: both values present → True."""
    rule = engine.load_rule_yaml(_RULE_CONTAINS_ALL)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "invoke-mimikatz -DumpCreds"}) is True


def test_yaml_contains_all_one_absent(engine: SigmaEngine) -> None:
    """`contains|all` via load_rule_yaml: one value absent → False."""
    rule = engine.load_rule_yaml(_RULE_CONTAINS_ALL)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "invoke-expression -DumpCreds"}) is False


def test_yaml_contains_all_none_present(engine: SigmaEngine) -> None:
    """`contains|all` via load_rule_yaml: no values present → False."""
    rule = engine.load_rule_yaml(_RULE_CONTAINS_ALL)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "python benign.py"}) is False


def test_yaml_startswith_all_matches(engine: SigmaEngine) -> None:
    """`startswith|all` via load_rule_yaml: nested prefixes present → True."""
    rule = engine.load_rule_yaml(_RULE_STARTSWITH_ALL)
    assert rule is not None
    assert rule._matcher.matches({"name": "powershell.exe"}) is True


def test_yaml_startswith_all_one_absent(engine: SigmaEngine) -> None:
    """`startswith|all` via load_rule_yaml: field starts with 'power' but not 'powershell' → False."""
    rule = engine.load_rule_yaml(_RULE_STARTSWITH_ALL)
    assert rule is not None
    # "powerpoint.exe" starts with "power" but NOT "powershell"
    assert rule._matcher.matches({"name": "powerpoint.exe"}) is False


def test_yaml_endswith_all_matches(engine: SigmaEngine) -> None:
    """`endswith|all` via load_rule_yaml: nested suffixes present → True."""
    rule = engine.load_rule_yaml(_RULE_ENDSWITH_ALL)
    assert rule is not None
    assert rule._matcher.matches({"name": "powershell.exe"}) is True


def test_yaml_endswith_all_one_absent(engine: SigmaEngine) -> None:
    """`endswith|all` via load_rule_yaml: ends with '.exe' but not 'shell.exe' → False."""
    rule = engine.load_rule_yaml(_RULE_ENDSWITH_ALL)
    assert rule is not None
    # "cmd.exe" ends with ".exe" but NOT "shell.exe"
    assert rule._matcher.matches({"name": "cmd.exe"}) is False


def test_yaml_re_all_matches(engine: SigmaEngine) -> None:
    """`re|all` via load_rule_yaml: all patterns match → True."""
    rule = engine.load_rule_yaml(_RULE_RE_ALL)
    assert rule is not None
    assert rule._matcher.matches({"name": "cmd.exe"}) is True


def test_yaml_re_all_one_pattern_fails(engine: SigmaEngine) -> None:
    """`re|all` via load_rule_yaml: one pattern fails → False."""
    rule = engine.load_rule_yaml(_RULE_RE_ALL)
    assert rule is not None
    # "powershell.exe" does NOT start with "cmd"
    assert rule._matcher.matches({"name": "powershell.exe"}) is False
