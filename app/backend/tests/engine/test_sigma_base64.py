"""Tests for feature 8.10 — Sigma: `base64` modifier.

The `base64` modifier encodes plaintext rule values to base64 before matching
against event field values.  Matching is case-sensitive because base64
character case is semantically meaningful.

Coverage:
  - Exact match: field equals base64(value) → True
  - Exact match: field differs from base64(value) → False
  - Matching is case-sensitive — wrong case in event field → False
  - Field absent → False
  - Field explicitly None → False
  - Numeric field coerced to string before comparing → works correctly
  - Nested field (dot notation) → matches correctly
  - List of values uses OR semantics — first encoded value matches → True
  - List of values uses OR semantics — last encoded value matches → True
  - List of values uses OR semantics — none match → False
  - `base64|all` with all encoded values matching → True
  - `base64|all` with one missing → False
  - `base64|contains` — encoded value is substring of field → True
  - `base64|contains` — encoded value absent from field → False
  - `base64|contains|all` — all encoded values substrings → True
  - `base64|contains|all` — one encoded value missing → False
  - `base64|startswith` — field starts with encoded value → True
  - `base64|startswith` — field does not start with encoded value → False
  - `base64|endswith` — field ends with encoded value → True
  - `base64|endswith` — field does not end with encoded value → False
  - Invalid / exception-safe encoding (empty string value) → handled gracefully
  - Via load_rule_yaml: rule with single `base64` value matches event
  - Via load_rule_yaml: rule with single `base64` value does not match
  - Via load_rule_yaml: rule with list `base64` values matches event (OR)
  - Via load_rule_yaml: `base64|contains` matches encoded substring in field
"""

from __future__ import annotations

import base64 as _b64

import pytest

from app.engine.sigma_engine import SigmaEngine, _Condition


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _enc(plain: str) -> str:
    """Return the base64 encoding of a UTF-8 string."""
    return _b64.b64encode(plain.encode("utf-8")).decode("ascii")


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
# Exact match (no additional modifier)
# ---------------------------------------------------------------------------

def test_base64_exact_match() -> None:
    """Field equals base64(value) → True."""
    plain = "cmd.exe"
    assert _matches("name|base64", plain, {"name": _enc(plain)}) is True


def test_base64_exact_no_match_wrong_value() -> None:
    """Field equals base64 of a different string → False."""
    assert _matches("name|base64", "cmd.exe", {"name": _enc("powershell.exe")}) is False


def test_base64_exact_no_match_plaintext() -> None:
    """Field holds plaintext (not encoded) → False (modifier requires encoded field)."""
    assert _matches("name|base64", "hello", {"name": "hello"}) is False


def test_base64_case_sensitive_wrong_case() -> None:
    """Base64 matching is case-sensitive — wrong-case field value → False."""
    plain = "hello"
    encoded = _enc(plain)          # e.g., "aGVsbG8="
    lower_encoded = encoded.lower()  # e.g., "agvsbg8="
    # Only matches if the field contains exactly the same case
    assert _matches("name|base64", plain, {"name": lower_encoded}) is False


def test_base64_case_sensitive_correct_case() -> None:
    """Base64 matching with correct case in field → True."""
    plain = "hello"
    assert _matches("name|base64", plain, {"name": _enc(plain)}) is True


# ---------------------------------------------------------------------------
# Field existence
# ---------------------------------------------------------------------------

def test_base64_field_missing_returns_false() -> None:
    """Field not present in event → False."""
    assert _matches("cmd_line|base64", "test", {"other_field": "value"}) is False


def test_base64_field_none_returns_false() -> None:
    """Field explicitly set to None → False."""
    assert _matches("cmd_line|base64", "test", {"cmd_line": None}) is False


# ---------------------------------------------------------------------------
# Nested field (dot notation)
# ---------------------------------------------------------------------------

def test_base64_nested_field_match() -> None:
    """Dot-notation field lookup works with base64 modifier."""
    plain = "evil"
    event = {"process": {"name": _enc(plain)}}
    assert _matches("process.name|base64", plain, event) is True


def test_base64_nested_field_no_match() -> None:
    """Dot-notation field that doesn't match → False."""
    event = {"process": {"name": _enc("benign")}}
    assert _matches("process.name|base64", "evil", event) is False


def test_base64_nested_field_missing() -> None:
    """Dot-notation where intermediate key is absent → False."""
    event = {"process": {}}
    assert _matches("process.name|base64", "evil", event) is False


# ---------------------------------------------------------------------------
# Non-string field types
# ---------------------------------------------------------------------------

def test_base64_numeric_field_coerced_no_match() -> None:
    """Numeric field is str()-coerced before comparison — str(42)='42' ≠ base64('42')='NDI='."""
    # The field value 42 is coerced to "42", but the encoded rule value is "NDI=".
    # They are not equal, so this returns False (coercion works but values differ).
    assert _matches("count|base64", "42", {"count": 42}) is False


def test_base64_numeric_field_coerced_string_holds_encoded() -> None:
    """Field holding a string value that equals the encoded rule value → True."""
    plain = "42"
    # Verify that when the field already holds the encoded string, it matches
    assert _matches("count|base64", plain, {"count": _enc(plain)}) is True


# ---------------------------------------------------------------------------
# List of values — OR semantics
# ---------------------------------------------------------------------------

def test_base64_list_first_value_matches() -> None:
    """OR semantics: first encoded value matches field → True."""
    plain_a, plain_b = "cmd.exe", "powershell.exe"
    assert _matches("name|base64", [plain_a, plain_b], {"name": _enc(plain_a)}) is True


def test_base64_list_last_value_matches() -> None:
    """OR semantics: only the last encoded value matches → still True."""
    plain_a, plain_b = "cmd.exe", "powershell.exe"
    assert _matches("name|base64", [plain_a, plain_b], {"name": _enc(plain_b)}) is True


def test_base64_list_no_value_matches() -> None:
    """OR semantics: no encoded value matches → False."""
    assert _matches("name|base64", ["cmd.exe", "powershell.exe"], {"name": _enc("wscript.exe")}) is False


# ---------------------------------------------------------------------------
# `base64|all` — AND semantics
# ---------------------------------------------------------------------------

def test_base64_all_single_value_matches() -> None:
    """base64|all with one value that matches → True."""
    plain = "hello"
    assert _matches("name|base64|all", [plain], {"name": _enc(plain)}) is True


def test_base64_all_requires_exact_match() -> None:
    """base64|all exact match: field must equal one encoded value exactly."""
    plain_a, plain_b = "hello", "world"
    # Field equals enc(plain_a) but not enc(plain_b) — with all, both must match exact
    assert _matches("name|base64|all", [plain_a, plain_b], {"name": _enc(plain_a)}) is False


# ---------------------------------------------------------------------------
# `base64|contains` — substring match
# ---------------------------------------------------------------------------

def test_base64_contains_match() -> None:
    """base64|contains: encoded value is substring of field → True."""
    plain = "cmd.exe"
    encoded = _enc(plain)
    field_value = f"run {encoded} now"
    assert _matches("cmd_line|base64|contains", plain, {"cmd_line": field_value}) is True


def test_base64_contains_no_match() -> None:
    """base64|contains: encoded value not in field → False."""
    plain = "cmd.exe"
    encoded = _enc("powershell.exe")  # different value encoded
    assert _matches("cmd_line|base64|contains", plain, {"cmd_line": encoded}) is False


def test_base64_contains_at_start() -> None:
    """base64|contains: encoded value at start of field → True."""
    plain = "powershell"
    encoded = _enc(plain)
    assert _matches("cmd_line|base64|contains", plain, {"cmd_line": f"{encoded} extra"}) is True


def test_base64_contains_at_end() -> None:
    """base64|contains: encoded value at end of field → True."""
    plain = "powershell"
    encoded = _enc(plain)
    assert _matches("cmd_line|base64|contains", plain, {"cmd_line": f"prefix {encoded}"}) is True


def test_base64_contains_case_sensitive() -> None:
    """base64|contains: comparison is case-sensitive — wrong-case encoded value → False."""
    plain = "hello"
    encoded = _enc(plain)
    lowered = encoded.lower()
    assert _matches("cmd_line|base64|contains", plain, {"cmd_line": lowered}) is False


def test_base64_contains_field_missing() -> None:
    """base64|contains: field absent → False."""
    assert _matches("cmd_line|base64|contains", "hello", {"other": "val"}) is False


def test_base64_contains_list_or_semantics() -> None:
    """base64|contains with list: OR semantics — any encoded value as substring → True."""
    plain_a, plain_b = "IEX", "Invoke-Expression"
    enc_a = _enc(plain_a)
    field = f"powershell -enc {enc_a} -nop"
    assert _matches("cmd_line|base64|contains", [plain_a, plain_b], {"cmd_line": field}) is True


def test_base64_contains_list_no_match() -> None:
    """base64|contains with list: no encoded value present → False."""
    assert _matches(
        "cmd_line|base64|contains",
        ["evil", "malware"],
        {"cmd_line": f"benign {_enc('benign')} process"},
    ) is False


# ---------------------------------------------------------------------------
# `base64|contains|all` — substring AND semantics
# ---------------------------------------------------------------------------

def test_base64_contains_all_both_present() -> None:
    """base64|contains|all: all encoded values as substrings → True."""
    plain_a, plain_b = "IEX", "powershell"
    field = f"{_enc(plain_a)} {_enc(plain_b)}"
    assert _matches("cmd_line|base64|contains|all", [plain_a, plain_b], {"cmd_line": field}) is True


def test_base64_contains_all_one_missing() -> None:
    """base64|contains|all: one encoded value absent → False."""
    plain_a, plain_b = "IEX", "powershell"
    field = f"only {_enc(plain_a)} here"
    assert _matches("cmd_line|base64|contains|all", [plain_a, plain_b], {"cmd_line": field}) is False


# ---------------------------------------------------------------------------
# `base64|startswith` — prefix match
# ---------------------------------------------------------------------------

def test_base64_startswith_match() -> None:
    """base64|startswith: field starts with encoded value → True."""
    plain = "cmd.exe"
    encoded = _enc(plain)
    assert _matches("name|base64|startswith", plain, {"name": f"{encoded}trailing"}) is True


def test_base64_startswith_no_match_not_at_start() -> None:
    """base64|startswith: encoded value not at start of field → False."""
    plain = "cmd.exe"
    encoded = _enc(plain)
    assert _matches("name|base64|startswith", plain, {"name": f"prefix{encoded}"}) is False


def test_base64_startswith_exact_also_matches() -> None:
    """base64|startswith: field equals encoded value exactly → also True (prefix of equal string)."""
    plain = "cmd.exe"
    assert _matches("name|base64|startswith", plain, {"name": _enc(plain)}) is True


def test_base64_startswith_field_missing() -> None:
    """base64|startswith: field absent → False."""
    assert _matches("name|base64|startswith", "hello", {"other": "val"}) is False


# ---------------------------------------------------------------------------
# `base64|endswith` — suffix match
# ---------------------------------------------------------------------------

def test_base64_endswith_match() -> None:
    """base64|endswith: field ends with encoded value → True."""
    plain = "cmd.exe"
    encoded = _enc(plain)
    assert _matches("name|base64|endswith", plain, {"name": f"prefix{encoded}"}) is True


def test_base64_endswith_no_match_not_at_end() -> None:
    """base64|endswith: encoded value not at end of field → False."""
    plain = "cmd.exe"
    encoded = _enc(plain)
    assert _matches("name|base64|endswith", plain, {"name": f"{encoded}trailing"}) is False


def test_base64_endswith_exact_also_matches() -> None:
    """base64|endswith: field equals encoded value exactly → True (suffix of equal string)."""
    plain = "cmd.exe"
    assert _matches("name|base64|endswith", plain, {"name": _enc(plain)}) is True


def test_base64_endswith_field_missing() -> None:
    """base64|endswith: field absent → False."""
    assert _matches("name|base64|endswith", "hello", {"other": "val"}) is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_base64_empty_string_value() -> None:
    """Empty string encodes to empty string — field that is empty string matches."""
    # base64.b64encode(b"") == b"" so encoded is ""
    # "" == "" → True
    assert _matches("name|base64", "", {"name": ""}) is True


def test_base64_empty_string_contains() -> None:
    """Empty string encoded (= empty) is a substring of any non-empty field → True."""
    assert _matches("name|base64|contains", "", {"name": "anything"}) is True


def test_base64_two_field_selection_both_match() -> None:
    """Two base64 fields in selection — both must match (AND across fields)."""
    detection = {
        "selection": {
            "name|base64": "cmd.exe",
            "user|base64": "admin",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"name": _enc("cmd.exe"), "user": _enc("admin")}
    assert cond.matches(event) is True


def test_base64_two_field_selection_one_fails() -> None:
    """Two base64 fields — one doesn't match → False."""
    detection = {
        "selection": {
            "name|base64": "cmd.exe",
            "user|base64": "admin",
        },
        "condition": "selection",
    }
    cond = _Condition(detection)
    event = {"name": _enc("cmd.exe"), "user": _enc("guest")}  # wrong user
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_SINGLE_BASE64 = """\
title: Detect Encoded CMD
id: test-base64-001
status: test
level: high
logsource:
  category: process_creation
detection:
  selection:
    name|base64: 'cmd.exe'
  condition: selection
"""

_RULE_LIST_BASE64 = """\
title: Detect Encoded Suspicious Processes
id: test-base64-002
status: test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    name|base64:
      - 'cmd.exe'
      - 'powershell.exe'
      - 'wscript.exe'
  condition: selection
"""

_RULE_BASE64_CONTAINS = """\
title: Detect Encoded Command in Line
id: test-base64-003
status: test
level: high
logsource:
  category: process_creation
detection:
  selection:
    cmd_line|base64|contains:
      - 'IEX'
      - 'Invoke-Expression'
  condition: selection
"""


def test_rule_single_base64_matches(engine: SigmaEngine) -> None:
    """Rule with single base64 value matches event whose field holds the encoded string."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_BASE64)
    assert rule is not None
    assert rule._matcher.matches({"name": _enc("cmd.exe")}) is True


def test_rule_single_base64_no_match_plaintext(engine: SigmaEngine) -> None:
    """Rule with base64 does not match when event field holds plaintext (not encoded)."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_BASE64)
    assert rule is not None
    assert rule._matcher.matches({"name": "cmd.exe"}) is False


def test_rule_single_base64_no_match_different_value(engine: SigmaEngine) -> None:
    """Rule with base64 does not match when event field holds a different encoded value."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_BASE64)
    assert rule is not None
    assert rule._matcher.matches({"name": _enc("powershell.exe")}) is False


def test_rule_list_base64_first_value_matches(engine: SigmaEngine) -> None:
    """Rule list base64 matches event whose field holds the first encoded value."""
    rule = engine.load_rule_yaml(_RULE_LIST_BASE64)
    assert rule is not None
    assert rule._matcher.matches({"name": _enc("cmd.exe")}) is True


def test_rule_list_base64_second_value_matches(engine: SigmaEngine) -> None:
    """Rule list base64 matches event whose field holds the second encoded value."""
    rule = engine.load_rule_yaml(_RULE_LIST_BASE64)
    assert rule is not None
    assert rule._matcher.matches({"name": _enc("powershell.exe")}) is True


def test_rule_list_base64_third_value_matches(engine: SigmaEngine) -> None:
    """Rule list base64 matches event whose field holds the third encoded value."""
    rule = engine.load_rule_yaml(_RULE_LIST_BASE64)
    assert rule is not None
    assert rule._matcher.matches({"name": _enc("wscript.exe")}) is True


def test_rule_list_base64_no_match(engine: SigmaEngine) -> None:
    """Rule list base64 does not match when encoded field holds an unlisted value."""
    rule = engine.load_rule_yaml(_RULE_LIST_BASE64)
    assert rule is not None
    assert rule._matcher.matches({"name": _enc("benign.exe")}) is False


def test_rule_base64_contains_first_encoded_substring_matches(engine: SigmaEngine) -> None:
    """base64|contains rule matches when first encoded value is substring of cmd_line."""
    rule = engine.load_rule_yaml(_RULE_BASE64_CONTAINS)
    assert rule is not None
    field_value = f"powershell -enc {_enc('IEX')} -nop"
    assert rule._matcher.matches({"cmd_line": field_value}) is True


def test_rule_base64_contains_second_encoded_substring_matches(engine: SigmaEngine) -> None:
    """base64|contains rule matches when second encoded value is substring of cmd_line."""
    rule = engine.load_rule_yaml(_RULE_BASE64_CONTAINS)
    assert rule is not None
    field_value = f"invoke {_enc('Invoke-Expression')} here"
    assert rule._matcher.matches({"cmd_line": field_value}) is True


def test_rule_base64_contains_no_match(engine: SigmaEngine) -> None:
    """base64|contains rule does not match when no encoded value is a substring."""
    rule = engine.load_rule_yaml(_RULE_BASE64_CONTAINS)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": "benign -nop -c whoami"}) is False


def test_rule_base64_field_missing(engine: SigmaEngine) -> None:
    """base64 rule does not match when the detection field is absent from event."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_BASE64)
    assert rule is not None
    assert rule._matcher.matches({"cmd_line": _enc("cmd.exe")}) is False
