"""Tests for feature 28.20 — Sigma: NOT condition — exclusion works.

Coverage for _Condition._eval_condition() with the `not` keyword:
  - Standalone `not filter` — filter matches → False (exclusion fires)
  - Standalone `not filter` — filter does not match → True
  - Standalone `not filter` — filtered field absent from event → True
  - Standalone `not filter` — multi-field filter: all fields must match for filter = True
  - Standalone `not filter` — multi-field filter: partial match → filter = False → not filter = True
  - `selection and not filter` — selection matches, filter absent → True (canonical whitelist pattern)
  - `selection and not filter` — selection matches, filter matches → False (suppressed)
  - `selection and not filter` — selection fails, filter absent → False (no detection)
  - `selection and not filter` — selection fails, filter matches → False
  - NOT filter with list values: any list item matching triggers filter = True → not filter = False
  - NOT filter with list values: no list item matches → not filter = True
  - Multiple NOT clauses: `selection and not filter1 and not filter2` — none match → True
  - Multiple NOT clauses: filter1 matches → False
  - Multiple NOT clauses: filter2 matches → False
  - Multiple NOT clauses: both filters match → False
  - Double NOT: `not not selection` — selection matches → True
  - Double NOT: `not not selection` — selection fails → False
  - NOT with `re` modifier in filter: filter|re matches → not filter = False
  - NOT with `re` modifier in filter: filter|re does not match → not filter = True
  - NOT with `re` modifier in filter: anchored regex, partial value → no match → True
  - NOT with contains modifier in filter: filter|contains matches → not filter = False
  - NOT with contains modifier in filter: filter|contains does not match → not filter = True
  - Via load_rule_yaml: `condition: not filter` — filter matches → False
  - Via load_rule_yaml: `condition: not filter` — filter absent → True
  - Via load_rule_yaml: `condition: selection and not filter` — classic whitelist suppresses alert
  - Via load_rule_yaml: `condition: selection and not filter` — filter absent allows detection
  - Via load_rule_yaml: multiple NOT filters — one match suppresses
  - Via load_rule_yaml: multiple NOT filters — none match → detection fires
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
# Standalone NOT
# ---------------------------------------------------------------------------

def test_not_standalone_filter_matches() -> None:
    """Standalone `not filter` — filter matches → False (event is excluded)."""
    cond = _make_condition_multi(
        {"filter": {"user": "svc_scanner"}},
        "not filter",
    )
    assert cond.matches({"user": "svc_scanner", "cmd_line": "nmap -sV"}) is False


def test_not_standalone_filter_does_not_match() -> None:
    """Standalone `not filter` — filter does not match → True."""
    cond = _make_condition_multi(
        {"filter": {"user": "svc_scanner"}},
        "not filter",
    )
    assert cond.matches({"user": "jdoe", "cmd_line": "nmap -sV"}) is True


def test_not_standalone_field_absent_from_event() -> None:
    """Standalone `not filter` — filter field missing from event → filter = False → not filter = True."""
    cond = _make_condition_multi(
        {"filter": {"user": "svc_scanner"}},
        "not filter",
    )
    # 'user' key is not in the event at all
    assert cond.matches({"cmd_line": "nmap -sV"}) is True


def test_not_standalone_multi_field_all_match() -> None:
    """Standalone `not filter` — multi-field filter, all fields match → filter = True → False."""
    cond = _make_condition_multi(
        {"filter": {"user": "svc_scanner", "name": "nmap"}},
        "not filter",
    )
    assert cond.matches({"user": "svc_scanner", "name": "nmap"}) is False


def test_not_standalone_multi_field_partial_match() -> None:
    """Standalone `not filter` — multi-field filter, only one field matches → filter = False → True."""
    cond = _make_condition_multi(
        {"filter": {"user": "svc_scanner", "name": "nmap"}},
        "not filter",
    )
    # user matches but name does not — dict semantics require ALL fields to match
    assert cond.matches({"user": "svc_scanner", "name": "curl"}) is True


# ---------------------------------------------------------------------------
# selection and not filter  (canonical whitelist / exclusion pattern)
# ---------------------------------------------------------------------------

def test_and_not_selection_matches_filter_absent() -> None:
    """`selection and not filter` — selection matches, filter field absent → True."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "mimikatz"},
            "filter": {"user": "svc_av"},
        },
        "selection and not filter",
    )
    event = {"cmd_line": "invoke-mimikatz", "user": "jdoe"}
    assert cond.matches(event) is True


def test_and_not_selection_matches_filter_matches() -> None:
    """`selection and not filter` — selection matches but filter also matches → False (suppressed)."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "mimikatz"},
            "filter": {"user": "svc_av"},
        },
        "selection and not filter",
    )
    event = {"cmd_line": "invoke-mimikatz", "user": "svc_av"}
    assert cond.matches(event) is False


def test_and_not_selection_fails_filter_absent() -> None:
    """`selection and not filter` — selection fails, filter absent → False (no detection)."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "mimikatz"},
            "filter": {"user": "svc_av"},
        },
        "selection and not filter",
    )
    event = {"cmd_line": "benign.exe", "user": "jdoe"}
    assert cond.matches(event) is False


def test_and_not_selection_fails_filter_matches() -> None:
    """`selection and not filter` — selection fails, filter matches → False."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "mimikatz"},
            "filter": {"user": "svc_av"},
        },
        "selection and not filter",
    )
    event = {"cmd_line": "benign.exe", "user": "svc_av"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# NOT filter with list values
# ---------------------------------------------------------------------------

def test_not_filter_list_matching_value() -> None:
    """NOT filter with a list — event value matches one list item → filter = True → False."""
    cond = _make_condition_multi(
        {"filter": {"name": ["cmd.exe", "powershell.exe", "wscript.exe"]}},
        "not filter",
    )
    assert cond.matches({"name": "powershell.exe"}) is False


def test_not_filter_list_non_matching_value() -> None:
    """NOT filter with a list — event value matches no list item → filter = False → True."""
    cond = _make_condition_multi(
        {"filter": {"name": ["cmd.exe", "powershell.exe", "wscript.exe"]}},
        "not filter",
    )
    assert cond.matches({"name": "python.exe"}) is True


# ---------------------------------------------------------------------------
# Multiple NOT clauses
# ---------------------------------------------------------------------------

def test_multiple_not_neither_filter_matches() -> None:
    """`selection and not filter1 and not filter2` — neither filter matches → True."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "nmap"},
            "filter1": {"user": "svc_netscan"},
            "filter2": {"name": "authorized_scanner.exe"},
        },
        "selection and not filter1 and not filter2",
    )
    event = {"cmd_line": "nmap -sV 10.0.0.1", "user": "attacker", "name": "nmap"}
    assert cond.matches(event) is True


def test_multiple_not_filter1_matches() -> None:
    """`selection and not filter1 and not filter2` — filter1 matches → False."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "nmap"},
            "filter1": {"user": "svc_netscan"},
            "filter2": {"name": "authorized_scanner.exe"},
        },
        "selection and not filter1 and not filter2",
    )
    event = {"cmd_line": "nmap -sV 10.0.0.1", "user": "svc_netscan", "name": "nmap"}
    assert cond.matches(event) is False


def test_multiple_not_filter2_matches() -> None:
    """`selection and not filter1 and not filter2` — filter2 matches → False."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "nmap"},
            "filter1": {"user": "svc_netscan"},
            "filter2": {"name": "authorized_scanner.exe"},
        },
        "selection and not filter1 and not filter2",
    )
    event = {"cmd_line": "nmap -sV 10.0.0.1", "user": "attacker", "name": "authorized_scanner.exe"}
    assert cond.matches(event) is False


def test_multiple_not_both_filters_match() -> None:
    """`selection and not filter1 and not filter2` — both filters match → False."""
    cond = _make_condition_multi(
        {
            "selection": {"cmd_line|contains": "nmap"},
            "filter1": {"user": "svc_netscan"},
            "filter2": {"name": "authorized_scanner.exe"},
        },
        "selection and not filter1 and not filter2",
    )
    event = {"cmd_line": "nmap -sV 10.0.0.1", "user": "svc_netscan", "name": "authorized_scanner.exe"}
    assert cond.matches(event) is False


# ---------------------------------------------------------------------------
# Double NOT
# ---------------------------------------------------------------------------

def test_double_not_selection_matches() -> None:
    """`not not selection` — selection matches → True (double negation)."""
    cond = _make_condition_multi(
        {"selection": {"name": "powershell.exe"}},
        "not not selection",
    )
    assert cond.matches({"name": "powershell.exe"}) is True


def test_double_not_selection_fails() -> None:
    """`not not selection` — selection does not match → False."""
    cond = _make_condition_multi(
        {"selection": {"name": "powershell.exe"}},
        "not not selection",
    )
    assert cond.matches({"name": "cmd.exe"}) is False


# ---------------------------------------------------------------------------
# NOT with re modifier in filter
# ---------------------------------------------------------------------------

def test_not_filter_re_modifier_matches() -> None:
    """`selection and not filter` — filter uses `re` modifier, regex matches → suppressed → False."""
    cond = _make_condition_multi(
        {
            "selection": {"event_type": "process_creation"},
            "filter": {"cmd_line|re": r"^(svchost|lsass|csrss)\.exe$"},
        },
        "selection and not filter",
    )
    event = {"event_type": "process_creation", "cmd_line": "svchost.exe"}
    assert cond.matches(event) is False


def test_not_filter_re_modifier_no_match() -> None:
    """`selection and not filter` — filter uses `re` modifier, regex does not match → True."""
    cond = _make_condition_multi(
        {
            "selection": {"event_type": "process_creation"},
            "filter": {"cmd_line|re": r"^(svchost|lsass|csrss)\.exe$"},
        },
        "selection and not filter",
    )
    event = {"event_type": "process_creation", "cmd_line": "malware.exe"}
    assert cond.matches(event) is True


def test_not_filter_re_modifier_partial_match() -> None:
    """`selection and not filter` — anchored regex, value is substring only → no match → True."""
    cond = _make_condition_multi(
        {
            "selection": {"event_type": "process_creation"},
            "filter": {"cmd_line|re": r"^svchost\.exe$"},
        },
        "selection and not filter",
    )
    # "run svchost.exe" does not match anchored regex → filter = False → not filter = True
    event = {"event_type": "process_creation", "cmd_line": "run svchost.exe"}
    assert cond.matches(event) is True


# ---------------------------------------------------------------------------
# NOT with modifier in filter
# ---------------------------------------------------------------------------

def test_not_filter_contains_modifier_matches() -> None:
    """`selection and not filter` — filter uses `contains` and matches → suppressed → False."""
    cond = _make_condition_multi(
        {
            "selection": {"event_type": "dns_query"},
            "filter": {"query|contains": "microsoft.com"},
        },
        "selection and not filter",
    )
    event = {"event_type": "dns_query", "query": "update.microsoft.com"}
    assert cond.matches(event) is False


def test_not_filter_contains_modifier_no_match() -> None:
    """`selection and not filter` — filter uses `contains` and does not match → True."""
    cond = _make_condition_multi(
        {
            "selection": {"event_type": "dns_query"},
            "filter": {"query|contains": "microsoft.com"},
        },
        "selection and not filter",
    )
    event = {"event_type": "dns_query", "query": "malicious-c2.xyz"}
    assert cond.matches(event) is True


# ---------------------------------------------------------------------------
# Via load_rule_yaml — integration tests
# ---------------------------------------------------------------------------

_RULE_NOT_ONLY = """\
title: Block Known Scanner
id: test-not-001
status: test
level: informational
logsource:
  category: process_creation
detection:
  filter:
    user: svc_scanner
  condition: not filter
"""

_RULE_AND_NOT = """\
title: Mimikatz Detection With Whitelist
id: test-not-002
status: test
level: critical
logsource:
  category: process_creation
detection:
  selection:
    cmd_line|contains: mimikatz
  filter:
    user: svc_edr
  condition: selection and not filter
"""

_RULE_MULTI_NOT = """\
title: Suspicious DNS Unless Whitelisted
id: test-not-003
status: test
level: medium
logsource:
  category: dns_query
detection:
  selection:
    event_type: dns_query
  filter_internal:
    query|contains: '.internal.corp'
  filter_known:
    user: svc_dns_monitor
  condition: selection and not filter_internal and not filter_known
"""


def test_rule_not_only_filter_matches(engine: SigmaEngine) -> None:
    """Rule `condition: not filter` — filter matches → False."""
    rule = engine.load_rule_yaml(_RULE_NOT_ONLY)
    assert rule is not None
    event = {"user": "svc_scanner", "cmd_line": "nmap -sV"}
    assert rule._matcher.matches(event) is False


def test_rule_not_only_filter_absent(engine: SigmaEngine) -> None:
    """Rule `condition: not filter` — filter field absent → True."""
    rule = engine.load_rule_yaml(_RULE_NOT_ONLY)
    assert rule is not None
    event = {"user": "attacker", "cmd_line": "nmap -sV"}
    assert rule._matcher.matches(event) is True


def test_rule_and_not_detection_allowed(engine: SigmaEngine) -> None:
    """Rule `selection and not filter` — selection matches, filter absent → True (alert fires)."""
    rule = engine.load_rule_yaml(_RULE_AND_NOT)
    assert rule is not None
    event = {"cmd_line": "invoke-mimikatz", "user": "attacker"}
    assert rule._matcher.matches(event) is True


def test_rule_and_not_detection_suppressed(engine: SigmaEngine) -> None:
    """Rule `selection and not filter` — selection matches, filter matches → False (suppressed)."""
    rule = engine.load_rule_yaml(_RULE_AND_NOT)
    assert rule is not None
    event = {"cmd_line": "invoke-mimikatz", "user": "svc_edr"}
    assert rule._matcher.matches(event) is False


def test_rule_and_not_no_selection_match(engine: SigmaEngine) -> None:
    """Rule `selection and not filter` — selection does not match → False regardless of filter."""
    rule = engine.load_rule_yaml(_RULE_AND_NOT)
    assert rule is not None
    event = {"cmd_line": "benign.exe", "user": "attacker"}
    assert rule._matcher.matches(event) is False


def test_rule_multi_not_no_filters_match(engine: SigmaEngine) -> None:
    """Multi-NOT rule — selection matches, neither filter matches → True."""
    rule = engine.load_rule_yaml(_RULE_MULTI_NOT)
    assert rule is not None
    event = {"event_type": "dns_query", "query": "malicious-c2.xyz", "user": "attacker"}
    assert rule._matcher.matches(event) is True


def test_rule_multi_not_filter_internal_matches(engine: SigmaEngine) -> None:
    """Multi-NOT rule — filter_internal matches (internal domain) → False."""
    rule = engine.load_rule_yaml(_RULE_MULTI_NOT)
    assert rule is not None
    event = {"event_type": "dns_query", "query": "db.internal.corp", "user": "attacker"}
    assert rule._matcher.matches(event) is False


def test_rule_multi_not_filter_known_matches(engine: SigmaEngine) -> None:
    """Multi-NOT rule — filter_known matches (known monitoring user) → False."""
    rule = engine.load_rule_yaml(_RULE_MULTI_NOT)
    assert rule is not None
    event = {"event_type": "dns_query", "query": "malicious-c2.xyz", "user": "svc_dns_monitor"}
    assert rule._matcher.matches(event) is False
