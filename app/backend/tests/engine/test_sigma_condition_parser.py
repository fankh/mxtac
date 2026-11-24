"""Condition expressions: and / or / not / parentheses / quantifiers, and the
rejection of unsupported detection syntax."""

from __future__ import annotations

import pytest

from app.engine.sigma_engine import SigmaEngine, SigmaRuleError, _Condition

# Three selections, each true when its own flag is present in the event.
SELECTIONS = {
    "a": {"a": "1"},
    "b": {"b": "1"},
    "c": {"c": "1"},
}


def evaluate(condition: str, true_selections: str, selections: dict | None = None) -> bool:
    """Evaluate *condition* with the selections named in *true_selections* true."""
    detection = {**(selections or SELECTIONS), "condition": condition}
    return _Condition(detection).matches({name: "1" for name in true_selections})


# ── Precedence and parentheses ───────────────────────────────────────────────

@pytest.mark.parametrize(
    ("condition", "true_selections", "expected"),
    [
        # and binds tighter than or
        ("a or b and c", "a", True),
        ("a or b and c", "b", False),
        ("a or b and c", "bc", True),
        # parentheses override precedence
        ("(a or b) and c", "a", False),
        ("(a or b) and c", "ac", True),
        ("(a or b) and c", "bc", True),
        ("a and (b or c)", "ac", True),
        ("a and (b or c)", "bc", False),
        # nested groups
        ("(a and (b or c)) or (b and c)", "bc", True),
        ("(a and (b or c)) or (b and c)", "a", False),
        ("((a))", "a", True),
        # not binds to the next operand only
        ("not a and b", "b", True),
        ("not a and b", "", False),
        ("not a and b", "ab", False),
        ("a and not b", "a", True),
        ("a and not b", "ab", False),
        ("not (a or b)", "", True),
        ("not (a or b)", "b", False),
        ("not not a", "a", True),
        ("a and not (b and c)", "ab", True),
        ("a and not (b and c)", "abc", False),
        # keywords are case-insensitive, whitespace is free
        ("a AND NOT b", "a", True),
        ("( a or b )and c", "bc", True),
    ],
)
def test_boolean_expression(condition: str, true_selections: str, expected: bool) -> None:
    assert evaluate(condition, true_selections) is expected


# ── Quantifiers ──────────────────────────────────────────────────────────────

QUANT_SELECTIONS = {
    "selection_a": {"a": "1"},
    "selection_b": {"b": "1"},
    "filter": {"c": "1"},
}


@pytest.mark.parametrize(
    ("condition", "true_selections", "expected"),
    [
        ("1 of them", "c", True),
        ("1 of them", "", False),
        ("all of them", "abc", True),
        ("all of them", "ab", False),
        ("1 of selection*", "b", True),
        ("1 of selection*", "c", False),
        ("1 of selection_*", "a", True),
        ("all of selection*", "ab", True),
        ("all of selection*", "a", False),
        ("2 of them", "ac", True),
        ("2 of them", "a", False),
        # quantifiers combine with the boolean operators and groups
        ("1 of selection* and not filter", "a", True),
        ("1 of selection* and not filter", "ac", False),
        ("(all of selection*) or filter", "c", True),
        ("not 1 of selection*", "c", True),
    ],
)
def test_quantifier(condition: str, true_selections: str, expected: bool) -> None:
    assert evaluate(condition, true_selections, QUANT_SELECTIONS) is expected


def test_condition_list_is_or_of_conditions() -> None:
    detection = {**SELECTIONS, "condition": ["a and b", "c"]}
    cond = _Condition(detection)
    assert cond.matches({"c": "1"}) is True
    assert cond.matches({"a": "1"}) is False


# ── Invalid and unsupported syntax is rejected with a clear error ────────────

@pytest.mark.parametrize(
    ("condition", "message"),
    [
        ("a and missing", "unknown selection 'missing'"),
        ("(a or b", "missing '\\)'"),
        ("a or b)", "unexpected '\\)'"),
        ("a and", "unexpected end of condition"),
        ("and a", "unexpected 'and'"),
        ("a b", "unexpected 'b'"),
        ("", "empty condition"),
        ("1 of nothing*", "does not match any selection"),
        ("a | count() > 5", "aggregation expressions"),
        ("a | near b", "aggregation expressions"),
    ],
)
def test_invalid_condition_is_rejected(condition: str, message: str) -> None:
    with pytest.raises(SigmaRuleError, match=message):
        _Condition({**SELECTIONS, "condition": condition})


def test_timeframe_is_rejected() -> None:
    with pytest.raises(SigmaRuleError, match="timeframe"):
        _Condition({"selection": {"a": "1"}, "timeframe": "5m", "condition": "selection"})


def test_unknown_modifier_is_rejected() -> None:
    with pytest.raises(SigmaRuleError, match="unsupported modifier 'windash'"):
        _Condition({"selection": {"CommandLine|windash|contains": "-enc"}, "condition": "selection"})


def test_detection_without_selections_is_rejected() -> None:
    with pytest.raises(SigmaRuleError, match="no selections"):
        _Condition({"condition": "selection"})


CORRELATION_RULE = """
title: Many failed logins
correlation:
  type: event_count
  rules: [failed_login]
  timespan: 5m
  condition:
    gte: 10
"""

AGGREGATION_RULE = """
title: Many failed logins
logsource:
  product: linux
detection:
  selection:
    message|contains: 'Failed password'
  timeframe: 5m
  condition: selection | count() by src_ip > 10
"""


@pytest.mark.parametrize("rule_yaml", [CORRELATION_RULE, AGGREGATION_RULE])
def test_engine_rejects_unsupported_rule(rule_yaml: str) -> None:
    engine = SigmaEngine()
    with pytest.raises(SigmaRuleError):
        engine.parse_rule_yaml(rule_yaml)
    # The lenient loader used for stored rules skips it instead of raising.
    assert engine.load_rule_yaml(rule_yaml) is None
