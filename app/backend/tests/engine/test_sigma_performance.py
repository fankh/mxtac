"""Tests for feature 28.42 — Performance: Sigma evaluates 10K rules in < 100ms.

Benchmark that the SigmaEngine can evaluate 10,000 compiled Sigma rules
against a single event within the 100 ms performance budget.

Coverage:
  - Engine correctly stores 10 000 rules (rule_count == 10_000)
  - Evaluating all 10 000 rules against one event completes in < 100 ms
  - A matching rule embedded among 9 999 non-matching rules is still found
  - Non-matching rules correctly return False (no false positives at scale)
"""

from __future__ import annotations

import time

import pytest

from app.engine.sigma_engine import SigmaEngine, SigmaRule, _Condition

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BUDGET_MS = 100
NUM_RULES = 10_000

# Unique token embedded in the one rule that SHOULD match the test event
MATCH_TOKEN = "mxtac_perf_match_signal"

# Test event used for all evaluation benchmarks
_BENCH_EVENT = {
    "cmd_line": f"python run.py --flag {MATCH_TOKEN}",
    "name": "python.exe",
    "pid": 1234,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_engine(num_rules: int = NUM_RULES, *, include_match: bool = True) -> SigmaEngine:
    """Return a SigmaEngine loaded with *num_rules* rules.

    One of the rules (at index num_rules // 2) uses the MATCH_TOKEN value so
    it will match ``_BENCH_EVENT``.  All other rules use unique tokens that
    are absent from the event.
    """
    engine = SigmaEngine()
    match_index = num_rules // 2

    for i in range(num_rules):
        if include_match and i == match_index:
            token = MATCH_TOKEN
        else:
            # Unique string that does NOT appear in _BENCH_EVENT
            token = f"no_match_unique_{i:06d}_xyz"

        detection = {
            "selection": {"cmd_line|contains": token},
            "condition": "selection",
        }
        rule = SigmaRule(
            id=f"perf-rule-{i:06d}",
            title=f"Perf Rule {i}",
            description="",
            status="stable",
            level="low",
            logsource={},   # no logsource → indexed under "*" (global)
            detection=detection,
        )
        rule._matcher = _Condition(detection)
        engine.add_rule(rule)

    return engine


# ---------------------------------------------------------------------------
# Correctness at scale
# ---------------------------------------------------------------------------


def test_engine_stores_10k_rules() -> None:
    """SigmaEngine.rule_count must equal NUM_RULES after bulk add."""
    engine = _build_engine()
    assert engine.rule_count == NUM_RULES


def test_matching_rule_found_among_10k() -> None:
    """A matching rule embedded in 9 999 non-matching rules still fires."""
    engine = _build_engine()
    matched = [
        rule.id
        for rule in engine._rules.values()
        if rule._matcher.matches(_BENCH_EVENT)
    ]
    assert len(matched) == 1, f"Expected exactly 1 match, got {len(matched)}: {matched}"


def test_non_matching_rules_return_false_at_scale() -> None:
    """All 10 000 non-matching rules return False (no false positives)."""
    engine = _build_engine(include_match=False)
    false_positives = [
        rule.id
        for rule in engine._rules.values()
        if rule._matcher.matches(_BENCH_EVENT)
    ]
    assert false_positives == [], (
        f"False positives detected: {false_positives[:5]}"
    )


# ---------------------------------------------------------------------------
# Performance benchmark
# ---------------------------------------------------------------------------


def test_sigma_10k_rules_under_100ms() -> None:
    """Evaluating 10 000 Sigma rules against one event must complete in < 100 ms.

    Steps:
      1. Pre-build the engine (loading time excluded from budget).
      2. Warm-up pass — ensures Python caches, branch predictors, and any
         lazy initialisations don't skew the timed measurement.
      3. Timed pass — wall-clock time for a full sweep of all rules.
    """
    engine = _build_engine()
    assert engine.rule_count == NUM_RULES

    rules = list(engine._rules.values())

    # Warm-up: run once to prime Python caches
    for rule in rules:
        rule._matcher.matches(_BENCH_EVENT)

    # Timed evaluation
    start = time.perf_counter()
    for rule in rules:
        rule._matcher.matches(_BENCH_EVENT)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert elapsed_ms < BUDGET_MS, (
        f"10K rule evaluation took {elapsed_ms:.1f} ms — budget is {BUDGET_MS} ms.\n"
        "The SigmaEngine _Condition.matches() path needs optimisation."
    )
