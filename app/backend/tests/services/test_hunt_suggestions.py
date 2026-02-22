"""Tests for hunt_suggestions service (Feature 11.8).

ATT&CK-guided hunt suggestions generated from:
  - Trending techniques (recent detections)
  - Coverage-gap techniques (rules exist but are all disabled)

Coverage:
  - _assign_priority: critical → high
  - _assign_priority: trending with no rules → high
  - _assign_priority: critical overrides rule coverage → high
  - _assign_priority: high severity → medium
  - _assign_priority: count>0 with rules → medium
  - _assign_priority: all zeros → low
  - _build_reason: gap with no detections → blind-spot message
  - _build_reason: gap with detections → detection-with-no-coverage message
  - _build_reason: trending — count, critical, high all reflected
  - _build_reason: rule_count=0 for non-gap → "no active rule coverage"
  - _build_reason: rule_count=1 → "1 active rule"
  - _build_reason: rule_count>1 → "N active rules"
  - _build_reason: all zeros, not gap → fallback phrase
  - _make_queries: returns 2 SuggestedQuery objects
  - _make_queries: technique-specific first query
  - _make_queries: tactic-based second query
  - _make_queries: time_from propagated
  - get_hunt_suggestions: empty DB → valid envelope, empty list
  - get_hunt_suggestions: window_hours reflected from hours param
  - get_hunt_suggestions: custom limit caps results
  - get_hunt_suggestions: trending technique → appears in suggestions
  - get_hunt_suggestions: critical detection → priority high
  - get_hunt_suggestions: high detection only → priority medium
  - get_hunt_suggestions: trending with no rule coverage → priority high
  - get_hunt_suggestions: trending with rule coverage → priority medium
  - get_hunt_suggestions: old detections outside window excluded
  - get_hunt_suggestions: coverage gap → surfaced with priority low, detection_count 0
  - get_hunt_suggestions: technique in trending AND gap → not duplicated
  - get_hunt_suggestions: coverage gaps capped at _GAP_LIMIT (5)
  - get_hunt_suggestions: sorting: high → medium → low, then detection_count desc
  - get_hunt_suggestions: rule_count reflected from enabled rules
  - get_hunt_suggestions: generated_at is ISO-8601 UTC timestamp
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detection import Detection
from app.models.rule import Rule
from app.services.hunt_suggestions import (
    _GAP_LIMIT,
    _assign_priority,
    _build_reason,
    _make_queries,
    get_hunt_suggestions,
)

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)
_IN_WINDOW = _NOW - timedelta(hours=1)
_OUT_OF_WINDOW_24H = _NOW - timedelta(hours=48)


def _detection(
    *,
    technique_id: str = "T1059.001",
    technique_name: str = "PowerShell",
    tactic: str = "Execution",
    tactic_id: str = "TA0002",
    severity: str = "high",
    name: str = "Test Alert",
    host: str = "host-01",
    time: datetime | None = None,
    status: str = "active",
    score: float = 0.8,
) -> Detection:
    return Detection(
        score=score,
        severity=severity,
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        tactic_id=tactic_id,
        name=name,
        host=host,
        time=time if time is not None else _IN_WINDOW,
        status=status,
    )


def _rule(
    *,
    title: str = "Test Rule",
    enabled: bool = True,
    technique_ids: list[str] | None = None,
) -> Rule:
    return Rule(
        title=title,
        content=f"title: {title}\n",
        level="high",
        enabled=enabled,
        technique_ids=json.dumps(technique_ids or ["T1059.001"]),
    )


# ---------------------------------------------------------------------------
# Unit tests: _assign_priority
# ---------------------------------------------------------------------------


class TestAssignPriority:
    """_assign_priority derives urgency from detection telemetry."""

    def test_critical_count_yields_high(self) -> None:
        assert _assign_priority(count=3, critical=1, high=0, rule_count=2) == "high"

    def test_trending_with_no_rules_yields_high(self) -> None:
        # count > 0 and rule_count == 0 → blind spot → high
        assert _assign_priority(count=5, critical=0, high=0, rule_count=0) == "high"

    def test_critical_overrides_rule_coverage(self) -> None:
        # Even with rules present, a critical detection forces high priority
        assert _assign_priority(count=2, critical=2, high=0, rule_count=5) == "high"

    def test_high_severity_yields_medium(self) -> None:
        assert _assign_priority(count=3, critical=0, high=2, rule_count=1) == "medium"

    def test_count_with_rules_yields_medium(self) -> None:
        # count > 0, rule_count > 0, no critical, no high → medium
        assert _assign_priority(count=4, critical=0, high=0, rule_count=3) == "medium"

    def test_all_zeros_yields_low(self) -> None:
        assert _assign_priority(count=0, critical=0, high=0, rule_count=0) == "low"

    def test_count_zero_with_rules_yields_low(self) -> None:
        # No detections, only rule coverage — gap case (no detections)
        assert _assign_priority(count=0, critical=0, high=0, rule_count=2) == "low"


# ---------------------------------------------------------------------------
# Unit tests: _build_reason
# ---------------------------------------------------------------------------


class TestBuildReason:
    """_build_reason generates explanations for hunt suggestions."""

    def test_gap_no_detections_blind_spot_message(self) -> None:
        reason = _build_reason(count=0, critical=0, high=0, rule_count=0, is_gap=True)
        assert "blind spot" in reason.lower() or "no active" in reason.lower()

    def test_gap_with_detections_includes_count_and_coverage_warning(self) -> None:
        reason = _build_reason(count=3, critical=0, high=0, rule_count=0, is_gap=True)
        assert "3" in reason
        assert "no active" in reason.lower() or "coverage" in reason.lower()

    def test_gap_count_singular(self) -> None:
        reason = _build_reason(count=1, critical=0, high=0, rule_count=0, is_gap=True)
        assert "1 detection" in reason

    def test_non_gap_count_reflected(self) -> None:
        reason = _build_reason(count=7, critical=0, high=0, rule_count=1, is_gap=False)
        assert "7" in reason

    def test_non_gap_critical_reflected(self) -> None:
        reason = _build_reason(count=5, critical=2, high=1, rule_count=1, is_gap=False)
        assert "2 critical" in reason

    def test_non_gap_high_reflected(self) -> None:
        reason = _build_reason(count=5, critical=0, high=3, rule_count=1, is_gap=False)
        assert "3 high" in reason

    def test_non_gap_no_rules_says_no_coverage(self) -> None:
        reason = _build_reason(count=2, critical=0, high=0, rule_count=0, is_gap=False)
        assert "no active rule coverage" in reason

    def test_non_gap_one_rule(self) -> None:
        reason = _build_reason(count=2, critical=0, high=0, rule_count=1, is_gap=False)
        assert "1 active rule" in reason

    def test_non_gap_multiple_rules(self) -> None:
        reason = _build_reason(count=2, critical=0, high=0, rule_count=4, is_gap=False)
        assert "4 active rules" in reason

    def test_all_zeros_non_gap_returns_no_coverage(self) -> None:
        # count=0, no severity, rule_count=0, not a gap
        # The if/elif/else on rule_count always adds a fragment, so "no active rule coverage"
        reason = _build_reason(count=0, critical=0, high=0, rule_count=0, is_gap=False)
        assert reason
        assert "no active rule coverage" in reason


# ---------------------------------------------------------------------------
# Unit tests: _make_queries
# ---------------------------------------------------------------------------


class TestMakeQueries:
    """_make_queries builds pre-canned hunt queries for a technique."""

    def test_returns_two_queries(self) -> None:
        queries = _make_queries("T1003.006", "DCSync", "Credential Access", "now-24h")
        assert len(queries) == 2

    def test_first_query_targets_technique(self) -> None:
        queries = _make_queries("T1003.006", "DCSync", "Credential Access", "now-24h")
        q = queries[0]
        assert "T1003.006" in q.label
        assert "DCSync" in q.label
        assert q.query == "T1003.006"

    def test_second_query_targets_tactic(self) -> None:
        queries = _make_queries("T1003.006", "DCSync", "Credential Access", "now-24h")
        q = queries[1]
        assert "Credential Access" in q.label
        assert q.query == "Credential Access"

    def test_time_from_propagated_to_all_queries(self) -> None:
        queries = _make_queries("T1059.001", "PowerShell", "Execution", "now-48h")
        for q in queries:
            assert q.time_from == "now-48h"

    def test_query_objects_have_all_fields(self) -> None:
        queries = _make_queries("T1078", "Valid Accounts", "Persistence", "now-7d")
        for q in queries:
            assert q.label
            assert q.query
            assert q.time_from


# ---------------------------------------------------------------------------
# Integration tests: get_hunt_suggestions
# ---------------------------------------------------------------------------


class TestGetHuntSuggestions:
    """get_hunt_suggestions returns ranked hunt suggestions from DB telemetry."""

    async def test_empty_db_returns_valid_envelope(
        self, db_session: AsyncSession
    ) -> None:
        resp = await get_hunt_suggestions(db_session)

        assert isinstance(resp.suggestions, list)
        assert resp.suggestions == []
        assert resp.window_hours == 24
        assert resp.generated_at  # not empty

    def test_generated_at_is_iso8601_utc(self) -> None:
        # Verify the timestamp format (not DB-dependent)
        from app.services.hunt_suggestions import get_hunt_suggestions as _fn
        import asyncio
        from unittest.mock import AsyncMock, patch

        async def _run():
            mock_session = object()  # won't be called in patched version
            with (
                patch(
                    "app.services.hunt_suggestions.DetectionRepo.get_technique_activity",
                    new=AsyncMock(return_value=[]),
                ),
                patch(
                    "app.services.hunt_suggestions.RuleRepo.get_enabled_rule_counts_by_technique",
                    new=AsyncMock(return_value={}),
                ),
                patch(
                    "app.services.hunt_suggestions.RuleRepo.get_coverage_gaps",
                    new=AsyncMock(return_value={"uncovered_techniques": []}),
                ),
            ):
                return await _fn(mock_session)

        resp = asyncio.get_event_loop().run_until_complete(_run())
        # Format: "2026-02-22T12:34:56Z"
        datetime.strptime(resp.generated_at, "%Y-%m-%dT%H:%M:%SZ")

    async def test_window_hours_reflected(self, db_session: AsyncSession) -> None:
        resp = await get_hunt_suggestions(db_session, hours=48)
        assert resp.window_hours == 48

    async def test_limit_caps_results(self, db_session: AsyncSession) -> None:
        # Add detections for 6 different techniques
        techniques = [
            ("T1059.001", "PowerShell", "Execution", "TA0002"),
            ("T1059.003", "Cmd Shell", "Execution", "TA0002"),
            ("T1003.001", "LSASS", "Credential Access", "TA0006"),
            ("T1003.006", "DCSync", "Credential Access", "TA0006"),
            ("T1021.001", "RDP", "Lateral Movement", "TA0008"),
            ("T1078.001", "Default Accounts", "Initial Access", "TA0001"),
        ]
        for tid, tname, tactic, tactic_id in techniques:
            db_session.add(
                _detection(
                    technique_id=tid,
                    technique_name=tname,
                    tactic=tactic,
                    tactic_id=tactic_id,
                )
            )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session, limit=3)
        assert len(resp.suggestions) <= 3

    async def test_trending_technique_appears(self, db_session: AsyncSession) -> None:
        db_session.add(_detection(technique_id="T1059.001", severity="high"))
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        ids = [s.technique_id for s in resp.suggestions]
        assert "T1059.001" in ids

    async def test_critical_detection_yields_high_priority(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_detection(technique_id="T1003.006", severity="critical"))
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        s = next(x for x in resp.suggestions if x.technique_id == "T1003.006")
        assert s.priority == "high"

    async def test_high_severity_only_yields_medium_priority(
        self, db_session: AsyncSession
    ) -> None:
        # Add an enabled rule so rule_count > 0 (prevents "no coverage → high")
        db_session.add(
            _detection(
                technique_id="T1059.001",
                severity="high",
            )
        )
        db_session.add(_rule(enabled=True, technique_ids=["T1059.001"]))
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        s = next(x for x in resp.suggestions if x.technique_id == "T1059.001")
        assert s.priority == "medium"

    async def test_trending_with_no_rule_coverage_yields_high(
        self, db_session: AsyncSession
    ) -> None:
        # count > 0, no critical/high, no enabled rules → "high" (blind spot)
        db_session.add(
            _detection(
                technique_id="T1547.001",
                technique_name="Registry Run Keys",
                tactic="Persistence",
                tactic_id="TA0003",
                severity="medium",
            )
        )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        s = next(x for x in resp.suggestions if x.technique_id == "T1547.001")
        assert s.priority == "high"

    async def test_trending_with_rule_coverage_medium_severity_yields_medium(
        self, db_session: AsyncSession
    ) -> None:
        # count > 0, rule_count > 0, no critical/high detections → "medium"
        db_session.add(
            _detection(
                technique_id="T1021.002",
                technique_name="SMB",
                tactic="Lateral Movement",
                tactic_id="TA0008",
                severity="medium",
            )
        )
        db_session.add(_rule(enabled=True, technique_ids=["T1021.002"]))
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        s = next(x for x in resp.suggestions if x.technique_id == "T1021.002")
        assert s.priority == "medium"

    async def test_old_detections_outside_window_excluded(
        self, db_session: AsyncSession
    ) -> None:
        # Detection is 48h old — outside a 24h window
        db_session.add(
            _detection(
                technique_id="T1021.003",
                time=_OUT_OF_WINDOW_24H,
            )
        )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session, hours=24)
        for s in resp.suggestions:
            if s.technique_id == "T1021.003":
                # If it appears (e.g. as a gap), detection_count must be 0
                assert s.detection_count == 0

    async def test_coverage_gap_surfaced_as_low_priority(
        self, db_session: AsyncSession
    ) -> None:
        # Disabled rule only → coverage gap → low priority
        db_session.add(
            _rule(
                title="Boot Persistence Rule",
                enabled=False,
                technique_ids=["T1547.001"],
            )
        )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        s = next(
            (x for x in resp.suggestions if x.technique_id == "T1547.001"), None
        )
        assert s is not None
        assert s.priority == "low"
        assert s.detection_count == 0
        assert s.rule_count == 0

    async def test_gap_suggestion_has_query(self, db_session: AsyncSession) -> None:
        db_session.add(
            _rule(enabled=False, technique_ids=["T1547.001"])
        )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        s = next(x for x in resp.suggestions if x.technique_id == "T1547.001")
        assert len(s.suggested_queries) >= 1
        assert all(q.time_from for q in s.suggested_queries)

    async def test_trending_technique_in_gap_not_duplicated(
        self, db_session: AsyncSession
    ) -> None:
        # T1547.001 has a detection (trending) AND a disabled rule (gap)
        db_session.add(
            _detection(
                technique_id="T1547.001",
                technique_name="Registry Run Keys",
                tactic="Persistence",
                tactic_id="TA0003",
            )
        )
        db_session.add(_rule(enabled=False, technique_ids=["T1547.001"]))
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        count = sum(1 for s in resp.suggestions if s.technique_id == "T1547.001")
        assert count == 1

    async def test_coverage_gaps_capped_at_gap_limit(
        self, db_session: AsyncSession
    ) -> None:
        # Create _GAP_LIMIT + 2 disabled rules — gap limit should cap output
        for i in range(_GAP_LIMIT + 2):
            tid = f"T9{i:03d}"
            db_session.add(
                _rule(
                    title=f"Gap Rule {i}",
                    enabled=False,
                    technique_ids=[tid],
                )
            )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        gap_suggestions = [s for s in resp.suggestions if s.priority == "low"]
        assert len(gap_suggestions) <= _GAP_LIMIT

    async def test_sorting_high_before_medium_before_low(
        self, db_session: AsyncSession
    ) -> None:
        # critical detection → high
        db_session.add(
            _detection(
                technique_id="T1003.006",
                technique_name="DCSync",
                tactic="Credential Access",
                tactic_id="TA0006",
                severity="critical",
            )
        )
        # high detection with rules → medium
        db_session.add(
            _detection(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="Execution",
                tactic_id="TA0002",
                severity="high",
            )
        )
        db_session.add(_rule(enabled=True, technique_ids=["T1059.001"]))
        # disabled rule only → gap → low
        db_session.add(
            _rule(
                title="Gap Only Rule",
                enabled=False,
                technique_ids=["T1547.001"],
            )
        )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        priorities = [s.priority for s in resp.suggestions]
        priority_order = {"high": 0, "medium": 1, "low": 2}
        ordered = [priority_order[p] for p in priorities]
        assert ordered == sorted(ordered), f"Suggestions not sorted correctly: {priorities}"

    async def test_same_priority_sorted_by_detection_count_desc(
        self, db_session: AsyncSession
    ) -> None:
        # Two techniques both at "high" priority (both have critical detections)
        # T1003.006 gets 3 detections, T1078.001 gets 1
        for _ in range(3):
            db_session.add(
                _detection(
                    technique_id="T1003.006",
                    technique_name="DCSync",
                    tactic="Credential Access",
                    tactic_id="TA0006",
                    severity="critical",
                )
            )
        db_session.add(
            _detection(
                technique_id="T1078.001",
                technique_name="Default Accounts",
                tactic="Initial Access",
                tactic_id="TA0001",
                severity="critical",
            )
        )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        high_suggestions = [s for s in resp.suggestions if s.priority == "high"]
        # Technique with 3 detections should come first
        assert high_suggestions[0].technique_id == "T1003.006"
        assert high_suggestions[1].technique_id == "T1078.001"

    async def test_rule_count_reflected_from_enabled_rules(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(
            _detection(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="Execution",
                tactic_id="TA0002",
                severity="high",
            )
        )
        # Add 3 enabled rules for T1059.001
        for i in range(3):
            db_session.add(_rule(title=f"PS Rule {i}", enabled=True, technique_ids=["T1059.001"]))
        # Add 1 disabled rule — should NOT count
        db_session.add(_rule(title="Disabled PS Rule", enabled=False, technique_ids=["T1059.001"]))
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        s = next(x for x in resp.suggestions if x.technique_id == "T1059.001")
        assert s.rule_count == 3

    async def test_suggested_queries_use_correct_time_from(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(
            _detection(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="Execution",
                tactic_id="TA0002",
            )
        )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session, hours=48)
        s = next(x for x in resp.suggestions if x.technique_id == "T1059.001")
        assert all(q.time_from == "now-48h" for q in s.suggested_queries)

    async def test_suggestion_has_all_required_fields(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(
            _detection(
                technique_id="T1055.001",
                technique_name="DLL Injection",
                tactic="Defense Evasion",
                tactic_id="TA0005",
                severity="high",
            )
        )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        s = next(x for x in resp.suggestions if x.technique_id == "T1055.001")

        assert isinstance(s.technique_id, str)
        assert isinstance(s.technique_name, str)
        assert isinstance(s.tactic, str)
        assert isinstance(s.tactic_id, str)
        assert isinstance(s.reason, str) and s.reason
        assert s.priority in ("high", "medium", "low")
        assert isinstance(s.detection_count, int)
        assert isinstance(s.rule_count, int)
        assert isinstance(s.suggested_queries, list) and s.suggested_queries

    async def test_duplicate_technique_in_activity_appears_once(
        self, db_session: AsyncSession
    ) -> None:
        # The repo deduplicates by technique_id, but service also has dedup guard
        # This test verifies the service-level dedup via seen_techniques set.
        # We add a second detection for the same technique (same time window).
        for _ in range(2):
            db_session.add(
                _detection(
                    technique_id="T1059.001",
                    technique_name="PowerShell",
                    tactic="Execution",
                    tactic_id="TA0002",
                )
            )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        count = sum(1 for s in resp.suggestions if s.technique_id == "T1059.001")
        assert count == 1

    async def test_default_hours_is_24(self, db_session: AsyncSession) -> None:
        resp = await get_hunt_suggestions(db_session)
        assert resp.window_hours == 24

    async def test_default_limit_is_10(self, db_session: AsyncSession) -> None:
        # Create 15 distinct techniques
        for i in range(15):
            db_session.add(
                _detection(
                    technique_id=f"T{1000 + i}",
                    technique_name=f"Technique {i}",
                    tactic="Execution",
                    tactic_id="TA0002",
                    severity="critical",
                )
            )
        await db_session.flush()

        resp = await get_hunt_suggestions(db_session)
        assert len(resp.suggestions) <= 10
