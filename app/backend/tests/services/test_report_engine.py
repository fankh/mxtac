"""Tests for ReportEngine — structured report data generation.

Feature 31.1 — Report template engine

Coverage:
  - generate(): missing from_date → ValueError
  - generate(): missing to_date → ValueError
  - generate(): non-datetime from_date → ValueError
  - generate(): from_date after to_date → ValueError
  - generate(): unknown template_type → ValueError
  - compliance_summary: invalid framework → ValueError
  - executive_summary: empty DB → all-zero KPIs, no crash
  - executive_summary: with detections + incidents → populated KPIs, top_risks
  - detection_report: no detections in range → empty groups
  - detection_report: detections in range → grouped by severity and tactic
  - incident_report: no incidents in range → empty list
  - incident_report: incidents in range → serialized with timeline
  - coverage_report: no rules → zero coverage, empty gaps
  - coverage_report: with rules → coverage_pct and rules_by_technique populated
  - compliance_summary(nist): NIST-only controls mapped
  - compliance_summary(pci_dss): PCI-only requirements mapped
  - compliance_summary(both): both frameworks present
  - _build_nist_mapping: known tactic maps to correct controls
  - _build_pci_mapping: known tactic maps to correct requirement
  - _build_incident_timeline: orders lifecycle events chronologically
  - _parse_time_range: adds UTC to naive datetimes
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import new_uuid
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.rule import Rule
from app.services.report_engine import (
    ReportEngine,
    _build_incident_timeline,
    _build_nist_mapping,
    _build_pci_mapping,
    _parse_time_range,
)

# ---------------------------------------------------------------------------
# Date fixtures used throughout
# ---------------------------------------------------------------------------

_FROM = datetime(2026, 1, 1, tzinfo=timezone.utc)
_TO = datetime(2026, 1, 31, 23, 59, 59, tzinfo=timezone.utc)
_IN_RANGE = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
_BEFORE = datetime(2025, 12, 15, tzinfo=timezone.utc)

_PARAMS = {"from_date": _FROM, "to_date": _TO}


# ---------------------------------------------------------------------------
# Helpers — insert ORM rows directly
# ---------------------------------------------------------------------------


def _make_detection(
    *,
    severity: str = "high",
    tactic: str = "Execution",
    technique_id: str = "T1059.001",
    time: datetime = _IN_RANGE,
    status: str = "active",
    score: float = 7.5,
    name: str = "Suspicious PowerShell",
) -> Detection:
    return Detection(
        id=new_uuid(),
        name=name,
        severity=severity,
        tactic=tactic,
        tactic_id="TA0002",
        technique_id=technique_id,
        technique_name="PowerShell",
        host="WIN-DC01",
        user="CORP\\admin",
        time=time,
        status=status,
        score=score,
        rule_name="Test Rule",
        description="Test detection",
        log_source="wazuh",
    )


def _make_incident(
    *,
    severity: str = "high",
    status: str = "investigating",
    created_at: datetime = _IN_RANGE,
    ttr_seconds: int | None = 3600,
    ttd_seconds: int | None = 1800,
    notes: list | None = None,
) -> Incident:
    return Incident(
        title="Test Incident",
        description="Test incident description",
        severity=severity,
        status=status,
        priority=2,
        created_by="analyst",
        created_at=created_at,
        ttr_seconds=ttr_seconds,
        ttd_seconds=ttd_seconds,
        notes=notes or [],
        detection_ids=[],
        technique_ids=["T1059.001"],
        tactic_ids=["TA0002"],
        hosts=["WIN-DC01"],
    )


def _make_rule(
    *,
    title: str = "Test Rule",
    enabled: bool = True,
    level: str = "high",
    technique_ids: list[str] | None = None,
    tactic_ids: list[str] | None = None,
    logsource_product: str = "windows",
) -> Rule:
    return Rule(
        id=new_uuid(),
        title=title,
        content="detection:\n  condition: all of them",
        status="stable",
        level=level,
        enabled=enabled,
        rule_type="sigma",
        technique_ids=json.dumps(technique_ids or ["T1059.001"]),
        tactic_ids=json.dumps(tactic_ids or ["TA0002"]),
        logsource_product=logsource_product,
        logsource_category="process_creation",
        logsource_service="",
        created_by="analyst",
    )


# ---------------------------------------------------------------------------
# generate() — parameter validation
# ---------------------------------------------------------------------------


class TestGenerateValidation:
    """generate() raises ValueError for invalid parameters."""

    async def test_missing_from_date(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        with pytest.raises(ValueError, match="from_date"):
            await engine.generate("executive_summary", {"to_date": _TO})

    async def test_missing_to_date(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        with pytest.raises(ValueError, match="to_date"):
            await engine.generate("executive_summary", {"from_date": _FROM})

    async def test_from_date_not_datetime(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        with pytest.raises(ValueError, match="datetime"):
            await engine.generate(
                "executive_summary",
                {"from_date": "2026-01-01", "to_date": _TO},
            )

    async def test_to_date_not_datetime(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        with pytest.raises(ValueError, match="datetime"):
            await engine.generate(
                "executive_summary",
                {"from_date": _FROM, "to_date": "2026-01-31"},
            )

    async def test_from_date_after_to_date(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        with pytest.raises(ValueError, match="from_date must not be after"):
            await engine.generate(
                "executive_summary",
                {"from_date": _TO, "to_date": _FROM},
            )

    async def test_unknown_template_type(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        with pytest.raises(ValueError, match="Unknown template type"):
            await engine.generate("nonexistent_report", _PARAMS)

    async def test_invalid_framework_compliance(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        with pytest.raises(ValueError, match="Invalid framework"):
            await engine.generate(
                "compliance_summary",
                {**_PARAMS, "framework": "iso27001"},
            )


# ---------------------------------------------------------------------------
# executive_summary
# ---------------------------------------------------------------------------


class TestExecutiveSummary:
    """executive_summary template returns correct KPI structure."""

    async def test_empty_db_returns_zero_kpis(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("executive_summary", _PARAMS)

        assert report["template"] == "executive_summary"
        assert report["kpis"]["total_detections"] == 0
        assert report["kpis"]["critical_detections"] == 0
        assert report["kpis"]["open_incidents"] == 0
        assert report["kpis"]["coverage_pct"] is None
        assert report["top_risks"] == []

    async def test_required_keys_present(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("executive_summary", _PARAMS)

        assert "template" in report
        assert "generated_at" in report
        assert "period" in report
        assert "kpis" in report
        assert "top_risks" in report
        assert "incident_severity_breakdown" in report
        assert "incident_status_breakdown" in report

    async def test_period_reflects_params(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("executive_summary", _PARAMS)

        assert report["period"]["from"] == _FROM.isoformat()
        assert report["period"]["to"] == _TO.isoformat()

    async def test_with_detections_counts_correctly(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_detection(severity="critical"))
        db_session.add(_make_detection(severity="high"))
        db_session.add(_make_detection(severity="critical", time=_BEFORE))  # out of range
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("executive_summary", _PARAMS)

        assert report["kpis"]["total_detections"] == 2
        assert report["kpis"]["critical_detections"] == 1

    async def test_top_risks_capped_at_five(self, db_session: AsyncSession) -> None:
        tactics = [
            "Execution", "Persistence", "Credential Access",
            "Discovery", "Lateral Movement", "Defense Evasion",
        ]
        for i, tactic in enumerate(tactics):
            db_session.add(_make_detection(tactic=tactic, technique_id=f"T100{i}"))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("executive_summary", _PARAMS)

        assert len(report["top_risks"]) <= 5

    async def test_mttr_hours_computed_from_ttr_seconds(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(
            _make_incident(status="closed", ttr_seconds=7200, created_at=_IN_RANGE)
        )
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("executive_summary", _PARAMS)

        assert report["kpis"]["mttr_hours"] == 2.0

    async def test_mttr_none_when_no_closed_incidents(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_incident(status="investigating", ttr_seconds=None))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("executive_summary", _PARAMS)

        assert report["kpis"]["mttr_hours"] is None


# ---------------------------------------------------------------------------
# detection_report
# ---------------------------------------------------------------------------


class TestDetectionReport:
    """detection_report template groups detections by severity and tactic."""

    async def test_empty_db_returns_empty_groups(
        self, db_session: AsyncSession
    ) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("detection_report", _PARAMS)

        assert report["template"] == "detection_report"
        assert report["summary"]["total"] == 0
        assert report["by_severity"] == {}
        assert report["by_tactic"] == {}

    async def test_detections_in_range_are_included(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_detection(severity="high", tactic="Execution"))
        db_session.add(_make_detection(severity="critical", tactic="Persistence"))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("detection_report", _PARAMS)

        assert report["summary"]["total"] == 2
        assert "high" in report["by_severity"]
        assert "critical" in report["by_severity"]
        assert "Execution" in report["by_tactic"]
        assert "Persistence" in report["by_tactic"]

    async def test_detections_outside_range_excluded(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_detection(time=_BEFORE))
        db_session.add(_make_detection(time=_IN_RANGE))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("detection_report", _PARAMS)

        assert report["summary"]["total"] == 1

    async def test_by_severity_contains_count_and_detections(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_detection(severity="high"))
        db_session.add(_make_detection(severity="high", name="Second Detection"))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("detection_report", _PARAMS)

        assert report["by_severity"]["high"]["count"] == 2
        assert len(report["by_severity"]["high"]["detections"]) == 2

    async def test_detection_dict_has_required_fields(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_detection())
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("detection_report", _PARAMS)

        det = report["by_severity"]["high"]["detections"][0]
        for field in ("id", "name", "severity", "tactic", "technique_id", "host", "time", "status", "score"):
            assert field in det, f"Missing field: {field}"

    async def test_timeline_present(self, db_session: AsyncSession) -> None:
        db_session.add(_make_detection())
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("detection_report", _PARAMS)

        assert "timeline" in report
        assert isinstance(report["timeline"], list)

    async def test_tactic_summary_present(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("detection_report", _PARAMS)

        assert "tactic_summary" in report
        assert isinstance(report["tactic_summary"], list)


# ---------------------------------------------------------------------------
# incident_report
# ---------------------------------------------------------------------------


class TestIncidentReport:
    """incident_report template serializes incidents with timelines."""

    async def test_empty_db_returns_empty_incidents(
        self, db_session: AsyncSession
    ) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("incident_report", _PARAMS)

        assert report["template"] == "incident_report"
        assert report["summary"]["total"] == 0
        assert report["incidents"] == []

    async def test_incident_in_range_included(self, db_session: AsyncSession) -> None:
        db_session.add(_make_incident(created_at=_IN_RANGE))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("incident_report", _PARAMS)

        assert report["summary"]["total"] == 1
        assert len(report["incidents"]) == 1

    async def test_incident_before_range_excluded(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_incident(created_at=_BEFORE))
        db_session.add(_make_incident(created_at=_IN_RANGE))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("incident_report", _PARAMS)

        assert report["summary"]["total"] == 1

    async def test_incident_dict_has_required_fields(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_incident())
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("incident_report", _PARAMS)

        inc = report["incidents"][0]
        for field in (
            "id", "title", "severity", "status", "created_at",
            "ttr_seconds", "detection_ids", "hosts", "timeline",
        ):
            assert field in inc, f"Missing field: {field}"

    async def test_incident_timeline_present(self, db_session: AsyncSession) -> None:
        db_session.add(_make_incident())
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("incident_report", _PARAMS)

        assert isinstance(report["incidents"][0]["timeline"], list)

    async def test_mttr_computed_from_closed_incidents(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(
            _make_incident(status="closed", ttr_seconds=3600, created_at=_IN_RANGE)
        )
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("incident_report", _PARAMS)

        assert report["summary"]["mttr_hours"] == 1.0

    async def test_mttd_computed_from_ttd_seconds(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(
            _make_incident(ttd_seconds=1800, created_at=_IN_RANGE)
        )
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("incident_report", _PARAMS)

        assert report["summary"]["mttd_hours"] == 0.5

    async def test_severity_breakdown_in_summary(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_incident(severity="critical", created_at=_IN_RANGE))
        db_session.add(_make_incident(severity="high", created_at=_IN_RANGE))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("incident_report", _PARAMS)

        assert "severity_breakdown" in report["summary"]


# ---------------------------------------------------------------------------
# coverage_report
# ---------------------------------------------------------------------------


class TestCoverageReport:
    """coverage_report template returns ATT&CK coverage data."""

    async def test_empty_db_zero_coverage(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("coverage_report", _PARAMS)

        assert report["template"] == "coverage_report"
        assert report["overall"]["coverage_pct"] == 0.0
        assert report["overall"]["covered_count"] == 0

    async def test_with_rules_coverage_nonzero(self, db_session: AsyncSession) -> None:
        db_session.add(_make_rule(technique_ids=["T1059.001", "T1078"]))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("coverage_report", _PARAMS)

        assert report["overall"]["covered_count"] == 2
        assert report["overall"]["coverage_pct"] > 0

    async def test_rules_by_technique_populated(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_rule(technique_ids=["T1059.001"]))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("coverage_report", _PARAMS)

        assert "T1059.001" in report["rules_by_technique"]
        assert report["rules_by_technique"]["T1059.001"] == 1

    async def test_coverage_by_datasource_present(
        self, db_session: AsyncSession
    ) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("coverage_report", _PARAMS)

        assert "coverage_by_datasource" in report
        assert "sources" in report["coverage_by_datasource"]

    async def test_uncovered_techniques_is_list(
        self, db_session: AsyncSession
    ) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("coverage_report", _PARAMS)

        assert isinstance(report["uncovered_techniques"], list)

    async def test_disabled_rules_not_counted(self, db_session: AsyncSession) -> None:
        db_session.add(_make_rule(enabled=False, technique_ids=["T1059.001"]))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate("coverage_report", _PARAMS)

        assert report["overall"]["covered_count"] == 0


# ---------------------------------------------------------------------------
# compliance_summary
# ---------------------------------------------------------------------------


class TestComplianceSummary:
    """compliance_summary maps detections to NIST/PCI-DSS controls."""

    async def test_empty_db_returns_empty_controls(
        self, db_session: AsyncSession
    ) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("compliance_summary", _PARAMS)

        assert report["template"] == "compliance_summary"
        assert report["nist_800_53"] == []
        assert report["pci_dss"] == []

    async def test_framework_both_includes_nist_and_pci(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_detection(tactic="Execution"))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate(
            "compliance_summary", {**_PARAMS, "framework": "both"}
        )

        assert report["nist_800_53"] is not None
        assert report["pci_dss"] is not None

    async def test_framework_nist_excludes_pci(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate(
            "compliance_summary", {**_PARAMS, "framework": "nist"}
        )

        assert report["nist_800_53"] is not None
        assert report["pci_dss"] is None

    async def test_framework_pci_dss_excludes_nist(
        self, db_session: AsyncSession
    ) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate(
            "compliance_summary", {**_PARAMS, "framework": "pci_dss"}
        )

        assert report["nist_800_53"] is None
        assert report["pci_dss"] is not None

    async def test_nist_controls_sorted_by_detection_count_desc(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_detection(tactic="Execution"))
        db_session.add(_make_detection(tactic="Execution"))
        db_session.add(_make_detection(tactic="Discovery"))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate(
            "compliance_summary", {**_PARAMS, "framework": "nist"}
        )

        counts = [c["detection_count"] for c in report["nist_800_53"]]
        assert counts == sorted(counts, reverse=True)

    async def test_nist_control_has_required_fields(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_detection(tactic="Execution"))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate(
            "compliance_summary", {**_PARAMS, "framework": "nist"}
        )

        assert len(report["nist_800_53"]) > 0
        control = report["nist_800_53"][0]
        assert "control_id" in control
        assert "detection_count" in control
        assert "tactics" in control

    async def test_pci_requirement_has_required_fields(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_detection(tactic="Execution"))
        await db_session.flush()

        engine = ReportEngine(db_session)
        report = await engine.generate(
            "compliance_summary", {**_PARAMS, "framework": "pci_dss"}
        )

        assert len(report["pci_dss"]) > 0
        req = report["pci_dss"][0]
        assert "requirement" in req
        assert "detection_count" in req
        assert "tactics" in req

    async def test_default_framework_is_both(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("compliance_summary", _PARAMS)

        assert report["framework"] == "both"

    async def test_coverage_context_included(self, db_session: AsyncSession) -> None:
        engine = ReportEngine(db_session)
        report = await engine.generate("compliance_summary", _PARAMS)

        assert "coverage_context" in report


# ---------------------------------------------------------------------------
# Unit tests for pure helper functions
# ---------------------------------------------------------------------------


class TestBuildNistMapping:
    """_build_nist_mapping maps tactic counts to NIST controls."""

    def test_known_tactic_mapped(self) -> None:
        result = _build_nist_mapping({"Execution": 5})
        control_ids = [c["control_id"] for c in result]
        assert "CM-7" in control_ids
        assert "SI-2" in control_ids

    def test_unknown_tactic_produces_empty_list(self) -> None:
        result = _build_nist_mapping({"UnknownTactic": 10})
        assert result == []

    def test_sorted_by_detection_count_desc(self) -> None:
        result = _build_nist_mapping({"Execution": 10, "Discovery": 1})
        counts = [c["detection_count"] for c in result]
        assert counts == sorted(counts, reverse=True)

    def test_tactic_listed_in_control(self) -> None:
        result = _build_nist_mapping({"Execution": 3})
        exec_controls = [c for c in result if "Execution" in c["tactics"]]
        assert len(exec_controls) > 0

    def test_shared_control_aggregates_counts(self) -> None:
        # "SI-4" is in both Reconnaissance and Defense Evasion mappings
        result = _build_nist_mapping({"Reconnaissance": 2, "Defense Evasion": 3})
        si4 = next((c for c in result if c["control_id"] == "SI-4"), None)
        assert si4 is not None
        assert si4["detection_count"] == 5


class TestBuildPciMapping:
    """_build_pci_mapping maps tactic counts to PCI-DSS requirements."""

    def test_known_tactic_mapped(self) -> None:
        result = _build_pci_mapping({"Initial Access": 4})
        req_ids = [r["requirement"] for r in result]
        assert "Req-1.3" in req_ids
        assert "Req-6.3" in req_ids

    def test_unknown_tactic_produces_empty_list(self) -> None:
        result = _build_pci_mapping({"UnknownTactic": 10})
        assert result == []

    def test_sorted_by_detection_count_desc(self) -> None:
        result = _build_pci_mapping({"Initial Access": 10, "Discovery": 2})
        counts = [r["detection_count"] for r in result]
        assert counts == sorted(counts, reverse=True)


class TestBuildIncidentTimeline:
    """_build_incident_timeline produces ordered events from incident data."""

    def _make_inc(self, **kwargs) -> object:
        from unittest.mock import MagicMock
        inc = MagicMock()
        inc.created_at = kwargs.get("created_at", datetime(2026, 1, 1, tzinfo=timezone.utc))
        inc.closed_at = kwargs.get("closed_at", None)
        inc.severity = kwargs.get("severity", "high")
        inc.status = kwargs.get("status", "closed")
        inc.notes = kwargs.get("notes", [])
        return inc

    def test_created_event_present(self) -> None:
        inc = self._make_inc()
        timeline = _build_incident_timeline(inc)
        events = [e["event"] for e in timeline]
        assert "created" in events

    def test_closed_event_present_when_closed_at_set(self) -> None:
        inc = self._make_inc(closed_at=datetime(2026, 1, 2, tzinfo=timezone.utc))
        timeline = _build_incident_timeline(inc)
        events = [e["event"] for e in timeline]
        assert "closed" in events

    def test_note_event_included(self) -> None:
        notes = [{"created_at": "2026-01-01T06:00:00+00:00", "author": "alice", "content": "Checked logs"}]
        inc = self._make_inc(notes=notes)
        timeline = _build_incident_timeline(inc)
        events = [e["event"] for e in timeline]
        assert "note" in events

    def test_events_sorted_by_timestamp(self) -> None:
        notes = [
            {"created_at": "2026-01-01T12:00:00+00:00", "author": "bob", "content": "Later note"},
            {"created_at": "2026-01-01T06:00:00+00:00", "author": "alice", "content": "Early note"},
        ]
        inc = self._make_inc(
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            closed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            notes=notes,
        )
        timeline = _build_incident_timeline(inc)
        timestamps = [e["timestamp"] for e in timeline]
        assert timestamps == sorted(timestamps)

    def test_no_events_when_no_dates(self) -> None:
        inc = self._make_inc(created_at=None, closed_at=None, notes=[])
        timeline = _build_incident_timeline(inc)
        assert timeline == []


class TestParseTimeRange:
    """_parse_time_range validates and returns UTC-aware datetimes."""

    def test_naive_datetimes_get_utc_added(self) -> None:
        naive_from = datetime(2026, 1, 1)
        naive_to = datetime(2026, 1, 31)
        from_dt, to_dt = _parse_time_range({"from_date": naive_from, "to_date": naive_to})
        assert from_dt.tzinfo is not None
        assert to_dt.tzinfo is not None

    def test_aware_datetimes_pass_through(self) -> None:
        from_dt, to_dt = _parse_time_range({"from_date": _FROM, "to_date": _TO})
        assert from_dt == _FROM
        assert to_dt == _TO

    def test_missing_from_date_raises(self) -> None:
        with pytest.raises(ValueError, match="from_date"):
            _parse_time_range({"to_date": _TO})

    def test_missing_to_date_raises(self) -> None:
        with pytest.raises(ValueError, match="to_date"):
            _parse_time_range({"from_date": _FROM})

    def test_invalid_from_type_raises(self) -> None:
        with pytest.raises(ValueError, match="datetime"):
            _parse_time_range({"from_date": "2026-01-01", "to_date": _TO})

    def test_from_after_to_raises(self) -> None:
        with pytest.raises(ValueError, match="from_date must not be after"):
            _parse_time_range({"from_date": _TO, "to_date": _FROM})
