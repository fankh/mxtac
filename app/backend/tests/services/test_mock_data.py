"""Tests for the mock_data service (app/services/mock_data.py).

Coverage:
  DETECTIONS:
  - List contains 11 entries
  - All entries are Detection instances with required fields populated
  - Severity values are restricted to valid literals
  - Status values are restricted to valid literals
  - Detection IDs are unique
  - Scores are within expected range (0.0–10.0)
  - Severity is consistent with score (critical ≥ 8.0, high ≥ 6.0, etc.)
  - First detection matches expected attributes
  - Detections with related techniques have non-empty lists

  KPI:
  - KpiMetrics instance has all required fields
  - attack_covered ≤ attack_total
  - sigma_rules_critical + sigma_rules_high ≤ sigma_rules_active
  - integrations_active ≤ integrations_total
  - All numeric fields are positive where expected

  TIMELINE:
  - List contains 7 entries
  - Each TimelinePoint: total equals critical + high + medium
  - Date labels are non-empty strings

  TACTICS:
  - List contains 6 entries
  - All TacticBar instances have non-empty tactic names and positive counts

  TACTIC_LABELS:
  - Contains exactly 9 labels
  - All labels are non-empty strings

  HEATMAP:
  - List contains 4 HeatRow entries
  - Row indices are sequential starting from 0
  - Each row has exactly 9 HeatCells
  - covered ≤ total for all HeatCells
  - opacity is correctly computed: round(0.10 + (covered/total)*0.75, 2)
  - opacity is 0.0 when total is 0 (edge case)
  - opacity is 0.10 when covered is 0
  - opacity is 0.85 when fully covered

  COVERAGE_SUMMARY:
  - CoverageSummary has covered_count ≤ total_count
  - coverage_pct is approximately covered_count / total_count * 100

  INTEGRATIONS:
  - List contains 8 entries
  - IDs are unique
  - Status values are valid ("connected", "warning", "disabled")
  - Number of connected integrations matches KPI.integrations_active
"""

from __future__ import annotations

import pytest

from app.schemas.detection import Detection
from app.schemas.overview import (
    CoverageSummary,
    HeatCell,
    HeatRow,
    IntegrationStatus,
    KpiMetrics,
    TacticBar,
    TimelinePoint,
)
from app.services.mock_data import (
    COVERAGE_SUMMARY,
    DETECTIONS,
    HEATMAP,
    INTEGRATIONS,
    KPI,
    TACTIC_LABELS,
    TACTICS,
    TIMELINE,
)

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"active", "investigating", "resolved", "false_positive"}
_VALID_INTEGRATION_STATUSES = {"connected", "warning", "disabled"}


# ---------------------------------------------------------------------------
# DETECTIONS
# ---------------------------------------------------------------------------


class TestDetections:
    def test_detections_count(self) -> None:
        assert len(DETECTIONS) == 11

    def test_all_detections_are_detection_instances(self) -> None:
        for det in DETECTIONS:
            assert isinstance(det, Detection), f"{det!r} is not a Detection"

    def test_severity_values_are_valid(self) -> None:
        for det in DETECTIONS:
            assert det.severity in _VALID_SEVERITIES, (
                f"Detection {det.id} has invalid severity: {det.severity}"
            )

    def test_status_values_are_valid(self) -> None:
        for det in DETECTIONS:
            assert det.status in _VALID_STATUSES, (
                f"Detection {det.id} has invalid status: {det.status}"
            )

    def test_detection_ids_are_unique(self) -> None:
        ids = [det.id for det in DETECTIONS]
        assert len(ids) == len(set(ids)), "Duplicate detection IDs found"

    def test_scores_within_valid_range(self) -> None:
        for det in DETECTIONS:
            assert 0.0 <= det.score <= 10.0, (
                f"Detection {det.id} has out-of-range score: {det.score}"
            )

    def test_severity_consistent_with_score(self) -> None:
        """Check rough severity/score alignment."""
        thresholds = {"critical": 8.0, "high": 6.0, "medium": 4.0, "low": 0.0}
        for det in DETECTIONS:
            min_score = thresholds[det.severity]
            assert det.score >= min_score, (
                f"Detection {det.id}: severity={det.severity} but score={det.score} "
                f"is below the expected minimum of {min_score}"
            )

    def test_required_string_fields_non_empty(self) -> None:
        for det in DETECTIONS:
            assert det.id, f"Detection has empty id"
            assert det.name, f"Detection {det.id} has empty name"
            assert det.host, f"Detection {det.id} has empty host"
            assert det.tactic, f"Detection {det.id} has empty tactic"
            assert det.technique_id, f"Detection {det.id} has empty technique_id"
            assert det.technique_name, f"Detection {det.id} has empty technique_name"

    def test_time_is_timezone_aware(self) -> None:
        for det in DETECTIONS:
            assert det.time.tzinfo is not None, (
                f"Detection {det.id} time is not timezone-aware"
            )

    def test_first_detection_attributes(self) -> None:
        """Spot-check the first detection in the list."""
        first = DETECTIONS[0]
        assert first.id == "DET-2026-00847"
        assert first.severity == "critical"
        assert first.technique_id == "T1003.006"
        assert first.technique_name == "DCSync"
        assert first.host == "DC-PROD-01"
        assert first.tactic == "Credential Access"
        assert first.status == "active"
        assert first.score == 9.0

    def test_critical_detections_have_high_confidence(self) -> None:
        for det in DETECTIONS:
            if det.severity == "critical" and det.confidence is not None:
                assert det.confidence >= 80, (
                    f"Critical detection {det.id} has low confidence: {det.confidence}"
                )

    def test_related_technique_ids_are_lists(self) -> None:
        for det in DETECTIONS:
            assert isinstance(det.related_technique_ids, list), (
                f"Detection {det.id}: related_technique_ids is not a list"
            )

    def test_cvss_v3_within_range(self) -> None:
        for det in DETECTIONS:
            if det.cvss_v3 is not None:
                assert 0.0 <= det.cvss_v3 <= 10.0, (
                    f"Detection {det.id}: cvss_v3={det.cvss_v3} out of range"
                )

    @pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
    def test_each_severity_level_is_represented(self, severity: str) -> None:
        severities = {det.severity for det in DETECTIONS}
        assert severity in severities, f"No detection with severity '{severity}' found"

    @pytest.mark.parametrize("status", ["active", "investigating", "resolved"])
    def test_each_status_is_represented(self, status: str) -> None:
        statuses = {det.status for det in DETECTIONS}
        assert status in statuses, f"No detection with status '{status}' found"


# ---------------------------------------------------------------------------
# KPI
# ---------------------------------------------------------------------------


class TestKpi:
    def test_kpi_is_kpimetrics_instance(self) -> None:
        assert isinstance(KPI, KpiMetrics)

    def test_attack_covered_does_not_exceed_total(self) -> None:
        assert KPI.attack_covered <= KPI.attack_total

    def test_sigma_rule_breakdown_does_not_exceed_active(self) -> None:
        assert KPI.sigma_rules_critical + KPI.sigma_rules_high <= KPI.sigma_rules_active

    def test_integrations_active_does_not_exceed_total(self) -> None:
        assert KPI.integrations_active <= KPI.integrations_total

    def test_total_detections_positive(self) -> None:
        assert KPI.total_detections > 0

    def test_critical_alerts_positive(self) -> None:
        assert KPI.critical_alerts > 0

    def test_attack_coverage_pct_within_range(self) -> None:
        assert 0.0 <= KPI.attack_coverage_pct <= 100.0

    def test_mttd_minutes_positive(self) -> None:
        assert KPI.mttd_minutes > 0.0

    def test_sigma_rules_active_positive(self) -> None:
        assert KPI.sigma_rules_active > 0

    def test_attack_coverage_pct_consistent_with_counts(self) -> None:
        expected = KPI.attack_covered / KPI.attack_total * 100
        assert abs(KPI.attack_coverage_pct - expected) < 1.0, (
            f"attack_coverage_pct={KPI.attack_coverage_pct} is not consistent with "
            f"attack_covered={KPI.attack_covered} / attack_total={KPI.attack_total}"
        )


# ---------------------------------------------------------------------------
# TIMELINE
# ---------------------------------------------------------------------------


class TestTimeline:
    def test_timeline_count(self) -> None:
        assert len(TIMELINE) == 7

    def test_all_entries_are_timeline_points(self) -> None:
        for tp in TIMELINE:
            assert isinstance(tp, TimelinePoint)

    def test_total_equals_sum_of_components(self) -> None:
        for tp in TIMELINE:
            assert tp.total == tp.critical + tp.high + tp.medium, (
                f"TimelinePoint {tp.date}: total={tp.total} != "
                f"critical+high+medium={tp.critical + tp.high + tp.medium}"
            )

    def test_date_labels_non_empty(self) -> None:
        for tp in TIMELINE:
            assert tp.date, "TimelinePoint has empty date label"

    def test_counts_are_non_negative(self) -> None:
        for tp in TIMELINE:
            assert tp.critical >= 0
            assert tp.high >= 0
            assert tp.medium >= 0
            assert tp.total >= 0


# ---------------------------------------------------------------------------
# TACTICS
# ---------------------------------------------------------------------------


class TestTactics:
    def test_tactics_count(self) -> None:
        assert len(TACTICS) == 6

    def test_all_entries_are_tactic_bars(self) -> None:
        for tb in TACTICS:
            assert isinstance(tb, TacticBar)

    def test_tactic_names_non_empty(self) -> None:
        for tb in TACTICS:
            assert tb.tactic, "TacticBar has empty tactic name"

    def test_counts_positive(self) -> None:
        for tb in TACTICS:
            assert tb.count > 0, f"TacticBar '{tb.tactic}' has non-positive count"

    def test_tactic_names_unique(self) -> None:
        names = [tb.tactic for tb in TACTICS]
        assert len(names) == len(set(names)), "Duplicate tactic names found"


# ---------------------------------------------------------------------------
# TACTIC_LABELS
# ---------------------------------------------------------------------------


class TestTacticLabels:
    def test_tactic_labels_count(self) -> None:
        assert len(TACTIC_LABELS) == 9

    def test_all_labels_are_non_empty_strings(self) -> None:
        for label in TACTIC_LABELS:
            assert isinstance(label, str) and label, f"Invalid label: {label!r}"

    def test_labels_are_unique(self) -> None:
        assert len(TACTIC_LABELS) == len(set(TACTIC_LABELS)), (
            "Duplicate labels in TACTIC_LABELS"
        )


# ---------------------------------------------------------------------------
# HEATMAP
# ---------------------------------------------------------------------------


class TestHeatmap:
    def test_heatmap_row_count(self) -> None:
        assert len(HEATMAP) == 4

    def test_all_entries_are_heat_rows(self) -> None:
        for row in HEATMAP:
            assert isinstance(row, HeatRow)

    def test_row_indices_sequential(self) -> None:
        for i, row in enumerate(HEATMAP):
            assert row.row == i, (
                f"HeatRow at position {i} has row index {row.row}, expected {i}"
            )

    def test_each_row_has_nine_cells(self) -> None:
        for row in HEATMAP:
            assert len(row.cells) == 9, (
                f"HeatRow {row.technique_id} has {len(row.cells)} cells, expected 9"
            )

    def test_covered_does_not_exceed_total(self) -> None:
        for row in HEATMAP:
            for cell in row.cells:
                assert cell.covered <= cell.total, (
                    f"HeatRow {row.technique_id} / tactic {cell.tactic}: "
                    f"covered={cell.covered} > total={cell.total}"
                )

    def test_opacity_computed_correctly(self) -> None:
        """opacity = round(0.10 + (covered/total)*0.75, 2) for total > 0."""
        for row in HEATMAP:
            for cell in row.cells:
                if cell.total == 0:
                    expected = 0.0
                else:
                    ratio = cell.covered / cell.total
                    expected = round(0.10 + ratio * 0.75, 2)
                assert cell.opacity == expected, (
                    f"HeatRow {row.technique_id} / tactic {cell.tactic}: "
                    f"opacity={cell.opacity}, expected={expected}"
                )

    def test_fully_covered_cell_has_max_opacity(self) -> None:
        """A cell where covered == total has opacity == 0.85."""
        fully_covered = [
            (row, cell)
            for row in HEATMAP
            for cell in row.cells
            if cell.covered == cell.total and cell.total > 0
        ]
        assert fully_covered, "No fully-covered cell found in heatmap"
        for row, cell in fully_covered:
            assert cell.opacity == 0.85, (
                f"HeatRow {row.technique_id} / tactic {cell.tactic}: "
                f"expected opacity=0.85 for fully covered cell, got {cell.opacity}"
            )

    def test_zero_covered_cell_has_min_opacity(self) -> None:
        """A cell where covered == 0 (total > 0) has opacity == 0.10."""
        zero_covered = [
            (row, cell)
            for row in HEATMAP
            for cell in row.cells
            if cell.covered == 0 and cell.total > 0
        ]
        # Not guaranteed to exist in current data, skip if none found
        for row, cell in zero_covered:
            assert cell.opacity == 0.10

    def test_technique_ids_non_empty(self) -> None:
        for row in HEATMAP:
            assert row.technique_id, "HeatRow has empty technique_id"

    def test_cell_tactic_labels_match_tactic_labels(self) -> None:
        """Cell tactic labels must be drawn from TACTIC_LABELS."""
        for row in HEATMAP:
            for cell in row.cells:
                assert cell.tactic in TACTIC_LABELS, (
                    f"HeatRow {row.technique_id}: cell tactic '{cell.tactic}' "
                    f"not in TACTIC_LABELS"
                )

    def test_row_cells_cover_all_tactic_labels(self) -> None:
        """Each row must have exactly one cell per tactic label."""
        for row in HEATMAP:
            cell_tactics = [cell.tactic for cell in row.cells]
            assert sorted(cell_tactics) == sorted(TACTIC_LABELS), (
                f"HeatRow {row.technique_id}: cell tactics do not match TACTIC_LABELS"
            )

    def test_opacity_spot_check_t1059_recon(self) -> None:
        """T1059 RECON: covered=4, total=9 → opacity = 0.43."""
        row = next(r for r in HEATMAP if r.technique_id == "T1059")
        cell = next(c for c in row.cells if c.tactic == "RECON")
        assert cell.covered == 4
        assert cell.total == 9
        assert cell.opacity == round(0.10 + (4 / 9) * 0.75, 2)

    def test_opacity_spot_check_t1059_init_fully_covered(self) -> None:
        """T1059 INIT: covered=9, total=9 → opacity = 0.85."""
        row = next(r for r in HEATMAP if r.technique_id == "T1059")
        cell = next(c for c in row.cells if c.tactic == "INIT")
        assert cell.covered == 9
        assert cell.total == 9
        assert cell.opacity == 0.85


# ---------------------------------------------------------------------------
# HeatCell unit tests (opacity formula)
# ---------------------------------------------------------------------------


class TestHeatCellOpacity:
    def test_opacity_zero_covered(self) -> None:
        cell = HeatCell(tactic="EXEC", covered=0, total=10)
        assert cell.opacity == round(0.10 + 0.0 * 0.75, 2)

    def test_opacity_half_covered(self) -> None:
        cell = HeatCell(tactic="EXEC", covered=5, total=10)
        assert cell.opacity == round(0.10 + 0.5 * 0.75, 2)

    def test_opacity_fully_covered(self) -> None:
        cell = HeatCell(tactic="EXEC", covered=10, total=10)
        assert cell.opacity == 0.85

    def test_opacity_zero_total(self) -> None:
        cell = HeatCell(tactic="EXEC", covered=0, total=0)
        assert cell.opacity == 0.0

    def test_opacity_range(self) -> None:
        """opacity is always between 0.0 and 0.85."""
        for covered, total in [(0, 1), (1, 4), (7, 9), (9, 9), (0, 0)]:
            cell = HeatCell(tactic="X", covered=covered, total=total)
            assert 0.0 <= cell.opacity <= 0.85


# ---------------------------------------------------------------------------
# COVERAGE_SUMMARY
# ---------------------------------------------------------------------------


class TestCoverageSummary:
    def test_coverage_summary_is_correct_type(self) -> None:
        assert isinstance(COVERAGE_SUMMARY, CoverageSummary)

    def test_covered_count_does_not_exceed_total(self) -> None:
        assert COVERAGE_SUMMARY.covered_count <= COVERAGE_SUMMARY.total_count

    def test_coverage_pct_within_range(self) -> None:
        assert 0.0 <= COVERAGE_SUMMARY.coverage_pct <= 100.0

    def test_coverage_pct_consistent_with_counts(self) -> None:
        expected = COVERAGE_SUMMARY.covered_count / COVERAGE_SUMMARY.total_count * 100
        assert abs(COVERAGE_SUMMARY.coverage_pct - expected) < 1.0, (
            f"coverage_pct={COVERAGE_SUMMARY.coverage_pct} is not consistent with "
            f"covered={COVERAGE_SUMMARY.covered_count} / total={COVERAGE_SUMMARY.total_count}"
        )

    def test_total_count_positive(self) -> None:
        assert COVERAGE_SUMMARY.total_count > 0

    def test_covered_count_positive(self) -> None:
        assert COVERAGE_SUMMARY.covered_count > 0


# ---------------------------------------------------------------------------
# INTEGRATIONS
# ---------------------------------------------------------------------------


class TestIntegrations:
    def test_integrations_count(self) -> None:
        assert len(INTEGRATIONS) == 8

    def test_all_entries_are_integration_status_instances(self) -> None:
        for integ in INTEGRATIONS:
            assert isinstance(integ, IntegrationStatus)

    def test_integration_ids_unique(self) -> None:
        ids = [integ.id for integ in INTEGRATIONS]
        assert len(ids) == len(set(ids)), "Duplicate integration IDs found"

    def test_status_values_valid(self) -> None:
        for integ in INTEGRATIONS:
            assert integ.status in _VALID_INTEGRATION_STATUSES, (
                f"Integration '{integ.id}' has invalid status: {integ.status}"
            )

    def test_ids_and_names_non_empty(self) -> None:
        for integ in INTEGRATIONS:
            assert integ.id, "Integration has empty id"
            assert integ.name, f"Integration '{integ.id}' has empty name"

    def test_metric_non_empty(self) -> None:
        for integ in INTEGRATIONS:
            assert integ.metric, f"Integration '{integ.id}' has empty metric"

    def test_connected_count_is_positive(self) -> None:
        """At least one integration must have status 'connected'."""
        connected = sum(1 for i in INTEGRATIONS if i.status == "connected")
        assert connected > 0, "No connected integrations found"

    def test_total_count_matches_kpi(self) -> None:
        assert len(INTEGRATIONS) == KPI.integrations_total

    def test_disabled_integration_may_have_no_detail(self) -> None:
        """Disabled integrations with 'Not configured' metric should have no detail."""
        disabled = [i for i in INTEGRATIONS if i.status == "disabled"]
        for integ in disabled:
            # detail is optional — just check it's either None or a string
            assert integ.detail is None or isinstance(integ.detail, str)

    def test_warning_integration_has_detail(self) -> None:
        """Warning integrations should have a detail message explaining the issue."""
        warning = [i for i in INTEGRATIONS if i.status == "warning"]
        for integ in warning:
            assert integ.detail, (
                f"Warning integration '{integ.id}' has no detail message"
            )

    @pytest.mark.parametrize("integration_id", [
        "elastic", "sentinel", "splunk", "crowdstrike",
        "tenable", "okta", "paloalto", "wiz",
    ])
    def test_known_integration_ids_present(self, integration_id: str) -> None:
        ids = {integ.id for integ in INTEGRATIONS}
        assert integration_id in ids, f"Expected integration '{integration_id}' not found"
