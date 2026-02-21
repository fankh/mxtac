"""Tests for ComplianceMapper — ATT&CK technique to compliance framework coverage.

Feature 31.6 — Compliance mapping (NIST 800-53, PCI-DSS)

Coverage:
  - get_compliance_status: invalid framework → ValueError
  - get_compliance_status("nist"): returns nist framework key
  - get_compliance_status("pci-dss"): returns pci-dss framework key
  - empty DB (no rules): all controls uncovered, coverage_pct = 0
  - with enabled rule covering T1078: AC-2, IA-2, IA-5 covered in NIST
  - with enabled rule covering T1078: Req-7.1, Req-8.2 covered in PCI
  - disabled rule: does not contribute to coverage
  - control dict has required fields: id, name, covered, techniques, covered_techniques
  - summary has required fields: total_controls, covered_controls, coverage_pct
  - covered_techniques is a subset of techniques
  - multiple rules with overlapping techniques: union of technique IDs used
  - coverage_pct computed correctly
  - get_technique_nist_map / get_technique_pci_map return non-empty dicts
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import new_uuid
from app.models.rule import Rule
from app.services.compliance_mapper import (
    ComplianceMapper,
    get_technique_nist_map,
    get_technique_pci_map,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rule(
    *,
    enabled: bool = True,
    technique_ids: list[str] | None = None,
) -> Rule:
    return Rule(
        id=new_uuid(),
        title="Test Rule",
        content="detection:\n  condition: all of them",
        status="stable",
        level="high",
        enabled=enabled,
        rule_type="sigma",
        technique_ids=json.dumps(technique_ids or []),
        tactic_ids=json.dumps(["TA0001"]),
        logsource_product="windows",
        logsource_category="process_creation",
        logsource_service="",
        created_by="analyst",
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestGetComplianceStatusValidation:
    async def test_invalid_framework_raises(self, db_session: AsyncSession) -> None:
        mapper = ComplianceMapper(db_session)
        with pytest.raises(ValueError, match="Unknown framework"):
            await mapper.get_compliance_status("iso27001")

    async def test_invalid_framework_suggests_valid(
        self, db_session: AsyncSession
    ) -> None:
        mapper = ComplianceMapper(db_session)
        with pytest.raises(ValueError, match="nist"):
            await mapper.get_compliance_status("invalid")


# ---------------------------------------------------------------------------
# NIST framework
# ---------------------------------------------------------------------------


class TestNistCoverage:
    async def test_returns_nist_framework_key(
        self, db_session: AsyncSession
    ) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")
        assert result["framework"] == "nist"

    async def test_empty_db_all_uncovered(self, db_session: AsyncSession) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        assert result["summary"]["covered_controls"] == 0
        assert result["summary"]["coverage_pct"] == 0.0
        assert all(not c["covered"] for c in result["controls"])

    async def test_empty_db_controls_list_not_empty(
        self, db_session: AsyncSession
    ) -> None:
        """Controls list should contain all mapped controls even when uncovered."""
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        assert len(result["controls"]) > 0
        assert result["summary"]["total_controls"] == len(result["controls"])

    async def test_enabled_rule_t1078_covers_nist_controls(
        self, db_session: AsyncSession
    ) -> None:
        """T1078 maps to AC-2, IA-2, IA-5 in NIST."""
        db_session.add(_make_rule(technique_ids=["T1078"]))
        await db_session.flush()

        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        covered_ids = {c["id"] for c in result["controls"] if c["covered"]}
        assert "AC-2" in covered_ids
        assert "IA-2" in covered_ids
        assert "IA-5" in covered_ids

    async def test_disabled_rule_does_not_contribute(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_rule(enabled=False, technique_ids=["T1078"]))
        await db_session.flush()

        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        assert result["summary"]["covered_controls"] == 0
        assert all(not c["covered"] for c in result["controls"])

    async def test_control_dict_has_required_fields(
        self, db_session: AsyncSession
    ) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        assert len(result["controls"]) > 0
        control = result["controls"][0]
        assert "id" in control
        assert "name" in control
        assert "covered" in control
        assert "techniques" in control
        assert "covered_techniques" in control

    async def test_covered_techniques_subset_of_techniques(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_rule(technique_ids=["T1078"]))
        await db_session.flush()

        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        for control in result["controls"]:
            covered = set(control["covered_techniques"])
            all_techs = set(control["techniques"])
            assert covered <= all_techs, (
                f"covered_techniques not a subset of techniques for {control['id']}"
            )

    async def test_coverage_pct_computed_correctly(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_rule(technique_ids=["T1078"]))
        await db_session.flush()

        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        total = result["summary"]["total_controls"]
        covered = result["summary"]["covered_controls"]
        expected_pct = round(covered / total * 100, 1)
        assert result["summary"]["coverage_pct"] == expected_pct

    async def test_multiple_rules_union_of_techniques(
        self, db_session: AsyncSession
    ) -> None:
        """Multiple rules contribute all their techniques to coverage."""
        db_session.add(_make_rule(technique_ids=["T1078"]))
        db_session.add(_make_rule(technique_ids=["T1059.001"]))
        await db_session.flush()

        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        covered_ids = {c["id"] for c in result["controls"] if c["covered"]}
        # T1078 → AC-2, IA-2, IA-5
        assert "AC-2" in covered_ids
        # T1059.001 → CM-7, SI-3
        assert "CM-7" in covered_ids
        assert "SI-3" in covered_ids

    async def test_summary_has_required_fields(
        self, db_session: AsyncSession
    ) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        summary = result["summary"]
        assert "total_controls" in summary
        assert "covered_controls" in summary
        assert "coverage_pct" in summary

    async def test_control_names_are_strings(
        self, db_session: AsyncSession
    ) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        for control in result["controls"]:
            assert isinstance(control["name"], str)
            assert len(control["name"]) > 0

    async def test_techniques_list_is_sorted(
        self, db_session: AsyncSession
    ) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("nist")

        for control in result["controls"]:
            assert control["techniques"] == sorted(control["techniques"])


# ---------------------------------------------------------------------------
# PCI-DSS framework
# ---------------------------------------------------------------------------


class TestPciCoverage:
    async def test_returns_pci_dss_framework_key(
        self, db_session: AsyncSession
    ) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("pci-dss")
        assert result["framework"] == "pci-dss"

    async def test_empty_db_all_uncovered(self, db_session: AsyncSession) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("pci-dss")

        assert result["summary"]["covered_controls"] == 0
        assert result["summary"]["coverage_pct"] == 0.0
        assert all(not c["covered"] for c in result["controls"])

    async def test_enabled_rule_t1078_covers_pci_requirements(
        self, db_session: AsyncSession
    ) -> None:
        """T1078 maps to Req-7.1, Req-8.2 in PCI-DSS."""
        db_session.add(_make_rule(technique_ids=["T1078"]))
        await db_session.flush()

        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("pci-dss")

        covered_ids = {c["id"] for c in result["controls"] if c["covered"]}
        assert "Req-7.1" in covered_ids
        assert "Req-8.2" in covered_ids

    async def test_disabled_rule_does_not_contribute(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(_make_rule(enabled=False, technique_ids=["T1078"]))
        await db_session.flush()

        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("pci-dss")

        assert result["summary"]["covered_controls"] == 0

    async def test_control_dict_has_required_fields(
        self, db_session: AsyncSession
    ) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("pci-dss")

        control = result["controls"][0]
        assert "id" in control
        assert "name" in control
        assert "covered" in control
        assert "techniques" in control
        assert "covered_techniques" in control

    async def test_pci_control_names_are_strings(
        self, db_session: AsyncSession
    ) -> None:
        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("pci-dss")

        for control in result["controls"]:
            assert isinstance(control["name"], str)

    async def test_t1003_covers_credential_requirements(
        self, db_session: AsyncSession
    ) -> None:
        """T1003 maps to Req-8.4, Req-8.6 in PCI-DSS."""
        db_session.add(_make_rule(technique_ids=["T1003"]))
        await db_session.flush()

        mapper = ComplianceMapper(db_session)
        result = await mapper.get_compliance_status("pci-dss")

        covered_ids = {c["id"] for c in result["controls"] if c["covered"]}
        assert "Req-8.4" in covered_ids
        assert "Req-8.6" in covered_ids


# ---------------------------------------------------------------------------
# Module-level accessor functions
# ---------------------------------------------------------------------------


class TestMappingAccessors:
    def test_get_technique_nist_map_not_empty(self) -> None:
        mapping = get_technique_nist_map()
        assert len(mapping) > 0

    def test_get_technique_pci_map_not_empty(self) -> None:
        mapping = get_technique_pci_map()
        assert len(mapping) > 0

    def test_nist_map_values_are_lists(self) -> None:
        mapping = get_technique_nist_map()
        for technique_id, controls in mapping.items():
            assert isinstance(controls, list), f"{technique_id} value is not a list"
            assert len(controls) > 0

    def test_pci_map_values_are_lists(self) -> None:
        mapping = get_technique_pci_map()
        for technique_id, reqs in mapping.items():
            assert isinstance(reqs, list), f"{technique_id} value is not a list"
            assert len(reqs) > 0

    def test_nist_map_contains_t1078(self) -> None:
        mapping = get_technique_nist_map()
        assert "T1078" in mapping
        assert "AC-2" in mapping["T1078"]

    def test_pci_map_contains_t1078(self) -> None:
        mapping = get_technique_pci_map()
        assert "T1078" in mapping
        assert "Req-7.1" in mapping["T1078"]
