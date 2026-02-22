"""Tests for feature 8.1 — `SigmaRule` dataclass.

Coverage:
  SigmaRule dataclass construction:
  - Instantiation with all required fields succeeds
  - Required fields are stored verbatim (id, title, description, status, level, logsource, detection)
  - Default value for `tags` is an empty list
  - Default value for `references` is an empty list
  - Default value for `enabled` is True
  - Default value for `technique_ids` is an empty list
  - Default value for `tactic_ids` is an empty list
  - Default value for `_matcher` is None
  - Mutable defaults (`tags`, `references`, `technique_ids`, `tactic_ids`) are independent per instance
  - `_matcher` is excluded from repr (repr=False)
  - Fields are mutable after construction
  - `enabled` can be set to False after construction
  - `_matcher` can be assigned a callable after construction
  - `logsource` dict is stored by reference (not copied)
  - `detection` dict is stored by reference (not copied)

  LEVEL_SEVERITY mapping:
  - Contains exactly the five expected keys
  - `critical` maps to 5
  - `high` maps to 4
  - `medium` maps to 3
  - `low` maps to 2
  - `informational` maps to 1
  - Severity values are strictly ordered (critical > high > medium > low > informational)
  - Unknown level is not present in mapping

  SigmaAlert dataclass construction:
  - Default `id` is a non-empty UUID string
  - Two default instances have distinct `id` values
  - Default `rule_id` is empty string
  - Default `rule_title` is empty string
  - Default `level` is "medium"
  - Default `severity_id` is 3
  - Default `technique_ids` is an empty list
  - Default `tactic_ids` is an empty list
  - Default `host` is empty string
  - Default `time` is a UTC-aware datetime
  - Default `event_snapshot` is an empty dict
  - Mutable defaults (`technique_ids`, `tactic_ids`, `event_snapshot`) are independent per instance
  - All fields can be supplied explicitly and are stored verbatim
  - `time` field carries UTC timezone info when default-constructed
"""

from __future__ import annotations

from dataclasses import asdict, fields
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.engine.sigma_engine import LEVEL_SEVERITY, SigmaAlert, SigmaRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(**overrides: Any) -> SigmaRule:
    """Create a minimal SigmaRule with sensible required-field defaults."""
    defaults: dict[str, Any] = {
        "id": "rule-001",
        "title": "Test Rule",
        "description": "A test rule.",
        "status": "experimental",
        "level": "medium",
        "logsource": {"category": "process_creation"},
        "detection": {"selection": {"cmd_line|contains": "evil"}, "condition": "selection"},
    }
    defaults.update(overrides)
    return SigmaRule(**defaults)


# ---------------------------------------------------------------------------
# SigmaRule — construction with required fields
# ---------------------------------------------------------------------------

class TestSigmaRuleConstruction:
    def test_instantiation_with_required_fields_succeeds(self) -> None:
        rule = _make_rule()
        assert isinstance(rule, SigmaRule)

    def test_id_stored_verbatim(self) -> None:
        rule = _make_rule(id="abc-123")
        assert rule.id == "abc-123"

    def test_title_stored_verbatim(self) -> None:
        rule = _make_rule(title="Suspicious PowerShell")
        assert rule.title == "Suspicious PowerShell"

    def test_description_stored_verbatim(self) -> None:
        rule = _make_rule(description="Detects encoded PowerShell.")
        assert rule.description == "Detects encoded PowerShell."

    def test_status_stored_verbatim(self) -> None:
        rule = _make_rule(status="stable")
        assert rule.status == "stable"

    def test_level_stored_verbatim(self) -> None:
        rule = _make_rule(level="high")
        assert rule.level == "high"

    def test_logsource_stored_verbatim(self) -> None:
        ls = {"category": "network_connection", "product": "linux"}
        rule = _make_rule(logsource=ls)
        assert rule.logsource == ls

    def test_detection_stored_verbatim(self) -> None:
        det = {"selection": {"dst_port": 4444}, "condition": "selection"}
        rule = _make_rule(detection=det)
        assert rule.detection == det


# ---------------------------------------------------------------------------
# SigmaRule — default optional fields
# ---------------------------------------------------------------------------

class TestSigmaRuleDefaults:
    def test_tags_default_is_empty_list(self) -> None:
        rule = _make_rule()
        assert rule.tags == []

    def test_references_default_is_empty_list(self) -> None:
        rule = _make_rule()
        assert rule.references == []

    def test_enabled_default_is_true(self) -> None:
        rule = _make_rule()
        assert rule.enabled is True

    def test_technique_ids_default_is_empty_list(self) -> None:
        rule = _make_rule()
        assert rule.technique_ids == []

    def test_tactic_ids_default_is_empty_list(self) -> None:
        rule = _make_rule()
        assert rule.tactic_ids == []

    def test_matcher_default_is_none(self) -> None:
        rule = _make_rule()
        assert rule._matcher is None


# ---------------------------------------------------------------------------
# SigmaRule — mutable default isolation
# ---------------------------------------------------------------------------

class TestSigmaRuleMutableDefaults:
    def test_tags_lists_are_independent_per_instance(self) -> None:
        rule_a = _make_rule()
        rule_b = _make_rule()
        rule_a.tags.append("attack.T1059")
        assert rule_b.tags == [], "Mutating rule_a.tags must not affect rule_b.tags"

    def test_references_lists_are_independent_per_instance(self) -> None:
        rule_a = _make_rule()
        rule_b = _make_rule()
        rule_a.references.append("https://example.com")
        assert rule_b.references == []

    def test_technique_ids_lists_are_independent_per_instance(self) -> None:
        rule_a = _make_rule()
        rule_b = _make_rule()
        rule_a.technique_ids.append("T1059.001")
        assert rule_b.technique_ids == []

    def test_tactic_ids_lists_are_independent_per_instance(self) -> None:
        rule_a = _make_rule()
        rule_b = _make_rule()
        rule_a.tactic_ids.append("TA0002")
        assert rule_b.tactic_ids == []


# ---------------------------------------------------------------------------
# SigmaRule — repr
# ---------------------------------------------------------------------------

class TestSigmaRuleRepr:
    def test_matcher_excluded_from_repr(self) -> None:
        """_matcher has repr=False — it must not appear in the repr string."""
        matcher = MagicMock()
        rule = _make_rule()
        rule._matcher = matcher
        repr_str = repr(rule)
        assert "_matcher" not in repr_str

    def test_id_present_in_repr(self) -> None:
        rule = _make_rule(id="repr-test-id")
        assert "repr-test-id" in repr(rule)

    def test_title_present_in_repr(self) -> None:
        rule = _make_rule(title="My Rule Title")
        assert "My Rule Title" in repr(rule)


# ---------------------------------------------------------------------------
# SigmaRule — mutability after construction
# ---------------------------------------------------------------------------

class TestSigmaRuleMutability:
    def test_enabled_can_be_set_to_false(self) -> None:
        rule = _make_rule()
        rule.enabled = False
        assert rule.enabled is False

    def test_enabled_can_be_toggled_back_to_true(self) -> None:
        rule = _make_rule()
        rule.enabled = False
        rule.enabled = True
        assert rule.enabled is True

    def test_matcher_can_be_assigned_callable(self) -> None:
        rule = _make_rule()
        matcher = MagicMock()
        rule._matcher = matcher
        assert rule._matcher is matcher

    def test_technique_ids_can_be_appended(self) -> None:
        rule = _make_rule()
        rule.technique_ids.append("T1003")
        assert "T1003" in rule.technique_ids

    def test_tactic_ids_can_be_appended(self) -> None:
        rule = _make_rule()
        rule.tactic_ids.append("TA0006")
        assert "TA0006" in rule.tactic_ids

    def test_tags_can_be_replaced(self) -> None:
        rule = _make_rule()
        rule.tags = ["attack.T1059"]
        assert rule.tags == ["attack.T1059"]

    def test_level_can_be_updated(self) -> None:
        rule = _make_rule(level="low")
        rule.level = "critical"
        assert rule.level == "critical"


# ---------------------------------------------------------------------------
# SigmaRule — explicit optional field values
# ---------------------------------------------------------------------------

class TestSigmaRuleExplicitOptionals:
    def test_tags_supplied_explicitly(self) -> None:
        tags = ["attack.T1059.001", "attack.TA0002"]
        rule = _make_rule(tags=tags)
        assert rule.tags == tags

    def test_references_supplied_explicitly(self) -> None:
        refs = ["https://attack.mitre.org/techniques/T1059/"]
        rule = _make_rule(references=refs)
        assert rule.references == refs

    def test_enabled_supplied_as_false(self) -> None:
        rule = _make_rule(enabled=False)
        assert rule.enabled is False

    def test_technique_ids_supplied_explicitly(self) -> None:
        rule = _make_rule(technique_ids=["T1059.001", "T1003.001"])
        assert rule.technique_ids == ["T1059.001", "T1003.001"]

    def test_tactic_ids_supplied_explicitly(self) -> None:
        rule = _make_rule(tactic_ids=["TA0002", "TA0006"])
        assert rule.tactic_ids == ["TA0002", "TA0006"]

    def test_matcher_supplied_explicitly(self) -> None:
        matcher = MagicMock()
        rule = _make_rule(_matcher=matcher)
        assert rule._matcher is matcher


# ---------------------------------------------------------------------------
# SigmaRule — dataclass structural invariants
# ---------------------------------------------------------------------------

class TestSigmaRuleStructure:
    def test_logsource_stored_by_reference(self) -> None:
        """logsource dict is stored by reference (not deep-copied by default_factory)."""
        ls: dict[str, str] = {"category": "process_creation"}
        rule = _make_rule(logsource=ls)
        assert rule.logsource is ls

    def test_detection_stored_by_reference(self) -> None:
        """detection dict is stored by reference."""
        det: dict[str, Any] = {"condition": "selection"}
        rule = _make_rule(detection=det)
        assert rule.detection is det

    def test_two_instances_are_independent(self) -> None:
        rule_a = _make_rule(id="a")
        rule_b = _make_rule(id="b")
        assert rule_a is not rule_b
        assert rule_a.id != rule_b.id

    def test_has_all_expected_field_names(self) -> None:
        expected = {
            "id", "title", "description", "status", "level",
            "logsource", "detection", "tags", "references", "enabled",
            "technique_ids", "tactic_ids", "_matcher",
        }
        actual = {f.name for f in fields(SigmaRule)}
        assert expected == actual


# ---------------------------------------------------------------------------
# LEVEL_SEVERITY mapping
# ---------------------------------------------------------------------------

class TestLevelSeverity:
    def test_critical_maps_to_5(self) -> None:
        assert LEVEL_SEVERITY["critical"] == 5

    def test_high_maps_to_4(self) -> None:
        assert LEVEL_SEVERITY["high"] == 4

    def test_medium_maps_to_3(self) -> None:
        assert LEVEL_SEVERITY["medium"] == 3

    def test_low_maps_to_2(self) -> None:
        assert LEVEL_SEVERITY["low"] == 2

    def test_informational_maps_to_1(self) -> None:
        assert LEVEL_SEVERITY["informational"] == 1

    def test_contains_exactly_five_entries(self) -> None:
        assert len(LEVEL_SEVERITY) == 5

    def test_all_expected_keys_present(self) -> None:
        assert set(LEVEL_SEVERITY.keys()) == {"critical", "high", "medium", "low", "informational"}

    def test_severity_strictly_ordered(self) -> None:
        """critical > high > medium > low > informational."""
        assert (
            LEVEL_SEVERITY["critical"]
            > LEVEL_SEVERITY["high"]
            > LEVEL_SEVERITY["medium"]
            > LEVEL_SEVERITY["low"]
            > LEVEL_SEVERITY["informational"]
        )

    def test_unknown_level_not_in_mapping(self) -> None:
        assert "unknown" not in LEVEL_SEVERITY

    def test_get_with_default_for_unknown_level(self) -> None:
        """Callers can safely use .get() with a fallback (e.g. SigmaEngine does this)."""
        assert LEVEL_SEVERITY.get("unknown", 3) == 3


# ---------------------------------------------------------------------------
# SigmaAlert dataclass — defaults
# ---------------------------------------------------------------------------

class TestSigmaAlertDefaults:
    def test_default_id_is_non_empty_string(self) -> None:
        alert = SigmaAlert()
        assert isinstance(alert.id, str)
        assert len(alert.id) > 0

    def test_two_default_instances_have_distinct_ids(self) -> None:
        alert_a = SigmaAlert()
        alert_b = SigmaAlert()
        assert alert_a.id != alert_b.id

    def test_default_rule_id_is_empty_string(self) -> None:
        assert SigmaAlert().rule_id == ""

    def test_default_rule_title_is_empty_string(self) -> None:
        assert SigmaAlert().rule_title == ""

    def test_default_level_is_medium(self) -> None:
        assert SigmaAlert().level == "medium"

    def test_default_severity_id_is_3(self) -> None:
        assert SigmaAlert().severity_id == 3

    def test_default_technique_ids_is_empty_list(self) -> None:
        assert SigmaAlert().technique_ids == []

    def test_default_tactic_ids_is_empty_list(self) -> None:
        assert SigmaAlert().tactic_ids == []

    def test_default_host_is_empty_string(self) -> None:
        assert SigmaAlert().host == ""

    def test_default_time_is_utc_aware_datetime(self) -> None:
        alert = SigmaAlert()
        assert isinstance(alert.time, datetime)
        assert alert.time.tzinfo is not None
        assert alert.time.tzinfo == timezone.utc

    def test_default_event_snapshot_is_empty_dict(self) -> None:
        assert SigmaAlert().event_snapshot == {}


# ---------------------------------------------------------------------------
# SigmaAlert — mutable default isolation
# ---------------------------------------------------------------------------

class TestSigmaAlertMutableDefaults:
    def test_technique_ids_independent_per_instance(self) -> None:
        a = SigmaAlert()
        b = SigmaAlert()
        a.technique_ids.append("T1059")
        assert b.technique_ids == []

    def test_tactic_ids_independent_per_instance(self) -> None:
        a = SigmaAlert()
        b = SigmaAlert()
        a.tactic_ids.append("TA0002")
        assert b.tactic_ids == []

    def test_event_snapshot_independent_per_instance(self) -> None:
        a = SigmaAlert()
        b = SigmaAlert()
        a.event_snapshot["key"] = "value"
        assert b.event_snapshot == {}


# ---------------------------------------------------------------------------
# SigmaAlert — explicit field construction
# ---------------------------------------------------------------------------

class TestSigmaAlertExplicitFields:
    def test_explicit_id(self) -> None:
        alert = SigmaAlert(id="fixed-id-001")
        assert alert.id == "fixed-id-001"

    def test_explicit_rule_id(self) -> None:
        alert = SigmaAlert(rule_id="sigma-rule-abc")
        assert alert.rule_id == "sigma-rule-abc"

    def test_explicit_rule_title(self) -> None:
        alert = SigmaAlert(rule_title="PowerShell Encoded Command")
        assert alert.rule_title == "PowerShell Encoded Command"

    def test_explicit_level(self) -> None:
        alert = SigmaAlert(level="critical")
        assert alert.level == "critical"

    def test_explicit_severity_id(self) -> None:
        alert = SigmaAlert(severity_id=5)
        assert alert.severity_id == 5

    def test_explicit_technique_ids(self) -> None:
        alert = SigmaAlert(technique_ids=["T1059.001"])
        assert alert.technique_ids == ["T1059.001"]

    def test_explicit_tactic_ids(self) -> None:
        alert = SigmaAlert(tactic_ids=["TA0002"])
        assert alert.tactic_ids == ["TA0002"]

    def test_explicit_host(self) -> None:
        alert = SigmaAlert(host="workstation-01")
        assert alert.host == "workstation-01"

    def test_explicit_time(self) -> None:
        t = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        alert = SigmaAlert(time=t)
        assert alert.time == t

    def test_explicit_event_snapshot(self) -> None:
        snap = {"cmd_line": "evil.exe", "pid": 1234}
        alert = SigmaAlert(event_snapshot=snap)
        assert alert.event_snapshot == snap

    def test_all_fields_set_together(self) -> None:
        t = datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        alert = SigmaAlert(
            id="test-alert-999",
            rule_id="rule-xyz",
            rule_title="Mimikatz Detected",
            level="high",
            severity_id=4,
            technique_ids=["T1003"],
            tactic_ids=["TA0006"],
            host="dc-01",
            time=t,
            event_snapshot={"user": "SYSTEM"},
        )
        assert alert.id == "test-alert-999"
        assert alert.rule_id == "rule-xyz"
        assert alert.rule_title == "Mimikatz Detected"
        assert alert.level == "high"
        assert alert.severity_id == 4
        assert alert.technique_ids == ["T1003"]
        assert alert.tactic_ids == ["TA0006"]
        assert alert.host == "dc-01"
        assert alert.time == t
        assert alert.event_snapshot == {"user": "SYSTEM"}
