"""Tests for feature 8.2 — `SigmaAlert` dataclass.

Coverage:
  Construction & defaults:
  - Default `id` is a non-empty string in canonical UUID4 format
  - Each default-constructed instance gets a fresh, unique UUID
  - Default `rule_id` is ""
  - Default `rule_title` is ""
  - Default `level` is "medium"
  - Default `severity_id` is 3
  - Default `technique_ids` is []
  - Default `tactic_ids` is []
  - Default `host` is ""
  - Default `time` is a UTC-aware datetime
  - Default `event_snapshot` is {}

  UUID correctness:
  - `id` matches the canonical UUID4 regex pattern
  - Ten consecutive instances all have distinct `id` values

  Mutable default isolation:
  - `technique_ids` lists are independent across instances
  - `tactic_ids` lists are independent across instances
  - `event_snapshot` dicts are independent across instances

  Explicit field construction:
  - Every field can be supplied explicitly and is stored verbatim
  - All fields supplied together produce the expected attribute values

  Type correctness:
  - `id` is str
  - `rule_id` is str
  - `rule_title` is str
  - `level` is str
  - `severity_id` is int
  - `technique_ids` is list
  - `tactic_ids` is list
  - `host` is str
  - `time` is datetime
  - `event_snapshot` is dict

  Time field semantics:
  - Default `time` carries timezone info equal to `timezone.utc`
  - Sequential instances have non-decreasing `time` values
  - An explicit naive datetime is stored as-is (no coercion)

  Structural invariants:
  - Dataclass has exactly the expected set of field names
  - `asdict()` round-trip preserves all field values
  - Fields are mutable after construction

  Event snapshot:
  - Nested dicts are stored by reference (not deep-copied)
  - Can hold arbitrary JSON-serialisable structures (nested dicts, lists, ints)

  Integration with LEVEL_SEVERITY:
  - Default level "medium" corresponds to LEVEL_SEVERITY default severity_id 3
  - Each named level paired with its LEVEL_SEVERITY value can be stored together
"""

from __future__ import annotations

import re
from dataclasses import asdict, fields
from datetime import datetime, timezone
from typing import Any

import pytest

from app.engine.sigma_engine import LEVEL_SEVERITY, SigmaAlert


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _make_alert(**overrides: Any) -> SigmaAlert:
    """Return a SigmaAlert with all defaults unless overridden."""
    return SigmaAlert(**overrides)


# ---------------------------------------------------------------------------
# Construction & defaults
# ---------------------------------------------------------------------------

class TestSigmaAlertDefaults:
    def test_instantiation_succeeds_with_no_arguments(self) -> None:
        alert = SigmaAlert()
        assert isinstance(alert, SigmaAlert)

    def test_default_id_is_non_empty_string(self) -> None:
        alert = SigmaAlert()
        assert isinstance(alert.id, str)
        assert len(alert.id) > 0

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

    def test_default_time_is_datetime(self) -> None:
        assert isinstance(SigmaAlert().time, datetime)

    def test_default_time_is_utc_aware(self) -> None:
        alert = SigmaAlert()
        assert alert.time.tzinfo is not None
        assert alert.time.tzinfo == timezone.utc

    def test_default_event_snapshot_is_empty_dict(self) -> None:
        assert SigmaAlert().event_snapshot == {}

    def test_two_default_instances_are_distinct_objects(self) -> None:
        a = SigmaAlert()
        b = SigmaAlert()
        assert a is not b


# ---------------------------------------------------------------------------
# UUID correctness
# ---------------------------------------------------------------------------

class TestSigmaAlertUUID:
    def test_default_id_matches_uuid4_pattern(self) -> None:
        alert = SigmaAlert()
        assert _UUID4_RE.match(alert.id), f"id {alert.id!r} is not a valid UUID4"

    def test_ten_consecutive_instances_have_distinct_ids(self) -> None:
        ids = {SigmaAlert().id for _ in range(10)}
        assert len(ids) == 10, "Not all 10 IDs were unique"

    def test_two_default_instances_have_distinct_ids(self) -> None:
        a = SigmaAlert()
        b = SigmaAlert()
        assert a.id != b.id


# ---------------------------------------------------------------------------
# Mutable default isolation
# ---------------------------------------------------------------------------

class TestSigmaAlertMutableDefaults:
    def test_technique_ids_are_independent_per_instance(self) -> None:
        a = SigmaAlert()
        b = SigmaAlert()
        a.technique_ids.append("T1059.001")
        assert b.technique_ids == [], "Mutating a.technique_ids must not affect b"

    def test_tactic_ids_are_independent_per_instance(self) -> None:
        a = SigmaAlert()
        b = SigmaAlert()
        a.tactic_ids.append("TA0002")
        assert b.tactic_ids == [], "Mutating a.tactic_ids must not affect b"

    def test_event_snapshot_is_independent_per_instance(self) -> None:
        a = SigmaAlert()
        b = SigmaAlert()
        a.event_snapshot["key"] = "value"
        assert b.event_snapshot == {}, "Mutating a.event_snapshot must not affect b"

    def test_three_instances_technique_ids_all_independent(self) -> None:
        alerts = [SigmaAlert() for _ in range(3)]
        alerts[0].technique_ids.append("T1003")
        assert alerts[1].technique_ids == []
        assert alerts[2].technique_ids == []


# ---------------------------------------------------------------------------
# Explicit field construction
# ---------------------------------------------------------------------------

class TestSigmaAlertExplicitFields:
    def test_explicit_id(self) -> None:
        alert = SigmaAlert(id="custom-id-001")
        assert alert.id == "custom-id-001"

    def test_explicit_rule_id(self) -> None:
        alert = SigmaAlert(rule_id="rule-abc-123")
        assert alert.rule_id == "rule-abc-123"

    def test_explicit_rule_title(self) -> None:
        alert = SigmaAlert(rule_title="Mimikatz Credential Access")
        assert alert.rule_title == "Mimikatz Credential Access"

    def test_explicit_level_critical(self) -> None:
        alert = SigmaAlert(level="critical")
        assert alert.level == "critical"

    def test_explicit_level_high(self) -> None:
        alert = SigmaAlert(level="high")
        assert alert.level == "high"

    def test_explicit_level_low(self) -> None:
        alert = SigmaAlert(level="low")
        assert alert.level == "low"

    def test_explicit_level_informational(self) -> None:
        alert = SigmaAlert(level="informational")
        assert alert.level == "informational"

    def test_explicit_severity_id_1(self) -> None:
        alert = SigmaAlert(severity_id=1)
        assert alert.severity_id == 1

    def test_explicit_severity_id_5(self) -> None:
        alert = SigmaAlert(severity_id=5)
        assert alert.severity_id == 5

    def test_explicit_technique_ids_single(self) -> None:
        alert = SigmaAlert(technique_ids=["T1059"])
        assert alert.technique_ids == ["T1059"]

    def test_explicit_technique_ids_multiple(self) -> None:
        ids = ["T1003.001", "T1059.001", "T1055"]
        alert = SigmaAlert(technique_ids=ids)
        assert alert.technique_ids == ids

    def test_explicit_tactic_ids_single(self) -> None:
        alert = SigmaAlert(tactic_ids=["TA0006"])
        assert alert.tactic_ids == ["TA0006"]

    def test_explicit_tactic_ids_multiple(self) -> None:
        ids = ["TA0002", "TA0006", "TA0040"]
        alert = SigmaAlert(tactic_ids=ids)
        assert alert.tactic_ids == ids

    def test_explicit_host(self) -> None:
        alert = SigmaAlert(host="workstation-42")
        assert alert.host == "workstation-42"

    def test_explicit_time(self) -> None:
        t = datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc)
        alert = SigmaAlert(time=t)
        assert alert.time == t

    def test_explicit_event_snapshot(self) -> None:
        snap = {"cmd_line": "mimikatz.exe", "pid": 4200, "user": "SYSTEM"}
        alert = SigmaAlert(event_snapshot=snap)
        assert alert.event_snapshot == snap

    def test_all_fields_set_together(self) -> None:
        t = datetime(2026, 2, 22, 10, 0, 0, tzinfo=timezone.utc)
        snap = {"process": {"name": "powershell.exe", "pid": 777}}
        alert = SigmaAlert(
            id="full-alert-001",
            rule_id="rule-ps-encoded",
            rule_title="PowerShell Encoded Command",
            level="high",
            severity_id=4,
            technique_ids=["T1059.001"],
            tactic_ids=["TA0002"],
            host="dc-prod-01",
            time=t,
            event_snapshot=snap,
        )
        assert alert.id == "full-alert-001"
        assert alert.rule_id == "rule-ps-encoded"
        assert alert.rule_title == "PowerShell Encoded Command"
        assert alert.level == "high"
        assert alert.severity_id == 4
        assert alert.technique_ids == ["T1059.001"]
        assert alert.tactic_ids == ["TA0002"]
        assert alert.host == "dc-prod-01"
        assert alert.time == t
        assert alert.event_snapshot == snap


# ---------------------------------------------------------------------------
# Type correctness
# ---------------------------------------------------------------------------

class TestSigmaAlertTypes:
    def test_id_is_str(self) -> None:
        assert isinstance(SigmaAlert().id, str)

    def test_rule_id_is_str(self) -> None:
        assert isinstance(SigmaAlert().rule_id, str)

    def test_rule_title_is_str(self) -> None:
        assert isinstance(SigmaAlert().rule_title, str)

    def test_level_is_str(self) -> None:
        assert isinstance(SigmaAlert().level, str)

    def test_severity_id_is_int(self) -> None:
        assert isinstance(SigmaAlert().severity_id, int)

    def test_technique_ids_is_list(self) -> None:
        assert isinstance(SigmaAlert().technique_ids, list)

    def test_tactic_ids_is_list(self) -> None:
        assert isinstance(SigmaAlert().tactic_ids, list)

    def test_host_is_str(self) -> None:
        assert isinstance(SigmaAlert().host, str)

    def test_time_is_datetime(self) -> None:
        assert isinstance(SigmaAlert().time, datetime)

    def test_event_snapshot_is_dict(self) -> None:
        assert isinstance(SigmaAlert().event_snapshot, dict)


# ---------------------------------------------------------------------------
# Time field semantics
# ---------------------------------------------------------------------------

class TestSigmaAlertTime:
    def test_default_time_tzinfo_is_utc(self) -> None:
        alert = SigmaAlert()
        assert alert.time.tzinfo == timezone.utc

    def test_sequential_instances_time_is_non_decreasing(self) -> None:
        a = SigmaAlert()
        b = SigmaAlert()
        assert b.time >= a.time

    def test_explicit_naive_datetime_stored_as_is(self) -> None:
        """SigmaAlert does not coerce naive datetimes — stores them verbatim."""
        naive = datetime(2026, 1, 1, 0, 0, 0)  # no tzinfo
        alert = SigmaAlert(time=naive)
        assert alert.time == naive
        assert alert.time.tzinfo is None

    def test_explicit_utc_datetime_stored_as_is(self) -> None:
        t = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        alert = SigmaAlert(time=t)
        assert alert.time == t
        assert alert.time.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------

class TestSigmaAlertStructure:
    def test_has_exactly_the_expected_field_names(self) -> None:
        expected = {
            "id", "rule_id", "rule_title", "level", "severity_id",
            "technique_ids", "tactic_ids", "host", "time", "event_snapshot",
        }
        actual = {f.name for f in fields(SigmaAlert)}
        assert actual == expected

    def test_asdict_contains_all_default_fields(self) -> None:
        alert = SigmaAlert(id="static-id")
        d = asdict(alert)
        assert d["id"] == "static-id"
        assert d["rule_id"] == ""
        assert d["rule_title"] == ""
        assert d["level"] == "medium"
        assert d["severity_id"] == 3
        assert d["technique_ids"] == []
        assert d["tactic_ids"] == []
        assert d["host"] == ""
        assert d["event_snapshot"] == {}
        assert isinstance(d["time"], datetime)

    def test_asdict_round_trips_explicit_values(self) -> None:
        t = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
        alert = SigmaAlert(
            id="roundtrip-id",
            rule_id="r1",
            rule_title="Test",
            level="critical",
            severity_id=5,
            technique_ids=["T1003"],
            tactic_ids=["TA0006"],
            host="server-01",
            time=t,
            event_snapshot={"a": 1},
        )
        d = asdict(alert)
        assert d["id"] == "roundtrip-id"
        assert d["rule_id"] == "r1"
        assert d["rule_title"] == "Test"
        assert d["level"] == "critical"
        assert d["severity_id"] == 5
        assert d["technique_ids"] == ["T1003"]
        assert d["tactic_ids"] == ["TA0006"]
        assert d["host"] == "server-01"
        assert d["time"] == t
        assert d["event_snapshot"] == {"a": 1}

    def test_fields_are_mutable_after_construction(self) -> None:
        alert = SigmaAlert()
        alert.rule_id = "updated-rule"
        alert.level = "critical"
        alert.severity_id = 5
        assert alert.rule_id == "updated-rule"
        assert alert.level == "critical"
        assert alert.severity_id == 5

    def test_technique_ids_can_be_appended_in_place(self) -> None:
        alert = SigmaAlert()
        alert.technique_ids.append("T1055")
        assert "T1055" in alert.technique_ids

    def test_tactic_ids_can_be_appended_in_place(self) -> None:
        alert = SigmaAlert()
        alert.tactic_ids.append("TA0040")
        assert "TA0040" in alert.tactic_ids

    def test_event_snapshot_can_be_updated_in_place(self) -> None:
        alert = SigmaAlert()
        alert.event_snapshot["process"] = {"name": "cmd.exe"}
        assert alert.event_snapshot["process"] == {"name": "cmd.exe"}


# ---------------------------------------------------------------------------
# Event snapshot semantics
# ---------------------------------------------------------------------------

class TestSigmaAlertEventSnapshot:
    def test_snapshot_stored_by_reference(self) -> None:
        snap: dict[str, Any] = {"key": "value"}
        alert = SigmaAlert(event_snapshot=snap)
        assert alert.event_snapshot is snap

    def test_snapshot_can_hold_nested_dict(self) -> None:
        snap = {"process": {"name": "evil.exe", "cmdline": "evil -v"}, "pid": 999}
        alert = SigmaAlert(event_snapshot=snap)
        assert alert.event_snapshot["process"]["name"] == "evil.exe"

    def test_snapshot_can_hold_list_values(self) -> None:
        snap = {"args": ["-enc", "base64string"], "pid": 1}
        alert = SigmaAlert(event_snapshot=snap)
        assert alert.event_snapshot["args"] == ["-enc", "base64string"]

    def test_snapshot_can_hold_integer_values(self) -> None:
        snap = {"pid": 4200, "ppid": 1}
        alert = SigmaAlert(event_snapshot=snap)
        assert alert.event_snapshot["pid"] == 4200

    def test_snapshot_mutation_via_reference_reflects_in_alert(self) -> None:
        snap: dict[str, Any] = {}
        alert = SigmaAlert(event_snapshot=snap)
        snap["injected"] = True
        assert alert.event_snapshot.get("injected") is True


# ---------------------------------------------------------------------------
# Integration with LEVEL_SEVERITY
# ---------------------------------------------------------------------------

class TestSigmaAlertLevelSeverityConsistency:
    @pytest.mark.parametrize("level,expected_id", [
        ("critical", 5),
        ("high", 4),
        ("medium", 3),
        ("low", 2),
        ("informational", 1),
    ])
    def test_level_and_severity_id_can_be_stored_consistently(
        self, level: str, expected_id: int
    ) -> None:
        """Verify each level from LEVEL_SEVERITY can be stored on a SigmaAlert."""
        alert = SigmaAlert(level=level, severity_id=LEVEL_SEVERITY[level])
        assert alert.level == level
        assert alert.severity_id == expected_id

    def test_default_level_medium_matches_level_severity_entry(self) -> None:
        alert = SigmaAlert()
        assert alert.severity_id == LEVEL_SEVERITY[alert.level]

    def test_level_severity_lookup_gives_correct_id_for_all_levels(self) -> None:
        for level, expected_id in LEVEL_SEVERITY.items():
            alert = SigmaAlert(level=level, severity_id=expected_id)
            assert alert.level == level
            assert alert.severity_id == expected_id
