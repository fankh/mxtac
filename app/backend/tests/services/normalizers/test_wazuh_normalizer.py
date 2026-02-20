"""Tests for WazuhNormalizer — Feature 7.2

Coverage:
  - LEVEL_TO_SEVERITY mapping: all boundary values and mid-range levels
  - _level_to_severity(): level 14 → severity_id 5, all tiers, edge cases
  - _classify(): process / network / auth / file / default routing
  - _build_attacks(): single tactic, multiple techniques, unknown tactic, empty MITRE
  - _parse_time(): ISO 8601 with Z, offset, invalid, missing
  - _safe_int() / _exe_name(): type coercion and path splitting
  - normalize(): full round-trip with realistic Wazuh alert fixture
  - normalize(): missing optional fields produce sensible defaults
  - normalize(): severity_id propagated to OCSFEvent AND FindingInfo
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.normalizers.wazuh import LEVEL_TO_SEVERITY, MITRE_TACTIC_MAP, WazuhNormalizer
from app.services.normalizers.ocsf import OCSFCategory, OCSFClass


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def normalizer() -> WazuhNormalizer:
    return WazuhNormalizer()


@pytest.fixture
def full_alert() -> dict:
    """Realistic Wazuh alert as documented in the module docstring."""
    return {
        "timestamp": "2026-02-19T08:30:00.000Z",
        "id": "1708331400.12345",
        "rule": {
            "id": "100234",
            "description": "LSASS Memory Dump Detected",
            "level": 12,
            "groups": ["process", "win_process"],
            "mitre": {
                "id": ["T1003.001"],
                "tactic": ["credential-access"],
            },
        },
        "agent": {
            "id": "001",
            "name": "WIN-DC01",
            "ip": "192.168.1.10",
        },
        "data": {
            "srcip": "10.0.0.5",
            "dstuser": "SYSTEM",
            "win": {
                "eventdata": {
                    "commandLine": "mimikatz.exe sekurlsa::logonpasswords",
                    "image": "C:\\mimikatz\\mimikatz.exe",
                    "processId": "3456",
                    "parentProcessId": "1234",
                }
            },
        },
    }


# ---------------------------------------------------------------------------
# LEVEL_TO_SEVERITY constant
# ---------------------------------------------------------------------------


def test_level_to_severity_constant_order() -> None:
    """Thresholds must be in descending order for the loop to work correctly."""
    thresholds = [t[0] for t in LEVEL_TO_SEVERITY]
    assert thresholds == sorted(thresholds, reverse=True)


def test_level_to_severity_constant_coverage() -> None:
    """All five OCSF tiers (1–5) must appear in the mapping."""
    severity_ids = {sev for _, sev in LEVEL_TO_SEVERITY}
    assert severity_ids == {1, 2, 3, 4, 5}


# ---------------------------------------------------------------------------
# _level_to_severity() — boundary and mid-range
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level,expected", [
    # Critical tier (≥14)
    (14,  5),
    (15,  5),
    (100, 5),
    # High tier (≥11, <14)
    (11,  4),
    (12,  4),
    (13,  4),
    # Medium tier (≥7, <11)
    (7,   3),
    (8,   3),
    (10,  3),
    # Low tier (≥4, <7)
    (4,   2),
    (5,   2),
    (6,   2),
    # Informational tier (≥0, <4)
    (0,   1),
    (1,   1),
    (3,   1),
])
def test_level_to_severity_mapping(normalizer: WazuhNormalizer, level: int, expected: int) -> None:
    """rule.level maps to the correct OCSF severity_id. (Feature 28.10)"""
    assert normalizer._level_to_severity(level) == expected


def test_level_to_severity_negative_falls_back(normalizer: WazuhNormalizer) -> None:
    """Negative levels (invalid Wazuh data) default to Informational (1)."""
    assert normalizer._level_to_severity(-1) == 1


def test_level_14_maps_to_severity_5(normalizer: WazuhNormalizer) -> None:
    """Explicit acceptance criterion from feature checklist 28.10."""
    assert normalizer._level_to_severity(14) == 5


# ---------------------------------------------------------------------------
# _classify() — OCSF class routing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("groups,expected_class,expected_category", [
    (["process"],              OCSFClass.PROCESS_ACTIVITY,  OCSFCategory.SYSTEM_ACTIVITY),
    (["win_process"],          OCSFClass.PROCESS_ACTIVITY,  OCSFCategory.SYSTEM_ACTIVITY),
    (["network"],              OCSFClass.NETWORK_ACTIVITY,  OCSFCategory.NETWORK),
    (["firewall"],             OCSFClass.NETWORK_ACTIVITY,  OCSFCategory.NETWORK),
    (["connection"],           OCSFClass.NETWORK_ACTIVITY,  OCSFCategory.NETWORK),
    (["authentication"],       OCSFClass.AUTHENTICATION,    OCSFCategory.IAM),
    (["login"],                OCSFClass.AUTHENTICATION,    OCSFCategory.IAM),
    (["logon"],                OCSFClass.AUTHENTICATION,    OCSFCategory.IAM),
    (["file"],                 OCSFClass.FILE_ACTIVITY,     OCSFCategory.SYSTEM_ACTIVITY),
    (["syscheck"],             OCSFClass.FILE_ACTIVITY,     OCSFCategory.SYSTEM_ACTIVITY),
    ([],                       OCSFClass.SECURITY_FINDING,  OCSFCategory.FINDINGS),
    (["other_group"],          OCSFClass.SECURITY_FINDING,  OCSFCategory.FINDINGS),
])
def test_classify_routes_correctly(
    normalizer: WazuhNormalizer,
    groups: list[str],
    expected_class: int,
    expected_category: int,
) -> None:
    class_uid, _, category_uid = normalizer._classify({"groups": groups}, {})
    assert class_uid == expected_class
    assert category_uid == expected_category


def test_classify_returns_class_name_string(normalizer: WazuhNormalizer) -> None:
    _, class_name, _ = normalizer._classify({"groups": ["process"]}, {})
    assert isinstance(class_name, str)
    assert class_name  # non-empty


# ---------------------------------------------------------------------------
# _build_attacks() — MITRE ATT&CK mapping
# ---------------------------------------------------------------------------


def test_build_attacks_single_technique(normalizer: WazuhNormalizer) -> None:
    mitre = {"id": ["T1003.001"], "tactic": ["credential-access"]}
    attacks = normalizer._build_attacks(mitre)
    assert len(attacks) == 1
    assert attacks[0].technique.uid == "T1003.001"
    assert attacks[0].tactic.uid == "TA0006"
    assert attacks[0].tactic.name == "Credential Access"


def test_build_attacks_multiple_techniques_aligned(normalizer: WazuhNormalizer) -> None:
    """Each technique is paired with its own tactic when counts match."""
    mitre = {
        "id": ["T1059.001", "T1055"],
        "tactic": ["execution", "privilege-escalation"],
    }
    attacks = normalizer._build_attacks(mitre)
    assert len(attacks) == 2
    assert attacks[0].tactic.uid == "TA0002"
    assert attacks[1].tactic.uid == "TA0004"


def test_build_attacks_more_techniques_than_tactics(normalizer: WazuhNormalizer) -> None:
    """Extra techniques reuse the first tactic when tactics list is shorter."""
    mitre = {
        "id": ["T1059", "T1055", "T1003"],
        "tactic": ["execution"],
    }
    attacks = normalizer._build_attacks(mitre)
    assert len(attacks) == 3
    for att in attacks:
        assert att.tactic.uid == "TA0002"


def test_build_attacks_unknown_tactic_passthrough(normalizer: WazuhNormalizer) -> None:
    """Unknown tactic slugs are preserved as-is for forward compatibility."""
    mitre = {"id": ["T9999"], "tactic": ["future-tactic"]}
    attacks = normalizer._build_attacks(mitre)
    assert attacks[0].tactic.name == "future-tactic"
    assert attacks[0].tactic.uid == ""


def test_build_attacks_empty_mitre(normalizer: WazuhNormalizer) -> None:
    """Empty MITRE block produces an empty attacks list."""
    assert normalizer._build_attacks({}) == []


def test_mitre_tactic_map_completeness() -> None:
    """All 14 ATT&CK Enterprise tactics must be mapped."""
    expected_uids = {
        "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
        "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
        "TA0011", "TA0040", "TA0042", "TA0043",
    }
    mapped_uids = {uid for _, uid in MITRE_TACTIC_MAP.values()}
    assert mapped_uids == expected_uids


# ---------------------------------------------------------------------------
# _parse_time()
# ---------------------------------------------------------------------------


def test_parse_time_iso_z_suffix(normalizer: WazuhNormalizer) -> None:
    ts = normalizer._parse_time("2026-02-19T08:30:00.000Z")
    assert ts.tzinfo is not None
    assert ts.year == 2026
    assert ts.hour == 8


def test_parse_time_iso_offset(normalizer: WazuhNormalizer) -> None:
    ts = normalizer._parse_time("2026-02-19T08:30:00+05:00")
    assert ts.tzinfo is not None


def test_parse_time_none_returns_utc_now(normalizer: WazuhNormalizer) -> None:
    before = datetime.now(timezone.utc)
    ts = normalizer._parse_time(None)
    after = datetime.now(timezone.utc)
    assert before <= ts <= after


def test_parse_time_invalid_returns_utc_now(normalizer: WazuhNormalizer) -> None:
    before = datetime.now(timezone.utc)
    ts = normalizer._parse_time("not-a-timestamp")
    after = datetime.now(timezone.utc)
    assert before <= ts <= after


# ---------------------------------------------------------------------------
# _safe_int() / _exe_name()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val,expected", [
    ("3456", 3456),
    (3456, 3456),
    ("0", 0),
    (None, None),
    ("abc", None),
    ("", None),
])
def test_safe_int(normalizer: WazuhNormalizer, val, expected) -> None:
    assert normalizer._safe_int(val) == expected


@pytest.mark.parametrize("path,expected", [
    (r"C:\mimikatz\mimikatz.exe", "mimikatz.exe"),
    ("/usr/bin/python3", "python3"),
    ("notepad.exe", "notepad.exe"),
    ("", None),
])
def test_exe_name(normalizer: WazuhNormalizer, path: str, expected) -> None:
    assert normalizer._exe_name(path) == expected


# ---------------------------------------------------------------------------
# normalize() — full round-trip
# ---------------------------------------------------------------------------


def test_normalize_returns_ocsf_event(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    from app.services.normalizers.ocsf import OCSFEvent
    event = normalizer.normalize(full_alert)
    assert isinstance(event, OCSFEvent)


def test_normalize_severity_id_from_level(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    """level=12 falls in High tier → severity_id=4."""
    event = normalizer.normalize(full_alert)
    assert event.severity_id == 4


def test_normalize_severity_propagated_to_finding_info(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    """severity_id must be consistent between OCSFEvent and FindingInfo."""
    event = normalizer.normalize(full_alert)
    assert event.finding_info is not None
    assert event.finding_info.severity_id == event.severity_id


def test_normalize_metadata_product(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.metadata_product == "Wazuh"


def test_normalize_metadata_uid(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.metadata_uid == "1708331400.12345"


def test_normalize_dst_endpoint_from_agent(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.dst_endpoint.hostname == "WIN-DC01"
    assert event.dst_endpoint.ip == "192.168.1.10"


def test_normalize_src_endpoint_from_data(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.src_endpoint.ip == "10.0.0.5"


def test_normalize_actor_user(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.actor_user.name == "SYSTEM"


def test_normalize_process_from_windows_event_data(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.process.cmd_line == "mimikatz.exe sekurlsa::logonpasswords"
    assert event.process.pid == 3456
    assert event.process.parent_pid == 1234
    assert event.process.name == "mimikatz.exe"


def test_normalize_finding_info_title(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.finding_info.title == "LSASS Memory Dump Detected"


def test_normalize_finding_info_analytic_uid(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.finding_info.analytic.uid == "100234"


def test_normalize_attacks_populated(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert len(event.finding_info.attacks) == 1
    assert event.finding_info.attacks[0].technique.uid == "T1003.001"


def test_normalize_class_uid_process_groups(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.class_uid == OCSFClass.PROCESS_ACTIVITY


def test_normalize_raw_preserved(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.raw == full_alert


def test_normalize_timestamp_parsed(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    event = normalizer.normalize(full_alert)
    assert event.time.year == 2026
    assert event.time.month == 2
    assert event.time.day == 19


# ---------------------------------------------------------------------------
# normalize() — missing/sparse fields produce safe defaults
# ---------------------------------------------------------------------------


def test_normalize_minimal_alert(normalizer: WazuhNormalizer) -> None:
    """Normalizer must not raise on a near-empty Wazuh alert.

    Default level=5 (from rule.get("level", 5)) falls in the Low tier → severity_id=2.
    """
    event = normalizer.normalize({})
    assert event.severity_id == 2           # level=5 default → Low
    assert event.metadata_product == "Wazuh"
    assert event.finding_info is not None
    assert event.finding_info.title == "Unknown Alert"


def test_normalize_missing_timestamp_uses_now(normalizer: WazuhNormalizer) -> None:
    before = datetime.now(timezone.utc)
    event = normalizer.normalize({"rule": {"level": 5}})
    after = datetime.now(timezone.utc)
    assert before <= event.time <= after


def test_normalize_zero_level_is_informational(normalizer: WazuhNormalizer) -> None:
    event = normalizer.normalize({"rule": {"level": 0}})
    assert event.severity_id == 1


def test_normalize_critical_level(normalizer: WazuhNormalizer) -> None:
    event = normalizer.normalize({"rule": {"level": 14}})
    assert event.severity_id == 5


def test_normalize_model_dump_json_serializable(normalizer: WazuhNormalizer, full_alert: dict) -> None:
    """model_dump(mode='json') must not raise — this is what the pipeline calls."""
    import json
    event = normalizer.normalize(full_alert)
    dumped = event.model_dump(mode="json")
    # Must be JSON-serializable (pipeline publishes this to the queue)
    json.dumps(dumped)


def test_normalize_no_mitre_data(normalizer: WazuhNormalizer) -> None:
    """Alert with no MITRE block produces an empty attacks list."""
    alert = {"rule": {"id": "1", "description": "Test", "level": 5}}
    event = normalizer.normalize(alert)
    assert event.finding_info.attacks == []


def test_normalize_linux_process_no_win_data(normalizer: WazuhNormalizer) -> None:
    """Linux alerts without win.eventdata still normalize without error."""
    alert = {
        "rule": {"level": 7, "description": "SSH brute force", "groups": ["authentication"]},
        "agent": {"name": "linux-host", "ip": "10.0.0.1"},
        "data": {"srcip": "172.16.0.5", "srcuser": "root"},
    }
    event = normalizer.normalize(alert)
    assert event.class_uid == OCSFClass.AUTHENTICATION
    assert event.actor_user.name == "root"
    assert event.severity_id == 3  # level 7 → Medium
