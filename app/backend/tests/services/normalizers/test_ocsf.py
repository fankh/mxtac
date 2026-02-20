"""Tests for OCSFEvent Pydantic schema — Feature 7.1

Coverage:
  - Sub-models: Endpoint, ProcessInfo, UserInfo, AttackTactic, AttackTechnique,
                AttackInfo, Analytic, FindingInfo
  - Severity mapping: SEVERITY_MAP, SEVERITY_ID_TO_NAME
  - OCSFEvent required fields and ValidationError on missing
  - OCSFEvent default factory values
  - severity_name property
  - OCSFClass and OCSFCategory constants
  - Serialization: model_dump(), model_dump(mode="json"), JSON round-trip
  - Full event construction for each OCSF event class
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.services.normalizers.ocsf import (
    Analytic,
    AttackInfo,
    AttackTactic,
    AttackTechnique,
    Endpoint,
    FindingInfo,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
    SEVERITY_ID_TO_NAME,
    SEVERITY_MAP,
    UserInfo,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_event(**overrides) -> OCSFEvent:
    """Build a minimal valid OCSFEvent with all required fields."""
    fields = {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "metadata_product": "Zeek",
    }
    fields.update(overrides)
    return OCSFEvent(**fields)


# ---------------------------------------------------------------------------
# Sub-models: Endpoint
# ---------------------------------------------------------------------------


def test_endpoint_all_fields_none_by_default() -> None:
    """Endpoint with no args has all fields as None."""
    ep = Endpoint()
    assert ep.hostname is None
    assert ep.ip is None
    assert ep.port is None
    assert ep.domain is None
    assert ep.os_name is None


def test_endpoint_all_fields_set() -> None:
    """Endpoint stores all provided fields."""
    ep = Endpoint(hostname="host1", ip="192.168.1.10", port=443, domain="example.com", os_name="Linux")
    assert ep.hostname == "host1"
    assert ep.ip == "192.168.1.10"
    assert ep.port == 443
    assert ep.domain == "example.com"
    assert ep.os_name == "Linux"


def test_endpoint_partial_fields() -> None:
    """Endpoint stores only the provided subset of fields."""
    ep = Endpoint(ip="10.0.0.1", port=8080)
    assert ep.ip == "10.0.0.1"
    assert ep.port == 8080
    assert ep.hostname is None
    assert ep.domain is None


# ---------------------------------------------------------------------------
# Sub-models: ProcessInfo
# ---------------------------------------------------------------------------


def test_process_info_all_none_by_default() -> None:
    """ProcessInfo with no args has all fields as None."""
    proc = ProcessInfo()
    assert proc.pid is None
    assert proc.name is None
    assert proc.cmd_line is None
    assert proc.path is None
    assert proc.parent_pid is None
    assert proc.parent_name is None
    assert proc.hash_sha256 is None


def test_process_info_all_fields_set() -> None:
    """ProcessInfo stores all provided fields."""
    proc = ProcessInfo(
        pid=1234,
        name="cmd.exe",
        cmd_line="cmd.exe /c whoami",
        path="C:\\Windows\\System32\\cmd.exe",
        parent_pid=999,
        parent_name="explorer.exe",
        hash_sha256="abc123deadbeef",
    )
    assert proc.pid == 1234
    assert proc.name == "cmd.exe"
    assert proc.cmd_line == "cmd.exe /c whoami"
    assert proc.path == "C:\\Windows\\System32\\cmd.exe"
    assert proc.parent_pid == 999
    assert proc.parent_name == "explorer.exe"
    assert proc.hash_sha256 == "abc123deadbeef"


# ---------------------------------------------------------------------------
# Sub-models: UserInfo
# ---------------------------------------------------------------------------


def test_user_info_all_none_by_default() -> None:
    """UserInfo with no args has all fields as None."""
    user = UserInfo()
    assert user.name is None
    assert user.uid is None
    assert user.domain is None
    assert user.is_privileged is None


def test_user_info_privileged_true() -> None:
    """UserInfo stores is_privileged=True."""
    assert UserInfo(is_privileged=True).is_privileged is True


def test_user_info_privileged_false() -> None:
    """UserInfo stores is_privileged=False (distinct from None)."""
    assert UserInfo(is_privileged=False).is_privileged is False


def test_user_info_all_fields_set() -> None:
    """UserInfo stores all provided fields."""
    user = UserInfo(name="jdoe", uid="S-1-5-21", domain="CORP", is_privileged=True)
    assert user.name == "jdoe"
    assert user.uid == "S-1-5-21"
    assert user.domain == "CORP"
    assert user.is_privileged is True


# ---------------------------------------------------------------------------
# Sub-models: AttackTactic
# ---------------------------------------------------------------------------


def test_attack_tactic_stores_name_and_uid() -> None:
    """AttackTactic stores name and uid."""
    tactic = AttackTactic(name="Execution", uid="TA0002")
    assert tactic.name == "Execution"
    assert tactic.uid == "TA0002"


def test_attack_tactic_requires_name() -> None:
    """AttackTactic without name raises ValidationError."""
    with pytest.raises(ValidationError):
        AttackTactic(uid="TA0002")


def test_attack_tactic_requires_uid() -> None:
    """AttackTactic without uid raises ValidationError."""
    with pytest.raises(ValidationError):
        AttackTactic(name="Execution")


# ---------------------------------------------------------------------------
# Sub-models: AttackTechnique
# ---------------------------------------------------------------------------


def test_attack_technique_stores_fields() -> None:
    """AttackTechnique stores name and uid; sub_technique defaults to None."""
    tech = AttackTechnique(name="PowerShell", uid="T1059.001")
    assert tech.name == "PowerShell"
    assert tech.uid == "T1059.001"
    assert tech.sub_technique is None


def test_attack_technique_with_sub_technique() -> None:
    """AttackTechnique stores sub_technique when provided."""
    tech = AttackTechnique(name="PowerShell", uid="T1059.001", sub_technique=".001")
    assert tech.sub_technique == ".001"


def test_attack_technique_requires_name() -> None:
    """AttackTechnique without name raises ValidationError."""
    with pytest.raises(ValidationError):
        AttackTechnique(uid="T1059")


def test_attack_technique_requires_uid() -> None:
    """AttackTechnique without uid raises ValidationError."""
    with pytest.raises(ValidationError):
        AttackTechnique(name="PowerShell")


# ---------------------------------------------------------------------------
# Sub-models: AttackInfo
# ---------------------------------------------------------------------------


def test_attack_info_defaults_to_none() -> None:
    """AttackInfo with no args defaults tactic and technique to None."""
    info = AttackInfo()
    assert info.tactic is None
    assert info.technique is None


def test_attack_info_with_tactic_and_technique() -> None:
    """AttackInfo stores nested tactic and technique models."""
    tactic = AttackTactic(name="Execution", uid="TA0002")
    technique = AttackTechnique(name="PowerShell", uid="T1059.001")
    info = AttackInfo(tactic=tactic, technique=technique)
    assert info.tactic.uid == "TA0002"
    assert info.technique.uid == "T1059.001"


def test_attack_info_tactic_only() -> None:
    """AttackInfo can be created with tactic only."""
    info = AttackInfo(tactic=AttackTactic(name="Discovery", uid="TA0007"))
    assert info.tactic.name == "Discovery"
    assert info.technique is None


# ---------------------------------------------------------------------------
# Sub-models: Analytic
# ---------------------------------------------------------------------------


def test_analytic_defaults() -> None:
    """Analytic defaults uid and name to None, type_id to 1."""
    analytic = Analytic()
    assert analytic.uid is None
    assert analytic.name is None
    assert analytic.type_id == 1


def test_analytic_all_fields_set() -> None:
    """Analytic stores all provided fields."""
    analytic = Analytic(uid="RULE-001", name="Suspicious PowerShell", type_id=2)
    assert analytic.uid == "RULE-001"
    assert analytic.name == "Suspicious PowerShell"
    assert analytic.type_id == 2


# ---------------------------------------------------------------------------
# Sub-models: FindingInfo
# ---------------------------------------------------------------------------


def test_finding_info_requires_title() -> None:
    """FindingInfo without title raises ValidationError."""
    with pytest.raises(ValidationError):
        FindingInfo()


def test_finding_info_defaults() -> None:
    """FindingInfo with only title has empty attacks list and severity_id=1."""
    fi = FindingInfo(title="Suspicious Activity")
    assert fi.title == "Suspicious Activity"
    assert fi.analytic is None
    assert fi.attacks == []
    assert fi.severity_id == 1


def test_finding_info_with_attacks() -> None:
    """FindingInfo stores a list of AttackInfo entries."""
    attack = AttackInfo(
        tactic=AttackTactic(name="Execution", uid="TA0002"),
        technique=AttackTechnique(name="PowerShell", uid="T1059.001"),
    )
    fi = FindingInfo(title="Test Finding", attacks=[attack], severity_id=4)
    assert len(fi.attacks) == 1
    assert fi.attacks[0].tactic.uid == "TA0002"
    assert fi.severity_id == 4


def test_finding_info_with_analytic() -> None:
    """FindingInfo stores the analytic sub-model."""
    analytic = Analytic(uid="RULE-42", name="Lateral Movement")
    fi = FindingInfo(title="LM Detected", analytic=analytic)
    assert fi.analytic.uid == "RULE-42"
    assert fi.analytic.name == "Lateral Movement"


def test_finding_info_multiple_attacks() -> None:
    """FindingInfo stores multiple AttackInfo entries."""
    attacks = [
        AttackInfo(tactic=AttackTactic(name="Execution", uid="TA0002")),
        AttackInfo(tactic=AttackTactic(name="Persistence", uid="TA0003")),
    ]
    fi = FindingInfo(title="Multi-tactic", attacks=attacks)
    assert len(fi.attacks) == 2


# ---------------------------------------------------------------------------
# SEVERITY_MAP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,expected_id", [
    ("critical", 5),
    ("high", 4),
    ("medium", 3),
    ("low", 2),
    ("info", 1),
    ("unknown", 0),
])
def test_severity_map_values(name: str, expected_id: int) -> None:
    """SEVERITY_MAP maps each severity name to the correct integer ID."""
    assert SEVERITY_MAP[name] == expected_id


def test_severity_map_has_six_entries() -> None:
    """SEVERITY_MAP contains exactly 6 severity levels."""
    assert len(SEVERITY_MAP) == 6


def test_severity_map_all_values_unique() -> None:
    """SEVERITY_MAP values are all distinct integers."""
    assert len(set(SEVERITY_MAP.values())) == 6


# ---------------------------------------------------------------------------
# SEVERITY_ID_TO_NAME
# ---------------------------------------------------------------------------


def test_severity_id_to_name_is_inverse() -> None:
    """SEVERITY_ID_TO_NAME is the exact inverse of SEVERITY_MAP."""
    for name, sid in SEVERITY_MAP.items():
        assert SEVERITY_ID_TO_NAME[sid] == name


def test_severity_id_to_name_has_six_entries() -> None:
    """SEVERITY_ID_TO_NAME contains exactly 6 entries."""
    assert len(SEVERITY_ID_TO_NAME) == 6


@pytest.mark.parametrize("sid,expected_name", [
    (0, "unknown"),
    (1, "info"),
    (2, "low"),
    (3, "medium"),
    (4, "high"),
    (5, "critical"),
])
def test_severity_id_to_name_values(sid: int, expected_name: str) -> None:
    """SEVERITY_ID_TO_NAME maps each integer to the correct severity name."""
    assert SEVERITY_ID_TO_NAME[sid] == expected_name


# ---------------------------------------------------------------------------
# OCSFClass constants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("attr,expected", [
    ("FILE_ACTIVITY", 1001),
    ("PROCESS_ACTIVITY", 1007),
    ("SECURITY_FINDING", 2001),
    ("AUTHENTICATION", 3002),
    ("NETWORK_ACTIVITY", 4001),
    ("HTTP_ACTIVITY", 4002),
    ("DNS_ACTIVITY", 4003),
])
def test_ocsf_class_constants(attr: str, expected: int) -> None:
    """OCSFClass constants have the correct values."""
    assert getattr(OCSFClass, attr) == expected


# ---------------------------------------------------------------------------
# OCSFCategory constants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("attr,expected", [
    ("SYSTEM_ACTIVITY", 1),
    ("FINDINGS", 2),
    ("IAM", 3),
    ("NETWORK", 4),
])
def test_ocsf_category_constants(attr: str, expected: int) -> None:
    """OCSFCategory constants have the correct values."""
    assert getattr(OCSFCategory, attr) == expected


# ---------------------------------------------------------------------------
# OCSFEvent: Required fields — ValidationError on missing
# ---------------------------------------------------------------------------


def test_ocsf_event_missing_class_uid_raises() -> None:
    """OCSFEvent without class_uid raises ValidationError."""
    with pytest.raises(ValidationError):
        OCSFEvent(class_name="Network Activity", category_uid=4, metadata_product="Zeek")


def test_ocsf_event_missing_class_name_raises() -> None:
    """OCSFEvent without class_name raises ValidationError."""
    with pytest.raises(ValidationError):
        OCSFEvent(class_uid=4001, category_uid=4, metadata_product="Zeek")


def test_ocsf_event_missing_category_uid_raises() -> None:
    """OCSFEvent without category_uid raises ValidationError."""
    with pytest.raises(ValidationError):
        OCSFEvent(class_uid=4001, class_name="Network Activity", metadata_product="Zeek")


def test_ocsf_event_missing_metadata_product_raises() -> None:
    """OCSFEvent without metadata_product raises ValidationError."""
    with pytest.raises(ValidationError):
        OCSFEvent(class_uid=4001, class_name="Network Activity", category_uid=4)


def test_ocsf_event_empty_construction_raises() -> None:
    """OCSFEvent with no args raises ValidationError."""
    with pytest.raises(ValidationError):
        OCSFEvent()


# ---------------------------------------------------------------------------
# OCSFEvent: Default values
# ---------------------------------------------------------------------------


def test_ocsf_event_default_severity_id() -> None:
    """OCSFEvent defaults severity_id to 1 (Informational)."""
    assert _minimal_event().severity_id == 1


def test_ocsf_event_default_metadata_version() -> None:
    """OCSFEvent defaults metadata_version to '1.1.0'."""
    assert _minimal_event().metadata_version == "1.1.0"


def test_ocsf_event_default_metadata_uid_is_none() -> None:
    """OCSFEvent defaults metadata_uid to None."""
    assert _minimal_event().metadata_uid is None


def test_ocsf_event_default_src_endpoint_is_endpoint() -> None:
    """OCSFEvent defaults src_endpoint to an empty Endpoint instance."""
    event = _minimal_event()
    assert isinstance(event.src_endpoint, Endpoint)
    assert event.src_endpoint.ip is None


def test_ocsf_event_default_dst_endpoint_is_endpoint() -> None:
    """OCSFEvent defaults dst_endpoint to an empty Endpoint instance."""
    event = _minimal_event()
    assert isinstance(event.dst_endpoint, Endpoint)
    assert event.dst_endpoint.ip is None


def test_ocsf_event_default_actor_user_is_user_info() -> None:
    """OCSFEvent defaults actor_user to an empty UserInfo instance."""
    event = _minimal_event()
    assert isinstance(event.actor_user, UserInfo)
    assert event.actor_user.name is None


def test_ocsf_event_default_process_is_process_info() -> None:
    """OCSFEvent defaults process to an empty ProcessInfo instance."""
    event = _minimal_event()
    assert isinstance(event.process, ProcessInfo)
    assert event.process.pid is None


def test_ocsf_event_default_network_traffic_is_empty_dict() -> None:
    """OCSFEvent defaults network_traffic to {}."""
    assert _minimal_event().network_traffic == {}


def test_ocsf_event_default_file_is_empty_dict() -> None:
    """OCSFEvent defaults file to {}."""
    assert _minimal_event().file == {}


def test_ocsf_event_default_raw_is_empty_dict() -> None:
    """OCSFEvent defaults raw to {}."""
    assert _minimal_event().raw == {}


def test_ocsf_event_default_unmapped_is_empty_dict() -> None:
    """OCSFEvent defaults unmapped to {}."""
    assert _minimal_event().unmapped == {}


def test_ocsf_event_default_finding_info_is_none() -> None:
    """OCSFEvent defaults finding_info to None."""
    assert _minimal_event().finding_info is None


def test_ocsf_event_default_time_is_utc_aware() -> None:
    """OCSFEvent time defaults to a timezone-aware UTC datetime."""
    before = datetime.now(timezone.utc)
    event = _minimal_event()
    after = datetime.now(timezone.utc)
    assert before <= event.time <= after
    assert event.time.tzinfo is not None


def test_ocsf_event_default_time_factory_called_each_time() -> None:
    """Each OCSFEvent construction gets its own default time value."""
    e1 = _minimal_event()
    e2 = _minimal_event()
    assert isinstance(e1.time, datetime)
    assert isinstance(e2.time, datetime)


def test_ocsf_event_default_endpoints_are_independent_objects() -> None:
    """Two OCSFEvent instances do not share the same Endpoint objects."""
    e1 = _minimal_event()
    e2 = _minimal_event()
    assert e1.src_endpoint is not e2.src_endpoint
    assert e1.dst_endpoint is not e2.dst_endpoint


def test_ocsf_event_default_dicts_are_independent_objects() -> None:
    """Two OCSFEvent instances do not share the same dict objects."""
    e1 = _minimal_event()
    e2 = _minimal_event()
    assert e1.raw is not e2.raw
    assert e1.unmapped is not e2.unmapped


# ---------------------------------------------------------------------------
# OCSFEvent: Custom field values override defaults
# ---------------------------------------------------------------------------


def test_ocsf_event_custom_severity_id() -> None:
    """An explicitly provided severity_id overrides the default."""
    assert _minimal_event(severity_id=4).severity_id == 4


def test_ocsf_event_custom_metadata_version() -> None:
    """metadata_version can be overridden from '1.1.0'."""
    assert _minimal_event(metadata_version="2.0.0").metadata_version == "2.0.0"


def test_ocsf_event_custom_metadata_uid() -> None:
    """metadata_uid is stored when explicitly provided."""
    assert _minimal_event(metadata_uid="alert-999").metadata_uid == "alert-999"


def test_ocsf_event_custom_time() -> None:
    """An explicit time value is stored as provided."""
    fixed_time = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert _minimal_event(time=fixed_time).time == fixed_time


def test_ocsf_event_raw_and_unmapped_stored() -> None:
    """raw and unmapped dicts store arbitrary content."""
    raw = {"_id": "log-001", "source": "agent1"}
    unmapped = {"vendor_code": 42}
    event = _minimal_event(raw=raw, unmapped=unmapped)
    assert event.raw == raw
    assert event.unmapped == unmapped


# ---------------------------------------------------------------------------
# OCSFEvent: severity_name property
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("severity_id,expected_name", [
    (0, "unknown"),
    (1, "info"),
    (2, "low"),
    (3, "medium"),
    (4, "high"),
    (5, "critical"),
])
def test_severity_name_property(severity_id: int, expected_name: str) -> None:
    """severity_name returns the correct string for each valid severity_id."""
    assert _minimal_event(severity_id=severity_id).severity_name == expected_name


def test_severity_name_unknown_for_unmapped_id() -> None:
    """severity_name returns 'unknown' for a severity_id not in the map."""
    assert _minimal_event(severity_id=99).severity_name == "unknown"


def test_severity_name_unknown_for_negative_id() -> None:
    """severity_name returns 'unknown' for a negative severity_id."""
    assert _minimal_event(severity_id=-1).severity_name == "unknown"


# ---------------------------------------------------------------------------
# OCSFEvent: Serialization
# ---------------------------------------------------------------------------


def test_model_dump_contains_required_fields() -> None:
    """model_dump() includes all required fields with correct values."""
    data = _minimal_event().model_dump()
    assert data["class_uid"] == 4001
    assert data["class_name"] == "Network Activity"
    assert data["category_uid"] == 4
    assert data["metadata_product"] == "Zeek"


def test_model_dump_json_mode_serializes_datetime_to_string() -> None:
    """model_dump(mode='json') converts datetime to an ISO 8601 string."""
    data = _minimal_event().model_dump(mode="json")
    assert isinstance(data["time"], str)
    parsed = datetime.fromisoformat(data["time"])
    assert isinstance(parsed, datetime)


def test_model_dump_default_dicts_are_empty() -> None:
    """Minimal event serializes network_traffic, file, raw, unmapped as {}."""
    data = _minimal_event().model_dump()
    assert data["network_traffic"] == {}
    assert data["file"] == {}
    assert data["raw"] == {}
    assert data["unmapped"] == {}


def test_model_dump_finding_info_is_none() -> None:
    """finding_info serializes to None when not set."""
    assert _minimal_event().model_dump()["finding_info"] is None


def test_json_round_trip_minimal_event() -> None:
    """Minimal OCSFEvent survives serialize → deserialize round-trip."""
    event = _minimal_event(severity_id=2, metadata_uid="evt-001")
    restored = OCSFEvent.model_validate_json(event.model_dump_json())
    assert restored.class_uid == event.class_uid
    assert restored.class_name == event.class_name
    assert restored.category_uid == event.category_uid
    assert restored.metadata_product == event.metadata_product
    assert restored.severity_id == 2
    assert restored.metadata_uid == "evt-001"


def test_json_round_trip_with_endpoints() -> None:
    """OCSFEvent with endpoints survives JSON round-trip."""
    event = _minimal_event(
        src_endpoint=Endpoint(ip="10.0.0.1", port=1234),
        dst_endpoint=Endpoint(ip="10.0.0.2", port=443),
    )
    restored = OCSFEvent.model_validate_json(event.model_dump_json())
    assert restored.src_endpoint.ip == "10.0.0.1"
    assert restored.src_endpoint.port == 1234
    assert restored.dst_endpoint.ip == "10.0.0.2"
    assert restored.dst_endpoint.port == 443


def test_json_round_trip_with_finding_info() -> None:
    """OCSFEvent with finding_info survives JSON round-trip."""
    attack = AttackInfo(
        tactic=AttackTactic(name="Execution", uid="TA0002"),
        technique=AttackTechnique(name="PowerShell", uid="T1059.001"),
    )
    finding = FindingInfo(
        title="PS Exec",
        severity_id=4,
        attacks=[attack],
        analytic=Analytic(uid="R-001", name="PowerShell Execution"),
    )
    event = _minimal_event(finding_info=finding)
    restored = OCSFEvent.model_validate_json(event.model_dump_json())
    assert restored.finding_info.title == "PS Exec"
    assert restored.finding_info.severity_id == 4
    assert len(restored.finding_info.attacks) == 1
    assert restored.finding_info.attacks[0].tactic.uid == "TA0002"
    assert restored.finding_info.analytic.uid == "R-001"


# ---------------------------------------------------------------------------
# OCSFEvent: Full event construction scenarios
# ---------------------------------------------------------------------------


def test_network_activity_event() -> None:
    """Construct a complete Network Activity (class_uid=4001) event."""
    event = OCSFEvent(
        class_uid=OCSFClass.NETWORK_ACTIVITY,
        class_name="Network Activity",
        category_uid=OCSFCategory.NETWORK,
        metadata_product="Zeek",
        metadata_uid="conn-abc123",
        severity_id=1,
        src_endpoint=Endpoint(ip="192.168.1.100", port=54321),
        dst_endpoint=Endpoint(ip="8.8.8.8", port=53),
        network_traffic={"protocol": "UDP", "bytes_in": 100, "bytes_out": 200},
        raw={"ts": "2024-01-01T00:00:00Z"},
    )
    assert event.class_uid == 4001
    assert event.category_uid == 4
    assert event.src_endpoint.ip == "192.168.1.100"
    assert event.dst_endpoint.port == 53
    assert event.network_traffic["protocol"] == "UDP"
    assert event.metadata_uid == "conn-abc123"
    assert event.severity_name == "info"


def test_security_finding_event_with_mitre_attack() -> None:
    """Construct a Security Finding (class_uid=2001) with full ATT&CK mapping."""
    attack = AttackInfo(
        tactic=AttackTactic(name="Execution", uid="TA0002"),
        technique=AttackTechnique(name="Command and Scripting Interpreter", uid="T1059"),
    )
    finding = FindingInfo(
        title="Suspicious PowerShell Execution",
        severity_id=4,
        analytic=Analytic(uid="RULE-100", name="PS Execution", type_id=1),
        attacks=[attack],
    )
    event = OCSFEvent(
        class_uid=OCSFClass.SECURITY_FINDING,
        class_name="Security Finding",
        category_uid=OCSFCategory.FINDINGS,
        metadata_product="Wazuh",
        severity_id=4,
        finding_info=finding,
        actor_user=UserInfo(name="SYSTEM", is_privileged=True),
        process=ProcessInfo(pid=4567, name="powershell.exe", cmd_line="powershell -enc BASE64=="),
    )
    assert event.class_uid == 2001
    assert event.category_uid == 2
    assert event.severity_id == 4
    assert event.severity_name == "high"
    assert event.finding_info.title == "Suspicious PowerShell Execution"
    assert event.finding_info.analytic.uid == "RULE-100"
    assert len(event.finding_info.attacks) == 1
    assert event.finding_info.attacks[0].tactic.uid == "TA0002"
    assert event.finding_info.attacks[0].technique.uid == "T1059"
    assert event.actor_user.is_privileged is True
    assert event.process.name == "powershell.exe"
    assert event.process.pid == 4567


def test_process_activity_event() -> None:
    """Construct a Process Activity (class_uid=1007) event."""
    event = OCSFEvent(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        class_name="Process Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        metadata_product="Wazuh",
        severity_id=3,
        process=ProcessInfo(
            pid=1337,
            name="nc.exe",
            cmd_line="nc.exe -lvp 4444",
            path="C:\\Users\\victim\\Downloads\\nc.exe",
            hash_sha256="deadbeef",
        ),
        actor_user=UserInfo(name="victim", domain="WORKGROUP"),
        src_endpoint=Endpoint(hostname="WORKSTATION01", os_name="Windows"),
    )
    assert event.class_uid == 1007
    assert event.category_uid == 1
    assert event.severity_name == "medium"
    assert event.process.pid == 1337
    assert event.process.hash_sha256 == "deadbeef"
    assert event.actor_user.domain == "WORKGROUP"
    assert event.src_endpoint.hostname == "WORKSTATION01"


def test_dns_activity_event() -> None:
    """Construct a DNS Activity (class_uid=4003) event."""
    event = OCSFEvent(
        class_uid=OCSFClass.DNS_ACTIVITY,
        class_name="DNS Activity",
        category_uid=OCSFCategory.NETWORK,
        metadata_product="Zeek",
        severity_id=1,
        src_endpoint=Endpoint(ip="10.0.0.5"),
        dst_endpoint=Endpoint(ip="8.8.8.8", port=53),
        network_traffic={"query": "malware.example.com", "qtype": "A"},
    )
    assert event.class_uid == 4003
    assert event.category_uid == 4
    assert event.network_traffic["query"] == "malware.example.com"
    assert event.dst_endpoint.port == 53


def test_authentication_event() -> None:
    """Construct an Authentication (class_uid=3002) event."""
    event = OCSFEvent(
        class_uid=OCSFClass.AUTHENTICATION,
        class_name="Authentication",
        category_uid=OCSFCategory.IAM,
        metadata_product="Wazuh",
        severity_id=2,
        actor_user=UserInfo(name="admin", domain="CORP", is_privileged=True),
        src_endpoint=Endpoint(ip="10.0.0.100"),
    )
    assert event.class_uid == 3002
    assert event.category_uid == 3
    assert event.severity_name == "low"
    assert event.actor_user.name == "admin"
    assert event.actor_user.is_privileged is True


def test_file_activity_event() -> None:
    """Construct a File Activity (class_uid=1001) event."""
    event = OCSFEvent(
        class_uid=OCSFClass.FILE_ACTIVITY,
        class_name="File Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        metadata_product="Wazuh",
        severity_id=5,
        src_endpoint=Endpoint(hostname="server01"),
        file={"path": "/etc/passwd", "name": "passwd", "action": "modified"},
    )
    assert event.class_uid == 1001
    assert event.severity_name == "critical"
    assert event.file["path"] == "/etc/passwd"


def test_http_activity_event() -> None:
    """Construct an HTTP Activity (class_uid=4002) event."""
    event = OCSFEvent(
        class_uid=OCSFClass.HTTP_ACTIVITY,
        class_name="HTTP Activity",
        category_uid=OCSFCategory.NETWORK,
        metadata_product="Zeek",
        severity_id=1,
        src_endpoint=Endpoint(ip="10.0.0.5", port=60000),
        dst_endpoint=Endpoint(ip="1.2.3.4", port=80),
        network_traffic={"method": "GET", "uri": "/admin", "status": 200},
    )
    assert event.class_uid == 4002
    assert event.network_traffic["uri"] == "/admin"
