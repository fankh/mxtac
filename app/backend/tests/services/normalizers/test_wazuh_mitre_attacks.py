"""Tests for WazuhNormalizer — Feature 7.3

Wazuh → OCSF: MITRE tags → attacks[]

Coverage (Feature 7.3 / Test 28.11):
  - MITRE_TACTIC_FULL_NAME_MAP: full-name → slug reverse lookup
  - _parse_technique_id(): dotted sub-technique splitting
  - _build_attacks(): technique.name from rule.mitre.technique field
  - _build_attacks(): technique.name fallback to UID when names absent
  - _build_attacks(): sub_technique populated for dotted IDs
  - _build_attacks(): sub_technique=None for plain (non-dotted) IDs
  - _build_attacks(): full-name tactic format ("Credential Access") resolved correctly
  - _build_attacks(): partial technique names list falls back to UID for overflow
  - _build_attacks(): tactics-only block (no id) → empty list
  - normalize(): attacks[] in OCSFEvent.finding_info carries technique name + sub_technique
  - normalize(): JSON serialization round-trip includes all MITRE fields
"""

from __future__ import annotations

import json

import pytest

from app.services.normalizers.wazuh import (
    MITRE_TACTIC_FULL_NAME_MAP,
    MITRE_TACTIC_MAP,
    WazuhNormalizer,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def normalizer() -> WazuhNormalizer:
    return WazuhNormalizer()


# ---------------------------------------------------------------------------
# MITRE_TACTIC_FULL_NAME_MAP — reverse lookup
# ---------------------------------------------------------------------------


def test_full_name_map_covers_all_slugs() -> None:
    """Every slug in MITRE_TACTIC_MAP must have a full-name entry."""
    for slug, (name, _uid) in MITRE_TACTIC_MAP.items():
        assert name in MITRE_TACTIC_FULL_NAME_MAP, f"Missing full-name entry for slug '{slug}'"
        assert MITRE_TACTIC_FULL_NAME_MAP[name] == slug


def test_full_name_map_credential_access() -> None:
    assert MITRE_TACTIC_FULL_NAME_MAP["Credential Access"] == "credential-access"


def test_full_name_map_command_and_control() -> None:
    assert MITRE_TACTIC_FULL_NAME_MAP["Command and Control"] == "command-and-control"


# ---------------------------------------------------------------------------
# _parse_technique_id() — sub-technique splitting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tech_id,expected_parent,expected_sub", [
    ("T1003.001", "T1003", "001"),
    ("T1059.003", "T1059", "003"),
    ("T1078.004", "T1078", "004"),
    ("T1059",     "T1059", None),
    ("T1003",     "T1003", None),
    ("T1105",     "T1105", None),
])
def test_parse_technique_id(
    normalizer: WazuhNormalizer,
    tech_id: str,
    expected_parent: str,
    expected_sub: str | None,
) -> None:
    parent, sub = normalizer._parse_technique_id(tech_id)
    assert parent == expected_parent
    assert sub == expected_sub


# ---------------------------------------------------------------------------
# _build_attacks() — technique.name from mitre.technique field
# ---------------------------------------------------------------------------


def test_technique_name_from_mitre_technique_field(normalizer: WazuhNormalizer) -> None:
    """When rule.mitre.technique is present, use it as technique.name."""
    mitre = {
        "id": ["T1003.001"],
        "tactic": ["credential-access"],
        "technique": ["OS Credential Dumping: LSASS Memory"],
    }
    attacks = normalizer._build_attacks(mitre)
    assert len(attacks) == 1
    assert attacks[0].technique.name == "OS Credential Dumping: LSASS Memory"
    assert attacks[0].technique.uid == "T1003.001"


def test_technique_name_fallback_to_uid_when_absent(normalizer: WazuhNormalizer) -> None:
    """When rule.mitre.technique is missing, technique.name falls back to the UID."""
    mitre = {
        "id": ["T1059.001"],
        "tactic": ["execution"],
    }
    attacks = normalizer._build_attacks(mitre)
    assert attacks[0].technique.name == "T1059.001"


def test_technique_name_fallback_for_overflow(normalizer: WazuhNormalizer) -> None:
    """When there are more technique IDs than names, extras fall back to their UIDs."""
    mitre = {
        "id": ["T1059.001", "T1055", "T1003"],
        "tactic": ["execution", "privilege-escalation", "credential-access"],
        "technique": ["Command and Scripting Interpreter: PowerShell"],
    }
    attacks = normalizer._build_attacks(mitre)
    assert len(attacks) == 3
    assert attacks[0].technique.name == "Command and Scripting Interpreter: PowerShell"
    assert attacks[1].technique.name == "T1055"    # fallback
    assert attacks[2].technique.name == "T1003"    # fallback


# ---------------------------------------------------------------------------
# _build_attacks() — sub_technique field
# ---------------------------------------------------------------------------


def test_sub_technique_set_for_dotted_id(normalizer: WazuhNormalizer) -> None:
    """Dotted technique IDs must populate sub_technique."""
    mitre = {"id": ["T1003.001"], "tactic": ["credential-access"]}
    attacks = normalizer._build_attacks(mitre)
    assert attacks[0].technique.sub_technique == "001"


def test_sub_technique_none_for_plain_id(normalizer: WazuhNormalizer) -> None:
    """Plain (non-dotted) technique IDs must leave sub_technique as None."""
    mitre = {"id": ["T1059"], "tactic": ["execution"]}
    attacks = normalizer._build_attacks(mitre)
    assert attacks[0].technique.sub_technique is None


def test_multiple_techniques_mixed_sub_techniques(normalizer: WazuhNormalizer) -> None:
    mitre = {
        "id": ["T1003.001", "T1059", "T1078.004"],
        "tactic": ["credential-access", "execution", "defense-evasion"],
    }
    attacks = normalizer._build_attacks(mitre)
    assert attacks[0].technique.sub_technique == "001"
    assert attacks[1].technique.sub_technique is None
    assert attacks[2].technique.sub_technique == "004"


# ---------------------------------------------------------------------------
# _build_attacks() — full-name tactic format
# ---------------------------------------------------------------------------


def test_full_name_tactic_format_resolved(normalizer: WazuhNormalizer) -> None:
    """Some Wazuh versions emit 'Credential Access' instead of 'credential-access'."""
    mitre = {
        "id": ["T1003.001"],
        "tactic": ["Credential Access"],
        "technique": ["OS Credential Dumping"],
    }
    attacks = normalizer._build_attacks(mitre)
    assert attacks[0].tactic.uid == "TA0006"
    assert attacks[0].tactic.name == "Credential Access"


def test_full_name_tactic_all_14_tactics(normalizer: WazuhNormalizer) -> None:
    """All 14 tactics resolve correctly in full-name format."""
    for full_name, slug in MITRE_TACTIC_FULL_NAME_MAP.items():
        expected_uid = MITRE_TACTIC_MAP[slug][1]
        mitre = {"id": ["T9999"], "tactic": [full_name]}
        attacks = normalizer._build_attacks(mitre)
        assert attacks[0].tactic.uid == expected_uid, (
            f"Full-name '{full_name}' did not resolve to UID '{expected_uid}'"
        )


# ---------------------------------------------------------------------------
# _build_attacks() — edge cases
# ---------------------------------------------------------------------------


def test_no_technique_ids_empty_attacks(normalizer: WazuhNormalizer) -> None:
    """Tactic-only block (no id list) → empty attacks."""
    mitre = {"tactic": ["execution"], "technique": ["PowerShell"]}
    assert normalizer._build_attacks(mitre) == []


def test_empty_mitre_block(normalizer: WazuhNormalizer) -> None:
    assert normalizer._build_attacks({}) == []


def test_multiple_techniques_aligned_names_and_sub_techniques(normalizer: WazuhNormalizer) -> None:
    """Full scenario: two techniques with names, mixed sub-technique status."""
    mitre = {
        "id": ["T1059.001", "T1055"],
        "tactic": ["execution", "privilege-escalation"],
        "technique": ["PowerShell", "Process Injection"],
    }
    attacks = normalizer._build_attacks(mitre)
    assert len(attacks) == 2

    ps = attacks[0]
    assert ps.technique.uid == "T1059.001"
    assert ps.technique.name == "PowerShell"
    assert ps.technique.sub_technique == "001"
    assert ps.tactic.uid == "TA0002"

    pi = attacks[1]
    assert pi.technique.uid == "T1055"
    assert pi.technique.name == "Process Injection"
    assert pi.technique.sub_technique is None
    assert pi.tactic.uid == "TA0004"


# ---------------------------------------------------------------------------
# normalize() — attacks[] in OCSFEvent.finding_info
# ---------------------------------------------------------------------------


@pytest.fixture
def full_mitre_alert() -> dict:
    """Wazuh alert with technique name and sub-technique ID."""
    return {
        "timestamp": "2026-02-19T08:30:00.000Z",
        "id": "1708331400.99999",
        "rule": {
            "id": "100234",
            "description": "LSASS Memory Dump Detected",
            "level": 12,
            "groups": ["process", "win_process"],
            "mitre": {
                "id": ["T1003.001"],
                "tactic": ["credential-access"],
                "technique": ["OS Credential Dumping: LSASS Memory"],
            },
        },
        "agent": {"id": "001", "name": "WIN-DC01", "ip": "192.168.1.10"},
        "data": {"srcip": "10.0.0.5", "dstuser": "SYSTEM"},
    }


def test_normalize_attacks_technique_name(normalizer: WazuhNormalizer, full_mitre_alert: dict) -> None:
    event = normalizer.normalize(full_mitre_alert)
    attacks = event.finding_info.attacks
    assert len(attacks) == 1
    assert attacks[0].technique.name == "OS Credential Dumping: LSASS Memory"


def test_normalize_attacks_sub_technique(normalizer: WazuhNormalizer, full_mitre_alert: dict) -> None:
    event = normalizer.normalize(full_mitre_alert)
    assert event.finding_info.attacks[0].technique.sub_technique == "001"


def test_normalize_attacks_tactic_uid(normalizer: WazuhNormalizer, full_mitre_alert: dict) -> None:
    event = normalizer.normalize(full_mitre_alert)
    assert event.finding_info.attacks[0].tactic.uid == "TA0006"


def test_normalize_attacks_full_name_tactic_format(normalizer: WazuhNormalizer) -> None:
    """Alert with full-name tactic (older Wazuh format) still resolves correctly."""
    alert = {
        "rule": {
            "level": 10,
            "mitre": {
                "id": ["T1059.003"],
                "tactic": ["Execution"],
                "technique": ["Windows Command Shell"],
            },
        },
    }
    event = normalizer.normalize(alert)
    attacks = event.finding_info.attacks
    assert attacks[0].tactic.uid == "TA0002"
    assert attacks[0].technique.name == "Windows Command Shell"
    assert attacks[0].technique.sub_technique == "003"


def test_normalize_no_mitre_produces_empty_attacks(normalizer: WazuhNormalizer) -> None:
    event = normalizer.normalize({"rule": {"level": 5, "description": "Generic"}})
    assert event.finding_info.attacks == []


# ---------------------------------------------------------------------------
# JSON serialization round-trip
# ---------------------------------------------------------------------------


def test_json_serialization_includes_technique_name(
    normalizer: WazuhNormalizer,
    full_mitre_alert: dict,
) -> None:
    """model_dump(mode='json') must carry through technique.name."""
    event = normalizer.normalize(full_mitre_alert)
    dumped = event.model_dump(mode="json")
    attack = dumped["finding_info"]["attacks"][0]
    assert attack["technique"]["name"] == "OS Credential Dumping: LSASS Memory"


def test_json_serialization_includes_sub_technique(
    normalizer: WazuhNormalizer,
    full_mitre_alert: dict,
) -> None:
    event = normalizer.normalize(full_mitre_alert)
    dumped = event.model_dump(mode="json")
    attack = dumped["finding_info"]["attacks"][0]
    assert attack["technique"]["sub_technique"] == "001"


def test_json_serialization_sub_technique_null_for_plain_id(normalizer: WazuhNormalizer) -> None:
    alert = {
        "rule": {
            "level": 7,
            "mitre": {"id": ["T1059"], "tactic": ["execution"]},
        }
    }
    event = normalizer.normalize(alert)
    dumped = event.model_dump(mode="json")
    attack = dumped["finding_info"]["attacks"][0]
    assert attack["technique"]["sub_technique"] is None


def test_full_json_round_trip_parseable(
    normalizer: WazuhNormalizer,
    full_mitre_alert: dict,
) -> None:
    """model_dump(mode='json') output must be JSON-serializable without error."""
    event = normalizer.normalize(full_mitre_alert)
    json_str = json.dumps(event.model_dump(mode="json"))
    parsed = json.loads(json_str)
    assert parsed["finding_info"]["attacks"][0]["technique"]["uid"] == "T1003.001"
