"""Tests for WazuhNormalizer — Feature 7.5: Windows event data → process

Coverage:
  - process.cmd_line    from win.eventdata.commandLine / CommandLine
  - process.path        from win.eventdata.image / Image
  - process.pid         from win.eventdata.processId / ProcessId (str → int coercion)
  - process.parent_pid  from win.eventdata.parentProcessId / ParentProcessId
  - process.name        derived from image path (basename extraction)
  - process.parent_name derived from parentImage / ParentImage (basename extraction)
  - process.hash_sha256 parsed from hashes / Hashes composite string
  - _parse_sha256()     helper: Sysmon composite hash → SHA256
  - Case variants: camelCase (Sysmon) vs PascalCase (WEC)
  - Non-Windows alerts: all process fields default to None
  - Empty win.eventdata: process fields are None (no exception)
  - JSON serialization round-trip preserves all process fields
"""

from __future__ import annotations

import json

import pytest

from app.services.normalizers.wazuh import WazuhNormalizer


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def normalizer() -> WazuhNormalizer:
    return WazuhNormalizer()


@pytest.fixture
def sysmon_process_alert() -> dict:
    """Realistic Wazuh alert from a Sysmon Event ID 1 (Process Create).

    Uses camelCase field names as emitted by most Wazuh+Sysmon setups.
    """
    return {
        "timestamp": "2026-02-20T09:15:00.000Z",
        "id": "sysmon-proc-001",
        "rule": {
            "id": "61603",
            "description": "Sysmon - Event 1: Process creation",
            "level": 5,
            "groups": ["process", "win_process", "sysmon"],
            "mitre": {
                "id": ["T1059.001"],
                "tactic": ["execution"],
                "technique": ["Command and Scripting Interpreter: PowerShell"],
            },
        },
        "agent": {
            "id": "015",
            "name": "WIN-WORKSTATION",
            "ip": "10.10.10.15",
            "os": {"name": "Microsoft Windows 10 Enterprise"},
        },
        "data": {
            "srcip": "10.10.10.1",
            "dstuser": "CORP\\jdoe",
            "win": {
                "eventdata": {
                    "commandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Tools\\recon.ps1",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "processId": "4892",
                    "parentProcessId": "2340",
                    "parentImage": "C:\\Windows\\Explorer.EXE",
                    "hashes": "SHA1=da39a3ee5e6b4b0d3255bfef95601890afd80709,MD5=7353f60b1739074eb17c5f4dddefe239,SHA256=de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3,IMPHASH=f34d5f2d4577ed6d9ceec516c1f5a744",
                },
            },
        },
    }


@pytest.fixture
def wec_process_alert() -> dict:
    """Wazuh alert from a Windows Event Collector (WEC) using PascalCase fields."""
    return {
        "timestamp": "2026-02-20T09:20:00.000Z",
        "id": "wec-proc-001",
        "rule": {
            "id": "60103",
            "description": "Windows process creation via WEC",
            "level": 6,
            "groups": ["process", "win_process"],
        },
        "agent": {
            "id": "020",
            "name": "WIN-SERVER",
            "ip": "192.168.1.20",
        },
        "data": {
            "win": {
                "eventdata": {
                    "CommandLine": "cmd.exe /c whoami",
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "ProcessId": "9876",
                    "ParentProcessId": "5432",
                    "ParentImage": "C:\\Windows\\System32\\services.exe",
                    "Hashes": "MD5=abc123,SHA256=6dcd4ce23d88e2ee9568ba546c007c63124d279b,IMPHASH=deadbeef",
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# _parse_sha256() — unit tests for the hash parsing helper
# ---------------------------------------------------------------------------


class TestParseSha256:
    """Unit tests for _parse_sha256()."""

    def test_extracts_sha256_from_sysmon_composite(self, normalizer: WazuhNormalizer) -> None:
        """Standard Sysmon hash string: SHA256 is present among others."""
        hashes = "SHA1=da39a3ee,MD5=d41d8cd9,SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,IMPHASH=00000000"
        result = normalizer._parse_sha256(hashes)
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_extracts_sha256_case_insensitive_prefix(self, normalizer: WazuhNormalizer) -> None:
        """SHA256= prefix matching must be case-insensitive."""
        hashes = "sha256=abc123def456"
        result = normalizer._parse_sha256(hashes)
        assert result == "abc123def456"

    def test_extracts_sha256_only_entry(self, normalizer: WazuhNormalizer) -> None:
        """Single SHA256 entry without other hash types."""
        hashes = "SHA256=6dcd4ce23d88e2ee9568ba546c007c63124d279b"
        result = normalizer._parse_sha256(hashes)
        assert result == "6dcd4ce23d88e2ee9568ba546c007c63124d279b"

    def test_returns_none_when_sha256_absent(self, normalizer: WazuhNormalizer) -> None:
        """Hash string without SHA256 returns None."""
        hashes = "SHA1=da39a3ee,MD5=d41d8cd9,IMPHASH=00000000"
        result = normalizer._parse_sha256(hashes)
        assert result is None

    def test_returns_none_for_none_input(self, normalizer: WazuhNormalizer) -> None:
        assert normalizer._parse_sha256(None) is None

    def test_returns_none_for_empty_string(self, normalizer: WazuhNormalizer) -> None:
        assert normalizer._parse_sha256("") is None

    def test_handles_spaces_around_entries(self, normalizer: WazuhNormalizer) -> None:
        """Hash entries may have surrounding whitespace."""
        hashes = "MD5=abc , SHA256=deadbeef , IMPHASH=0"
        result = normalizer._parse_sha256(hashes)
        assert result == "deadbeef"

    def test_sha256_first_in_string(self, normalizer: WazuhNormalizer) -> None:
        """SHA256 appearing first in the hash string is extracted correctly."""
        hashes = "SHA256=firsthash,MD5=secondhash"
        result = normalizer._parse_sha256(hashes)
        assert result == "firsthash"


# ---------------------------------------------------------------------------
# process.cmd_line — commandLine / CommandLine
# ---------------------------------------------------------------------------


def test_process_cmd_line_from_sysmon_camelcase(
    normalizer: WazuhNormalizer, sysmon_process_alert: dict
) -> None:
    event = normalizer.normalize(sysmon_process_alert)
    assert event.process.cmd_line == (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Tools\\recon.ps1"
    )


def test_process_cmd_line_from_wec_pascalcase(
    normalizer: WazuhNormalizer, wec_process_alert: dict
) -> None:
    event = normalizer.normalize(wec_process_alert)
    assert event.process.cmd_line == "cmd.exe /c whoami"


def test_process_cmd_line_none_when_absent(normalizer: WazuhNormalizer) -> None:
    alert = {"data": {"win": {"eventdata": {"processId": "100"}}}}
    event = normalizer.normalize(alert)
    assert event.process.cmd_line is None


# ---------------------------------------------------------------------------
# process.path — image / Image
# ---------------------------------------------------------------------------


def test_process_path_from_sysmon_camelcase(
    normalizer: WazuhNormalizer, sysmon_process_alert: dict
) -> None:
    event = normalizer.normalize(sysmon_process_alert)
    assert event.process.path == (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )


def test_process_path_from_wec_pascalcase(
    normalizer: WazuhNormalizer, wec_process_alert: dict
) -> None:
    event = normalizer.normalize(wec_process_alert)
    assert event.process.path == "C:\\Windows\\System32\\cmd.exe"


def test_process_path_none_when_absent(normalizer: WazuhNormalizer) -> None:
    alert = {"data": {"win": {"eventdata": {}}}}
    event = normalizer.normalize(alert)
    assert event.process.path is None


# ---------------------------------------------------------------------------
# process.name — basename of image / Image
# ---------------------------------------------------------------------------


def test_process_name_derived_from_sysmon_image(
    normalizer: WazuhNormalizer, sysmon_process_alert: dict
) -> None:
    event = normalizer.normalize(sysmon_process_alert)
    assert event.process.name == "powershell.exe"


def test_process_name_derived_from_wec_image(
    normalizer: WazuhNormalizer, wec_process_alert: dict
) -> None:
    event = normalizer.normalize(wec_process_alert)
    assert event.process.name == "cmd.exe"


def test_process_name_none_when_image_absent(normalizer: WazuhNormalizer) -> None:
    alert = {"data": {"win": {"eventdata": {"commandLine": "notepad"}}}}
    event = normalizer.normalize(alert)
    assert event.process.name is None


# ---------------------------------------------------------------------------
# process.pid — processId / ProcessId (string → int coercion)
# ---------------------------------------------------------------------------


def test_process_pid_from_sysmon_string(
    normalizer: WazuhNormalizer, sysmon_process_alert: dict
) -> None:
    event = normalizer.normalize(sysmon_process_alert)
    assert event.process.pid == 4892


def test_process_pid_from_wec_string(
    normalizer: WazuhNormalizer, wec_process_alert: dict
) -> None:
    event = normalizer.normalize(wec_process_alert)
    assert event.process.pid == 9876


def test_process_pid_as_integer(normalizer: WazuhNormalizer) -> None:
    """processId can arrive as a Python int (not just string)."""
    alert = {"data": {"win": {"eventdata": {"processId": 1234}}}}
    event = normalizer.normalize(alert)
    assert event.process.pid == 1234


def test_process_pid_none_when_absent(normalizer: WazuhNormalizer) -> None:
    alert = {"data": {"win": {"eventdata": {}}}}
    event = normalizer.normalize(alert)
    assert event.process.pid is None


def test_process_pid_none_for_non_numeric(normalizer: WazuhNormalizer) -> None:
    """Non-numeric processId must not raise — returns None."""
    alert = {"data": {"win": {"eventdata": {"processId": "N/A"}}}}
    event = normalizer.normalize(alert)
    assert event.process.pid is None


# ---------------------------------------------------------------------------
# process.parent_pid — parentProcessId / ParentProcessId
# ---------------------------------------------------------------------------


def test_process_parent_pid_from_sysmon(
    normalizer: WazuhNormalizer, sysmon_process_alert: dict
) -> None:
    event = normalizer.normalize(sysmon_process_alert)
    assert event.process.parent_pid == 2340


def test_process_parent_pid_from_wec(
    normalizer: WazuhNormalizer, wec_process_alert: dict
) -> None:
    event = normalizer.normalize(wec_process_alert)
    assert event.process.parent_pid == 5432


def test_process_parent_pid_none_when_absent(normalizer: WazuhNormalizer) -> None:
    alert = {"data": {"win": {"eventdata": {"processId": "100"}}}}
    event = normalizer.normalize(alert)
    assert event.process.parent_pid is None


# ---------------------------------------------------------------------------
# Feature 7.5: process.parent_name — basename of parentImage / ParentImage
# ---------------------------------------------------------------------------


def test_process_parent_name_from_sysmon_camelcase(
    normalizer: WazuhNormalizer, sysmon_process_alert: dict
) -> None:
    """parentImage field (Sysmon) → process.parent_name (basename)."""
    event = normalizer.normalize(sysmon_process_alert)
    assert event.process.parent_name == "Explorer.EXE"


def test_process_parent_name_from_wec_pascalcase(
    normalizer: WazuhNormalizer, wec_process_alert: dict
) -> None:
    """ParentImage field (WEC) → process.parent_name (basename)."""
    event = normalizer.normalize(wec_process_alert)
    assert event.process.parent_name == "services.exe"


def test_process_parent_name_linux_path(normalizer: WazuhNormalizer) -> None:
    """Parent image paths with forward slashes also produce correct basename."""
    alert = {"data": {"win": {"eventdata": {"parentImage": "/usr/bin/bash"}}}}
    event = normalizer.normalize(alert)
    assert event.process.parent_name == "bash"


def test_process_parent_name_none_when_parent_image_absent(normalizer: WazuhNormalizer) -> None:
    """No parentImage/ParentImage → process.parent_name is None."""
    alert = {
        "data": {
            "win": {
                "eventdata": {
                    "image": "C:\\Windows\\notepad.exe",
                    "processId": "100",
                },
            },
        },
    }
    event = normalizer.normalize(alert)
    assert event.process.parent_name is None


# ---------------------------------------------------------------------------
# Feature 7.5: process.hash_sha256 — parsed from hashes / Hashes
# ---------------------------------------------------------------------------


def test_process_hash_sha256_from_sysmon_hashes(
    normalizer: WazuhNormalizer, sysmon_process_alert: dict
) -> None:
    """Sysmon composite hash string → process.hash_sha256 extracted correctly."""
    event = normalizer.normalize(sysmon_process_alert)
    assert event.process.hash_sha256 == "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"


def test_process_hash_sha256_from_wec_hashes(
    normalizer: WazuhNormalizer, wec_process_alert: dict
) -> None:
    """WEC PascalCase Hashes field → process.hash_sha256 extracted correctly."""
    event = normalizer.normalize(wec_process_alert)
    assert event.process.hash_sha256 == "6dcd4ce23d88e2ee9568ba546c007c63124d279b"


def test_process_hash_sha256_none_when_hashes_absent(normalizer: WazuhNormalizer) -> None:
    """No hashes field → process.hash_sha256 is None."""
    alert = {
        "data": {
            "win": {
                "eventdata": {
                    "image": "C:\\Windows\\notepad.exe",
                    "processId": "100",
                },
            },
        },
    }
    event = normalizer.normalize(alert)
    assert event.process.hash_sha256 is None


def test_process_hash_sha256_none_when_no_sha256_in_hashes(normalizer: WazuhNormalizer) -> None:
    """Hash string without SHA256 → process.hash_sha256 is None."""
    alert = {
        "data": {
            "win": {
                "eventdata": {
                    "hashes": "SHA1=da39a3ee,MD5=d41d8cd9,IMPHASH=00000000",
                },
            },
        },
    }
    event = normalizer.normalize(alert)
    assert event.process.hash_sha256 is None


# ---------------------------------------------------------------------------
# Non-Windows alerts: no win.eventdata → all process fields are None
# ---------------------------------------------------------------------------


def test_linux_alert_process_all_none(normalizer: WazuhNormalizer) -> None:
    """Linux alerts without win.eventdata must not raise; all process fields are None."""
    alert = {
        "rule": {
            "level": 7,
            "description": "SSH brute force",
            "groups": ["authentication"],
        },
        "agent": {"name": "linux-host", "ip": "10.0.0.1"},
        "data": {"srcip": "172.16.0.5", "srcuser": "root"},
    }
    event = normalizer.normalize(alert)
    assert event.process.cmd_line is None
    assert event.process.path is None
    assert event.process.pid is None
    assert event.process.parent_pid is None
    assert event.process.name is None
    assert event.process.parent_name is None
    assert event.process.hash_sha256 is None


def test_empty_win_eventdata_no_exception(normalizer: WazuhNormalizer) -> None:
    """Empty win.eventdata dict must normalize without error."""
    alert = {"data": {"win": {"eventdata": {}}}}
    event = normalizer.normalize(alert)
    assert event.process.cmd_line is None
    assert event.process.pid is None
    assert event.process.hash_sha256 is None


def test_missing_data_block_no_exception(normalizer: WazuhNormalizer) -> None:
    """Alert with no data block at all must normalize without error."""
    alert = {"rule": {"level": 5, "description": "test"}}
    event = normalizer.normalize(alert)
    assert event.process.cmd_line is None
    assert event.process.name is None
    assert event.process.parent_name is None
    assert event.process.hash_sha256 is None


# ---------------------------------------------------------------------------
# Full round-trip: all process fields extracted together
# ---------------------------------------------------------------------------


def test_all_process_fields_populated_sysmon(
    normalizer: WazuhNormalizer, sysmon_process_alert: dict
) -> None:
    """All six process fields must be populated simultaneously from a Sysmon alert."""
    event = normalizer.normalize(sysmon_process_alert)
    p = event.process
    assert p.cmd_line is not None
    assert p.path is not None
    assert p.pid == 4892
    assert p.parent_pid == 2340
    assert p.name == "powershell.exe"
    assert p.parent_name == "Explorer.EXE"
    assert p.hash_sha256 == "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"


def test_all_process_fields_populated_wec(
    normalizer: WazuhNormalizer, wec_process_alert: dict
) -> None:
    """All six process fields must be populated simultaneously from a WEC alert."""
    event = normalizer.normalize(wec_process_alert)
    p = event.process
    assert p.cmd_line == "cmd.exe /c whoami"
    assert p.path == "C:\\Windows\\System32\\cmd.exe"
    assert p.pid == 9876
    assert p.parent_pid == 5432
    assert p.name == "cmd.exe"
    assert p.parent_name == "services.exe"
    assert p.hash_sha256 == "6dcd4ce23d88e2ee9568ba546c007c63124d279b"


# ---------------------------------------------------------------------------
# JSON serialization round-trip
# ---------------------------------------------------------------------------


def test_process_json_serializable_sysmon(
    normalizer: WazuhNormalizer, sysmon_process_alert: dict
) -> None:
    """model_dump(mode='json') must not raise and include all process fields."""
    event = normalizer.normalize(sysmon_process_alert)
    dumped = event.model_dump(mode="json")
    json.dumps(dumped)  # must not raise
    p = dumped["process"]
    assert p["name"] == "powershell.exe"
    assert p["parent_name"] == "Explorer.EXE"
    assert p["hash_sha256"] == "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
    assert p["pid"] == 4892
    assert p["parent_pid"] == 2340


def test_process_json_round_trip_wec(
    normalizer: WazuhNormalizer, wec_process_alert: dict
) -> None:
    """Full serialization + deserialization preserves all process fields."""
    event = normalizer.normalize(wec_process_alert)
    dumped = event.model_dump(mode="json")
    serialized = json.dumps(dumped)
    restored = json.loads(serialized)
    p = restored["process"]
    assert p["name"] == "cmd.exe"
    assert p["parent_name"] == "services.exe"
    assert p["hash_sha256"] == "6dcd4ce23d88e2ee9568ba546c007c63124d279b"


def test_process_fields_none_serialize_cleanly(normalizer: WazuhNormalizer) -> None:
    """None process fields must serialize to null (not omit the key)."""
    event = normalizer.normalize({"rule": {"level": 5}})
    dumped = event.model_dump(mode="json")
    p = dumped["process"]
    assert "parent_name" in p
    assert p["parent_name"] is None
    assert "hash_sha256" in p
    assert p["hash_sha256"] is None


# ---------------------------------------------------------------------------
# End-to-end: Sysmon mimikatz-style alert with all features combined
# ---------------------------------------------------------------------------


def test_end_to_end_mimikatz_alert(normalizer: WazuhNormalizer) -> None:
    """Full Wazuh alert combining MITRE, agent, and process fields (Feature 7.5)."""
    alert = {
        "timestamp": "2026-02-20T11:00:00.000Z",
        "id": "e2e-mimikatz-001",
        "rule": {
            "id": "100234",
            "description": "LSASS Memory Dump via mimikatz",
            "level": 14,
            "groups": ["process", "win_process"],
            "mitre": {
                "id": ["T1003.001"],
                "tactic": ["credential-access"],
                "technique": ["OS Credential Dumping: LSASS Memory"],
            },
        },
        "agent": {
            "id": "001",
            "name": "WIN-DC01",
            "ip": "192.168.1.10",
            "os": {"name": "Microsoft Windows Server 2022"},
        },
        "data": {
            "srcip": "10.0.0.5",
            "dstuser": "SYSTEM",
            "win": {
                "eventdata": {
                    "commandLine": "mimikatz.exe sekurlsa::logonpasswords",
                    "image": "C:\\Users\\attacker\\mimikatz\\mimikatz.exe",
                    "processId": "3456",
                    "parentProcessId": "1234",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "hashes": (
                        "SHA1=da39a3ee5e6b4b0d3255bfef95601890afd80709,"
                        "MD5=7353f60b1739074eb17c5f4dddefe239,"
                        "SHA256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08,"
                        "IMPHASH=f34d5f2d4577ed6d9ceec516c1f5a744"
                    ),
                },
            },
        },
    }
    event = normalizer.normalize(alert)

    # Severity: level 14 → Critical (5)
    assert event.severity_id == 5

    # Agent → dst_endpoint (Feature 7.4)
    assert event.dst_endpoint.uid == "001"
    assert event.dst_endpoint.hostname == "WIN-DC01"
    assert event.dst_endpoint.os_name == "Microsoft Windows Server 2022"

    # MITRE → attacks[] (Feature 7.3)
    assert len(event.finding_info.attacks) == 1
    attack = event.finding_info.attacks[0]
    assert attack.tactic.uid == "TA0006"
    assert attack.technique.uid == "T1003.001"
    assert attack.technique.sub_technique == "001"

    # Windows event data → process (Feature 7.5)
    p = event.process
    assert p.cmd_line == "mimikatz.exe sekurlsa::logonpasswords"
    assert p.path == "C:\\Users\\attacker\\mimikatz\\mimikatz.exe"
    assert p.pid == 3456
    assert p.parent_pid == 1234
    assert p.name == "mimikatz.exe"
    assert p.parent_name == "cmd.exe"
    assert p.hash_sha256 == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
