"""Tests for WazuhNormalizer — Feature 7.4: agent → dst_endpoint

Coverage:
  - agent.name  → dst_endpoint.hostname
  - agent.ip    → dst_endpoint.ip
  - agent.os.name → dst_endpoint.os_name
  - agent.id    → unmapped["agent_id"]
  - Fallback: agent.ip absent → data.dstip used for dst_endpoint.ip
  - Graceful handling of missing/empty agent block
  - Minimal alert (no agent key) normalizes without error
  - JSON serialization round-trip preserves all dst_endpoint fields
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
def agent_alert() -> dict:
    """Wazuh alert with a fully populated agent block including OS info."""
    return {
        "timestamp": "2026-02-19T08:30:00.000Z",
        "id": "1708331400.99999",
        "rule": {
            "id": "100500",
            "description": "Suspicious PowerShell Execution",
            "level": 10,
            "groups": ["process", "win_process"],
        },
        "agent": {
            "id": "007",
            "name": "WIN-SRV01",
            "ip": "10.1.2.3",
            "os": {
                "name": "Microsoft Windows Server 2022",
                "platform": "windows",
                "arch": "x86_64",
                "version": "10.0.20348",
            },
        },
        "data": {
            "srcip": "172.16.0.50",
            "dstuser": "Administrator",
        },
    }


# ---------------------------------------------------------------------------
# agent.name → dst_endpoint.hostname
# ---------------------------------------------------------------------------


def test_agent_name_maps_to_dst_endpoint_hostname(
    normalizer: WazuhNormalizer, agent_alert: dict
) -> None:
    event = normalizer.normalize(agent_alert)
    assert event.dst_endpoint.hostname == "WIN-SRV01"


def test_agent_name_missing_hostname_is_none(normalizer: WazuhNormalizer) -> None:
    alert = {"agent": {"id": "002", "ip": "192.168.0.1"}}
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.hostname is None


# ---------------------------------------------------------------------------
# agent.ip → dst_endpoint.ip
# ---------------------------------------------------------------------------


def test_agent_ip_maps_to_dst_endpoint_ip(
    normalizer: WazuhNormalizer, agent_alert: dict
) -> None:
    event = normalizer.normalize(agent_alert)
    assert event.dst_endpoint.ip == "10.1.2.3"


def test_agent_ip_absent_falls_back_to_data_dstip(normalizer: WazuhNormalizer) -> None:
    """When agent.ip is missing, data.dstip is used as dst_endpoint.ip."""
    alert = {
        "agent": {"id": "003", "name": "LINUX-HOST"},
        "data": {"dstip": "192.168.5.100"},
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.ip == "192.168.5.100"


def test_agent_ip_takes_precedence_over_data_dstip(normalizer: WazuhNormalizer) -> None:
    """agent.ip is preferred over data.dstip when both are present."""
    alert = {
        "agent": {"id": "004", "name": "HOST", "ip": "10.0.0.1"},
        "data": {"dstip": "10.0.0.99"},
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.ip == "10.0.0.1"


def test_both_agent_ip_and_dstip_absent_ip_is_none(normalizer: WazuhNormalizer) -> None:
    alert = {"agent": {"id": "005", "name": "HOST"}}
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.ip is None


# ---------------------------------------------------------------------------
# Feature 7.4: agent.os.name → dst_endpoint.os_name
# ---------------------------------------------------------------------------


def test_agent_os_name_maps_to_dst_endpoint_os_name(
    normalizer: WazuhNormalizer, agent_alert: dict
) -> None:
    """agent.os.name must appear as dst_endpoint.os_name."""
    event = normalizer.normalize(agent_alert)
    assert event.dst_endpoint.os_name == "Microsoft Windows Server 2022"


def test_agent_linux_os_name(normalizer: WazuhNormalizer) -> None:
    alert = {
        "agent": {
            "id": "010",
            "name": "UBUNTU-HOST",
            "ip": "10.2.0.5",
            "os": {"name": "Ubuntu 22.04.3 LTS", "platform": "ubuntu"},
        },
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.os_name == "Ubuntu 22.04.3 LTS"


def test_agent_os_absent_os_name_is_none(normalizer: WazuhNormalizer) -> None:
    """agent without an 'os' block → dst_endpoint.os_name is None."""
    alert = {
        "agent": {"id": "011", "name": "LEGACY-HOST", "ip": "10.3.0.1"},
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.os_name is None


def test_agent_os_name_key_absent_os_name_is_none(normalizer: WazuhNormalizer) -> None:
    """agent.os block present but without 'name' → dst_endpoint.os_name is None."""
    alert = {
        "agent": {
            "id": "012",
            "name": "HOST",
            "ip": "10.4.0.1",
            "os": {"platform": "windows", "arch": "x86_64"},
        },
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.os_name is None


# ---------------------------------------------------------------------------
# Feature 7.4: agent.id → unmapped["agent_id"]
# ---------------------------------------------------------------------------


def test_agent_id_stored_in_unmapped(
    normalizer: WazuhNormalizer, agent_alert: dict
) -> None:
    """agent.id must be preserved in unmapped for traceability."""
    event = normalizer.normalize(agent_alert)
    assert event.unmapped.get("agent_id") == "007"


def test_agent_id_absent_not_in_unmapped(normalizer: WazuhNormalizer) -> None:
    """When agent.id is missing, unmapped must not contain 'agent_id'."""
    alert = {"agent": {"name": "NOAGENTID-HOST", "ip": "10.5.0.1"}}
    event = normalizer.normalize(alert)
    assert "agent_id" not in event.unmapped


def test_agent_block_absent_no_agent_id_in_unmapped(normalizer: WazuhNormalizer) -> None:
    """Completely missing agent block → no agent_id in unmapped."""
    event = normalizer.normalize({"rule": {"level": 3}})
    assert "agent_id" not in event.unmapped


# ---------------------------------------------------------------------------
# Graceful degradation: no agent block at all
# ---------------------------------------------------------------------------


def test_missing_agent_block_does_not_raise(normalizer: WazuhNormalizer) -> None:
    event = normalizer.normalize({})
    assert event.dst_endpoint.hostname is None
    assert event.dst_endpoint.ip is None
    assert event.dst_endpoint.os_name is None


def test_empty_agent_block_produces_none_fields(normalizer: WazuhNormalizer) -> None:
    alert = {"agent": {}}
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.hostname is None
    assert event.dst_endpoint.ip is None
    assert event.dst_endpoint.os_name is None


# ---------------------------------------------------------------------------
# JSON serialization round-trip
# ---------------------------------------------------------------------------


def test_dst_endpoint_os_name_in_json_dump(
    normalizer: WazuhNormalizer, agent_alert: dict
) -> None:
    """model_dump(mode='json') must include os_name in dst_endpoint."""
    event = normalizer.normalize(agent_alert)
    dumped = event.model_dump(mode="json")
    assert dumped["dst_endpoint"]["os_name"] == "Microsoft Windows Server 2022"
    assert dumped["dst_endpoint"]["hostname"] == "WIN-SRV01"
    assert dumped["dst_endpoint"]["ip"] == "10.1.2.3"


def test_agent_id_in_unmapped_json_serializable(
    normalizer: WazuhNormalizer, agent_alert: dict
) -> None:
    """unmapped["agent_id"] must survive JSON serialization."""
    event = normalizer.normalize(agent_alert)
    dumped = event.model_dump(mode="json")
    json.dumps(dumped)  # must not raise
    assert dumped["unmapped"]["agent_id"] == "007"


def test_full_agent_alert_json_round_trip(
    normalizer: WazuhNormalizer, agent_alert: dict
) -> None:
    """Complete normalization + JSON dump must not raise for a fully populated alert."""
    event = normalizer.normalize(agent_alert)
    dumped = event.model_dump(mode="json")
    serialized = json.dumps(dumped)
    restored = json.loads(serialized)
    assert restored["dst_endpoint"]["hostname"] == "WIN-SRV01"
    assert restored["dst_endpoint"]["ip"] == "10.1.2.3"
    assert restored["dst_endpoint"]["os_name"] == "Microsoft Windows Server 2022"
    assert restored["unmapped"]["agent_id"] == "007"
    assert restored["src_endpoint"]["ip"] == "172.16.0.50"


# ---------------------------------------------------------------------------
# End-to-end: full pipeline with all agent fields
# ---------------------------------------------------------------------------


def test_normalize_all_agent_fields_end_to_end(normalizer: WazuhNormalizer) -> None:
    """Full alert with all agent fields produces the correct dst_endpoint."""
    alert = {
        "timestamp": "2026-02-20T12:00:00.000Z",
        "id": "alert-e2e-001",
        "rule": {
            "id": "200001",
            "description": "Detected lateral movement via PsExec",
            "level": 11,
            "groups": ["network"],
            "mitre": {
                "id": ["T1021.002"],
                "tactic": ["lateral-movement"],
                "technique": ["Remote Services: SMB/Windows Admin Shares"],
            },
        },
        "agent": {
            "id": "042",
            "name": "WIN-WORKSTATION",
            "ip": "192.168.10.42",
            "os": {
                "name": "Microsoft Windows 10 Enterprise",
                "platform": "windows",
                "arch": "x86_64",
                "version": "10.0.19045",
            },
        },
        "data": {
            "srcip": "192.168.10.5",
            "dstuser": "DOMAIN\\svcaccount",
        },
    }
    event = normalizer.normalize(alert)

    # dst_endpoint fields (Feature 7.4)
    assert event.dst_endpoint.hostname == "WIN-WORKSTATION"
    assert event.dst_endpoint.ip == "192.168.10.42"
    assert event.dst_endpoint.os_name == "Microsoft Windows 10 Enterprise"

    # unmapped.agent_id (Feature 7.4)
    assert event.unmapped["agent_id"] == "042"

    # src_endpoint (unchanged)
    assert event.src_endpoint.ip == "192.168.10.5"

    # attacks[] (Feature 7.3)
    assert len(event.finding_info.attacks) == 1
    attack = event.finding_info.attacks[0]
    assert attack.tactic.uid == "TA0008"
    assert attack.technique.uid == "T1021.002"
    assert attack.technique.sub_technique == "002"

    # severity (Feature 7.2)
    assert event.severity_id == 4  # level 11 → High
