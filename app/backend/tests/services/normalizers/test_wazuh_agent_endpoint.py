"""Tests for WazuhNormalizer — Feature 7.4: agent → dst_endpoint

Coverage:
  - Endpoint.uid field exists on the OCSF model
  - agent.id → dst_endpoint.uid (primary mapping)
  - agent.name → dst_endpoint.hostname
  - agent.ip → dst_endpoint.ip
  - agent.os.name → dst_endpoint.os_name
  - agent.ip takes priority over data.dstip when both present
  - agent.ip absent → dst_endpoint.ip falls back to data.dstip
  - agent.id no longer stored in unmapped (moved to dst_endpoint.uid)
  - missing agent block produces empty/None dst_endpoint fields (no errors)
  - agent with no OS block → os_name is None
  - agent with no id → uid is None
  - full round-trip: model_dump(mode='json') includes uid cleanly
"""

from __future__ import annotations

import json
import pytest

from app.services.normalizers.ocsf import Endpoint
from app.services.normalizers.wazuh import WazuhNormalizer


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def normalizer() -> WazuhNormalizer:
    return WazuhNormalizer()


@pytest.fixture
def full_agent_alert() -> dict:
    """Wazuh alert with a fully-populated agent block."""
    return {
        "timestamp": "2026-02-20T10:00:00.000Z",
        "id": "1708331400.99999",
        "rule": {
            "id": "100100",
            "description": "Suspicious activity detected",
            "level": 10,
        },
        "agent": {
            "id": "042",
            "name": "WIN-DC01",
            "ip": "192.168.10.42",
            "os": {
                "name": "Windows Server 2022",
                "version": "10.0.20348",
            },
        },
        "data": {
            "srcip": "10.0.0.1",
            "dstip": "192.168.10.99",  # should be overridden by agent.ip
        },
    }


@pytest.fixture
def minimal_alert() -> dict:
    """Wazuh alert with bare-minimum fields (no agent block)."""
    return {
        "rule": {"level": 5, "description": "Minimal alert"},
    }


# ---------------------------------------------------------------------------
# Endpoint model — uid field existence
# ---------------------------------------------------------------------------


def test_endpoint_has_uid_field() -> None:
    """Endpoint must expose a uid field (added for Feature 7.4)."""
    ep = Endpoint(uid="001", hostname="host1", ip="1.2.3.4")
    assert ep.uid == "001"


def test_endpoint_uid_defaults_to_none() -> None:
    """uid must default to None when not provided."""
    ep = Endpoint(hostname="host1")
    assert ep.uid is None


# ---------------------------------------------------------------------------
# normalize() — agent.id → dst_endpoint.uid
# ---------------------------------------------------------------------------


def test_agent_id_mapped_to_dst_endpoint_uid(
    normalizer: WazuhNormalizer, full_agent_alert: dict
) -> None:
    """agent.id must appear as dst_endpoint.uid (primary acceptance criterion)."""
    event = normalizer.normalize(full_agent_alert)
    assert event.dst_endpoint.uid == "042"


def test_agent_id_none_when_agent_has_no_id(normalizer: WazuhNormalizer) -> None:
    """When agent block has no id, dst_endpoint.uid must be None."""
    alert = {
        "rule": {"level": 5},
        "agent": {"name": "linux-box", "ip": "10.0.0.5"},
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.uid is None


def test_agent_id_none_when_no_agent_block(
    normalizer: WazuhNormalizer, minimal_alert: dict
) -> None:
    """Missing agent block entirely → dst_endpoint.uid is None (no exception)."""
    event = normalizer.normalize(minimal_alert)
    assert event.dst_endpoint.uid is None


# ---------------------------------------------------------------------------
# normalize() — agent.name → dst_endpoint.hostname
# ---------------------------------------------------------------------------


def test_agent_name_mapped_to_dst_endpoint_hostname(
    normalizer: WazuhNormalizer, full_agent_alert: dict
) -> None:
    event = normalizer.normalize(full_agent_alert)
    assert event.dst_endpoint.hostname == "WIN-DC01"


def test_agent_name_none_when_absent(normalizer: WazuhNormalizer) -> None:
    alert = {"rule": {"level": 5}, "agent": {"id": "001", "ip": "10.0.0.5"}}
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.hostname is None


# ---------------------------------------------------------------------------
# normalize() — agent.ip → dst_endpoint.ip (with fallback to data.dstip)
# ---------------------------------------------------------------------------


def test_agent_ip_mapped_to_dst_endpoint_ip(
    normalizer: WazuhNormalizer, full_agent_alert: dict
) -> None:
    """agent.ip must populate dst_endpoint.ip."""
    event = normalizer.normalize(full_agent_alert)
    assert event.dst_endpoint.ip == "192.168.10.42"


def test_agent_ip_takes_priority_over_data_dstip(normalizer: WazuhNormalizer) -> None:
    """When both agent.ip and data.dstip are present, agent.ip wins."""
    alert = {
        "rule": {"level": 5},
        "agent": {"id": "001", "ip": "192.168.1.10"},
        "data": {"dstip": "10.0.0.99"},
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.ip == "192.168.1.10"


def test_data_dstip_used_as_fallback_when_agent_ip_absent(
    normalizer: WazuhNormalizer,
) -> None:
    """When agent.ip is absent, data.dstip is used as the fallback IP."""
    alert = {
        "rule": {"level": 5},
        "agent": {"id": "002", "name": "linux-server"},
        "data": {"dstip": "10.0.0.99"},
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.ip == "10.0.0.99"


def test_dst_endpoint_ip_none_when_both_absent(normalizer: WazuhNormalizer) -> None:
    """No agent.ip and no data.dstip → dst_endpoint.ip is None."""
    alert = {"rule": {"level": 5}, "agent": {"id": "003", "name": "bare-agent"}}
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.ip is None


# ---------------------------------------------------------------------------
# normalize() — agent.os.name → dst_endpoint.os_name
# ---------------------------------------------------------------------------


def test_agent_os_name_mapped_to_dst_endpoint_os_name(
    normalizer: WazuhNormalizer, full_agent_alert: dict
) -> None:
    event = normalizer.normalize(full_agent_alert)
    assert event.dst_endpoint.os_name == "Windows Server 2022"


def test_agent_os_name_none_when_no_os_block(normalizer: WazuhNormalizer) -> None:
    """Agent without an os sub-object → os_name is None (no exception)."""
    alert = {
        "rule": {"level": 5},
        "agent": {"id": "010", "name": "bare-agent", "ip": "10.10.10.10"},
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.os_name is None


def test_agent_os_name_none_when_os_block_empty(normalizer: WazuhNormalizer) -> None:
    """Agent with an empty os block → os_name is None."""
    alert = {
        "rule": {"level": 5},
        "agent": {"id": "011", "name": "bare-agent", "os": {}},
    }
    event = normalizer.normalize(alert)
    assert event.dst_endpoint.os_name is None


# ---------------------------------------------------------------------------
# normalize() — agent.id no longer in unmapped
# ---------------------------------------------------------------------------


def test_agent_id_not_in_unmapped(
    normalizer: WazuhNormalizer, full_agent_alert: dict
) -> None:
    """agent.id must NOT appear in unmapped now that it's in dst_endpoint.uid."""
    event = normalizer.normalize(full_agent_alert)
    assert "agent_id" not in event.unmapped


def test_unmapped_empty_for_standard_alert(
    normalizer: WazuhNormalizer, full_agent_alert: dict
) -> None:
    """The unmapped dict should be empty for a standard Wazuh alert."""
    event = normalizer.normalize(full_agent_alert)
    assert event.unmapped == {}


# ---------------------------------------------------------------------------
# normalize() — full dst_endpoint mapping in one assertion
# ---------------------------------------------------------------------------


def test_full_dst_endpoint_mapping(
    normalizer: WazuhNormalizer, full_agent_alert: dict
) -> None:
    """All four agent fields must be present on dst_endpoint simultaneously."""
    event = normalizer.normalize(full_agent_alert)
    ep = event.dst_endpoint
    assert ep.uid == "042"
    assert ep.hostname == "WIN-DC01"
    assert ep.ip == "192.168.10.42"
    assert ep.os_name == "Windows Server 2022"


# ---------------------------------------------------------------------------
# normalize() — serialization
# ---------------------------------------------------------------------------


def test_dst_endpoint_uid_in_model_dump(
    normalizer: WazuhNormalizer, full_agent_alert: dict
) -> None:
    """model_dump(mode='json') must include dst_endpoint.uid."""
    event = normalizer.normalize(full_agent_alert)
    dumped = event.model_dump(mode="json")
    assert dumped["dst_endpoint"]["uid"] == "042"


def test_dst_endpoint_model_dump_json_serializable(
    normalizer: WazuhNormalizer, full_agent_alert: dict
) -> None:
    """Full event must remain JSON-serializable after the uid addition."""
    event = normalizer.normalize(full_agent_alert)
    dumped = event.model_dump(mode="json")
    json.dumps(dumped)  # must not raise


def test_dst_endpoint_uid_none_in_model_dump_when_absent(
    normalizer: WazuhNormalizer,
) -> None:
    """uid=None must serialize cleanly (not raise, not omit key)."""
    alert = {"rule": {"level": 5}, "agent": {"name": "no-id-agent"}}
    event = normalizer.normalize(alert)
    dumped = event.model_dump(mode="json")
    assert "uid" in dumped["dst_endpoint"]
    assert dumped["dst_endpoint"]["uid"] is None
