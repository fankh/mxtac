"""Tests for SuricataNormalizer — Feature 28.13

Coverage:
  - SURICATA_SEV_MAP constant: all four documented severity values
  - Acceptance criterion: severity 1 → severity_id 4 (High)
  - _normalize_alert(): full alert fields → SecurityFinding (class_uid=2001)
  - _normalize_alert(): severity 1→4, 2→3, 3→2, 4→1, unknown→default 3
  - _normalize_alert(): ATT&CK technique extraction from alert.metadata
  - _normalize_alert(): missing optional fields produce sensible defaults
  - _normalize_dns(): dns event → DNS Activity (class_uid=4003)
  - _normalize_network(): http/tls events → Network Activity (class_uid=4001)
  - normalize(): routing dispatches by event_type
  - normalize(): unknown event_type falls back to NetworkActivity
  - _parse_time(): ISO 8601 with +0000 suffix, None, invalid string
  - _build_attacks(): single technique, multiple techniques, empty metadata
  - Full round-trip: realistic Suricata alert → OCSFEvent with all fields
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.normalizers.suricata import (
    SURICATA_SEV_MAP,
    SuricataNormalizer,
)
from app.services.normalizers.ocsf import OCSFCategory, OCSFClass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def normalizer() -> SuricataNormalizer:
    return SuricataNormalizer()


@pytest.fixture
def alert_event() -> dict:
    """Realistic Suricata EVE JSON alert event (severity 1 = high)."""
    return {
        "timestamp": "2026-02-19T08:30:00.123456+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.200",
        "src_port": 4444,
        "dest_ip": "10.0.0.5",
        "dest_port": 443,
        "proto": "TCP",
        "flow_id": 1234567890,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2030358,
            "rev": 1,
            "signature": "ET MALWARE CobaltStrike Beacon Activity",
            "category": "A Network Trojan was detected",
            "severity": 1,
            "metadata": {
                "mitre_technique_id": ["T1071.001"],
            },
        },
    }


@pytest.fixture
def dns_event() -> dict:
    """Realistic Suricata EVE JSON dns event."""
    return {
        "timestamp": "2026-02-19T09:00:00.000000+0000",
        "event_type": "dns",
        "src_ip": "10.0.0.5",
        "dest_ip": "8.8.8.8",
        "flow_id": 9876543210,
        "dns": {
            "rrname": "evil.example.com",
            "rrtype": "A",
            "answers": ["1.2.3.4"],
            "rcode": "NOERROR",
        },
    }


@pytest.fixture
def http_event() -> dict:
    """Realistic Suricata EVE JSON http event."""
    return {
        "timestamp": "2026-02-19T10:00:00.000000+0000",
        "event_type": "http",
        "src_ip": "10.0.0.20",
        "src_port": 55001,
        "dest_ip": "203.0.113.1",
        "dest_port": 80,
        "flow_id": 1111111111,
        "http": {
            "hostname": "www.example.com",
            "url": "/path/to/resource",
            "http_method": "GET",
            "status": 200,
        },
    }


@pytest.fixture
def tls_event() -> dict:
    """Realistic Suricata EVE JSON tls event."""
    return {
        "timestamp": "2026-02-19T11:00:00.000000+0000",
        "event_type": "tls",
        "src_ip": "10.0.0.5",
        "src_port": 55002,
        "dest_ip": "203.0.113.50",
        "dest_port": 443,
        "flow_id": 2222222222,
        "tls": {
            "sni": "secure.example.com",
            "version": "TLS 1.3",
        },
    }


# ---------------------------------------------------------------------------
# SURICATA_SEV_MAP constant
# ---------------------------------------------------------------------------


def test_suricata_sev_map_has_all_four_keys() -> None:
    """All four documented Suricata severity levels must be present."""
    assert set(SURICATA_SEV_MAP.keys()) == {1, 2, 3, 4}


@pytest.mark.parametrize("suricata_sev,expected_ocsf", [
    (1, 4),   # High → OCSF High
    (2, 3),   # Medium → OCSF Medium
    (3, 2),   # Low → OCSF Low
    (4, 1),   # Informational → OCSF Informational
])
def test_suricata_sev_map_values(suricata_sev: int, expected_ocsf: int) -> None:
    """Each Suricata severity maps to the correct OCSF severity_id."""
    assert SURICATA_SEV_MAP[suricata_sev] == expected_ocsf


def test_suricata_sev_map_severity_1_is_4() -> None:
    """Acceptance criterion (Feature 28.13): severity 1 → severity_id 4 (High)."""
    assert SURICATA_SEV_MAP[1] == 4


# ---------------------------------------------------------------------------
# normalize() — routing
# ---------------------------------------------------------------------------


def test_normalize_alert_routing(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.class_uid == OCSFClass.SECURITY_FINDING


def test_normalize_dns_routing(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.class_uid == OCSFClass.DNS_ACTIVITY


def test_normalize_http_routing(
    normalizer: SuricataNormalizer, http_event: dict
) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.class_uid == OCSFClass.NETWORK_ACTIVITY


def test_normalize_tls_routing(
    normalizer: SuricataNormalizer, tls_event: dict
) -> None:
    ocsf = normalizer.normalize(tls_event)
    assert ocsf.class_uid == OCSFClass.NETWORK_ACTIVITY


def test_normalize_unknown_event_type_falls_back_to_network_activity(
    normalizer: SuricataNormalizer,
) -> None:
    """Unknown event_type (e.g. 'flow') falls back to NetworkActivity."""
    event = {"event_type": "flow", "src_ip": "1.2.3.4"}
    ocsf = normalizer.normalize(event)
    assert ocsf.class_uid == OCSFClass.NETWORK_ACTIVITY


def test_normalize_missing_event_type_defaults_to_alert(
    normalizer: SuricataNormalizer,
) -> None:
    """Missing event_type defaults to 'alert' dispatch path."""
    event = {"alert": {"signature": "Test", "severity": 2}}
    ocsf = normalizer.normalize(event)
    assert ocsf.class_uid == OCSFClass.SECURITY_FINDING


# ---------------------------------------------------------------------------
# _normalize_alert() — SecurityFinding (class_uid=2001)
# ---------------------------------------------------------------------------


def test_normalize_alert_class_uid(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.class_uid == OCSFClass.SECURITY_FINDING


def test_normalize_alert_class_uid_is_2001(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """Explicit acceptance criterion: alert event → class_uid 2001."""
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.class_uid == 2001


def test_normalize_alert_class_name(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.class_name == "Security Finding"


def test_normalize_alert_category_uid(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.category_uid == OCSFCategory.FINDINGS
    assert ocsf.category_uid == 2


def test_normalize_alert_metadata_product(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.metadata_product == "Suricata"


def test_normalize_alert_metadata_uid_from_flow_id(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """flow_id (int in EVE JSON) is converted to str for metadata_uid."""
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.metadata_uid == "1234567890"


def test_normalize_alert_src_endpoint_ip(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.src_endpoint.ip == "192.168.1.200"


def test_normalize_alert_src_endpoint_port(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.src_endpoint.port == 4444


def test_normalize_alert_dst_endpoint_ip(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.dst_endpoint.ip == "10.0.0.5"


def test_normalize_alert_dst_endpoint_port(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.dst_endpoint.port == 443


def test_normalize_alert_network_traffic_proto(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.network_traffic["proto"] == "TCP"


def test_normalize_alert_network_traffic_action(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.network_traffic["action"] == "allowed"


def test_normalize_alert_raw_preserved(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """Original raw event is stored in ocsf.raw for traceability."""
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.raw["src_ip"] == "192.168.1.200"
    assert ocsf.raw["event_type"] == "alert"


# ---------------------------------------------------------------------------
# Severity mapping — the core of feature 28.13
# ---------------------------------------------------------------------------


def test_alert_severity_1_maps_to_severity_id_4(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """Feature 28.13 acceptance test: Suricata severity 1 → OCSF severity_id 4."""
    alert_event["alert"]["severity"] = 1
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.severity_id == 4


def test_alert_severity_1_propagates_to_finding_info(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """severity_id=4 also appears in finding_info for Security Findings."""
    alert_event["alert"]["severity"] = 1
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.finding_info is not None
    assert ocsf.finding_info.severity_id == 4


@pytest.mark.parametrize("suricata_sev,expected_ocsf", [
    (1, 4),   # High
    (2, 3),   # Medium
    (3, 2),   # Low
    (4, 1),   # Informational
])
def test_alert_severity_mapping_all_values(
    normalizer: SuricataNormalizer,
    alert_event: dict,
    suricata_sev: int,
    expected_ocsf: int,
) -> None:
    """Each Suricata severity level maps correctly through normalize()."""
    alert_event["alert"]["severity"] = suricata_sev
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.severity_id == expected_ocsf


def test_alert_severity_unknown_defaults_to_3(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """Unmapped severity (e.g. 99) falls back to default severity_id=3."""
    alert_event["alert"]["severity"] = 99
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.severity_id == 3


def test_alert_severity_missing_defaults_to_2_then_maps_to_3(
    normalizer: SuricataNormalizer,
) -> None:
    """Missing severity field: alert.get('severity', 2) → 2 → severity_id 3."""
    event = {"event_type": "alert", "alert": {"signature": "Test Alert"}}
    ocsf = normalizer.normalize(event)
    # default raw severity = 2 → SURICATA_SEV_MAP[2] = 3
    assert ocsf.severity_id == 3


# ---------------------------------------------------------------------------
# _normalize_alert() — FindingInfo
# ---------------------------------------------------------------------------


def test_normalize_alert_finding_info_title(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.finding_info is not None
    assert ocsf.finding_info.title == "ET MALWARE CobaltStrike Beacon Activity"


def test_normalize_alert_finding_info_analytic_uid(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.finding_info is not None
    assert ocsf.finding_info.analytic is not None
    assert ocsf.finding_info.analytic.uid == "2030358"


def test_normalize_alert_finding_info_analytic_name(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.finding_info.analytic.name == "ET MALWARE CobaltStrike Beacon Activity"


def test_normalize_alert_finding_info_analytic_type_id(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.finding_info.analytic.type_id == 1


# ---------------------------------------------------------------------------
# _build_attacks() — ATT&CK technique extraction
# ---------------------------------------------------------------------------


def test_normalize_alert_attack_technique_extracted(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.finding_info is not None
    assert len(ocsf.finding_info.attacks) == 1
    attack = ocsf.finding_info.attacks[0]
    assert attack.technique is not None
    assert attack.technique.uid == "T1071.001"


def test_normalize_alert_multiple_attack_techniques(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    alert_event["alert"]["metadata"]["mitre_technique_id"] = [
        "T1071.001", "T1059.001", "T1003"
    ]
    ocsf = normalizer.normalize(alert_event)
    assert len(ocsf.finding_info.attacks) == 3
    uids = {a.technique.uid for a in ocsf.finding_info.attacks}
    assert uids == {"T1071.001", "T1059.001", "T1003"}


def test_normalize_alert_no_attack_techniques(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    alert_event["alert"]["metadata"] = {}
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.finding_info.attacks == []


def test_normalize_alert_missing_metadata(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    del alert_event["alert"]["metadata"]
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.finding_info.attacks == []


# ---------------------------------------------------------------------------
# _normalize_alert() — missing optional fields
# ---------------------------------------------------------------------------


def test_normalize_alert_missing_src_ip(
    normalizer: SuricataNormalizer,
) -> None:
    event = {"event_type": "alert", "alert": {"severity": 1}}
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.ip is None


def test_normalize_alert_missing_dest_ip(
    normalizer: SuricataNormalizer,
) -> None:
    event = {"event_type": "alert", "alert": {"severity": 1}}
    ocsf = normalizer.normalize(event)
    assert ocsf.dst_endpoint.ip is None


def test_normalize_alert_missing_ports(
    normalizer: SuricataNormalizer,
) -> None:
    event = {
        "event_type": "alert",
        "src_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
        "alert": {"severity": 1},
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.port is None


def test_normalize_alert_missing_signature_uses_default_title(
    normalizer: SuricataNormalizer,
) -> None:
    event = {"event_type": "alert", "alert": {"severity": 1}}
    ocsf = normalizer.normalize(event)
    assert ocsf.finding_info.title == "Unknown Suricata Alert"


def test_normalize_alert_missing_flow_id(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    del alert_event["flow_id"]
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.metadata_uid is None


# ---------------------------------------------------------------------------
# _normalize_dns() — DNS Activity (class_uid=4003)
# ---------------------------------------------------------------------------


def test_normalize_dns_class_uid(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.class_uid == OCSFClass.DNS_ACTIVITY
    assert ocsf.class_uid == 4003


def test_normalize_dns_class_name(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.class_name == "DNS Activity"


def test_normalize_dns_category_uid(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.category_uid == OCSFCategory.NETWORK
    assert ocsf.category_uid == 4


def test_normalize_dns_metadata_product(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.metadata_product == "Suricata"


def test_normalize_dns_src_endpoint(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.src_endpoint.ip == "10.0.0.5"


def test_normalize_dns_dst_endpoint(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.dst_endpoint.ip == "8.8.8.8"


def test_normalize_dns_query(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.network_traffic["query"] == "evil.example.com"


def test_normalize_dns_qtype(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.network_traffic["qtype"] == "A"


def test_normalize_dns_answers(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.network_traffic["answers"] == ["1.2.3.4"]


def test_normalize_dns_rcode(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.network_traffic["rcode"] == "NOERROR"


def test_normalize_dns_severity_is_informational(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    """DNS events carry severity_id=1 (Informational)."""
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.severity_id == 1


def test_normalize_dns_raw_preserved(
    normalizer: SuricataNormalizer, dns_event: dict
) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.raw["event_type"] == "dns"
    assert ocsf.raw["src_ip"] == "10.0.0.5"


# ---------------------------------------------------------------------------
# _normalize_network() — HTTP / TLS (class_uid=4001)
# ---------------------------------------------------------------------------


def test_normalize_http_class_uid(
    normalizer: SuricataNormalizer, http_event: dict
) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.class_uid == OCSFClass.NETWORK_ACTIVITY
    assert ocsf.class_uid == 4001


def test_normalize_http_class_name(
    normalizer: SuricataNormalizer, http_event: dict
) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.class_name == "Network Activity"


def test_normalize_http_src_endpoint(
    normalizer: SuricataNormalizer, http_event: dict
) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.src_endpoint.ip == "10.0.0.20"
    assert ocsf.src_endpoint.port == 55001


def test_normalize_http_dst_endpoint(
    normalizer: SuricataNormalizer, http_event: dict
) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.dst_endpoint.ip == "203.0.113.1"
    assert ocsf.dst_endpoint.port == 80


def test_normalize_http_network_traffic_event_type(
    normalizer: SuricataNormalizer, http_event: dict
) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.network_traffic["event_type"] == "http"


def test_normalize_http_network_traffic_contains_http_fields(
    normalizer: SuricataNormalizer, http_event: dict
) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.network_traffic["hostname"] == "www.example.com"
    assert ocsf.network_traffic["http_method"] == "GET"


def test_normalize_tls_class_uid(
    normalizer: SuricataNormalizer, tls_event: dict
) -> None:
    ocsf = normalizer.normalize(tls_event)
    assert ocsf.class_uid == OCSFClass.NETWORK_ACTIVITY


def test_normalize_tls_network_traffic_event_type(
    normalizer: SuricataNormalizer, tls_event: dict
) -> None:
    ocsf = normalizer.normalize(tls_event)
    assert ocsf.network_traffic["event_type"] == "tls"


def test_normalize_tls_network_traffic_contains_tls_fields(
    normalizer: SuricataNormalizer, tls_event: dict
) -> None:
    ocsf = normalizer.normalize(tls_event)
    assert ocsf.network_traffic["sni"] == "secure.example.com"


# ---------------------------------------------------------------------------
# _parse_time() helper
# ---------------------------------------------------------------------------


def test_parse_time_iso8601_with_plus0000(
    normalizer: SuricataNormalizer,
) -> None:
    """ISO 8601 timestamp with +0000 suffix parses to UTC datetime."""
    ts = "2026-02-19T08:30:00.123456+0000"
    result = normalizer._parse_time(ts)
    assert result.tzinfo is not None
    assert result.year == 2026
    assert result.month == 2
    assert result.day == 19
    assert result.hour == 8
    assert result.minute == 30


def test_parse_time_none_returns_utc_now(
    normalizer: SuricataNormalizer,
) -> None:
    before = datetime.now(timezone.utc)
    result = normalizer._parse_time(None)
    after = datetime.now(timezone.utc)
    assert result.tzinfo is not None
    assert before <= result <= after


def test_parse_time_invalid_string_returns_utc_now(
    normalizer: SuricataNormalizer,
) -> None:
    before = datetime.now(timezone.utc)
    result = normalizer._parse_time("not-a-timestamp")
    after = datetime.now(timezone.utc)
    assert result.tzinfo is not None
    assert before <= result <= after


def test_parse_time_iso8601_with_utc_offset(
    normalizer: SuricataNormalizer,
) -> None:
    ts = "2026-02-19T08:30:00+00:00"
    result = normalizer._parse_time(ts)
    assert result.year == 2026
    assert result.hour == 8


# ---------------------------------------------------------------------------
# Full round-trip — realistic Suricata alert
# ---------------------------------------------------------------------------


def test_full_round_trip_severity_1_alert(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """Feature 28.13 end-to-end: realistic severity-1 alert produces correct OCSF."""
    ocsf = normalizer.normalize(alert_event)

    # Class / category
    assert ocsf.class_uid == 2001
    assert ocsf.class_name == "Security Finding"
    assert ocsf.category_uid == 2

    # Key acceptance criterion: severity 1 → severity_id 4
    assert ocsf.severity_id == 4

    # Source identification
    assert ocsf.metadata_product == "Suricata"
    assert ocsf.metadata_uid == "1234567890"

    # Endpoints
    assert ocsf.src_endpoint.ip == "192.168.1.200"
    assert ocsf.src_endpoint.port == 4444
    assert ocsf.dst_endpoint.ip == "10.0.0.5"
    assert ocsf.dst_endpoint.port == 443

    # Finding info
    assert ocsf.finding_info is not None
    assert ocsf.finding_info.title == "ET MALWARE CobaltStrike Beacon Activity"
    assert ocsf.finding_info.severity_id == 4
    assert ocsf.finding_info.analytic.uid == "2030358"
    assert len(ocsf.finding_info.attacks) == 1
    assert ocsf.finding_info.attacks[0].technique.uid == "T1071.001"

    # Network traffic metadata
    assert ocsf.network_traffic["proto"] == "TCP"
    assert ocsf.network_traffic["action"] == "allowed"

    # Raw preserved
    assert ocsf.raw["src_ip"] == "192.168.1.200"

    # Timestamp is UTC-aware
    assert ocsf.time.tzinfo is not None
    assert ocsf.time.year == 2026

    # Pydantic serialization round-trip
    data = ocsf.model_dump(mode="json")
    assert data["severity_id"] == 4
    assert data["class_uid"] == 2001
    assert data["finding_info"]["severity_id"] == 4
    assert isinstance(data["time"], str)
