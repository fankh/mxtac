"""Tests for SuricataNormalizer — Feature 7.12: IPs/ports → src/dst_endpoint

Coverage:
  - alert events: src_ip/src_port → src_endpoint, dest_ip/dest_port → dst_endpoint
  - dns events: src_ip/src_port → src_endpoint, dest_ip/dest_port → dst_endpoint
  - http events: src_ip/src_port → src_endpoint, dest_ip/dest_port → dst_endpoint
  - tls events: src_ip/src_port → src_endpoint, dest_ip/dest_port → dst_endpoint
  - generic/unknown event_type: same endpoint mapping applies
  - Missing src_ip → src_endpoint.ip is None
  - Missing dest_ip → dst_endpoint.ip is None
  - Missing src_port → src_endpoint.port is None
  - Missing dest_port → dst_endpoint.port is None
  - Endpoint fields are Endpoint objects (not raw dicts)
  - JSON serialization round-trip preserves src/dst_endpoint IP and port
"""

from __future__ import annotations

import pytest

from app.services.normalizers.suricata import SuricataNormalizer
from app.services.normalizers.ocsf import Endpoint


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def normalizer() -> SuricataNormalizer:
    return SuricataNormalizer()


@pytest.fixture
def alert_event() -> dict:
    """Suricata EVE JSON alert with full IP/port info on both sides."""
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
            "signature_id": 2030358,
            "signature": "ET MALWARE CobaltStrike Beacon Activity",
            "severity": 1,
            "metadata": {},
        },
    }


@pytest.fixture
def dns_event_with_ports() -> dict:
    """Suricata DNS event including src/dest ports (common in real EVE JSON)."""
    return {
        "timestamp": "2026-02-19T09:00:00.000000+0000",
        "event_type": "dns",
        "src_ip": "10.0.0.5",
        "src_port": 52345,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "flow_id": 9876543210,
        "dns": {
            "rrname": "evil.example.com",
            "rrtype": "A",
            "answers": ["1.2.3.4"],
            "rcode": "NOERROR",
        },
    }


@pytest.fixture
def dns_event_no_ports() -> dict:
    """Suricata DNS event without port fields."""
    return {
        "timestamp": "2026-02-19T09:00:00.000000+0000",
        "event_type": "dns",
        "src_ip": "10.0.0.5",
        "dest_ip": "8.8.8.8",
        "flow_id": 9876543210,
        "dns": {"rrname": "example.com", "rrtype": "A"},
    }


@pytest.fixture
def http_event() -> dict:
    """Suricata HTTP event with full IP/port info."""
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
        },
    }


@pytest.fixture
def tls_event() -> dict:
    """Suricata TLS event with full IP/port info."""
    return {
        "timestamp": "2026-02-19T11:00:00.000000+0000",
        "event_type": "tls",
        "src_ip": "10.0.0.5",
        "src_port": 55002,
        "dest_ip": "203.0.113.50",
        "dest_port": 443,
        "flow_id": 2222222222,
        "tls": {"sni": "secure.example.com", "version": "TLS 1.3"},
    }


@pytest.fixture
def flow_event() -> dict:
    """Suricata flow event (unknown type) with full IP/port info."""
    return {
        "timestamp": "2026-02-19T12:00:00.000000+0000",
        "event_type": "flow",
        "src_ip": "172.16.0.10",
        "src_port": 60000,
        "dest_ip": "172.16.0.1",
        "dest_port": 22,
        "flow_id": 3333333333,
        "flow": {"pkts_toserver": 5, "pkts_toclient": 3},
    }


# ---------------------------------------------------------------------------
# Alert event — src/dst endpoint IP and port
# ---------------------------------------------------------------------------


def test_alert_src_endpoint_ip(normalizer: SuricataNormalizer, alert_event: dict) -> None:
    """Feature 7.12: src_ip maps to src_endpoint.ip for alert events."""
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.src_endpoint.ip == "192.168.1.200"


def test_alert_src_endpoint_port(normalizer: SuricataNormalizer, alert_event: dict) -> None:
    """Feature 7.12: src_port maps to src_endpoint.port for alert events."""
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.src_endpoint.port == 4444


def test_alert_dst_endpoint_ip(normalizer: SuricataNormalizer, alert_event: dict) -> None:
    """Feature 7.12: dest_ip maps to dst_endpoint.ip for alert events."""
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.dst_endpoint.ip == "10.0.0.5"


def test_alert_dst_endpoint_port(normalizer: SuricataNormalizer, alert_event: dict) -> None:
    """Feature 7.12: dest_port maps to dst_endpoint.port for alert events."""
    ocsf = normalizer.normalize(alert_event)
    assert ocsf.dst_endpoint.port == 443


def test_alert_src_endpoint_is_endpoint_object(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """src_endpoint must be an Endpoint instance, not a raw dict."""
    ocsf = normalizer.normalize(alert_event)
    assert isinstance(ocsf.src_endpoint, Endpoint)


def test_alert_dst_endpoint_is_endpoint_object(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """dst_endpoint must be an Endpoint instance, not a raw dict."""
    ocsf = normalizer.normalize(alert_event)
    assert isinstance(ocsf.dst_endpoint, Endpoint)


# ---------------------------------------------------------------------------
# DNS event — src/dst endpoint IP and port
# ---------------------------------------------------------------------------


def test_dns_src_endpoint_ip_with_ports(
    normalizer: SuricataNormalizer, dns_event_with_ports: dict
) -> None:
    """Feature 7.12: src_ip maps to src_endpoint.ip for DNS events."""
    ocsf = normalizer.normalize(dns_event_with_ports)
    assert ocsf.src_endpoint.ip == "10.0.0.5"


def test_dns_src_endpoint_port_with_ports(
    normalizer: SuricataNormalizer, dns_event_with_ports: dict
) -> None:
    """Feature 7.12: src_port maps to src_endpoint.port for DNS events."""
    ocsf = normalizer.normalize(dns_event_with_ports)
    assert ocsf.src_endpoint.port == 52345


def test_dns_dst_endpoint_ip_with_ports(
    normalizer: SuricataNormalizer, dns_event_with_ports: dict
) -> None:
    """Feature 7.12: dest_ip maps to dst_endpoint.ip for DNS events."""
    ocsf = normalizer.normalize(dns_event_with_ports)
    assert ocsf.dst_endpoint.ip == "8.8.8.8"


def test_dns_dst_endpoint_port_with_ports(
    normalizer: SuricataNormalizer, dns_event_with_ports: dict
) -> None:
    """Feature 7.12: dest_port maps to dst_endpoint.port for DNS events (port 53)."""
    ocsf = normalizer.normalize(dns_event_with_ports)
    assert ocsf.dst_endpoint.port == 53


def test_dns_src_endpoint_port_absent_is_none(
    normalizer: SuricataNormalizer, dns_event_no_ports: dict
) -> None:
    """Missing src_port in DNS event → src_endpoint.port is None."""
    ocsf = normalizer.normalize(dns_event_no_ports)
    assert ocsf.src_endpoint.port is None


def test_dns_dst_endpoint_port_absent_is_none(
    normalizer: SuricataNormalizer, dns_event_no_ports: dict
) -> None:
    """Missing dest_port in DNS event → dst_endpoint.port is None."""
    ocsf = normalizer.normalize(dns_event_no_ports)
    assert ocsf.dst_endpoint.port is None


def test_dns_src_endpoint_ip_no_ports_fixture(
    normalizer: SuricataNormalizer, dns_event_no_ports: dict
) -> None:
    """src_ip still maps correctly even when no ports are present."""
    ocsf = normalizer.normalize(dns_event_no_ports)
    assert ocsf.src_endpoint.ip == "10.0.0.5"


def test_dns_dst_endpoint_ip_no_ports_fixture(
    normalizer: SuricataNormalizer, dns_event_no_ports: dict
) -> None:
    """dest_ip still maps correctly even when no ports are present."""
    ocsf = normalizer.normalize(dns_event_no_ports)
    assert ocsf.dst_endpoint.ip == "8.8.8.8"


# ---------------------------------------------------------------------------
# HTTP event — src/dst endpoint IP and port
# ---------------------------------------------------------------------------


def test_http_src_endpoint_ip(normalizer: SuricataNormalizer, http_event: dict) -> None:
    """Feature 7.12: src_ip maps to src_endpoint.ip for HTTP events."""
    ocsf = normalizer.normalize(http_event)
    assert ocsf.src_endpoint.ip == "10.0.0.20"


def test_http_src_endpoint_port(normalizer: SuricataNormalizer, http_event: dict) -> None:
    """Feature 7.12: src_port maps to src_endpoint.port for HTTP events."""
    ocsf = normalizer.normalize(http_event)
    assert ocsf.src_endpoint.port == 55001


def test_http_dst_endpoint_ip(normalizer: SuricataNormalizer, http_event: dict) -> None:
    """Feature 7.12: dest_ip maps to dst_endpoint.ip for HTTP events."""
    ocsf = normalizer.normalize(http_event)
    assert ocsf.dst_endpoint.ip == "203.0.113.1"


def test_http_dst_endpoint_port(normalizer: SuricataNormalizer, http_event: dict) -> None:
    """Feature 7.12: dest_port maps to dst_endpoint.port for HTTP events."""
    ocsf = normalizer.normalize(http_event)
    assert ocsf.dst_endpoint.port == 80


# ---------------------------------------------------------------------------
# TLS event — src/dst endpoint IP and port
# ---------------------------------------------------------------------------


def test_tls_src_endpoint_ip(normalizer: SuricataNormalizer, tls_event: dict) -> None:
    """Feature 7.12: src_ip maps to src_endpoint.ip for TLS events."""
    ocsf = normalizer.normalize(tls_event)
    assert ocsf.src_endpoint.ip == "10.0.0.5"


def test_tls_src_endpoint_port(normalizer: SuricataNormalizer, tls_event: dict) -> None:
    """Feature 7.12: src_port maps to src_endpoint.port for TLS events."""
    ocsf = normalizer.normalize(tls_event)
    assert ocsf.src_endpoint.port == 55002


def test_tls_dst_endpoint_ip(normalizer: SuricataNormalizer, tls_event: dict) -> None:
    """Feature 7.12: dest_ip maps to dst_endpoint.ip for TLS events."""
    ocsf = normalizer.normalize(tls_event)
    assert ocsf.dst_endpoint.ip == "203.0.113.50"


def test_tls_dst_endpoint_port(normalizer: SuricataNormalizer, tls_event: dict) -> None:
    """Feature 7.12: dest_port maps to dst_endpoint.port for TLS events."""
    ocsf = normalizer.normalize(tls_event)
    assert ocsf.dst_endpoint.port == 443


# ---------------------------------------------------------------------------
# Generic/unknown event_type — same endpoint mapping applies
# ---------------------------------------------------------------------------


def test_generic_src_endpoint_ip(normalizer: SuricataNormalizer, flow_event: dict) -> None:
    """Feature 7.12: src_ip maps to src_endpoint.ip for unknown/generic events."""
    ocsf = normalizer.normalize(flow_event)
    assert ocsf.src_endpoint.ip == "172.16.0.10"


def test_generic_src_endpoint_port(normalizer: SuricataNormalizer, flow_event: dict) -> None:
    """Feature 7.12: src_port maps to src_endpoint.port for unknown/generic events."""
    ocsf = normalizer.normalize(flow_event)
    assert ocsf.src_endpoint.port == 60000


def test_generic_dst_endpoint_ip(normalizer: SuricataNormalizer, flow_event: dict) -> None:
    """Feature 7.12: dest_ip maps to dst_endpoint.ip for unknown/generic events."""
    ocsf = normalizer.normalize(flow_event)
    assert ocsf.dst_endpoint.ip == "172.16.0.1"


def test_generic_dst_endpoint_port(normalizer: SuricataNormalizer, flow_event: dict) -> None:
    """Feature 7.12: dest_port maps to dst_endpoint.port for unknown/generic events."""
    ocsf = normalizer.normalize(flow_event)
    assert ocsf.dst_endpoint.port == 22


# ---------------------------------------------------------------------------
# Missing IP/port fields — graceful None handling
# ---------------------------------------------------------------------------


def test_missing_src_ip_yields_none(normalizer: SuricataNormalizer) -> None:
    """No src_ip in raw event → src_endpoint.ip is None (no error)."""
    event = {
        "event_type": "alert",
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "alert": {"severity": 2},
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.ip is None


def test_missing_dest_ip_yields_none(normalizer: SuricataNormalizer) -> None:
    """No dest_ip in raw event → dst_endpoint.ip is None (no error)."""
    event = {
        "event_type": "alert",
        "src_ip": "10.0.0.1",
        "src_port": 12345,
        "alert": {"severity": 2},
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.dst_endpoint.ip is None


def test_missing_src_port_yields_none(normalizer: SuricataNormalizer) -> None:
    """No src_port in raw event → src_endpoint.port is None (no error)."""
    event = {
        "event_type": "http",
        "src_ip": "10.0.0.1",
        "dest_ip": "20.0.0.1",
        "dest_port": 80,
        "http": {},
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port is None


def test_missing_dest_port_yields_none(normalizer: SuricataNormalizer) -> None:
    """No dest_port in raw event → dst_endpoint.port is None (no error)."""
    event = {
        "event_type": "tls",
        "src_ip": "10.0.0.1",
        "src_port": 55000,
        "dest_ip": "20.0.0.1",
        "tls": {},
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.dst_endpoint.port is None


def test_completely_empty_event_endpoints_are_none(normalizer: SuricataNormalizer) -> None:
    """Completely empty event normalizes without error; both endpoints have all-None fields."""
    ocsf = normalizer.normalize({})
    assert ocsf.src_endpoint.ip is None
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.ip is None
    assert ocsf.dst_endpoint.port is None


def test_missing_both_ips_and_ports_for_dns(normalizer: SuricataNormalizer) -> None:
    """DNS event with no IPs or ports → both endpoints have all-None fields."""
    event = {"event_type": "dns", "dns": {"rrname": "test.com"}}
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.ip is None
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.ip is None
    assert ocsf.dst_endpoint.port is None


# ---------------------------------------------------------------------------
# JSON serialization round-trip
# ---------------------------------------------------------------------------


def test_alert_endpoints_in_json_dump(
    normalizer: SuricataNormalizer, alert_event: dict
) -> None:
    """model_dump(mode='json') must include src/dst endpoint IP and port for alert."""
    ocsf = normalizer.normalize(alert_event)
    data = ocsf.model_dump(mode="json")
    assert data["src_endpoint"]["ip"] == "192.168.1.200"
    assert data["src_endpoint"]["port"] == 4444
    assert data["dst_endpoint"]["ip"] == "10.0.0.5"
    assert data["dst_endpoint"]["port"] == 443


def test_dns_endpoints_in_json_dump(
    normalizer: SuricataNormalizer, dns_event_with_ports: dict
) -> None:
    """model_dump(mode='json') must include src/dst endpoint IP and port for DNS."""
    ocsf = normalizer.normalize(dns_event_with_ports)
    data = ocsf.model_dump(mode="json")
    assert data["src_endpoint"]["ip"] == "10.0.0.5"
    assert data["src_endpoint"]["port"] == 52345
    assert data["dst_endpoint"]["ip"] == "8.8.8.8"
    assert data["dst_endpoint"]["port"] == 53


def test_http_endpoints_in_json_dump(
    normalizer: SuricataNormalizer, http_event: dict
) -> None:
    """model_dump(mode='json') must include src/dst endpoint IP and port for HTTP."""
    ocsf = normalizer.normalize(http_event)
    data = ocsf.model_dump(mode="json")
    assert data["src_endpoint"]["ip"] == "10.0.0.20"
    assert data["src_endpoint"]["port"] == 55001
    assert data["dst_endpoint"]["ip"] == "203.0.113.1"
    assert data["dst_endpoint"]["port"] == 80


def test_tls_endpoints_in_json_dump(
    normalizer: SuricataNormalizer, tls_event: dict
) -> None:
    """model_dump(mode='json') must include src/dst endpoint IP and port for TLS."""
    ocsf = normalizer.normalize(tls_event)
    data = ocsf.model_dump(mode="json")
    assert data["src_endpoint"]["ip"] == "10.0.0.5"
    assert data["src_endpoint"]["port"] == 55002
    assert data["dst_endpoint"]["ip"] == "203.0.113.50"
    assert data["dst_endpoint"]["port"] == 443


# ---------------------------------------------------------------------------
# Full round-trip — all four event types in one test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("event_type,src_ip,src_port,dest_ip,dest_port,extra", [
    ("alert",   "192.168.1.1",  1234,  "10.0.0.1",   443,  {"alert": {"severity": 2, "metadata": {}}}),
    ("dns",     "192.168.1.2",  52345, "8.8.8.8",     53,   {"dns": {"rrname": "example.com"}}),
    ("http",    "192.168.1.3",  55001, "203.0.113.1", 80,   {"http": {"hostname": "x.com"}}),
    ("tls",     "192.168.1.4",  55002, "203.0.113.2", 443,  {"tls": {"sni": "y.com"}}),
    ("flow",    "192.168.1.5",  60000, "172.16.0.1",  22,   {"flow": {}}),
])
def test_endpoint_mapping_all_event_types(
    normalizer: SuricataNormalizer,
    event_type: str,
    src_ip: str,
    src_port: int,
    dest_ip: str,
    dest_port: int,
    extra: dict,
) -> None:
    """Feature 7.12: src_ip/src_port and dest_ip/dest_port map correctly for every event type."""
    raw = {
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        **extra,
    }
    ocsf = normalizer.normalize(raw)
    assert ocsf.src_endpoint.ip == src_ip
    assert ocsf.src_endpoint.port == src_port
    assert ocsf.dst_endpoint.ip == dest_ip
    assert ocsf.dst_endpoint.port == dest_port
