"""Tests for ZeekNormalizer — Feature 7.6 + Feature 7.7 + Feature 7.9 + Feature 28.12

Coverage (Feature 7.6):
  - CONN_STATE_SEVERITY mapping: all documented states and default fallback
  - _normalize_conn(): full conn.log fields → NetworkActivity (class_uid=4001)
  - _normalize_conn(): missing optional fields produce sensible defaults
  - _normalize_conn(): conn_state drives severity_id
  - _normalize_dns(): dns.log fields → DNS Activity (class_uid=4003)
  - _normalize_http(): http.log fields → HTTP Activity (class_uid=4002)
  - _normalize_ssl(): ssl.log fields → Network Activity (class_uid=4001)
  - normalize(): routing dispatches on _log_type
  - normalize(): unknown _log_type falls back to NetworkActivity
  - _parse_ts(): Unix float timestamp, None, invalid string
  - _safe_int(): int, str-int, None, invalid string
  - Full round-trip: realistic conn.log event → OCSFEvent with all fields

Coverage (Feature 7.7 — Zeek dns → DNSActivity (class_uid 4003)):
  - Endpoint ports captured from id.orig_p / id.resp_p
  - Extended DNS fields: trans_id, rtt
  - QCLASS fields: qclass (numeric), qclass_name
  - Query type: qtype (qtype_name), qtype_id (numeric qtype)
  - Response code: rcode (rcode_name), rcode_id (numeric rcode)
  - DNS flags: AA, TC, RD, RA, Z
  - TTLs list defaults to []
  - rejected boolean field
  - Full round-trip: all extended fields → JSON-serializable OCSFEvent

Coverage (Feature 7.9 — Zeek ssl → NetworkActivity (class_uid 4001)):
  - Endpoint ports captured from id.orig_p / id.resp_p
  - server_name (SNI) maps to dst_endpoint.hostname
  - Extended TLS fields: curve, resumed, next_protocol, ssl_history
  - Certificate fields: subject, issuer, not_valid_before, not_valid_after
  - JA3/JA3S fingerprints: ja3, ja3s
  - validation_status, client_cert_chain (client_cert_chain_fuids)
  - Absent optional fields default to None
  - Full round-trip: all extended fields → JSON-serializable OCSFEvent

Coverage (Feature 28.12 — Zeek conn → NetworkActivity):
  - Extended conn fields: missed_bytes, history, orig_pkts, resp_pkts,
    orig_ip_bytes, resp_ip_bytes, local_orig, local_resp, tunnel_parents, vlan
  - All Zeek conn_state values and severity mapping
  - IPv6 address support in src/dst endpoints
  - Protocol variations: tcp, udp, icmp, icmp6
  - Large byte counts (100GB+)
  - Tunnel parent tracking
  - Full round-trip: realistic conn event with all extended fields
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.normalizers.zeek import (
    CONN_STATE_SEVERITY,
    ZeekNormalizer,
)
from app.services.normalizers.ocsf import OCSFCategory, OCSFClass


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def normalizer() -> ZeekNormalizer:
    return ZeekNormalizer()


@pytest.fixture
def conn_event() -> dict:
    """Realistic Zeek conn.log JSON event."""
    return {
        "_log_type":  "conn",
        "ts":         1708331400.123456,
        "uid":        "CsWDhq4k5b6Ioam1Mj",
        "id.orig_h":  "10.0.0.5",
        "id.orig_p":  "54321",
        "id.resp_h":  "192.168.1.10",
        "id.resp_p":  "443",
        "proto":      "tcp",
        "service":    "ssl",
        "duration":   12.345,
        "orig_bytes": 1024,
        "resp_bytes": 4096,
        "conn_state": "SF",
    }


@pytest.fixture
def dns_event() -> dict:
    """Realistic Zeek dns.log JSON event."""
    return {
        "_log_type":   "dns",
        "ts":          1708331400.0,
        "uid":         "Dns123456",
        "id.orig_h":   "10.0.0.5",
        "id.orig_p":   "54321",
        "id.resp_h":   "8.8.8.8",
        "id.resp_p":   "53",
        "query":       "evil.example.com",
        "qtype_name":  "A",
        "answers":     ["1.2.3.4"],
        "rcode_name":  "NOERROR",
        "proto":       "udp",
    }


@pytest.fixture
def http_event() -> dict:
    """Realistic Zeek http.log JSON event."""
    return {
        "_log_type":        "http",
        "ts":               1708331400.0,
        "uid":              "Http789",
        "id.orig_h":        "10.0.0.20",
        "id.orig_p":        "60000",
        "id.resp_h":        "203.0.113.1",
        "id.resp_p":        "80",
        "host":             "www.example.com",
        "method":           "GET",
        "uri":              "/path/to/resource",
        "status_code":      200,
        "user_agent":       "Mozilla/5.0",
        "referrer":         "https://example.com/",
        "resp_mime_types":  ["text/html"],
    }


@pytest.fixture
def ssl_event() -> dict:
    """Realistic Zeek ssl.log JSON event."""
    return {
        "_log_type":         "ssl",
        "ts":                1708331400.0,
        "uid":               "Ssl999",
        "id.orig_h":         "10.0.0.5",
        "id.resp_h":         "203.0.113.50",
        "server_name":       "secure.example.com",
        "version":           "TLSv13",
        "cipher":            "TLS_AES_256_GCM_SHA384",
        "established":       True,
        "cert_chain_fuids":  ["FuuidA", "FuuidB"],
    }


# ---------------------------------------------------------------------------
# CONN_STATE_SEVERITY constant
# ---------------------------------------------------------------------------


def test_conn_state_severity_all_keys() -> None:
    """All documented Zeek connection states must be present in the mapping."""
    expected_states = {"S0", "REJ", "RSTO", "RSTR", "OTH"}
    assert expected_states.issubset(set(CONN_STATE_SEVERITY.keys()))


@pytest.mark.parametrize("state,expected_severity", [
    ("S0",   2),   # SYN sent, no reply → Low
    ("REJ",  3),   # Rejected → Medium
    ("RSTO", 2),   # Orig RST → Low
    ("RSTR", 2),   # Resp RST → Low
    ("OTH",  1),   # Other → Informational
])
def test_conn_state_severity_values(state: str, expected_severity: int) -> None:
    """Each documented conn_state maps to the correct OCSF severity_id."""
    assert CONN_STATE_SEVERITY[state] == expected_severity


def test_conn_state_severity_missing_defaults_to_informational(
    normalizer: ZeekNormalizer,
) -> None:
    """Undocumented conn_state (e.g. 'SF') defaults to severity_id=1 in normalize."""
    event = {"_log_type": "conn", "conn_state": "SF"}
    ocsf = normalizer.normalize(event)
    assert ocsf.severity_id == 1   # SF = successful → no entry → default 1


def test_conn_state_rej_produces_medium_severity(
    normalizer: ZeekNormalizer, conn_event: dict
) -> None:
    """REJ conn_state propagates severity_id=3 (Medium) into OCSFEvent."""
    conn_event["conn_state"] = "REJ"
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.severity_id == 3


def test_conn_state_s0_produces_low_severity(
    normalizer: ZeekNormalizer, conn_event: dict
) -> None:
    """S0 conn_state propagates severity_id=2 (Low) into OCSFEvent."""
    conn_event["conn_state"] = "S0"
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.severity_id == 2


# ---------------------------------------------------------------------------
# _normalize_conn() — NetworkActivity (4001)
# ---------------------------------------------------------------------------


def test_normalize_conn_class_uid(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.class_uid == OCSFClass.NETWORK_ACTIVITY


def test_normalize_conn_class_uid_is_4001(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    """Explicit acceptance criterion: conn log → class_uid 4001."""
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.class_uid == 4001


def test_normalize_conn_class_name(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.class_name == "Network Activity"


def test_normalize_conn_category_uid(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.category_uid == OCSFCategory.NETWORK
    assert ocsf.category_uid == 4


def test_normalize_conn_metadata_product(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.metadata_product == "Zeek"


def test_normalize_conn_metadata_uid(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    """Zeek uid field maps to metadata_uid."""
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.metadata_uid == "CsWDhq4k5b6Ioam1Mj"


def test_normalize_conn_src_endpoint_ip(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.src_endpoint.ip == "10.0.0.5"


def test_normalize_conn_src_endpoint_port(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.src_endpoint.port == 54321


def test_normalize_conn_dst_endpoint_ip(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.dst_endpoint.ip == "192.168.1.10"


def test_normalize_conn_dst_endpoint_port(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.dst_endpoint.port == 443


def test_normalize_conn_network_traffic_protocol(
    normalizer: ZeekNormalizer, conn_event: dict
) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.network_traffic["protocol"] == "tcp"


def test_normalize_conn_network_traffic_service(
    normalizer: ZeekNormalizer, conn_event: dict
) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.network_traffic["service"] == "ssl"


def test_normalize_conn_network_traffic_duration(
    normalizer: ZeekNormalizer, conn_event: dict
) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.network_traffic["duration"] == 12.345


def test_normalize_conn_network_traffic_bytes(
    normalizer: ZeekNormalizer, conn_event: dict
) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.network_traffic["orig_bytes"] == 1024
    assert ocsf.network_traffic["resp_bytes"] == 4096


def test_normalize_conn_network_traffic_conn_state(
    normalizer: ZeekNormalizer, conn_event: dict
) -> None:
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.network_traffic["conn_state"] == "SF"


def test_normalize_conn_raw_preserved(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    """Original raw event dict is stored in ocsf.raw for traceability."""
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.raw["uid"] == "CsWDhq4k5b6Ioam1Mj"
    assert ocsf.raw["id.orig_h"] == "10.0.0.5"


def test_normalize_conn_time_from_ts(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    """Unix timestamp field maps to UTC datetime."""
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.time.tzinfo is not None
    assert ocsf.time.year == 2024  # 1708331400 ≈ 2024-02-19


def test_normalize_conn_missing_optional_fields(normalizer: ZeekNormalizer) -> None:
    """Minimal conn event (only _log_type) produces a valid OCSFEvent."""
    ocsf = normalizer.normalize({"_log_type": "conn"})
    assert ocsf.class_uid == 4001
    assert ocsf.src_endpoint.ip is None
    assert ocsf.dst_endpoint.ip is None
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.port is None
    assert ocsf.network_traffic["protocol"] is None


def test_normalize_conn_missing_uid_maps_to_none(normalizer: ZeekNormalizer) -> None:
    ocsf = normalizer.normalize({"_log_type": "conn"})
    assert ocsf.metadata_uid is None


def test_normalize_conn_port_as_string_is_cast(normalizer: ZeekNormalizer) -> None:
    """Ports stored as strings in TSV-parsed events are safely cast to int."""
    event = {
        "_log_type":  "conn",
        "id.orig_p":  "12345",
        "id.resp_p":  "80",
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port == 12345
    assert ocsf.dst_endpoint.port == 80


def test_normalize_conn_invalid_port_is_none(normalizer: ZeekNormalizer) -> None:
    """Non-numeric port string maps to None without raising."""
    event = {"_log_type": "conn", "id.orig_p": "N/A", "id.resp_p": "-"}
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.port is None


# ---------------------------------------------------------------------------
# _normalize_dns() — DNS Activity (4003)
# ---------------------------------------------------------------------------


def test_normalize_dns_class_uid(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.class_uid == OCSFClass.DNS_ACTIVITY
    assert ocsf.class_uid == 4003


def test_normalize_dns_class_name(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.class_name == "DNS Activity"


def test_normalize_dns_category_uid(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.category_uid == OCSFCategory.NETWORK


def test_normalize_dns_metadata_product(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.metadata_product == "Zeek"


def test_normalize_dns_src_endpoint_ip(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.src_endpoint.ip == "10.0.0.5"


def test_normalize_dns_dst_endpoint_ip(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.dst_endpoint.ip == "8.8.8.8"


def test_normalize_dns_query(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.network_traffic["query"] == "evil.example.com"


def test_normalize_dns_qtype(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.network_traffic["qtype"] == "A"


def test_normalize_dns_answers(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.network_traffic["answers"] == ["1.2.3.4"]


def test_normalize_dns_rcode(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.network_traffic["rcode"] == "NOERROR"


def test_normalize_dns_proto(normalizer: ZeekNormalizer, dns_event: dict) -> None:
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.network_traffic["proto"] == "udp"


def test_normalize_dns_answers_defaults_to_empty_list(normalizer: ZeekNormalizer) -> None:
    """Missing answers field defaults to [] not None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["answers"] == []


def test_normalize_dns_severity_is_informational(
    normalizer: ZeekNormalizer, dns_event: dict
) -> None:
    """DNS events are always severity_id=1 (Informational)."""
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.severity_id == 1


# ---------------------------------------------------------------------------
# _normalize_http() — HTTP Activity (4002)
# ---------------------------------------------------------------------------


def test_normalize_http_class_uid(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.class_uid == OCSFClass.HTTP_ACTIVITY
    assert ocsf.class_uid == 4002


def test_normalize_http_class_name(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.class_name == "HTTP Activity"


def test_normalize_http_category_uid(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.category_uid == OCSFCategory.NETWORK


def test_normalize_http_src_endpoint(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.src_endpoint.ip == "10.0.0.20"


def test_normalize_http_dst_endpoint_ip(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.dst_endpoint.ip == "203.0.113.1"


def test_normalize_http_dst_endpoint_hostname(normalizer: ZeekNormalizer, http_event: dict) -> None:
    """'host' field from http.log maps to dst_endpoint.hostname."""
    ocsf = normalizer.normalize(http_event)
    assert ocsf.dst_endpoint.hostname == "www.example.com"


def test_normalize_http_method(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.network_traffic["method"] == "GET"


def test_normalize_http_uri(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.network_traffic["uri"] == "/path/to/resource"


def test_normalize_http_status_code(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.network_traffic["status_code"] == 200


def test_normalize_http_user_agent(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.network_traffic["user_agent"] == "Mozilla/5.0"


def test_normalize_http_referrer(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.network_traffic["referrer"] == "https://example.com/"


def test_normalize_http_resp_mime(normalizer: ZeekNormalizer, http_event: dict) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.network_traffic["resp_mime"] == ["text/html"]


def test_normalize_http_severity_is_informational(
    normalizer: ZeekNormalizer, http_event: dict
) -> None:
    ocsf = normalizer.normalize(http_event)
    assert ocsf.severity_id == 1


# ---------------------------------------------------------------------------
# _normalize_ssl() — Network Activity (4001) with TLS context
# ---------------------------------------------------------------------------


def test_normalize_ssl_class_uid(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.class_uid == OCSFClass.NETWORK_ACTIVITY
    assert ocsf.class_uid == 4001


def test_normalize_ssl_class_name(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.class_name == "Network Activity"


def test_normalize_ssl_category_uid(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.category_uid == OCSFCategory.NETWORK


def test_normalize_ssl_src_endpoint(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.src_endpoint.ip == "10.0.0.5"


def test_normalize_ssl_dst_endpoint_ip(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.dst_endpoint.ip == "203.0.113.50"


def test_normalize_ssl_dst_endpoint_hostname(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    """server_name (SNI) maps to dst_endpoint.hostname."""
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.dst_endpoint.hostname == "secure.example.com"


def test_normalize_ssl_tls_version(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.network_traffic["version"] == "TLSv13"


def test_normalize_ssl_cipher(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.network_traffic["cipher"] == "TLS_AES_256_GCM_SHA384"


def test_normalize_ssl_server_name(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.network_traffic["server_name"] == "secure.example.com"


def test_normalize_ssl_established(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.network_traffic["established"] is True


def test_normalize_ssl_cert_chain(normalizer: ZeekNormalizer, ssl_event: dict) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.network_traffic["cert_chain"] == ["FuuidA", "FuuidB"]


def test_normalize_ssl_severity_is_informational(
    normalizer: ZeekNormalizer, ssl_event: dict
) -> None:
    ocsf = normalizer.normalize(ssl_event)
    assert ocsf.severity_id == 1


# ---------------------------------------------------------------------------
# normalize() — routing by _log_type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("log_type,expected_class_uid,expected_class_name", [
    ("conn",    4001, "Network Activity"),
    ("dns",     4003, "DNS Activity"),
    ("http",    4002, "HTTP Activity"),
    ("ssl",     4001, "Network Activity"),
])
def test_normalize_routing(
    normalizer: ZeekNormalizer,
    log_type: str,
    expected_class_uid: int,
    expected_class_name: str,
) -> None:
    """normalize() dispatches to the correct handler based on _log_type."""
    ocsf = normalizer.normalize({"_log_type": log_type})
    assert ocsf.class_uid == expected_class_uid
    assert ocsf.class_name == expected_class_name


def test_normalize_unknown_log_type_falls_back_to_network_activity(
    normalizer: ZeekNormalizer,
) -> None:
    """Unknown _log_type falls back to _normalize_conn → NetworkActivity."""
    ocsf = normalizer.normalize({"_log_type": "files", "id.orig_h": "10.0.0.1"})
    assert ocsf.class_uid == 4001
    assert ocsf.class_name == "Network Activity"


def test_normalize_missing_log_type_defaults_to_conn(
    normalizer: ZeekNormalizer,
) -> None:
    """Event without _log_type is treated as conn (NetworkActivity)."""
    ocsf = normalizer.normalize({})
    assert ocsf.class_uid == 4001


# ---------------------------------------------------------------------------
# _parse_ts()
# ---------------------------------------------------------------------------


def test_parse_ts_unix_float(normalizer: ZeekNormalizer) -> None:
    """Unix epoch float converts to UTC datetime."""
    ts = normalizer._parse_ts(1708331400.0)
    assert ts.tzinfo is not None
    assert ts.year == 2024
    assert ts.month == 2
    assert ts.day == 19


def test_parse_ts_unix_string(normalizer: ZeekNormalizer) -> None:
    """Unix epoch as string (TSV format) also converts correctly."""
    ts = normalizer._parse_ts("1708331400.0")
    assert ts.year == 2024


def test_parse_ts_none_returns_utc_now(normalizer: ZeekNormalizer) -> None:
    before = datetime.now(timezone.utc)
    ts = normalizer._parse_ts(None)
    after = datetime.now(timezone.utc)
    assert before <= ts <= after
    assert ts.tzinfo is not None


def test_parse_ts_invalid_string_returns_utc_now(normalizer: ZeekNormalizer) -> None:
    before = datetime.now(timezone.utc)
    ts = normalizer._parse_ts("not-a-timestamp")
    after = datetime.now(timezone.utc)
    assert before <= ts <= after


def test_parse_ts_zero_epoch(normalizer: ZeekNormalizer) -> None:
    """ts=0.0 maps to 1970-01-01 UTC without raising."""
    ts = normalizer._parse_ts(0.0)
    assert ts.year == 1970
    assert ts.tzinfo is not None


# ---------------------------------------------------------------------------
# _safe_int()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val,expected", [
    (443,     443),
    ("443",   443),
    ("0",     0),
    (0,       0),
    (None,    None),
    ("N/A",   None),
    ("-",     None),
    ("",      None),
    ([],      None),
])
def test_safe_int_conversions(
    normalizer: ZeekNormalizer, val, expected
) -> None:
    assert normalizer._safe_int(val) == expected


# ---------------------------------------------------------------------------
# metadata_version
# ---------------------------------------------------------------------------


def test_metadata_version_is_ocsf_1_1_0(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    """All Zeek-normalized events carry OCSF version 1.1.0."""
    ocsf = normalizer.normalize(conn_event)
    assert ocsf.metadata_version == "1.1.0"


# ---------------------------------------------------------------------------
# Full round-trip: realistic conn.log → serializable OCSFEvent
# ---------------------------------------------------------------------------


def test_full_conn_round_trip(normalizer: ZeekNormalizer, conn_event: dict) -> None:
    """End-to-end: realistic conn event → OCSFEvent → JSON-serializable dict."""
    ocsf = normalizer.normalize(conn_event)

    # Core OCSF fields
    assert ocsf.class_uid == 4001
    assert ocsf.class_name == "Network Activity"
    assert ocsf.category_uid == 4
    assert ocsf.metadata_product == "Zeek"
    assert ocsf.metadata_version == "1.1.0"
    assert ocsf.metadata_uid == "CsWDhq4k5b6Ioam1Mj"

    # Severity derived from conn_state=SF (not in mapping → default 1)
    assert ocsf.severity_id == 1
    assert ocsf.severity_name == "info"

    # Endpoints
    assert ocsf.src_endpoint.ip == "10.0.0.5"
    assert ocsf.src_endpoint.port == 54321
    assert ocsf.dst_endpoint.ip == "192.168.1.10"
    assert ocsf.dst_endpoint.port == 443

    # Network traffic context
    nt = ocsf.network_traffic
    assert nt["protocol"] == "tcp"
    assert nt["service"] == "ssl"
    assert nt["duration"] == 12.345
    assert nt["orig_bytes"] == 1024
    assert nt["resp_bytes"] == 4096
    assert nt["conn_state"] == "SF"

    # Timestamp
    assert ocsf.time.tzinfo is not None

    # Raw preserved
    assert ocsf.raw["uid"] == "CsWDhq4k5b6Ioam1Mj"

    # JSON serialisation must not raise
    data = ocsf.model_dump(mode="json")
    assert isinstance(data["time"], str)
    assert data["class_uid"] == 4001
    assert data["src_endpoint"]["ip"] == "10.0.0.5"
    assert data["network_traffic"]["protocol"] == "tcp"


# ===========================================================================
# Feature 28.12 — Zeek conn → NetworkActivity: Extended Test Coverage
# ===========================================================================


# ---------------------------------------------------------------------------
# Extended conn fields: missed_bytes, history, packet counts,
# local_orig/local_resp, tunnel_parents, vlan
# ---------------------------------------------------------------------------


@pytest.fixture
def full_conn_event() -> dict:
    """Realistic Zeek conn.log event with ALL fields populated."""
    return {
        "_log_type":      "conn",
        "ts":             1708331400.123456,
        "uid":            "CfullEvent123",
        "id.orig_h":      "10.0.0.5",
        "id.orig_p":      "54321",
        "id.resp_h":      "192.168.1.10",
        "id.resp_p":      "443",
        "proto":          "tcp",
        "service":        "ssl",
        "duration":       12.345,
        "orig_bytes":     1024,
        "resp_bytes":     4096,
        "conn_state":     "SF",
        "local_orig":     True,
        "local_resp":     False,
        "missed_bytes":   0,
        "history":        "ShADadFf",
        "orig_pkts":      10,
        "orig_ip_bytes":  1064,
        "resp_pkts":      8,
        "resp_ip_bytes":  4136,
        "tunnel_parents": [],
        "vlan":           100,
    }


def test_normalize_conn_missed_bytes(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """missed_bytes field is captured in network_traffic."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["missed_bytes"] == 0


def test_normalize_conn_missed_bytes_nonzero(normalizer: ZeekNormalizer) -> None:
    """Non-zero missed_bytes (packet loss) is preserved."""
    event = {"_log_type": "conn", "missed_bytes": 512}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["missed_bytes"] == 512


def test_normalize_conn_missed_bytes_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent missed_bytes defaults to None (not 0)."""
    ocsf = normalizer.normalize({"_log_type": "conn"})
    assert ocsf.network_traffic["missed_bytes"] is None


def test_normalize_conn_history(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """Zeek connection history flags are captured in network_traffic."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["history"] == "ShADadFf"


def test_normalize_conn_history_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent history field defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "conn"})
    assert ocsf.network_traffic["history"] is None


def test_normalize_conn_orig_pkts(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """orig_pkts (originator packet count) is captured in network_traffic."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["orig_pkts"] == 10


def test_normalize_conn_resp_pkts(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """resp_pkts (responder packet count) is captured in network_traffic."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["resp_pkts"] == 8


def test_normalize_conn_orig_ip_bytes(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """orig_ip_bytes is captured in network_traffic."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["orig_ip_bytes"] == 1064


def test_normalize_conn_resp_ip_bytes(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """resp_ip_bytes is captured in network_traffic."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["resp_ip_bytes"] == 4136


def test_normalize_conn_local_orig_true(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """local_orig=True (originator is local) is preserved."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["local_orig"] is True


def test_normalize_conn_local_resp_false(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """local_resp=False (responder is external) is preserved."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["local_resp"] is False


def test_normalize_conn_local_orig_false(normalizer: ZeekNormalizer) -> None:
    """Outbound connection: local_orig=False is preserved."""
    event = {"_log_type": "conn", "local_orig": False, "local_resp": True}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["local_orig"] is False
    assert ocsf.network_traffic["local_resp"] is True


def test_normalize_conn_local_orig_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent local_orig/local_resp default to None (not False)."""
    ocsf = normalizer.normalize({"_log_type": "conn"})
    assert ocsf.network_traffic["local_orig"] is None
    assert ocsf.network_traffic["local_resp"] is None


def test_normalize_conn_tunnel_parents_empty(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """Empty tunnel_parents list is preserved as []."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["tunnel_parents"] == []


def test_normalize_conn_tunnel_parents_populated(normalizer: ZeekNormalizer) -> None:
    """Non-empty tunnel_parents (tunneled connection) is preserved."""
    event = {"_log_type": "conn", "tunnel_parents": ["CpFwgz1jEBPHIqvXy5"]}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["tunnel_parents"] == ["CpFwgz1jEBPHIqvXy5"]


def test_normalize_conn_tunnel_parents_defaults_to_empty_when_absent(
    normalizer: ZeekNormalizer,
) -> None:
    """Absent tunnel_parents defaults to [] (not None)."""
    ocsf = normalizer.normalize({"_log_type": "conn"})
    assert ocsf.network_traffic["tunnel_parents"] == []


def test_normalize_conn_vlan(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """VLAN tag is captured in network_traffic."""
    ocsf = normalizer.normalize(full_conn_event)
    assert ocsf.network_traffic["vlan"] == 100


def test_normalize_conn_vlan_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent vlan defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "conn"})
    assert ocsf.network_traffic["vlan"] is None


# ---------------------------------------------------------------------------
# All Zeek conn_state values and their severity mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("conn_state,expected_severity", [
    # States explicitly in CONN_STATE_SEVERITY
    ("S0",   2),    # SYN sent, no reply — potential scan → Low
    ("REJ",  3),    # Rejected → Medium
    ("RSTO", 2),    # Orig RST → Low
    ("RSTR", 2),    # Resp RST → Low
    ("OTH",  1),    # Other → Informational
    # States that fall through to default → Informational
    ("SF",    1),   # Successful full connection
    ("S1",    1),   # Established, not terminated
    ("S2",    1),   # Established, orig closed
    ("S3",    1),   # Established, resp closed
    ("SH",    1),   # Orig SYN+FIN (abnormal but not in explicit map)
    ("SHR",   1),   # Resp SYN+FIN
    ("RSTOS0", 1),  # Orig RST before handshake (not in explicit map)
    ("RSTRH", 1),   # Resp RST before handshake
])
def test_all_conn_states_severity(
    normalizer: ZeekNormalizer, conn_state: str, expected_severity: int
) -> None:
    """Every known Zeek conn_state maps to the expected OCSF severity_id."""
    event = {"_log_type": "conn", "conn_state": conn_state}
    ocsf = normalizer.normalize(event)
    assert ocsf.severity_id == expected_severity, (
        f"conn_state={conn_state!r} should map to severity_id={expected_severity}, "
        f"got {ocsf.severity_id}"
    )


# ---------------------------------------------------------------------------
# IPv6 address support
# ---------------------------------------------------------------------------


def test_normalize_conn_ipv6_src_endpoint(normalizer: ZeekNormalizer) -> None:
    """IPv6 addresses in id.orig_h map correctly to src_endpoint.ip."""
    event = {
        "_log_type": "conn",
        "id.orig_h": "2001:db8::1",
        "id.orig_p": "12345",
        "id.resp_h": "2001:db8::2",
        "id.resp_p": "443",
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.ip == "2001:db8::1"
    assert ocsf.dst_endpoint.ip == "2001:db8::2"


def test_normalize_conn_ipv6_ports(normalizer: ZeekNormalizer) -> None:
    """IPv6 conn events also have numeric ports cast from string."""
    event = {
        "_log_type": "conn",
        "id.orig_h": "::1",
        "id.orig_p": "54321",
        "id.resp_h": "::1",
        "id.resp_p": "8080",
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port == 54321
    assert ocsf.dst_endpoint.port == 8080


# ---------------------------------------------------------------------------
# Protocol variations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("proto", ["tcp", "udp", "icmp", "icmp6"])
def test_normalize_conn_protocol_variants(
    normalizer: ZeekNormalizer, proto: str
) -> None:
    """Each transport protocol is preserved verbatim in network_traffic."""
    event = {"_log_type": "conn", "proto": proto}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["protocol"] == proto


# ---------------------------------------------------------------------------
# Large byte counts
# ---------------------------------------------------------------------------


def test_normalize_conn_large_byte_counts(normalizer: ZeekNormalizer) -> None:
    """Byte counts in the 100GB range are stored without truncation."""
    large = 100 * 1024 * 1024 * 1024  # 100 GiB
    event = {
        "_log_type":     "conn",
        "orig_bytes":    large,
        "resp_bytes":    large,
        "orig_ip_bytes": large + 40,
        "resp_ip_bytes": large + 40,
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["orig_bytes"] == large
    assert ocsf.network_traffic["resp_bytes"] == large
    assert ocsf.network_traffic["orig_ip_bytes"] == large + 40
    assert ocsf.network_traffic["resp_ip_bytes"] == large + 40


# ---------------------------------------------------------------------------
# History flag edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("history", [
    "Sh",           # SYN+half-open
    "ShADadFfRr",   # Full bidirectional with RST
    "D",            # Data without SYN (mid-stream capture)
    "",             # Empty history
])
def test_normalize_conn_history_various_flags(
    normalizer: ZeekNormalizer, history: str
) -> None:
    """Zeek history strings of any format are stored verbatim."""
    event = {"_log_type": "conn", "history": history}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["history"] == history


# ---------------------------------------------------------------------------
# Full round-trip: all extended fields serialise cleanly
# ---------------------------------------------------------------------------


def test_full_conn_extended_round_trip(
    normalizer: ZeekNormalizer, full_conn_event: dict
) -> None:
    """End-to-end: conn event with all extended fields → JSON-serializable OCSFEvent."""
    ocsf = normalizer.normalize(full_conn_event)

    # Core classification
    assert ocsf.class_uid == 4001
    assert ocsf.class_name == "Network Activity"
    assert ocsf.category_uid == 4
    assert ocsf.metadata_product == "Zeek"
    assert ocsf.metadata_uid == "CfullEvent123"

    nt = ocsf.network_traffic

    # Original fields
    assert nt["protocol"] == "tcp"
    assert nt["service"] == "ssl"
    assert nt["duration"] == 12.345
    assert nt["orig_bytes"] == 1024
    assert nt["resp_bytes"] == 4096
    assert nt["conn_state"] == "SF"

    # Extended fields
    assert nt["missed_bytes"] == 0
    assert nt["history"] == "ShADadFf"
    assert nt["orig_pkts"] == 10
    assert nt["resp_pkts"] == 8
    assert nt["orig_ip_bytes"] == 1064
    assert nt["resp_ip_bytes"] == 4136
    assert nt["local_orig"] is True
    assert nt["local_resp"] is False
    assert nt["tunnel_parents"] == []
    assert nt["vlan"] == 100

    # Raw preserved
    assert ocsf.raw["uid"] == "CfullEvent123"

    # JSON serialisation must not raise and preserve all extended keys
    data = ocsf.model_dump(mode="json")
    assert data["class_uid"] == 4001
    traffic = data["network_traffic"]
    assert traffic["missed_bytes"] == 0
    assert traffic["history"] == "ShADadFf"
    assert traffic["orig_pkts"] == 10
    assert traffic["resp_pkts"] == 8
    assert traffic["orig_ip_bytes"] == 1064
    assert traffic["resp_ip_bytes"] == 4136
    assert traffic["local_orig"] is True
    assert traffic["local_resp"] is False
    assert traffic["tunnel_parents"] == []
    assert traffic["vlan"] == 100


# ===========================================================================
# Feature 7.8 — Zeek http → HTTPActivity (class_uid 4002): Extended Coverage
# ===========================================================================


# ---------------------------------------------------------------------------
# Extended http_event fixture with all Zeek http.log fields
# ---------------------------------------------------------------------------


@pytest.fixture
def full_http_event() -> dict:
    """Realistic Zeek http.log event with ALL fields populated."""
    return {
        "_log_type":           "http",
        "ts":                  1708331400.0,
        "uid":                 "HttpFull001",
        "id.orig_h":           "10.0.0.20",
        "id.orig_p":           "60001",
        "id.resp_h":           "203.0.113.50",
        "id.resp_p":           "8080",
        "host":                "api.example.com",
        "method":              "POST",
        "uri":                 "/api/v1/login",
        "version":             "1.1",
        "referrer":            "https://example.com/login",
        "user_agent":          "Mozilla/5.0 (compatible; scanner/1.0)",
        "request_body_len":    256,
        "response_body_len":   1024,
        "status_code":         200,
        "status_msg":          "OK",
        "trans_depth":         1,
        "orig_mime_types":     ["application/json"],
        "resp_mime_types":     ["application/json"],
        "username":            "admin",
        "orig_fuids":          ["ForigA1", "ForigA2"],
        "resp_fuids":          ["FrespB1"],
    }


# ---------------------------------------------------------------------------
# Feature 7.8: HTTP endpoint port mapping
# ---------------------------------------------------------------------------


def test_normalize_http_src_endpoint_port(
    normalizer: ZeekNormalizer, http_event: dict
) -> None:
    """HTTP source port (id.orig_p) maps to src_endpoint.port."""
    ocsf = normalizer.normalize(http_event)
    assert ocsf.src_endpoint.port == 60000


def test_normalize_http_dst_endpoint_port(
    normalizer: ZeekNormalizer, http_event: dict
) -> None:
    """HTTP destination port (id.resp_p) maps to dst_endpoint.port."""
    ocsf = normalizer.normalize(http_event)
    assert ocsf.dst_endpoint.port == 80


def test_normalize_http_port_as_string_cast(normalizer: ZeekNormalizer) -> None:
    """String ports in HTTP events are safely cast to int."""
    event = {
        "_log_type":  "http",
        "id.orig_p":  "54321",
        "id.resp_p":  "443",
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port == 54321
    assert ocsf.dst_endpoint.port == 443


def test_normalize_http_invalid_port_is_none(normalizer: ZeekNormalizer) -> None:
    """Non-numeric HTTP port string maps to None without raising."""
    event = {"_log_type": "http", "id.orig_p": "-", "id.resp_p": "N/A"}
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.port is None


def test_normalize_http_missing_ports_are_none(normalizer: ZeekNormalizer) -> None:
    """Absent port fields default to None in HTTP events."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.port is None


# ---------------------------------------------------------------------------
# Feature 7.8: Extended HTTP fields
# ---------------------------------------------------------------------------


def test_normalize_http_version(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """HTTP version string is captured in network_traffic."""
    ocsf = normalizer.normalize(full_http_event)
    assert ocsf.network_traffic["version"] == "1.1"


def test_normalize_http_version_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent version field defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.network_traffic["version"] is None


def test_normalize_http_status_msg(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """HTTP status_msg (e.g., 'OK') is captured in network_traffic."""
    ocsf = normalizer.normalize(full_http_event)
    assert ocsf.network_traffic["status_msg"] == "OK"


def test_normalize_http_status_msg_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent status_msg defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.network_traffic["status_msg"] is None


@pytest.mark.parametrize("status_msg", ["OK", "Not Found", "Forbidden", "Internal Server Error"])
def test_normalize_http_status_msg_variants(
    normalizer: ZeekNormalizer, status_msg: str
) -> None:
    """Various HTTP status messages are preserved verbatim."""
    event = {"_log_type": "http", "status_msg": status_msg}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["status_msg"] == status_msg


def test_normalize_http_request_body_len(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """request_body_len (HTTP request body bytes) is captured."""
    ocsf = normalizer.normalize(full_http_event)
    assert ocsf.network_traffic["request_body_len"] == 256


def test_normalize_http_request_body_len_zero(normalizer: ZeekNormalizer) -> None:
    """request_body_len=0 (GET request, no body) is preserved."""
    event = {"_log_type": "http", "request_body_len": 0}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["request_body_len"] == 0


def test_normalize_http_request_body_len_none_when_absent(
    normalizer: ZeekNormalizer,
) -> None:
    """Absent request_body_len defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.network_traffic["request_body_len"] is None


def test_normalize_http_response_body_len(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """response_body_len (HTTP response body bytes) is captured."""
    ocsf = normalizer.normalize(full_http_event)
    assert ocsf.network_traffic["response_body_len"] == 1024


def test_normalize_http_response_body_len_zero(normalizer: ZeekNormalizer) -> None:
    """response_body_len=0 (HEAD/empty responses) is preserved."""
    event = {"_log_type": "http", "response_body_len": 0}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["response_body_len"] == 0


def test_normalize_http_response_body_len_none_when_absent(
    normalizer: ZeekNormalizer,
) -> None:
    """Absent response_body_len defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.network_traffic["response_body_len"] is None


def test_normalize_http_trans_depth(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """HTTP pipeline depth (trans_depth) is captured."""
    ocsf = normalizer.normalize(full_http_event)
    assert ocsf.network_traffic["trans_depth"] == 1


def test_normalize_http_trans_depth_pipelined(normalizer: ZeekNormalizer) -> None:
    """HTTP pipelined requests (trans_depth > 1) are preserved."""
    event = {"_log_type": "http", "trans_depth": 5}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["trans_depth"] == 5


def test_normalize_http_trans_depth_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent trans_depth defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.network_traffic["trans_depth"] is None


def test_normalize_http_orig_mime_types(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """Request MIME types (orig_mime_types) are captured."""
    ocsf = normalizer.normalize(full_http_event)
    assert ocsf.network_traffic["orig_mime_types"] == ["application/json"]


def test_normalize_http_orig_mime_types_none_when_absent(
    normalizer: ZeekNormalizer,
) -> None:
    """Absent orig_mime_types defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.network_traffic["orig_mime_types"] is None


def test_normalize_http_username(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """HTTP auth username is captured in network_traffic."""
    ocsf = normalizer.normalize(full_http_event)
    assert ocsf.network_traffic["username"] == "admin"


def test_normalize_http_username_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent username defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.network_traffic["username"] is None


def test_normalize_http_orig_fuids(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """Originator file UIDs (orig_fuids) are captured."""
    ocsf = normalizer.normalize(full_http_event)
    assert ocsf.network_traffic["orig_fuids"] == ["ForigA1", "ForigA2"]


def test_normalize_http_orig_fuids_defaults_to_empty(normalizer: ZeekNormalizer) -> None:
    """Absent orig_fuids defaults to [] (not None)."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.network_traffic["orig_fuids"] == []


def test_normalize_http_resp_fuids(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """Response file UIDs (resp_fuids) are captured."""
    ocsf = normalizer.normalize(full_http_event)
    assert ocsf.network_traffic["resp_fuids"] == ["FrespB1"]


def test_normalize_http_resp_fuids_defaults_to_empty(normalizer: ZeekNormalizer) -> None:
    """Absent resp_fuids defaults to [] (not None)."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.network_traffic["resp_fuids"] == []


def test_normalize_http_resp_fuids_multiple(normalizer: ZeekNormalizer) -> None:
    """Multiple resp_fuids (e.g., inline images) are preserved."""
    event = {"_log_type": "http", "resp_fuids": ["FA", "FB", "FC"]}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["resp_fuids"] == ["FA", "FB", "FC"]


# ---------------------------------------------------------------------------
# Feature 7.8: Full round-trip with all extended HTTP fields
# ---------------------------------------------------------------------------


def test_full_http_extended_round_trip(
    normalizer: ZeekNormalizer, full_http_event: dict
) -> None:
    """End-to-end: http event with all extended fields → JSON-serializable OCSFEvent."""
    ocsf = normalizer.normalize(full_http_event)

    # Core OCSF classification
    assert ocsf.class_uid == 4002
    assert ocsf.class_name == "HTTP Activity"
    assert ocsf.category_uid == 4
    assert ocsf.metadata_product == "Zeek"
    assert ocsf.metadata_uid == "HttpFull001"
    assert ocsf.severity_id == 1

    # Endpoints with ports
    assert ocsf.src_endpoint.ip == "10.0.0.20"
    assert ocsf.src_endpoint.port == 60001
    assert ocsf.dst_endpoint.ip == "203.0.113.50"
    assert ocsf.dst_endpoint.port == 8080
    assert ocsf.dst_endpoint.hostname == "api.example.com"

    nt = ocsf.network_traffic

    # Core HTTP fields
    assert nt["method"] == "POST"
    assert nt["uri"] == "/api/v1/login"
    assert nt["status_code"] == 200
    assert nt["user_agent"] == "Mozilla/5.0 (compatible; scanner/1.0)"
    assert nt["referrer"] == "https://example.com/login"
    assert nt["resp_mime"] == ["application/json"]

    # Extended fields
    assert nt["version"] == "1.1"
    assert nt["status_msg"] == "OK"
    assert nt["request_body_len"] == 256
    assert nt["response_body_len"] == 1024
    assert nt["trans_depth"] == 1
    assert nt["orig_mime_types"] == ["application/json"]
    assert nt["username"] == "admin"
    assert nt["orig_fuids"] == ["ForigA1", "ForigA2"]
    assert nt["resp_fuids"] == ["FrespB1"]

    # Raw preserved
    assert ocsf.raw["uid"] == "HttpFull001"

    # JSON serialisation must not raise
    data = ocsf.model_dump(mode="json")
    assert data["class_uid"] == 4002
    assert data["class_name"] == "HTTP Activity"
    traffic = data["network_traffic"]
    assert traffic["method"] == "POST"
    assert traffic["uri"] == "/api/v1/login"
    assert traffic["status_code"] == 200
    assert traffic["status_msg"] == "OK"
    assert traffic["version"] == "1.1"
    assert traffic["request_body_len"] == 256
    assert traffic["response_body_len"] == 1024
    assert traffic["trans_depth"] == 1
    assert traffic["orig_mime_types"] == ["application/json"]
    assert traffic["username"] == "admin"
    assert traffic["orig_fuids"] == ["ForigA1", "ForigA2"]
    assert traffic["resp_fuids"] == ["FrespB1"]
    assert data["src_endpoint"]["port"] == 60001
    assert data["dst_endpoint"]["port"] == 8080


# ---------------------------------------------------------------------------
# Feature 7.8: HTTP-specific status code scenarios
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def test_normalize_http_method_variants(
    normalizer: ZeekNormalizer, method: str
) -> None:
    """All standard HTTP methods are preserved verbatim."""
    event = {"_log_type": "http", "method": method}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["method"] == method


@pytest.mark.parametrize("status_code,status_msg", [
    (200, "OK"),
    (201, "Created"),
    (301, "Moved Permanently"),
    (400, "Bad Request"),
    (401, "Unauthorized"),
    (403, "Forbidden"),
    (404, "Not Found"),
    (500, "Internal Server Error"),
])
def test_normalize_http_status_code_and_msg_pairs(
    normalizer: ZeekNormalizer, status_code: int, status_msg: str
) -> None:
    """Status code and message pairs are both captured correctly."""
    event = {"_log_type": "http", "status_code": status_code, "status_msg": status_msg}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["status_code"] == status_code
    assert ocsf.network_traffic["status_msg"] == status_msg


def test_normalize_http_large_body_sizes(normalizer: ZeekNormalizer) -> None:
    """Large request/response body sizes (multi-MB) are stored without truncation."""
    large = 50 * 1024 * 1024  # 50 MiB
    event = {
        "_log_type":          "http",
        "request_body_len":   large,
        "response_body_len":  large * 2,
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["request_body_len"] == large
    assert ocsf.network_traffic["response_body_len"] == large * 2


def test_normalize_http_missing_all_optional_fields(normalizer: ZeekNormalizer) -> None:
    """Minimal HTTP event (only _log_type) produces valid OCSFEvent with None defaults."""
    ocsf = normalizer.normalize({"_log_type": "http"})
    assert ocsf.class_uid == 4002
    assert ocsf.class_name == "HTTP Activity"
    assert ocsf.src_endpoint.ip is None
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.ip is None
    assert ocsf.dst_endpoint.port is None
    assert ocsf.dst_endpoint.hostname is None
    nt = ocsf.network_traffic
    assert nt["method"] is None
    assert nt["uri"] is None
    assert nt["version"] is None
    assert nt["status_code"] is None
    assert nt["status_msg"] is None
    assert nt["user_agent"] is None
    assert nt["referrer"] is None
    assert nt["request_body_len"] is None
    assert nt["response_body_len"] is None
    assert nt["trans_depth"] is None
    assert nt["orig_mime_types"] is None
    assert nt["resp_mime"] is None
    assert nt["username"] is None
    assert nt["orig_fuids"] == []
    assert nt["resp_fuids"] == []


# ===========================================================================
# Feature 7.7 — Zeek dns → DNSActivity (class_uid 4003): Extended Coverage
# ===========================================================================


# ---------------------------------------------------------------------------
# Full dns_event fixture with all Zeek dns.log fields
# ---------------------------------------------------------------------------


@pytest.fixture
def full_dns_event() -> dict:
    """Realistic Zeek dns.log event with ALL fields populated."""
    return {
        "_log_type":    "dns",
        "ts":           1708331400.0,
        "uid":          "DnsFull001",
        "id.orig_h":    "10.0.0.5",
        "id.orig_p":    "54321",
        "id.resp_h":    "8.8.8.8",
        "id.resp_p":    "53",
        "proto":        "udp",
        "trans_id":     12345,
        "rtt":          0.002345,
        "query":        "malware.example.com",
        "qclass":       1,
        "qclass_name":  "C_INTERNET",
        "qtype":        1,
        "qtype_name":   "A",
        "rcode":        0,
        "rcode_name":   "NOERROR",
        "AA":           False,
        "TC":           False,
        "RD":           True,
        "RA":           True,
        "Z":            0,
        "answers":      ["1.2.3.4", "5.6.7.8"],
        "TTLs":         [300.0, 300.0],
        "rejected":     False,
    }


# ---------------------------------------------------------------------------
# Feature 7.7: DNS endpoint port mapping
# ---------------------------------------------------------------------------


def test_normalize_dns_src_endpoint_port(
    normalizer: ZeekNormalizer, dns_event: dict
) -> None:
    """DNS source port (id.orig_p) maps to src_endpoint.port."""
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.src_endpoint.port == 54321


def test_normalize_dns_dst_endpoint_port(
    normalizer: ZeekNormalizer, dns_event: dict
) -> None:
    """DNS destination port (id.resp_p) maps to dst_endpoint.port."""
    ocsf = normalizer.normalize(dns_event)
    assert ocsf.dst_endpoint.port == 53


def test_normalize_dns_port_as_string_cast(normalizer: ZeekNormalizer) -> None:
    """String ports in DNS events are safely cast to int."""
    event = {
        "_log_type":  "dns",
        "id.orig_p":  "12345",
        "id.resp_p":  "53",
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port == 12345
    assert ocsf.dst_endpoint.port == 53


def test_normalize_dns_invalid_port_is_none(normalizer: ZeekNormalizer) -> None:
    """Non-numeric DNS port string maps to None without raising."""
    event = {"_log_type": "dns", "id.orig_p": "-", "id.resp_p": "N/A"}
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.port is None


def test_normalize_dns_missing_ports_are_none(normalizer: ZeekNormalizer) -> None:
    """Absent port fields default to None in DNS events."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.port is None


# ---------------------------------------------------------------------------
# Feature 7.7: trans_id and rtt
# ---------------------------------------------------------------------------


def test_normalize_dns_trans_id(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """DNS transaction ID (trans_id) is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["trans_id"] == 12345


def test_normalize_dns_trans_id_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent trans_id defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["trans_id"] is None


def test_normalize_dns_rtt(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """DNS round-trip time (rtt) is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["rtt"] == pytest.approx(0.002345)


def test_normalize_dns_rtt_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent rtt defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["rtt"] is None


# ---------------------------------------------------------------------------
# Feature 7.7: QCLASS fields
# ---------------------------------------------------------------------------


def test_normalize_dns_qclass_numeric(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """Numeric DNS class (qclass=1 for IN) is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["qclass"] == 1


def test_normalize_dns_qclass_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent qclass defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["qclass"] is None


def test_normalize_dns_qclass_name(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """DNS class name (qclass_name) is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["qclass_name"] == "C_INTERNET"


def test_normalize_dns_qclass_name_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent qclass_name defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["qclass_name"] is None


# ---------------------------------------------------------------------------
# Feature 7.7: Query type — qtype (name) and qtype_id (numeric)
# ---------------------------------------------------------------------------


def test_normalize_dns_qtype_id_numeric(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """Numeric DNS query type (qtype=1 for A) is captured as qtype_id."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["qtype_id"] == 1


def test_normalize_dns_qtype_id_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent numeric qtype defaults to None in qtype_id."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["qtype_id"] is None


@pytest.mark.parametrize("qtype,qtype_name", [
    (1,  "A"),
    (28, "AAAA"),
    (15, "MX"),
    (6,  "SOA"),
    (2,  "NS"),
    (16, "TXT"),
    (5,  "CNAME"),
    (12, "PTR"),
])
def test_normalize_dns_qtype_name_variants(
    normalizer: ZeekNormalizer, qtype: int, qtype_name: str
) -> None:
    """Various DNS query types are captured in both qtype (name) and qtype_id."""
    event = {"_log_type": "dns", "qtype": qtype, "qtype_name": qtype_name}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["qtype"] == qtype_name
    assert ocsf.network_traffic["qtype_id"] == qtype


# ---------------------------------------------------------------------------
# Feature 7.7: Response code — rcode (name) and rcode_id (numeric)
# ---------------------------------------------------------------------------


def test_normalize_dns_rcode_id_numeric(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """Numeric DNS response code (rcode=0 for NOERROR) is captured as rcode_id."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["rcode_id"] == 0


def test_normalize_dns_rcode_id_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent numeric rcode defaults to None in rcode_id."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["rcode_id"] is None


@pytest.mark.parametrize("rcode,rcode_name", [
    (0,  "NOERROR"),
    (1,  "FORMERR"),
    (2,  "SERVFAIL"),
    (3,  "NXDOMAIN"),
    (5,  "REFUSED"),
])
def test_normalize_dns_rcode_variants(
    normalizer: ZeekNormalizer, rcode: int, rcode_name: str
) -> None:
    """Various DNS response codes are captured in both rcode (name) and rcode_id."""
    event = {"_log_type": "dns", "rcode": rcode, "rcode_name": rcode_name}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["rcode"] == rcode_name
    assert ocsf.network_traffic["rcode_id"] == rcode


# ---------------------------------------------------------------------------
# Feature 7.7: DNS flags — AA, TC, RD, RA, Z
# ---------------------------------------------------------------------------


def test_normalize_dns_AA_false(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """AA (authoritative answer) flag is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["AA"] is False


def test_normalize_dns_AA_true(normalizer: ZeekNormalizer) -> None:
    """AA=True (response from authoritative server) is preserved."""
    event = {"_log_type": "dns", "AA": True}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["AA"] is True


def test_normalize_dns_AA_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent AA flag defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["AA"] is None


def test_normalize_dns_TC_false(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """TC (truncated) flag is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["TC"] is False


def test_normalize_dns_TC_true(normalizer: ZeekNormalizer) -> None:
    """TC=True (DNS message was truncated) is preserved."""
    event = {"_log_type": "dns", "TC": True}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["TC"] is True


def test_normalize_dns_TC_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent TC flag defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["TC"] is None


def test_normalize_dns_RD_true(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """RD (recursion desired) flag is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["RD"] is True


def test_normalize_dns_RD_false(normalizer: ZeekNormalizer) -> None:
    """RD=False (iterative query) is preserved."""
    event = {"_log_type": "dns", "RD": False}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["RD"] is False


def test_normalize_dns_RD_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent RD flag defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["RD"] is None


def test_normalize_dns_RA_true(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """RA (recursion available) flag is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["RA"] is True


def test_normalize_dns_RA_false(normalizer: ZeekNormalizer) -> None:
    """RA=False (server does not support recursion) is preserved."""
    event = {"_log_type": "dns", "RA": False}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["RA"] is False


def test_normalize_dns_RA_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent RA flag defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["RA"] is None


def test_normalize_dns_Z_zero(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """Z (reserved DNS field) value is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["Z"] == 0


def test_normalize_dns_Z_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent Z field defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["Z"] is None


# ---------------------------------------------------------------------------
# Feature 7.7: TTLs list
# ---------------------------------------------------------------------------


def test_normalize_dns_TTLs(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """TTLs list is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["TTLs"] == [300.0, 300.0]


def test_normalize_dns_TTLs_defaults_to_empty(normalizer: ZeekNormalizer) -> None:
    """Absent TTLs defaults to []."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["TTLs"] == []


def test_normalize_dns_TTLs_single_entry(normalizer: ZeekNormalizer) -> None:
    """Single-answer TTL list is preserved."""
    event = {"_log_type": "dns", "TTLs": [60.0]}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["TTLs"] == [60.0]


def test_normalize_dns_TTLs_varied(normalizer: ZeekNormalizer) -> None:
    """Varied TTL values (e.g., CNAME chains) are preserved."""
    event = {"_log_type": "dns", "TTLs": [86400.0, 3600.0, 300.0]}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["TTLs"] == [86400.0, 3600.0, 300.0]


# ---------------------------------------------------------------------------
# Feature 7.7: rejected field
# ---------------------------------------------------------------------------


def test_normalize_dns_rejected_false(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """rejected=False is captured in network_traffic."""
    ocsf = normalizer.normalize(full_dns_event)
    assert ocsf.network_traffic["rejected"] is False


def test_normalize_dns_rejected_true(normalizer: ZeekNormalizer) -> None:
    """rejected=True (DNS reply rejected by client) is preserved."""
    event = {"_log_type": "dns", "rejected": True}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["rejected"] is True


def test_normalize_dns_rejected_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent rejected field defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.network_traffic["rejected"] is None


# ---------------------------------------------------------------------------
# Feature 7.7: Multiple answers with matching TTLs
# ---------------------------------------------------------------------------


def test_normalize_dns_multiple_answers(normalizer: ZeekNormalizer) -> None:
    """Multiple DNS answers are all preserved."""
    event = {
        "_log_type": "dns",
        "answers": ["1.2.3.4", "5.6.7.8", "9.10.11.12"],
        "TTLs":    [300.0, 300.0, 300.0],
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["answers"] == ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
    assert ocsf.network_traffic["TTLs"] == [300.0, 300.0, 300.0]


def test_normalize_dns_answers_and_ttls_aligned(normalizer: ZeekNormalizer) -> None:
    """answers and TTLs lists have the same length (one TTL per answer)."""
    event = {
        "_log_type": "dns",
        "answers": ["ns1.example.com", "ns2.example.com"],
        "TTLs":    [86400.0, 86400.0],
    }
    ocsf = normalizer.normalize(event)
    assert len(ocsf.network_traffic["answers"]) == len(ocsf.network_traffic["TTLs"])


# ---------------------------------------------------------------------------
# Feature 7.7: NXDOMAIN and SERVFAIL detection scenarios
# ---------------------------------------------------------------------------


def test_normalize_dns_nxdomain(normalizer: ZeekNormalizer) -> None:
    """NXDOMAIN response (non-existent domain) is preserved with empty answers."""
    event = {
        "_log_type":    "dns",
        "uid":          "DnsNx001",
        "id.orig_h":    "10.0.0.5",
        "id.resp_h":    "8.8.8.8",
        "query":        "nonexistent.invalid",
        "qtype_name":   "A",
        "qtype":        1,
        "rcode":        3,
        "rcode_name":   "NXDOMAIN",
        "answers":      [],
        "TTLs":         [],
        "RD":           True,
        "RA":           True,
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["rcode"] == "NXDOMAIN"
    assert ocsf.network_traffic["rcode_id"] == 3
    assert ocsf.network_traffic["answers"] == []
    assert ocsf.network_traffic["TTLs"] == []


def test_normalize_dns_servfail(normalizer: ZeekNormalizer) -> None:
    """SERVFAIL response (server failure) is correctly mapped."""
    event = {
        "_log_type":  "dns",
        "query":      "example.com",
        "qtype_name": "A",
        "rcode":      2,
        "rcode_name": "SERVFAIL",
        "answers":    [],
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["rcode"] == "SERVFAIL"
    assert ocsf.network_traffic["rcode_id"] == 2


def test_normalize_dns_refused(normalizer: ZeekNormalizer) -> None:
    """REFUSED response is correctly mapped."""
    event = {
        "_log_type":  "dns",
        "query":      "internal.corp",
        "rcode":      5,
        "rcode_name": "REFUSED",
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["rcode"] == "REFUSED"
    assert ocsf.network_traffic["rcode_id"] == 5


# ---------------------------------------------------------------------------
# Feature 7.7: All-fields-absent minimal event
# ---------------------------------------------------------------------------


def test_normalize_dns_missing_all_extended_fields(normalizer: ZeekNormalizer) -> None:
    """Minimal DNS event (only _log_type) produces valid OCSFEvent with defaults."""
    ocsf = normalizer.normalize({"_log_type": "dns"})
    assert ocsf.class_uid == 4003
    assert ocsf.class_name == "DNS Activity"
    assert ocsf.src_endpoint.ip is None
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.ip is None
    assert ocsf.dst_endpoint.port is None
    nt = ocsf.network_traffic
    assert nt["proto"] is None
    assert nt["trans_id"] is None
    assert nt["rtt"] is None
    assert nt["query"] is None
    assert nt["qclass"] is None
    assert nt["qclass_name"] is None
    assert nt["qtype"] is None
    assert nt["qtype_id"] is None
    assert nt["rcode"] is None
    assert nt["rcode_id"] is None
    assert nt["AA"] is None
    assert nt["TC"] is None
    assert nt["RD"] is None
    assert nt["RA"] is None
    assert nt["Z"] is None
    assert nt["answers"] == []
    assert nt["TTLs"] == []
    assert nt["rejected"] is None


# ---------------------------------------------------------------------------
# Feature 7.7: Full round-trip with all extended DNS fields
# ---------------------------------------------------------------------------


def test_full_dns_extended_round_trip(
    normalizer: ZeekNormalizer, full_dns_event: dict
) -> None:
    """End-to-end: dns event with all extended fields → JSON-serializable OCSFEvent."""
    ocsf = normalizer.normalize(full_dns_event)

    # Core OCSF classification
    assert ocsf.class_uid == 4003
    assert ocsf.class_name == "DNS Activity"
    assert ocsf.category_uid == 4
    assert ocsf.metadata_product == "Zeek"
    assert ocsf.metadata_uid == "DnsFull001"
    assert ocsf.severity_id == 1

    # Endpoints with ports
    assert ocsf.src_endpoint.ip == "10.0.0.5"
    assert ocsf.src_endpoint.port == 54321
    assert ocsf.dst_endpoint.ip == "8.8.8.8"
    assert ocsf.dst_endpoint.port == 53

    nt = ocsf.network_traffic

    # Connection
    assert nt["proto"] == "udp"
    assert nt["trans_id"] == 12345
    assert nt["rtt"] == pytest.approx(0.002345)

    # Query classification
    assert nt["query"] == "malware.example.com"
    assert nt["qclass"] == 1
    assert nt["qclass_name"] == "C_INTERNET"
    assert nt["qtype"] == "A"
    assert nt["qtype_id"] == 1

    # Response classification
    assert nt["rcode"] == "NOERROR"
    assert nt["rcode_id"] == 0

    # DNS flags
    assert nt["AA"] is False
    assert nt["TC"] is False
    assert nt["RD"] is True
    assert nt["RA"] is True
    assert nt["Z"] == 0

    # Results
    assert nt["answers"] == ["1.2.3.4", "5.6.7.8"]
    assert nt["TTLs"] == [300.0, 300.0]
    assert nt["rejected"] is False

    # Raw preserved
    assert ocsf.raw["uid"] == "DnsFull001"

    # JSON serialisation must not raise
    data = ocsf.model_dump(mode="json")
    assert data["class_uid"] == 4003
    assert data["class_name"] == "DNS Activity"
    assert data["src_endpoint"]["port"] == 54321
    assert data["dst_endpoint"]["port"] == 53
    traffic = data["network_traffic"]
    assert traffic["proto"] == "udp"
    assert traffic["trans_id"] == 12345
    assert traffic["query"] == "malware.example.com"
    assert traffic["qclass"] == 1
    assert traffic["qclass_name"] == "C_INTERNET"
    assert traffic["qtype"] == "A"
    assert traffic["qtype_id"] == 1
    assert traffic["rcode"] == "NOERROR"
    assert traffic["rcode_id"] == 0
    assert traffic["AA"] is False
    assert traffic["TC"] is False
    assert traffic["RD"] is True
    assert traffic["RA"] is True
    assert traffic["Z"] == 0
    assert traffic["answers"] == ["1.2.3.4", "5.6.7.8"]
    assert traffic["TTLs"] == [300.0, 300.0]
    assert traffic["rejected"] is False


# ===========================================================================
# Feature 7.9 — Zeek ssl → NetworkActivity (class_uid 4001): Extended Coverage
# ===========================================================================


# ---------------------------------------------------------------------------
# Full ssl_event fixture with all Zeek ssl.log fields
# ---------------------------------------------------------------------------


@pytest.fixture
def full_ssl_event() -> dict:
    """Realistic Zeek ssl.log event with ALL fields populated."""
    return {
        "_log_type":                "ssl",
        "ts":                       1708331400.0,
        "uid":                      "SslFull001",
        "id.orig_h":                "10.0.0.5",
        "id.orig_p":                "54321",
        "id.resp_h":                "203.0.113.50",
        "id.resp_p":                "443",
        "version":                  "TLSv13",
        "cipher":                   "TLS_AES_256_GCM_SHA384",
        "curve":                    "x25519",
        "server_name":              "secure.example.com",
        "resumed":                  False,
        "next_protocol":            "h2",
        "established":              True,
        "ssl_history":              "Cc",
        "cert_chain_fuids":         ["FuuidA", "FuuidB"],
        "client_cert_chain_fuids":  ["FclientA"],
        "subject":                  "CN=secure.example.com,O=Example Corp,C=US",
        "issuer":                   "CN=Example CA,O=Example Corp,C=US",
        "not_valid_before":         1700000000.0,
        "not_valid_after":          1731535999.0,
        "ja3":                      "abc123def456",
        "ja3s":                     "789xyz012uvw",
        "validation_status":        "ok",
    }


# ---------------------------------------------------------------------------
# Feature 7.9: SSL endpoint port mapping
# ---------------------------------------------------------------------------


def test_normalize_ssl_src_endpoint_port(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """SSL source port (id.orig_p) maps to src_endpoint.port."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.src_endpoint.port == 54321


def test_normalize_ssl_dst_endpoint_port(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """SSL destination port (id.resp_p) maps to dst_endpoint.port."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.dst_endpoint.port == 443


def test_normalize_ssl_port_as_string_cast(normalizer: ZeekNormalizer) -> None:
    """String ports in SSL events are safely cast to int."""
    event = {
        "_log_type":  "ssl",
        "id.orig_p":  "12345",
        "id.resp_p":  "443",
    }
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port == 12345
    assert ocsf.dst_endpoint.port == 443


def test_normalize_ssl_invalid_port_is_none(normalizer: ZeekNormalizer) -> None:
    """Non-numeric SSL port string maps to None without raising."""
    event = {"_log_type": "ssl", "id.orig_p": "-", "id.resp_p": "N/A"}
    ocsf = normalizer.normalize(event)
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.port is None


def test_normalize_ssl_missing_ports_are_none(normalizer: ZeekNormalizer) -> None:
    """Absent port fields default to None in SSL events."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.port is None


# ---------------------------------------------------------------------------
# Feature 7.9: TLS curve
# ---------------------------------------------------------------------------


def test_normalize_ssl_curve(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """TLS elliptic curve (curve) is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["curve"] == "x25519"


def test_normalize_ssl_curve_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent curve field defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["curve"] is None


@pytest.mark.parametrize("curve", ["secp256r1", "secp384r1", "x25519", "x448"])
def test_normalize_ssl_curve_variants(
    normalizer: ZeekNormalizer, curve: str
) -> None:
    """Various TLS curves are preserved verbatim."""
    event = {"_log_type": "ssl", "curve": curve}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["curve"] == curve


# ---------------------------------------------------------------------------
# Feature 7.9: Session resumption
# ---------------------------------------------------------------------------


def test_normalize_ssl_resumed_false(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """resumed=False (new TLS session) is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["resumed"] is False


def test_normalize_ssl_resumed_true(normalizer: ZeekNormalizer) -> None:
    """resumed=True (session ticket/ID reuse) is preserved."""
    event = {"_log_type": "ssl", "resumed": True}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["resumed"] is True


def test_normalize_ssl_resumed_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent resumed field defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["resumed"] is None


# ---------------------------------------------------------------------------
# Feature 7.9: ALPN next protocol
# ---------------------------------------------------------------------------


def test_normalize_ssl_next_protocol(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """next_protocol (ALPN) is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["next_protocol"] == "h2"


def test_normalize_ssl_next_protocol_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent next_protocol defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["next_protocol"] is None


@pytest.mark.parametrize("proto", ["h2", "http/1.1", "ftp", "smtp"])
def test_normalize_ssl_next_protocol_variants(
    normalizer: ZeekNormalizer, proto: str
) -> None:
    """Various ALPN protocols are preserved verbatim."""
    event = {"_log_type": "ssl", "next_protocol": proto}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["next_protocol"] == proto


# ---------------------------------------------------------------------------
# Feature 7.9: SSL history flags
# ---------------------------------------------------------------------------


def test_normalize_ssl_history(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """ssl_history flags are captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["ssl_history"] == "Cc"


def test_normalize_ssl_history_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent ssl_history defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["ssl_history"] is None


@pytest.mark.parametrize("history", ["Cc", "CcDd", "Ff", ""])
def test_normalize_ssl_history_variants(
    normalizer: ZeekNormalizer, history: str
) -> None:
    """Various ssl_history flag strings are stored verbatim."""
    event = {"_log_type": "ssl", "ssl_history": history}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["ssl_history"] == history


# ---------------------------------------------------------------------------
# Feature 7.9: Client certificate chain
# ---------------------------------------------------------------------------


def test_normalize_ssl_client_cert_chain(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """client_cert_chain_fuids maps to client_cert_chain in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["client_cert_chain"] == ["FclientA"]


def test_normalize_ssl_client_cert_chain_none_when_absent(
    normalizer: ZeekNormalizer,
) -> None:
    """Absent client_cert_chain_fuids defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["client_cert_chain"] is None


def test_normalize_ssl_client_cert_chain_multiple(normalizer: ZeekNormalizer) -> None:
    """Multiple client cert UIDs are preserved."""
    event = {"_log_type": "ssl", "client_cert_chain_fuids": ["FA", "FB", "FC"]}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["client_cert_chain"] == ["FA", "FB", "FC"]


# ---------------------------------------------------------------------------
# Feature 7.9: Certificate subject and issuer
# ---------------------------------------------------------------------------


def test_normalize_ssl_subject(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """Certificate subject DN is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["subject"] == "CN=secure.example.com,O=Example Corp,C=US"


def test_normalize_ssl_subject_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent subject field defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["subject"] is None


def test_normalize_ssl_issuer(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """Certificate issuer DN is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["issuer"] == "CN=Example CA,O=Example Corp,C=US"


def test_normalize_ssl_issuer_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent issuer field defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["issuer"] is None


# ---------------------------------------------------------------------------
# Feature 7.9: Certificate validity timestamps
# ---------------------------------------------------------------------------


def test_normalize_ssl_not_valid_before(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """Certificate not_valid_before timestamp is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["not_valid_before"] == 1700000000.0


def test_normalize_ssl_not_valid_before_none_when_absent(
    normalizer: ZeekNormalizer,
) -> None:
    """Absent not_valid_before defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["not_valid_before"] is None


def test_normalize_ssl_not_valid_after(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """Certificate not_valid_after timestamp is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["not_valid_after"] == 1731535999.0


def test_normalize_ssl_not_valid_after_none_when_absent(
    normalizer: ZeekNormalizer,
) -> None:
    """Absent not_valid_after defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["not_valid_after"] is None


# ---------------------------------------------------------------------------
# Feature 7.9: JA3 / JA3S fingerprints
# ---------------------------------------------------------------------------


def test_normalize_ssl_ja3(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """JA3 client fingerprint is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["ja3"] == "abc123def456"


def test_normalize_ssl_ja3_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent ja3 defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["ja3"] is None


def test_normalize_ssl_ja3s(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """JA3S server fingerprint is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["ja3s"] == "789xyz012uvw"


def test_normalize_ssl_ja3s_none_when_absent(normalizer: ZeekNormalizer) -> None:
    """Absent ja3s defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["ja3s"] is None


# ---------------------------------------------------------------------------
# Feature 7.9: Certificate validation status
# ---------------------------------------------------------------------------


def test_normalize_ssl_validation_status_ok(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """validation_status='ok' is captured in network_traffic."""
    ocsf = normalizer.normalize(full_ssl_event)
    assert ocsf.network_traffic["validation_status"] == "ok"


def test_normalize_ssl_validation_status_none_when_absent(
    normalizer: ZeekNormalizer,
) -> None:
    """Absent validation_status defaults to None."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.network_traffic["validation_status"] is None


@pytest.mark.parametrize("status", [
    "ok",
    "self signed certificate",
    "certificate has expired",
    "unable to get local issuer certificate",
])
def test_normalize_ssl_validation_status_variants(
    normalizer: ZeekNormalizer, status: str
) -> None:
    """Various validation_status strings are preserved verbatim."""
    event = {"_log_type": "ssl", "validation_status": status}
    ocsf = normalizer.normalize(event)
    assert ocsf.network_traffic["validation_status"] == status


# ---------------------------------------------------------------------------
# Feature 7.9: Minimal SSL event — all optional fields absent
# ---------------------------------------------------------------------------


def test_normalize_ssl_missing_all_optional_fields(normalizer: ZeekNormalizer) -> None:
    """Minimal SSL event (only _log_type) produces valid OCSFEvent with None defaults."""
    ocsf = normalizer.normalize({"_log_type": "ssl"})
    assert ocsf.class_uid == 4001
    assert ocsf.class_name == "Network Activity"
    assert ocsf.src_endpoint.ip is None
    assert ocsf.src_endpoint.port is None
    assert ocsf.dst_endpoint.ip is None
    assert ocsf.dst_endpoint.port is None
    assert ocsf.dst_endpoint.hostname is None
    nt = ocsf.network_traffic
    assert nt["version"] is None
    assert nt["cipher"] is None
    assert nt["curve"] is None
    assert nt["server_name"] is None
    assert nt["established"] is None
    assert nt["resumed"] is None
    assert nt["next_protocol"] is None
    assert nt["ssl_history"] is None
    assert nt["cert_chain"] is None
    assert nt["client_cert_chain"] is None
    assert nt["subject"] is None
    assert nt["issuer"] is None
    assert nt["not_valid_before"] is None
    assert nt["not_valid_after"] is None
    assert nt["ja3"] is None
    assert nt["ja3s"] is None
    assert nt["validation_status"] is None


# ---------------------------------------------------------------------------
# Feature 7.9: Full round-trip with all extended TLS fields
# ---------------------------------------------------------------------------


def test_full_ssl_extended_round_trip(
    normalizer: ZeekNormalizer, full_ssl_event: dict
) -> None:
    """End-to-end: ssl event with all extended fields → JSON-serializable OCSFEvent."""
    ocsf = normalizer.normalize(full_ssl_event)

    # Core OCSF classification
    assert ocsf.class_uid == 4001
    assert ocsf.class_name == "Network Activity"
    assert ocsf.category_uid == 4
    assert ocsf.metadata_product == "Zeek"
    assert ocsf.metadata_uid == "SslFull001"
    assert ocsf.severity_id == 1

    # Endpoints with ports
    assert ocsf.src_endpoint.ip == "10.0.0.5"
    assert ocsf.src_endpoint.port == 54321
    assert ocsf.dst_endpoint.ip == "203.0.113.50"
    assert ocsf.dst_endpoint.port == 443
    assert ocsf.dst_endpoint.hostname == "secure.example.com"

    nt = ocsf.network_traffic

    # Core TLS fields
    assert nt["version"] == "TLSv13"
    assert nt["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert nt["server_name"] == "secure.example.com"
    assert nt["established"] is True

    # Extended TLS fields
    assert nt["curve"] == "x25519"
    assert nt["resumed"] is False
    assert nt["next_protocol"] == "h2"
    assert nt["ssl_history"] == "Cc"
    assert nt["cert_chain"] == ["FuuidA", "FuuidB"]
    assert nt["client_cert_chain"] == ["FclientA"]
    assert nt["subject"] == "CN=secure.example.com,O=Example Corp,C=US"
    assert nt["issuer"] == "CN=Example CA,O=Example Corp,C=US"
    assert nt["not_valid_before"] == 1700000000.0
    assert nt["not_valid_after"] == 1731535999.0
    assert nt["ja3"] == "abc123def456"
    assert nt["ja3s"] == "789xyz012uvw"
    assert nt["validation_status"] == "ok"

    # Raw preserved
    assert ocsf.raw["uid"] == "SslFull001"

    # JSON serialisation must not raise
    data = ocsf.model_dump(mode="json")
    assert data["class_uid"] == 4001
    assert data["class_name"] == "Network Activity"
    assert data["src_endpoint"]["port"] == 54321
    assert data["dst_endpoint"]["port"] == 443
    assert data["dst_endpoint"]["hostname"] == "secure.example.com"
    traffic = data["network_traffic"]
    assert traffic["version"] == "TLSv13"
    assert traffic["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert traffic["curve"] == "x25519"
    assert traffic["server_name"] == "secure.example.com"
    assert traffic["established"] is True
    assert traffic["resumed"] is False
    assert traffic["next_protocol"] == "h2"
    assert traffic["ssl_history"] == "Cc"
    assert traffic["cert_chain"] == ["FuuidA", "FuuidB"]
    assert traffic["client_cert_chain"] == ["FclientA"]
    assert traffic["subject"] == "CN=secure.example.com,O=Example Corp,C=US"
    assert traffic["issuer"] == "CN=Example CA,O=Example Corp,C=US"
    assert traffic["not_valid_before"] == 1700000000.0
    assert traffic["not_valid_after"] == 1731535999.0
    assert traffic["ja3"] == "abc123def456"
    assert traffic["ja3s"] == "789xyz012uvw"
    assert traffic["validation_status"] == "ok"
