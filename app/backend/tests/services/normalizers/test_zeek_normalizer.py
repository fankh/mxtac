"""Tests for ZeekNormalizer — Feature 7.6

Coverage:
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
        "id.resp_h":   "8.8.8.8",
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
        "id.resp_h":        "203.0.113.1",
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
