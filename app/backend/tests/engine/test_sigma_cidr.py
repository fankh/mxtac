"""Tests for feature 8.11 — Sigma: `cidr` modifier.

The `cidr` modifier checks whether an event field value (an IP address) falls
within one or more CIDR network ranges specified in the rule.

Coverage:
  - IP within single CIDR → True
  - IP outside single CIDR → False
  - /32 host route matches exact IP → True
  - /32 host route does not match other IP → False
  - IP at network boundary (first address) → True
  - IP at network boundary (broadcast address) → True
  - Field absent from event → False
  - Field explicitly None → False
  - Field holds non-IP string → False (graceful degradation)
  - Field holds integer (not a valid IP string) → False
  - Nested field (dot notation) → matches correctly
  - List of CIDRs — OR semantics: IP in first network → True
  - List of CIDRs — OR semantics: IP in last network → True
  - List of CIDRs — OR semantics: IP in none → False
  - `cidr|all` — AND semantics: IP in all networks → True
  - `cidr|all` — AND semantics: IP in some but not all → False
  - Invalid CIDR in rule (single value) → False (graceful degradation)
  - Invalid CIDR mixed with valid: IP in valid network → True
  - IPv6 address within IPv6 CIDR → True
  - IPv6 address outside IPv6 CIDR → False
  - IPv4 address against IPv6 CIDR → False (type mismatch)
  - CIDR with host bits set (strict=False) → accepted and matches
  - Private RFC-1918 ranges: 10.x.x.x, 172.16.x.x, 192.168.x.x
  - Via load_rule_yaml: rule with single CIDR matches event
  - Via load_rule_yaml: rule with single CIDR does not match event
  - Via load_rule_yaml: rule with list of CIDRs matches event (OR)
  - Via load_rule_yaml: rule with list of CIDRs — no match
  - Via load_rule_yaml: detection field absent from event → no match
"""

from __future__ import annotations

import pytest

from app.engine.sigma_engine import SigmaEngine, _Condition


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_condition(field_expr: str, values: object, condition: str = "selection") -> _Condition:
    """Build a _Condition with a single selection using the given field expression."""
    detection = {
        "selection": {field_expr: values},
        "condition": condition,
    }
    return _Condition(detection)


def _matches(field_expr: str, values: object, event: dict) -> bool:
    return _make_condition(field_expr, values).matches(event)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


# ---------------------------------------------------------------------------
# Basic matching — IPv4
# ---------------------------------------------------------------------------

def test_cidr_ip_within_network_matches() -> None:
    """IP address within CIDR network → True."""
    assert _matches("src_ip|cidr", "192.168.1.0/24", {"src_ip": "192.168.1.100"}) is True


def test_cidr_ip_outside_network_no_match() -> None:
    """IP address outside CIDR network → False."""
    assert _matches("src_ip|cidr", "192.168.1.0/24", {"src_ip": "192.168.2.1"}) is False


def test_cidr_host_route_exact_match() -> None:
    """/32 CIDR matches only the exact IP → True."""
    assert _matches("ip|cidr", "10.0.0.5/32", {"ip": "10.0.0.5"}) is True


def test_cidr_host_route_no_match() -> None:
    """/32 CIDR does not match a neighbouring IP → False."""
    assert _matches("ip|cidr", "10.0.0.5/32", {"ip": "10.0.0.6"}) is False


def test_cidr_network_first_address_matches() -> None:
    """IP at the network address (first) of a CIDR range → True."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"src_ip": "10.0.0.0"}) is True


def test_cidr_network_broadcast_address_matches() -> None:
    """IP at the broadcast address (last) of a CIDR range → True."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"src_ip": "10.255.255.255"}) is True


def test_cidr_slash16_range_matches() -> None:
    """IP within a /16 range → True."""
    assert _matches("dst_ip|cidr", "172.16.0.0/16", {"dst_ip": "172.16.42.7"}) is True


def test_cidr_slash16_range_no_match() -> None:
    """IP outside a /16 range → False."""
    assert _matches("dst_ip|cidr", "172.16.0.0/16", {"dst_ip": "172.17.0.1"}) is False


def test_cidr_host_bits_set_strict_false() -> None:
    """CIDR with host bits set (e.g. 192.168.1.5/24) is accepted (strict=False) and matches."""
    # 192.168.1.5/24 → treated as 192.168.1.0/24
    assert _matches("src_ip|cidr", "192.168.1.5/24", {"src_ip": "192.168.1.200"}) is True


def test_cidr_host_bits_set_outside_range() -> None:
    """CIDR with host bits set, IP from a different /24 → False."""
    assert _matches("src_ip|cidr", "192.168.1.5/24", {"src_ip": "192.168.2.1"}) is False


# ---------------------------------------------------------------------------
# RFC-1918 private ranges
# ---------------------------------------------------------------------------

def test_cidr_rfc1918_10_range() -> None:
    """IP in 10.0.0.0/8 private range → True."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"src_ip": "10.123.45.67"}) is True


def test_cidr_rfc1918_172_range() -> None:
    """IP in 172.16.0.0/12 private range → True."""
    assert _matches("src_ip|cidr", "172.16.0.0/12", {"src_ip": "172.31.255.254"}) is True


def test_cidr_rfc1918_172_outside() -> None:
    """IP 172.32.x.x is outside 172.16.0.0/12 → False."""
    assert _matches("src_ip|cidr", "172.16.0.0/12", {"src_ip": "172.32.0.1"}) is False


def test_cidr_rfc1918_192_range() -> None:
    """IP in 192.168.0.0/16 private range → True."""
    assert _matches("src_ip|cidr", "192.168.0.0/16", {"src_ip": "192.168.255.1"}) is True


# ---------------------------------------------------------------------------
# Field existence
# ---------------------------------------------------------------------------

def test_cidr_field_missing_returns_false() -> None:
    """Field not present in event → False."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"other_field": "10.1.2.3"}) is False


def test_cidr_field_none_returns_false() -> None:
    """Field explicitly set to None → False."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"src_ip": None}) is False


# ---------------------------------------------------------------------------
# Non-IP field values (graceful degradation)
# ---------------------------------------------------------------------------

def test_cidr_non_ip_string_returns_false() -> None:
    """Field holds a non-IP string → False (exception caught gracefully)."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"src_ip": "not-an-ip"}) is False


def test_cidr_integer_field_returns_false() -> None:
    """Field holds an integer (str coerced to '42', not a valid IP) → False."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"src_ip": 42}) is False


def test_cidr_empty_string_field_returns_false() -> None:
    """Field holds an empty string → False."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"src_ip": ""}) is False


def test_cidr_hostname_in_field_returns_false() -> None:
    """Field holds a hostname instead of an IP → False."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"src_ip": "malicious.example.com"}) is False


# ---------------------------------------------------------------------------
# Nested field (dot notation)
# ---------------------------------------------------------------------------

def test_cidr_nested_field_match() -> None:
    """Dot-notation nested field lookup works with cidr modifier."""
    event = {"src_endpoint": {"ip": "192.168.5.10"}}
    assert _matches("src_endpoint.ip|cidr", "192.168.0.0/16", event) is True


def test_cidr_nested_field_no_match() -> None:
    """Dot-notation nested field with IP outside network → False."""
    event = {"src_endpoint": {"ip": "10.0.0.1"}}
    assert _matches("src_endpoint.ip|cidr", "192.168.0.0/16", event) is False


def test_cidr_nested_field_missing_intermediate() -> None:
    """Dot-notation where intermediate key is absent → False."""
    event = {"src_endpoint": {}}
    assert _matches("src_endpoint.ip|cidr", "192.168.0.0/16", event) is False


def test_cidr_nested_field_missing_parent() -> None:
    """Dot-notation where parent key is absent entirely → False."""
    event = {"dst_endpoint": {"ip": "192.168.1.1"}}
    assert _matches("src_endpoint.ip|cidr", "192.168.0.0/16", event) is False


# ---------------------------------------------------------------------------
# List of CIDRs — OR semantics
# ---------------------------------------------------------------------------

def test_cidr_list_ip_in_first_network() -> None:
    """OR semantics: IP in first listed CIDR → True."""
    cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert _matches("src_ip|cidr", cidrs, {"src_ip": "10.50.1.1"}) is True


def test_cidr_list_ip_in_middle_network() -> None:
    """OR semantics: IP in second listed CIDR → True."""
    cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert _matches("src_ip|cidr", cidrs, {"src_ip": "172.20.0.1"}) is True


def test_cidr_list_ip_in_last_network() -> None:
    """OR semantics: IP in last listed CIDR → True."""
    cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert _matches("src_ip|cidr", cidrs, {"src_ip": "192.168.100.200"}) is True


def test_cidr_list_ip_in_none() -> None:
    """OR semantics: IP in no listed CIDR → False."""
    cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert _matches("src_ip|cidr", cidrs, {"src_ip": "8.8.8.8"}) is False


def test_cidr_list_single_cidr() -> None:
    """Single-element list behaves as a plain value."""
    assert _matches("src_ip|cidr", ["10.0.0.0/8"], {"src_ip": "10.1.2.3"}) is True


# ---------------------------------------------------------------------------
# `cidr|all` — AND semantics
# ---------------------------------------------------------------------------

def test_cidr_all_ip_in_all_networks() -> None:
    """cidr|all: IP that falls in every listed CIDR → True.

    10.0.0.1 is in 0.0.0.0/0 (all IPs) AND 10.0.0.0/8 AND 10.0.0.0/24.
    """
    cidrs = ["0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/24"]
    assert _matches("src_ip|cidr|all", cidrs, {"src_ip": "10.0.0.1"}) is True


def test_cidr_all_ip_in_some_but_not_all() -> None:
    """cidr|all: IP in only some CIDRs → False."""
    # 10.1.2.3 is in 10.0.0.0/8 but NOT in 192.168.0.0/16
    cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
    assert _matches("src_ip|cidr|all", cidrs, {"src_ip": "10.1.2.3"}) is False


def test_cidr_all_ip_in_none() -> None:
    """cidr|all: IP in no CIDR → False."""
    cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
    assert _matches("src_ip|cidr|all", cidrs, {"src_ip": "8.8.4.4"}) is False


def test_cidr_all_single_value_matches() -> None:
    """cidr|all with single CIDR: IP in that network → True."""
    assert _matches("ip|cidr|all", ["10.0.0.0/8"], {"ip": "10.99.0.1"}) is True


def test_cidr_all_single_value_no_match() -> None:
    """cidr|all with single CIDR: IP outside → False."""
    assert _matches("ip|cidr|all", ["10.0.0.0/8"], {"ip": "172.16.0.1"}) is False


# ---------------------------------------------------------------------------
# Invalid CIDR in rule (graceful degradation)
# ---------------------------------------------------------------------------

def test_cidr_invalid_single_cidr_returns_false() -> None:
    """Invalid CIDR in rule appends None — matching returns False."""
    assert _matches("src_ip|cidr", "not-a-cidr", {"src_ip": "10.0.0.1"}) is False


def test_cidr_invalid_cidr_in_list_others_valid() -> None:
    """Invalid CIDR mixed with valid: valid network still matches (OR semantics)."""
    cidrs = ["bad-cidr", "10.0.0.0/8"]
    assert _matches("src_ip|cidr", cidrs, {"src_ip": "10.5.5.5"}) is True


def test_cidr_invalid_cidr_in_list_no_valid_match() -> None:
    """Invalid CIDR mixed with valid: IP outside valid network → False."""
    cidrs = ["bad-cidr", "10.0.0.0/8"]
    assert _matches("src_ip|cidr", cidrs, {"src_ip": "8.8.8.8"}) is False


def test_cidr_all_invalid_cidr_in_list() -> None:
    """cidr|all with an invalid CIDR (None) in the list → False (None check fails)."""
    cidrs = ["0.0.0.0/0", "bad-cidr"]
    assert _matches("src_ip|cidr|all", cidrs, {"src_ip": "1.2.3.4"}) is False


# ---------------------------------------------------------------------------
# IPv6 support
# ---------------------------------------------------------------------------

def test_cidr_ipv6_address_within_network() -> None:
    """IPv6 address within an IPv6 CIDR → True."""
    assert _matches("src_ip|cidr", "2001:db8::/32", {"src_ip": "2001:db8::1"}) is True


def test_cidr_ipv6_address_outside_network() -> None:
    """IPv6 address outside an IPv6 CIDR → False."""
    assert _matches("src_ip|cidr", "2001:db8::/32", {"src_ip": "2001:db9::1"}) is False


def test_cidr_ipv6_loopback() -> None:
    """IPv6 loopback (::1) in ::1/128 → True."""
    assert _matches("src_ip|cidr", "::1/128", {"src_ip": "::1"}) is True


def test_cidr_ipv6_loopback_no_match() -> None:
    """Non-loopback IPv6 address against ::1/128 → False."""
    assert _matches("src_ip|cidr", "::1/128", {"src_ip": "::2"}) is False


def test_cidr_ipv4_against_ipv6_cidr_returns_false() -> None:
    """IPv4 address event field against IPv6 CIDR → False (type mismatch, caught gracefully)."""
    assert _matches("src_ip|cidr", "2001:db8::/32", {"src_ip": "192.168.1.1"}) is False


def test_cidr_ipv6_against_ipv4_cidr_returns_false() -> None:
    """IPv6 address event field against IPv4 CIDR → False (type mismatch, caught gracefully)."""
    assert _matches("src_ip|cidr", "10.0.0.0/8", {"src_ip": "2001:db8::1"}) is False


# ---------------------------------------------------------------------------
# Integration — via load_rule_yaml
# ---------------------------------------------------------------------------

_RULE_SINGLE_CIDR = """\
title: Detect Private IP Source
id: test-cidr-001
status: test
level: medium
logsource:
  category: network_connection
detection:
  selection:
    src_ip|cidr: '192.168.0.0/16'
  condition: selection
"""

_RULE_LIST_CIDR = """\
title: Detect RFC-1918 Source IPs
id: test-cidr-002
status: test
level: low
logsource:
  category: network_connection
detection:
  selection:
    src_ip|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  condition: selection
"""

_RULE_NESTED_CIDR = """\
title: Detect Lateral Movement Source
id: test-cidr-003
status: test
level: high
logsource:
  category: network_connection
detection:
  selection:
    src_endpoint.ip|cidr: '10.0.0.0/8'
  condition: selection
"""


def test_rule_single_cidr_matches(engine: SigmaEngine) -> None:
    """Rule with single CIDR matches event whose src_ip is in the range."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_CIDR)
    assert rule is not None
    assert rule._matcher.matches({"src_ip": "192.168.42.1"}) is True


def test_rule_single_cidr_no_match_outside_range(engine: SigmaEngine) -> None:
    """Rule with single CIDR does not match event with IP outside range."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_CIDR)
    assert rule is not None
    assert rule._matcher.matches({"src_ip": "8.8.8.8"}) is False


def test_rule_single_cidr_no_match_different_field(engine: SigmaEngine) -> None:
    """Rule does not match when the IP is in a different (non-detection) field."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_CIDR)
    assert rule is not None
    assert rule._matcher.matches({"dst_ip": "192.168.1.1"}) is False


def test_rule_list_cidr_first_network_matches(engine: SigmaEngine) -> None:
    """Rule list CIDRs: IP in first network (10.x.x.x) → True."""
    rule = engine.load_rule_yaml(_RULE_LIST_CIDR)
    assert rule is not None
    assert rule._matcher.matches({"src_ip": "10.20.30.40"}) is True


def test_rule_list_cidr_second_network_matches(engine: SigmaEngine) -> None:
    """Rule list CIDRs: IP in second network (172.16-31.x.x) → True."""
    rule = engine.load_rule_yaml(_RULE_LIST_CIDR)
    assert rule is not None
    assert rule._matcher.matches({"src_ip": "172.16.0.1"}) is True


def test_rule_list_cidr_third_network_matches(engine: SigmaEngine) -> None:
    """Rule list CIDRs: IP in third network (192.168.x.x) → True."""
    rule = engine.load_rule_yaml(_RULE_LIST_CIDR)
    assert rule is not None
    assert rule._matcher.matches({"src_ip": "192.168.1.254"}) is True


def test_rule_list_cidr_no_match_public_ip(engine: SigmaEngine) -> None:
    """Rule list CIDRs: public IP not in any private range → False."""
    rule = engine.load_rule_yaml(_RULE_LIST_CIDR)
    assert rule is not None
    assert rule._matcher.matches({"src_ip": "1.1.1.1"}) is False


def test_rule_nested_cidr_field_matches(engine: SigmaEngine) -> None:
    """Rule with dot-notation CIDR field matches nested event structure."""
    rule = engine.load_rule_yaml(_RULE_NESTED_CIDR)
    assert rule is not None
    event = {"src_endpoint": {"ip": "10.0.50.100"}}
    assert rule._matcher.matches(event) is True


def test_rule_nested_cidr_field_no_match(engine: SigmaEngine) -> None:
    """Rule with dot-notation CIDR field: IP outside range → False."""
    rule = engine.load_rule_yaml(_RULE_NESTED_CIDR)
    assert rule is not None
    event = {"src_endpoint": {"ip": "172.16.0.1"}}
    assert rule._matcher.matches(event) is False


def test_rule_cidr_field_missing_from_event(engine: SigmaEngine) -> None:
    """CIDR rule: detection field absent from event → False."""
    rule = engine.load_rule_yaml(_RULE_SINGLE_CIDR)
    assert rule is not None
    assert rule._matcher.matches({"dst_ip": "192.168.1.1", "port": 443}) is False
