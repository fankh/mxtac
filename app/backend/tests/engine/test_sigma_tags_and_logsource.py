"""ATT&CK tag parsing (tactics by name) and logsource matching
(product / category / service, each optional)."""

from __future__ import annotations

from typing import Any

import pytest

from app.engine.sigma_engine import SigmaEngine, parse_attack_tags
from app.services.normalizers.ocsf import Endpoint, OCSFClass, OCSFEvent

# ── Tags ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("tag", "tactic_id"),
    [
        ("attack.credential-access", "TA0006"),
        ("attack.credential_access", "TA0006"),
        ("attack.Credential-Access", "TA0006"),
        ("attack.initial-access", "TA0001"),
        ("attack.execution", "TA0002"),
        ("attack.persistence", "TA0003"),
        ("attack.privilege-escalation", "TA0004"),
        ("attack.defense-evasion", "TA0005"),
        ("attack.discovery", "TA0007"),
        ("attack.lateral-movement", "TA0008"),
        ("attack.collection", "TA0009"),
        ("attack.exfiltration", "TA0010"),
        ("attack.command-and-control", "TA0011"),
        ("attack.impact", "TA0040"),
        ("attack.resource-development", "TA0042"),
        ("attack.reconnaissance", "TA0043"),
        ("attack.ta0006", "TA0006"),
        ("attack.TA0006", "TA0006"),
    ],
)
def test_tactic_tag(tag: str, tactic_id: str) -> None:
    assert parse_attack_tags([tag]) == ([], [tactic_id])


def test_technique_and_tactic_tags_together() -> None:
    techniques, tactics = parse_attack_tags([
        "attack.credential-access",
        "attack.t1003.001",
        "attack.T1110",
        "attack.ta0006",          # same tactic by id: not duplicated
        "attack.g0016",           # group tag: ignored
        "cve.2024.1234",          # other namespace: ignored
        "attack.not-a-tactic",
    ])
    assert techniques == ["T1003.001", "T1110"]
    assert tactics == ["TA0006"]


def test_rule_with_named_tactic_gets_tactic_id() -> None:
    rule = SigmaEngine().parse_rule_yaml(
        """
title: Named tactic
logsource: {product: linux}
detection:
  selection: {message: x}
  condition: selection
tags:
  - attack.lateral_movement
  - attack.t1021.004
"""
    )
    assert rule.tactic_ids == ["TA0008"]
    assert rule.technique_ids == ["T1021.004"]


# ── Logsource matching ───────────────────────────────────────────────────────


def _event(product: str, class_uid: int = 0, **kwargs: Any) -> OCSFEvent:
    return OCSFEvent(
        class_uid=class_uid, class_name="x", category_uid=0, metadata_product=product, **kwargs
    )


def _applies(logsource: dict[str, str], event: OCSFEvent) -> bool:
    engine = SigmaEngine()
    rule = engine.parse_rule_yaml("title: t\ndetection:\n  selection: {a: b}\n  condition: selection\n")
    rule.logsource = logsource
    engine.add_rule(rule)
    return rule in engine._get_candidates(event)


WINDOWS_HOST = Endpoint(hostname="WIN-DC01", os_name="Microsoft Windows Server 2019")
LINUX_HOST = Endpoint(hostname="web01", os_name="Ubuntu 22.04")


def test_product_only_rule_applies_to_host_events_of_that_os() -> None:
    """A rule with only ``product: windows`` is evaluated for Windows hosts."""
    windows_event = _event("Wazuh", dst_endpoint=WINDOWS_HOST)
    linux_event = _event("Wazuh", dst_endpoint=LINUX_HOST)
    assert _applies({"product": "windows"}, windows_event) is True
    assert _applies({"product": "windows"}, linux_event) is False
    assert _applies({"product": "linux"}, linux_event) is True
    assert _applies({"product": "linux"}, windows_event) is False


def test_product_matches_the_source_name() -> None:
    assert _applies({"product": "wazuh"}, _event("Wazuh", dst_endpoint=WINDOWS_HOST)) is True
    assert _applies({"product": "zeek"}, _event("Zeek")) is True
    assert _applies({"product": "suricata"}, _event("Zeek")) is False
    assert _applies({"product": "syslog"}, _event("Syslog")) is True


def test_host_event_with_unknown_os_accepts_any_os_product() -> None:
    """Syslog and webhook events do not name the OS: the fields decide."""
    for product in ("Syslog", "Webhook", "Wazuh"):
        event = _event(product)
        assert _applies({"product": "linux"}, event) is True
        assert _applies({"product": "windows"}, event) is True
    assert _applies({"product": "zeek"}, _event("Syslog")) is False


def test_network_sources_never_satisfy_an_os_product() -> None:
    for product in ("Zeek", "Suricata"):
        assert _applies({"product": "windows"}, _event(product)) is False
        assert _applies({"product": "linux"}, _event(product)) is False


@pytest.mark.parametrize(
    ("class_uid", "category", "expected"),
    [
        (OCSFClass.PROCESS_ACTIVITY, "process_creation", True),
        (OCSFClass.NETWORK_ACTIVITY, "network_connection", True),
        (OCSFClass.DNS_ACTIVITY, "dns_query", True),
        (OCSFClass.DNS_ACTIVITY, "dns", True),
        (OCSFClass.AUTHENTICATION, "authentication", True),
        (OCSFClass.FILE_ACTIVITY, "file_event", True),
        (OCSFClass.HTTP_ACTIVITY, "proxy", True),
        (OCSFClass.HTTP_ACTIVITY, "webserver", True),
        (OCSFClass.PROCESS_ACTIVITY, "dns_query", False),
        (OCSFClass.SECURITY_FINDING, "process_creation", False),
        (OCSFClass.PROCESS_ACTIVITY, "registry_event", False),
    ],
)
def test_category(class_uid: int, category: str, expected: bool) -> None:
    assert _applies({"category": category}, _event("Wazuh", class_uid)) is expected


def test_product_and_category_must_both_match() -> None:
    logsource = {"product": "windows", "category": "process_creation"}
    windows_process = _event("Wazuh", OCSFClass.PROCESS_ACTIVITY, dst_endpoint=WINDOWS_HOST)
    linux_process = _event("Wazuh", OCSFClass.PROCESS_ACTIVITY, dst_endpoint=LINUX_HOST)
    windows_dns = _event("Wazuh", OCSFClass.DNS_ACTIVITY, dst_endpoint=WINDOWS_HOST)
    zeek_dns = _event("Zeek", OCSFClass.DNS_ACTIVITY)
    assert _applies(logsource, windows_process) is True
    assert _applies(logsource, linux_process) is False
    assert _applies(logsource, windows_dns) is False
    assert _applies({"product": "zeek", "category": "dns_query"}, zeek_dns) is True
    assert _applies({"product": "zeek", "category": "process_creation"}, zeek_dns) is False


def test_service_matches_services_named_by_the_normalizer() -> None:
    sshd = _event("Syslog", unmapped={"service": ["syslog", "sshd", "auth"]})
    assert _applies({"product": "linux", "service": "sshd"}, sshd) is True
    assert _applies({"product": "linux", "service": "auth"}, sshd) is True
    assert _applies({"service": "SSHD"}, sshd) is True
    assert _applies({"product": "linux", "service": "cron"}, sshd) is False


def test_service_is_ignored_when_the_event_names_none() -> None:
    assert _applies({"product": "windows", "service": "security"}, _event("Wazuh")) is True


def test_rule_without_logsource_applies_to_every_event() -> None:
    assert _applies({}, _event("Zeek", OCSFClass.DNS_ACTIVITY)) is True
    assert _applies({}, _event("Syslog")) is True


async def test_product_only_windows_rule_fires_end_to_end() -> None:
    engine = SigmaEngine()
    engine.add_rule(engine.parse_rule_yaml(
        """
title: Product only
id: 6d9f3b65-7a36-4f0e-9a8e-4b3ad3f6f1c2
logsource:
  product: windows
detection:
  selection:
    process.cmd_line|contains: 'vssadmin delete shadows'
  condition: selection
"""
    ))
    event = _event(
        "Wazuh",
        OCSFClass.SECURITY_FINDING,
        dst_endpoint=WINDOWS_HOST,
        process={"cmd_line": "vssadmin delete shadows /all /quiet"},
    )
    assert [a.rule_title async for a in engine.evaluate(event)] == ["Product only"]
