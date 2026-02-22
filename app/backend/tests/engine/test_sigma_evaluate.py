"""Tests for feature 8.17 — `SigmaEngine.evaluate(event)` → `SigmaAlert`.

Coverage:

  Basic matching — single rule, single event:
  - Matching event yields exactly one SigmaAlert
  - Alert `rule_id` equals the matching rule's id
  - Alert `rule_title` equals the matching rule's title
  - Alert `level` equals the matching rule's level
  - Alert `severity_id` is derived from LEVEL_SEVERITY for the rule's level
  - Alert `technique_ids` are propagated from the rule
  - Alert `tactic_ids` are propagated from the rule
  - Alert `host` is taken from event.dst_endpoint.hostname
  - Alert `host` falls back to event.dst_endpoint.ip when hostname is None
  - Alert `host` is empty string when both hostname and ip are None
  - Alert `time` equals event.time
  - Alert `event_snapshot` contains the flattened event data
  - Alert `event_snapshot` includes process fields at top level

  Severity mapping:
  - critical rule → severity_id 5
  - high rule → severity_id 4
  - medium rule → severity_id 3
  - low rule → severity_id 2
  - informational rule → severity_id 1
  - unknown level → severity_id 3 (LEVEL_SEVERITY default)

  Multiple rules:
  - Two matching rules yield two alerts
  - Three matching rules yield three alerts
  - One matching and one non-matching rule → only one alert
  - Alert ids are distinct when multiple rules fire

  Logsource routing:
  - Process Activity (class_uid 1007) event hits category:process_creation rules
  - Network Activity (class_uid 4001) event hits category:network_connection rules
  - DNS Activity (class_uid 4003) event hits category:dns_query rules
  - Authentication (class_uid 3002) event hits category:authentication rules
  - Product-scoped rule fires for matching product event
  - Product-scoped rule fires regardless of class_uid
  - Global rule (no logsource) fires for any event

  Field propagation in event_snapshot:
  - Flattened event_snapshot includes process.name at top level
  - Flattened event_snapshot includes process.cmd_line at top level
  - Flattened event_snapshot includes src_endpoint fields at top level
  - event_snapshot contains _product key set to lowercase metadata_product

  Alert structural correctness:
  - Each yielded alert is an instance of SigmaAlert
  - Alert id is a non-empty UUID4-formatted string
  - Alert id is unique across multiple evaluations
  - Alert rule_id matches the fired rule's id exactly
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from app.engine.sigma_engine import LEVEL_SEVERITY, SigmaAlert, SigmaEngine
from app.services.normalizers.ocsf import (
    Endpoint,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _ocsf_process_event(**overrides: object) -> OCSFEvent:
    """Return a minimal OCSFEvent for a process-activity source."""
    kwargs: dict = dict(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        class_name="Process Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc123"),
        dst_endpoint=Endpoint(hostname="workstation-01", ip="10.0.0.1"),
    )
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)  # type: ignore[arg-type]


def _ocsf_network_event(**overrides: object) -> OCSFEvent:
    kwargs: dict = dict(
        class_uid=OCSFClass.NETWORK_ACTIVITY,
        class_name="Network Activity",
        category_uid=OCSFCategory.NETWORK,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="zeek",
        dst_endpoint=Endpoint(hostname="target-host", ip="192.168.1.1"),
    )
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)  # type: ignore[arg-type]


def _ocsf_dns_event(**overrides: object) -> OCSFEvent:
    kwargs: dict = dict(
        class_uid=OCSFClass.DNS_ACTIVITY,
        class_name="DNS Activity",
        category_uid=OCSFCategory.NETWORK,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        dst_endpoint=Endpoint(hostname="dns-server-01"),
    )
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)  # type: ignore[arg-type]


def _ocsf_auth_event(**overrides: object) -> OCSFEvent:
    kwargs: dict = dict(
        class_uid=OCSFClass.AUTHENTICATION,
        class_name="Authentication",
        category_uid=OCSFCategory.IAM,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        dst_endpoint=Endpoint(hostname="dc-01"),
    )
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Sigma rule YAML fixtures
# ---------------------------------------------------------------------------

_RULE_PS_ENCODED = """\
title: PowerShell Encoded Command
id: rule-ps-encoded-001
status: stable
level: high
description: Detects Base64-encoded PowerShell commands.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: powershell.exe
    cmd_line|contains: -enc
  condition: selection
tags:
  - attack.T1059.001
  - attack.TA0002
"""

_RULE_MIMIKATZ = """\
title: Mimikatz Credential Access
id: rule-mimikatz-001
status: stable
level: critical
description: Detects mimikatz credential dumping.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    cmd_line|contains: mimikatz
  condition: selection
tags:
  - attack.T1003.001
  - attack.TA0006
"""

_RULE_MEDIUM = """\
title: Medium Level Rule
id: rule-medium-001
status: experimental
level: medium
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: powershell.exe
  condition: selection
"""

_RULE_LOW = """\
title: Low Level Rule
id: rule-low-001
status: experimental
level: low
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: powershell.exe
  condition: selection
"""

_RULE_INFORMATIONAL = """\
title: Informational Rule
id: rule-info-001
status: experimental
level: informational
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: powershell.exe
  condition: selection
"""

_RULE_NETWORK = """\
title: Network Connection Detected
id: rule-network-001
status: experimental
level: medium
logsource:
  category: network_connection
  product: zeek
detection:
  selection:
    hostname|contains: network-probe
  condition: selection
"""

_RULE_DNS = """\
title: Suspicious DNS Query
id: rule-dns-001
status: experimental
level: medium
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    hostname|contains: dns-probe
  condition: selection
"""

_RULE_AUTH = """\
title: Failed Authentication
id: rule-auth-001
status: experimental
level: medium
logsource:
  category: authentication
  product: windows
detection:
  selection:
    hostname|contains: auth-probe
  condition: selection
"""

_RULE_PRODUCT_ONLY = """\
title: Windows Product Rule
id: rule-product-001
status: experimental
level: medium
logsource:
  product: windows
detection:
  selection:
    name: powershell.exe
  condition: selection
"""

_RULE_GLOBAL = """\
title: Global Rule No Logsource
id: rule-global-001
status: experimental
level: low
detection:
  selection:
    name: powershell.exe
  condition: selection
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine()


@pytest.fixture
def engine_with_ps_encoded(engine: SigmaEngine) -> SigmaEngine:
    rule = engine.load_rule_yaml(_RULE_PS_ENCODED)
    assert rule is not None
    engine.add_rule(rule)
    return engine


# ---------------------------------------------------------------------------
# Basic matching — single rule, single event
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_matching_event_yields_one_alert(engine_with_ps_encoded: SigmaEngine) -> None:
    """A matching event yields exactly one SigmaAlert."""
    event = _ocsf_process_event()
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_alert_rule_id_matches_rule(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.rule_id equals the matched rule's id."""
    event = _ocsf_process_event()
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].rule_id == "rule-ps-encoded-001"


@pytest.mark.asyncio
async def test_alert_rule_title_matches_rule(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.rule_title equals the matched rule's title."""
    event = _ocsf_process_event()
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].rule_title == "PowerShell Encoded Command"


@pytest.mark.asyncio
async def test_alert_level_matches_rule_level(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.level equals the matched rule's level."""
    event = _ocsf_process_event()
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].level == "high"


@pytest.mark.asyncio
async def test_alert_severity_id_from_level_severity_map(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.severity_id is derived from LEVEL_SEVERITY for the matched rule's level."""
    event = _ocsf_process_event()
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].severity_id == LEVEL_SEVERITY["high"]  # 4


@pytest.mark.asyncio
async def test_alert_technique_ids_from_rule(engine: SigmaEngine) -> None:
    """Alert.technique_ids is propagated from the matched rule."""
    rule = engine.load_rule_yaml(_RULE_PS_ENCODED)
    assert rule is not None
    engine.add_rule(rule)
    event = _ocsf_process_event()
    alerts = [a async for a in engine.evaluate(event)]
    assert "T1059.001" in alerts[0].technique_ids


@pytest.mark.asyncio
async def test_alert_tactic_ids_from_rule(engine: SigmaEngine) -> None:
    """Alert.tactic_ids is propagated from the matched rule."""
    rule = engine.load_rule_yaml(_RULE_PS_ENCODED)
    assert rule is not None
    engine.add_rule(rule)
    event = _ocsf_process_event()
    alerts = [a async for a in engine.evaluate(event)]
    assert "TA0002" in alerts[0].tactic_ids


@pytest.mark.asyncio
async def test_alert_host_from_dst_endpoint_hostname(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.host equals event.dst_endpoint.hostname when set."""
    event = _ocsf_process_event(dst_endpoint=Endpoint(hostname="dc-prod-01", ip="10.1.1.1"))
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].host == "dc-prod-01"


@pytest.mark.asyncio
async def test_alert_host_falls_back_to_ip(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.host falls back to dst_endpoint.ip when hostname is None."""
    event = _ocsf_process_event(dst_endpoint=Endpoint(hostname=None, ip="192.168.1.50"))
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].host == "192.168.1.50"


@pytest.mark.asyncio
async def test_alert_host_empty_when_neither_hostname_nor_ip(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.host is empty string when both hostname and ip are None."""
    event = _ocsf_process_event(dst_endpoint=Endpoint(hostname=None, ip=None))
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].host == ""


@pytest.mark.asyncio
async def test_alert_time_matches_event_time(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.time equals the event's time field."""
    t = datetime(2026, 2, 22, 15, 30, 0, tzinfo=timezone.utc)
    event = _ocsf_process_event(time=t)
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].time == t


@pytest.mark.asyncio
async def test_alert_event_snapshot_is_dict(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.event_snapshot is a non-empty dict."""
    event = _ocsf_process_event()
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert isinstance(alerts[0].event_snapshot, dict)
    assert len(alerts[0].event_snapshot) > 0


@pytest.mark.asyncio
async def test_alert_event_snapshot_contains_process_name(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.event_snapshot has process.name flattened to top-level 'name' key."""
    event = _ocsf_process_event(process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc"))
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].event_snapshot.get("name") == "powershell.exe"


@pytest.mark.asyncio
async def test_alert_event_snapshot_contains_cmd_line(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.event_snapshot has process.cmd_line flattened to top-level 'cmd_line' key."""
    event = _ocsf_process_event(process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc secretstuff"))
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert "secretstuff" in alerts[0].event_snapshot.get("cmd_line", "")


@pytest.mark.asyncio
async def test_alert_event_snapshot_contains_product_key(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.event_snapshot has a '_product' key set to lowercase metadata_product."""
    event = _ocsf_process_event(metadata_product="Windows")
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].event_snapshot.get("_product") == "windows"


# ---------------------------------------------------------------------------
# Severity mapping — all five levels
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_critical_rule_yields_severity_5(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_RULE_MIMIKATZ)
    assert rule is not None
    engine.add_rule(rule)
    event = _ocsf_process_event(
        process=ProcessInfo(name="cmd.exe", cmd_line="cmd /c mimikatz.exe"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1
    assert alerts[0].severity_id == 5
    assert alerts[0].level == "critical"


@pytest.mark.asyncio
async def test_high_rule_yields_severity_4(engine_with_ps_encoded: SigmaEngine) -> None:
    event = _ocsf_process_event()
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert alerts[0].severity_id == 4
    assert alerts[0].level == "high"


@pytest.mark.asyncio
async def test_medium_rule_yields_severity_3(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_RULE_MEDIUM)
    assert rule is not None
    engine.add_rule(rule)
    event = _ocsf_process_event()
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1
    assert alerts[0].severity_id == 3
    assert alerts[0].level == "medium"


@pytest.mark.asyncio
async def test_low_rule_yields_severity_2(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_RULE_LOW)
    assert rule is not None
    engine.add_rule(rule)
    event = _ocsf_process_event()
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1
    assert alerts[0].severity_id == 2
    assert alerts[0].level == "low"


@pytest.mark.asyncio
async def test_informational_rule_yields_severity_1(engine: SigmaEngine) -> None:
    rule = engine.load_rule_yaml(_RULE_INFORMATIONAL)
    assert rule is not None
    engine.add_rule(rule)
    event = _ocsf_process_event()
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1
    assert alerts[0].severity_id == 1
    assert alerts[0].level == "informational"


@pytest.mark.asyncio
async def test_unknown_level_yields_severity_3_default(engine: SigmaEngine) -> None:
    """LEVEL_SEVERITY.get(unknown, 3) → severity_id 3."""
    yaml_text = """\
title: Unknown Level Rule
id: rule-unknown-level
status: experimental
level: mysterious
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: powershell.exe
  condition: selection
"""
    rule = engine.load_rule_yaml(yaml_text)
    assert rule is not None
    engine.add_rule(rule)
    event = _ocsf_process_event()
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1
    assert alerts[0].severity_id == 3  # LEVEL_SEVERITY default


# ---------------------------------------------------------------------------
# Multiple rules
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_two_matching_rules_yield_two_alerts(engine: SigmaEngine) -> None:
    """Two rules that both match the event yield two alerts."""
    for yaml_text in (_RULE_PS_ENCODED, _RULE_MEDIUM):
        rule = engine.load_rule_yaml(yaml_text)
        assert rule is not None
        engine.add_rule(rule)

    event = _ocsf_process_event(
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 2


@pytest.mark.asyncio
async def test_three_matching_rules_yield_three_alerts(engine: SigmaEngine) -> None:
    for yaml_text in (_RULE_PS_ENCODED, _RULE_MEDIUM, _RULE_LOW):
        rule = engine.load_rule_yaml(yaml_text)
        assert rule is not None
        engine.add_rule(rule)

    event = _ocsf_process_event(
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 3


@pytest.mark.asyncio
async def test_one_match_one_no_match_yields_one_alert(engine: SigmaEngine) -> None:
    """Only the matching rule fires; the non-matching rule is silent."""
    # PS encoded rule requires cmd_line|contains: -enc  (matches)
    ps_rule = engine.load_rule_yaml(_RULE_PS_ENCODED)
    assert ps_rule is not None
    engine.add_rule(ps_rule)

    # Mimikatz rule requires cmd_line|contains: mimikatz  (does not match)
    mimi_rule = engine.load_rule_yaml(_RULE_MIMIKATZ)
    assert mimi_rule is not None
    engine.add_rule(mimi_rule)

    event = _ocsf_process_event(
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1
    assert alerts[0].rule_id == "rule-ps-encoded-001"


@pytest.mark.asyncio
async def test_alert_ids_distinct_across_multiple_fired_rules(engine: SigmaEngine) -> None:
    """Each fired rule yields an alert with a unique id."""
    for yaml_text in (_RULE_PS_ENCODED, _RULE_MEDIUM, _RULE_LOW):
        rule = engine.load_rule_yaml(yaml_text)
        assert rule is not None
        engine.add_rule(rule)

    event = _ocsf_process_event(
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    ids = [a.id for a in alerts]
    assert len(ids) == len(set(ids)), "Each alert must have a distinct id"


# ---------------------------------------------------------------------------
# Logsource routing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_process_activity_event_triggers_process_creation_rule(engine: SigmaEngine) -> None:
    """class_uid=1007 (Process Activity) matches category:process_creation rules."""
    rule = engine.load_rule_yaml(_RULE_PS_ENCODED)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event(class_uid=OCSFClass.PROCESS_ACTIVITY)
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_network_activity_event_triggers_network_connection_rule(engine: SigmaEngine) -> None:
    """class_uid=4001 (Network Activity) matches category:network_connection rules.

    The rule matches on `hostname` which is flattened to the top level of flat_event
    from event.src_endpoint.model_dump() in SigmaEngine.evaluate().
    """
    rule = engine.load_rule_yaml(_RULE_NETWORK)
    assert rule is not None
    engine.add_rule(rule)

    event = OCSFEvent(
        class_uid=OCSFClass.NETWORK_ACTIVITY,
        class_name="Network Activity",
        category_uid=OCSFCategory.NETWORK,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="zeek",
        src_endpoint=Endpoint(hostname="network-probe-sensor"),
        dst_endpoint=Endpoint(hostname="target-host"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_dns_activity_event_triggers_dns_query_rule(engine: SigmaEngine) -> None:
    """class_uid=4003 (DNS Activity) matches category:dns_query rules.

    The rule matches on `hostname` which is flattened from event.src_endpoint.
    """
    rule = engine.load_rule_yaml(_RULE_DNS)
    assert rule is not None
    engine.add_rule(rule)

    event = OCSFEvent(
        class_uid=OCSFClass.DNS_ACTIVITY,
        class_name="DNS Activity",
        category_uid=OCSFCategory.NETWORK,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        src_endpoint=Endpoint(hostname="dns-probe-client"),
        dst_endpoint=Endpoint(hostname="dns-server-01"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_authentication_event_triggers_authentication_rule(engine: SigmaEngine) -> None:
    """class_uid=3002 (Authentication) matches category:authentication rules.

    The rule matches on `hostname` which is flattened from event.src_endpoint.
    """
    rule = engine.load_rule_yaml(_RULE_AUTH)
    assert rule is not None
    engine.add_rule(rule)

    event = OCSFEvent(
        class_uid=OCSFClass.AUTHENTICATION,
        class_name="Authentication",
        category_uid=OCSFCategory.IAM,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        src_endpoint=Endpoint(hostname="auth-probe-workstation"),
        dst_endpoint=Endpoint(hostname="dc-01"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_product_only_rule_fires_for_matching_product(engine: SigmaEngine) -> None:
    """A rule with only `product: windows` fires for a windows event."""
    rule = engine.load_rule_yaml(_RULE_PRODUCT_ONLY)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event(metadata_product="windows")
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_product_only_rule_does_not_fire_for_other_product(engine: SigmaEngine) -> None:
    """A rule with only `product: windows` does NOT fire for a linux event."""
    rule = engine.load_rule_yaml(_RULE_PRODUCT_ONLY)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event(metadata_product="linux")
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 0


@pytest.mark.asyncio
async def test_global_rule_fires_for_any_event(engine: SigmaEngine) -> None:
    """A rule with no logsource (indexed under '*') fires for any matching event."""
    rule = engine.load_rule_yaml(_RULE_GLOBAL)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event(metadata_product="linux")
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Alert structural correctness
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_alert_is_instance_of_sigma_alert(engine_with_ps_encoded: SigmaEngine) -> None:
    """Each yielded alert is a SigmaAlert instance."""
    event = _ocsf_process_event()
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert all(isinstance(a, SigmaAlert) for a in alerts)


@pytest.mark.asyncio
async def test_alert_id_is_uuid4_format(engine_with_ps_encoded: SigmaEngine) -> None:
    """Alert.id matches the canonical UUID4 pattern."""
    event = _ocsf_process_event()
    alerts = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert _UUID4_RE.match(alerts[0].id), f"id {alerts[0].id!r} is not UUID4"


@pytest.mark.asyncio
async def test_alert_rule_id_is_exact_match(engine: SigmaEngine) -> None:
    """Alert.rule_id is an exact match to the rule id string, not partial."""
    rule = engine.load_rule_yaml(_RULE_MIMIKATZ)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event(
        process=ProcessInfo(name="cmd.exe", cmd_line="cmd /c mimikatz.exe sekurlsa::logonpasswords"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1
    assert alerts[0].rule_id == "rule-mimikatz-001"


@pytest.mark.asyncio
async def test_alert_technique_ids_exact_list(engine: SigmaEngine) -> None:
    """Alert.technique_ids is exactly the list from the rule, not empty."""
    rule = engine.load_rule_yaml(_RULE_MIMIKATZ)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event(
        process=ProcessInfo(name="cmd.exe", cmd_line="cmd /c mimikatz.exe"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert alerts[0].technique_ids == ["T1003.001"]


@pytest.mark.asyncio
async def test_alert_tactic_ids_exact_list(engine: SigmaEngine) -> None:
    """Alert.tactic_ids is exactly the list from the rule, not empty."""
    rule = engine.load_rule_yaml(_RULE_MIMIKATZ)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event(
        process=ProcessInfo(name="cmd.exe", cmd_line="cmd /c mimikatz.exe"),
    )
    alerts = [a async for a in engine.evaluate(event)]
    assert alerts[0].tactic_ids == ["TA0006"]


@pytest.mark.asyncio
async def test_alert_from_rule_with_no_tags_has_empty_attack_lists(engine: SigmaEngine) -> None:
    """A rule with no ATT&CK tags produces an alert with empty technique/tactic ids."""
    rule = engine.load_rule_yaml(_RULE_MEDIUM)
    assert rule is not None
    engine.add_rule(rule)

    event = _ocsf_process_event()
    alerts = [a async for a in engine.evaluate(event)]
    assert len(alerts) == 1
    assert alerts[0].technique_ids == []
    assert alerts[0].tactic_ids == []


# ---------------------------------------------------------------------------
# Evaluate returns an async generator (not a list, not a coroutine)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_evaluate_is_async_generator(engine_with_ps_encoded: SigmaEngine) -> None:
    """engine.evaluate() must be an async generator, consumable via 'async for'."""
    import inspect
    event = _ocsf_process_event()
    gen = engine_with_ps_encoded.evaluate(event)
    assert inspect.isasyncgen(gen)
    # Consume so we don't leave it dangling
    _ = [a async for a in gen]


@pytest.mark.asyncio
async def test_evaluate_can_be_called_multiple_times_independently(engine_with_ps_encoded: SigmaEngine) -> None:
    """evaluate() can be called multiple times on the same engine; each call is independent."""
    event = _ocsf_process_event()
    alerts_first  = [a async for a in engine_with_ps_encoded.evaluate(event)]
    alerts_second = [a async for a in engine_with_ps_encoded.evaluate(event)]
    assert len(alerts_first) == 1
    assert len(alerts_second) == 1
    # Each call produces a fresh alert with a new UUID
    assert alerts_first[0].id != alerts_second[0].id
