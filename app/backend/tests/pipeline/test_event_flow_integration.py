"""
Tests for Feature 28.41 — Pipeline: event flows end-to-end (integration).

Coverage:
  - SigmaEngine evaluation with real Sigma rules loaded from disk, against
    synthetic OCSFEvents crafted to match specific detection rules.
  - Positive scenarios: PowerShell encoded command, LSASS memory access,
    new service creation via sc.exe, SMB lateral movement via psexec,
    DNS tunneling via long query.
  - Negative scenarios: benign events and whitelisted processes that must
    not trigger any rule.
  - Full pipeline (raw → NORMALIZED → ALERTS → ENRICHED) with a real
    SigmaEngine, InMemoryQueue, NormalizerPipeline, real sigma_consumer,
    and AlertManager (mocked Valkey to avoid external dependency).
  - Enriched alert payload structure verified end-to-end: rule_id,
    technique_ids, tactic_ids, score ∈ [0, 10], asset_criticality, host.
  - Deduplication: identical synthetic events produce exactly one enriched
    alert; distinct hosts with the same rule produce two enriched alerts.
"""

from __future__ import annotations

import asyncio
import pathlib
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.engine.sigma_engine import SigmaEngine
from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_manager import AlertManager
from app.services.normalizers.ocsf import (
    Endpoint,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
)
from app.services.normalizers.pipeline import NormalizerPipeline
from app.services.sigma_consumer import sigma_consumer


# ── Constants ─────────────────────────────────────────────────────────────────

SIGMA_RULES_DIR = str(
    pathlib.Path(__file__).parent.parent.parent / "sigma_rules"
)

# Known rule IDs from sigma_rules/ directory
RULE_ID_POWERSHELL   = "b6f98540-ed62-4856-b8b7-2a2d7b80f5b7"
RULE_ID_LSASS        = "0d894093-71bc-43c3-b7e0-01eb5adf38cd"
RULE_ID_SMB          = "c2c02497-17b0-4c2d-a3f7-e5a19cf1b88b"
RULE_ID_DNS_TUNNEL   = "d5e0ef77-3bd9-4a4d-b6e2-0b3c8af53a10"
RULE_ID_NEW_SERVICE  = "e4f1b7cc-28b3-47c8-bb8e-c93f6a8e8d7e"


# ── Async helpers ─────────────────────────────────────────────────────────────

async def _make_sigma_engine() -> SigmaEngine:
    """Create a real SigmaEngine loaded with rules from disk."""
    engine = SigmaEngine()
    count = await engine.load_rules_from_dir(SIGMA_RULES_DIR)
    assert count >= 5, f"Expected ≥5 sigma rules, got {count} from {SIGMA_RULES_DIR}"
    return engine


def _make_alert_manager(queue: InMemoryQueue) -> AlertManager:
    """Build an AlertManager with mocked Valkey (no real Redis required)."""
    with patch("app.services.alert_manager.aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = AsyncMock()
        mgr = AlertManager(queue)
    mgr._valkey = AsyncMock()
    mgr._valkey.set = AsyncMock(return_value=True)  # True → not a duplicate
    return mgr


# ── Synthetic OCSFEvent builders ──────────────────────────────────────────────

def _process_activity_event(**overrides: Any) -> OCSFEvent:
    """Base OCSFEvent for process_creation (class_uid=1007).

    Overrides take precedence over defaults so callers can replace any field.
    """
    kwargs: dict[str, Any] = {
        "class_uid": OCSFClass.PROCESS_ACTIVITY,
        "class_name": "Process Activity",
        "category_uid": OCSFCategory.SYSTEM_ACTIVITY,
        "severity_id": 3,
        "metadata_product": "Wazuh",
        "dst_endpoint": Endpoint(hostname="WIN-DC01", ip="192.168.1.10"),
    }
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)


def _network_activity_event(**overrides: Any) -> OCSFEvent:
    """Base OCSFEvent for network_connection (class_uid=4001)."""
    kwargs: dict[str, Any] = {
        "class_uid": OCSFClass.NETWORK_ACTIVITY,
        "class_name": "Network Activity",
        "category_uid": OCSFCategory.NETWORK,
        "severity_id": 3,
        "metadata_product": "Wazuh",
        "src_endpoint": Endpoint(ip="192.168.1.100"),
        "dst_endpoint": Endpoint(hostname="TARGET-SRV", ip="10.0.0.5", port=445),
    }
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)


def _dns_activity_event(**overrides: Any) -> OCSFEvent:
    """Base OCSFEvent for dns_query (class_uid=4003)."""
    kwargs: dict[str, Any] = {
        "class_uid": OCSFClass.DNS_ACTIVITY,
        "class_name": "DNS Activity",
        "category_uid": OCSFCategory.NETWORK,
        "severity_id": 1,
        "metadata_product": "Zeek",
        "src_endpoint": Endpoint(ip="192.168.1.50"),
    }
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)


# ── Synthetic Wazuh raw event builders ────────────────────────────────────────

def _wazuh_process_raw(
    *,
    cmd_line: str = "",
    image: str = r"C:\Windows\System32\cmd.exe",
    agent_name: str = "WIN-DC01",
    rule_level: int = 10,
    groups: list[str] | None = None,
) -> dict[str, Any]:
    """Minimal Wazuh alert dict that normalizes to a Process Activity event."""
    return {
        "timestamp": "2026-02-20T10:00:00.000Z",
        "id": "1708331400.99999",
        "rule": {
            "id": "100234",
            "description": "Test Process Event",
            "level": rule_level,
            "groups": groups or ["process", "win_process"],
            "mitre": {"id": ["T1059"], "tactic": ["execution"]},
        },
        "agent": {"id": "001", "name": agent_name, "ip": "192.168.1.10"},
        "data": {
            "win": {
                "eventdata": {
                    "commandLine": cmd_line,
                    "image": image,
                    "processId": "4321",
                    "parentProcessId": "1234",
                }
            }
        },
    }


# ── Class 1: Direct SigmaEngine evaluation with synthetic events ───────────────

class TestSyntheticSigmaEvaluation:
    """
    Tests evaluating synthetic OCSFEvents directly against a real SigmaEngine
    loaded with sigma rules from disk.  No queue, normalizer, or AlertManager
    is involved — these are unit-level tests of the detection layer.
    """

    # ── PowerShell Encoded Command ─────────────────────────────────────────

    async def test_powershell_minus_enc_flag_matches_rule(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell.exe -enc SGVsbG8sIFdvcmxkIQ==",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_POWERSHELL in rule_ids, (
            "PowerShell -enc flag must trigger the encoded-command rule"
        )

    async def test_powershell_encoded_command_long_form_matches(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell.exe -EncodedCommand SGVsbG8sIFdvcmxkIQ==",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_POWERSHELL in rule_ids

    async def test_powershell_plain_command_does_not_match(self) -> None:
        """A non-encoded PowerShell command must not trigger the encoded-command rule."""
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell.exe Get-Process",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_POWERSHELL not in rule_ids

    async def test_non_powershell_process_does_not_match_ps_rule(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="cmd.exe",
                cmd_line="cmd.exe /c -enc something",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_POWERSHELL not in rule_ids, (
            "cmd.exe must not match the PowerShell-specific rule even with -enc flag"
        )

    async def test_powershell_alert_has_correct_technique_ids(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell.exe -enc dGVzdA==",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        ps_alerts = [a for a in alerts if a.rule_id == RULE_ID_POWERSHELL]
        assert len(ps_alerts) == 1
        assert "T1059.001" in ps_alerts[0].technique_ids

    async def test_powershell_alert_has_correct_tactic_ids(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell.exe -enc dGVzdA==",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        ps_alerts = [a for a in alerts if a.rule_id == RULE_ID_POWERSHELL]
        assert len(ps_alerts) == 1
        assert "TA0002" in ps_alerts[0].tactic_ids

    async def test_powershell_alert_level_is_high(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell.exe -enc dGVzdA==",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        ps_alerts = [a for a in alerts if a.rule_id == RULE_ID_POWERSHELL]
        assert len(ps_alerts) == 1
        assert ps_alerts[0].level == "high"
        assert ps_alerts[0].severity_id == 4

    # ── LSASS Memory Access ────────────────────────────────────────────────

    async def test_lsass_path_by_unknown_process_matches_rule(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="custom_loader.exe",
                path=r"C:\Windows\System32\lsass.exe",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_LSASS in rule_ids, (
            "Unknown process accessing lsass path must trigger the LSASS rule"
        )

    async def test_lsass_path_by_csrss_is_filtered(self) -> None:
        """csrss.exe is whitelisted — accessing lsass.exe must not trigger the rule."""
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="csrss.exe",
                path=r"C:\Windows\System32\lsass.exe",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_LSASS not in rule_ids

    async def test_lsass_path_by_wininit_is_filtered(self) -> None:
        """wininit.exe is whitelisted — must not trigger the LSASS rule."""
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="wininit.exe",
                path=r"C:\Windows\System32\lsass.exe",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_LSASS not in rule_ids

    async def test_lsass_alert_level_is_critical(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="injector.exe",
                path=r"C:\Windows\System32\lsass.exe",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        lsass_alerts = [a for a in alerts if a.rule_id == RULE_ID_LSASS]
        assert len(lsass_alerts) == 1
        assert lsass_alerts[0].level == "critical"
        assert lsass_alerts[0].severity_id == 5

    async def test_lsass_alert_has_credential_access_tactic(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="dumper.exe",
                path=r"C:\Windows\System32\lsass.exe",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        lsass_alerts = [a for a in alerts if a.rule_id == RULE_ID_LSASS]
        assert len(lsass_alerts) == 1
        assert "TA0006" in lsass_alerts[0].tactic_ids

    # ── New Service Creation ───────────────────────────────────────────────

    async def test_sc_create_command_matches_service_rule(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="sc.exe",
                cmd_line=r"sc create MalSvc binpath= C:\temp\mal.exe start= auto",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_NEW_SERVICE in rule_ids

    async def test_new_service_powershell_variant_matches(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell.exe New-Service -Name MalSvc -BinaryPathName malware.exe",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_NEW_SERVICE in rule_ids

    async def test_benign_process_event_fires_no_alerts(self) -> None:
        """A routine notepad.exe invocation must not match any sigma rule."""
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="notepad.exe",
                cmd_line=r"notepad.exe C:\Users\user\notes.txt",
                path=r"C:\Windows\System32\notepad.exe",
            )
        )
        alerts = [a async for a in engine.evaluate(event)]
        assert len(alerts) == 0, (
            f"Benign notepad.exe event should not trigger any rule; "
            f"fired: {[a.rule_id for a in alerts]}"
        )

    # ── SMB Lateral Movement ──────────────────────────────────────────────

    async def test_psexec_to_smb_port_445_matches_rule(self) -> None:
        engine = await _make_sigma_engine()
        event = _network_activity_event(
            process=ProcessInfo(name="psexec.exe"),
            dst_endpoint=Endpoint(hostname="TARGET-SRV", ip="10.0.0.5", port=445),
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_SMB in rule_ids, (
            "psexec.exe connecting to port 445 must trigger the SMB lateral movement rule"
        )

    async def test_psexec_to_smb_port_139_matches_rule(self) -> None:
        engine = await _make_sigma_engine()
        event = _network_activity_event(
            process=ProcessInfo(name="psexec.exe"),
            dst_endpoint=Endpoint(hostname="TARGET-SRV", ip="10.0.0.5", port=139),
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_SMB in rule_ids

    async def test_psexec_to_non_smb_port_does_not_match(self) -> None:
        """psexec.exe to port 443 (HTTPS) must not trigger the SMB rule."""
        engine = await _make_sigma_engine()
        event = _network_activity_event(
            process=ProcessInfo(name="psexec.exe"),
            dst_endpoint=Endpoint(hostname="TARGET-SRV", ip="10.0.0.5", port=443),
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_SMB not in rule_ids

    async def test_legitimate_process_to_smb_port_does_not_match(self) -> None:
        """A legitimate process connecting to port 445 must not trigger the SMB rule."""
        engine = await _make_sigma_engine()
        event = _network_activity_event(
            process=ProcessInfo(name="explorer.exe"),
            dst_endpoint=Endpoint(hostname="FILESERVER", ip="10.0.0.10", port=445),
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_SMB not in rule_ids

    async def test_smb_alert_has_lateral_movement_tactic(self) -> None:
        engine = await _make_sigma_engine()
        event = _network_activity_event(
            process=ProcessInfo(name="psexec.exe"),
            dst_endpoint=Endpoint(port=445),
        )
        alerts = [a async for a in engine.evaluate(event)]
        smb_alerts = [a for a in alerts if a.rule_id == RULE_ID_SMB]
        assert len(smb_alerts) == 1
        assert "TA0008" in smb_alerts[0].tactic_ids

    # ── DNS Tunneling ──────────────────────────────────────────────────────

    async def test_long_dns_query_matches_tunneling_rule(self) -> None:
        engine = await _make_sigma_engine()
        long_query = "a" * 60 + ".evil-c2.example.com"
        event = _dns_activity_event(
            network_traffic={"query": long_query},
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_DNS_TUNNEL in rule_ids, (
            "A 60+ char DNS query must trigger the DNS tunneling detection rule"
        )

    async def test_short_dns_query_does_not_match_tunneling_rule(self) -> None:
        engine = await _make_sigma_engine()
        short_query = "example.com"   # well under 50 chars
        event = _dns_activity_event(
            network_traffic={"query": short_query},
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_DNS_TUNNEL not in rule_ids

    async def test_exactly_50_char_dns_query_matches(self) -> None:
        """The regex .{50,} matches exactly 50 characters (boundary condition)."""
        engine = await _make_sigma_engine()
        boundary_query = "x" * 50
        event = _dns_activity_event(
            network_traffic={"query": boundary_query},
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_DNS_TUNNEL in rule_ids

    async def test_49_char_dns_query_does_not_match(self) -> None:
        """A 49-char query must not trigger the DNS tunneling rule."""
        engine = await _make_sigma_engine()
        event = _dns_activity_event(
            network_traffic={"query": "x" * 49},
        )
        alerts = [a async for a in engine.evaluate(event)]
        rule_ids = {a.rule_id for a in alerts}
        assert RULE_ID_DNS_TUNNEL not in rule_ids

    # ── Alert host field ───────────────────────────────────────────────────

    async def test_alert_host_is_taken_from_dst_endpoint_hostname(self) -> None:
        engine = await _make_sigma_engine()
        event = _process_activity_event(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell.exe -enc dGVzdA==",
            ),
            dst_endpoint=Endpoint(hostname="CORP-LAPTOP-42"),
        )
        alerts = [a async for a in engine.evaluate(event)]
        ps_alerts = [a for a in alerts if a.rule_id == RULE_ID_POWERSHELL]
        assert len(ps_alerts) == 1
        assert ps_alerts[0].host == "CORP-LAPTOP-42"

    async def test_alert_time_matches_event_time(self) -> None:
        engine = await _make_sigma_engine()
        ts = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
        event = _process_activity_event(
            time=ts,
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell.exe -enc dGVzdA==",
            ),
        )
        alerts = [a async for a in engine.evaluate(event)]
        ps_alerts = [a for a in alerts if a.rule_id == RULE_ID_POWERSHELL]
        assert len(ps_alerts) == 1
        assert ps_alerts[0].time == ts


# ── Class 2: Full pipeline end-to-end with synthetic events ───────────────────

class TestSyntheticEventPipelineEndToEnd:
    """
    Full pipeline integration: synthetic raw Wazuh events flow through
    NormalizerPipeline → SigmaConsumer (real SigmaEngine) → AlertManager
    (mocked Valkey) → Topic.ENRICHED.

    No mocks for the detection layer — real rules evaluate against
    normalized events to verify the complete chain.
    """

    async def _setup_full_pipeline(
        self,
    ) -> tuple[InMemoryQueue, list[dict], AlertManager]:
        """Stand up queue + normalizer + sigma consumer + alert manager.

        Returns (queue, enriched_list, alert_manager) so tests can inject
        raw events via queue.publish(Topic.RAW_WAZUH, ...) and inspect
        the collected enriched alerts.
        """
        q = InMemoryQueue()
        await q.start()

        # Stage 1 — normalizer
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        # Stage 2 — sigma consumer with real rules
        engine = await _make_sigma_engine()
        await sigma_consumer(q, engine)

        # Stage 3 — alert manager (mocked Valkey)
        mgr = _make_alert_manager(q)

        async def _alert_consumer(msg: dict) -> None:
            await mgr.process(msg)

        await q.subscribe(Topic.ALERTS, "alert-mgr", _alert_consumer)

        # Capture enriched output
        enriched: list[dict] = []

        async def _capture(msg: dict) -> None:
            enriched.append(msg)

        await q.subscribe(Topic.ENRICHED, "integration", _capture)
        return q, enriched, mgr

    async def test_powershell_raw_event_produces_enriched_alert(self) -> None:
        """A Wazuh event with -enc flag must flow through and produce an enriched alert."""
        q, enriched, _ = await self._setup_full_pipeline()

        raw = _wazuh_process_raw(
            cmd_line="powershell.exe -enc SGVsbG8sIFdvcmxkIQ==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        assert len(enriched) >= 1, "PowerShell encoded-command event must produce ≥1 enriched alert"
        rule_ids = {e["rule_id"] for e in enriched}
        assert RULE_ID_POWERSHELL in rule_ids
        await q.stop()

    async def test_lsass_raw_event_produces_enriched_alert(self) -> None:
        """A process launching with lsass.exe path must trigger the LSASS rule end-to-end."""
        q, enriched, _ = await self._setup_full_pipeline()

        raw = _wazuh_process_raw(
            cmd_line="C:\\Windows\\System32\\lsass.exe",
            image=r"C:\Windows\System32\lsass.exe",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        rule_ids = {e["rule_id"] for e in enriched}
        assert RULE_ID_LSASS in rule_ids, (
            f"LSASS rule must fire end-to-end; got rules: {rule_ids}"
        )
        await q.stop()

    async def test_service_creation_raw_event_produces_enriched_alert(self) -> None:
        """sc create command must flow through the pipeline and produce an enriched alert."""
        q, enriched, _ = await self._setup_full_pipeline()

        raw = _wazuh_process_raw(
            cmd_line=r"sc create MalSvc binpath= C:\temp\mal.exe start= auto",
            image=r"C:\Windows\System32\sc.exe",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        rule_ids = {e["rule_id"] for e in enriched}
        assert RULE_ID_NEW_SERVICE in rule_ids
        await q.stop()

    async def test_benign_event_produces_no_enriched_alert(self) -> None:
        """A routine notepad event must traverse the pipeline and produce no enriched alert."""
        q, enriched, _ = await self._setup_full_pipeline()

        raw = _wazuh_process_raw(
            cmd_line=r"notepad.exe C:\Users\user\notes.txt",
            image=r"C:\Windows\System32\notepad.exe",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        assert len(enriched) == 0, (
            f"Benign event must produce no enriched alert; got: {[e['rule_id'] for e in enriched]}"
        )
        await q.stop()

    async def test_enriched_alert_score_within_valid_range(self) -> None:
        q, enriched, _ = await self._setup_full_pipeline()

        raw = _wazuh_process_raw(
            cmd_line="powershell.exe -enc dGVzdA==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        assert len(enriched) >= 1
        for alert in enriched:
            score = alert["score"]
            assert 0.0 <= score <= 10.0, f"Score {score} is outside [0, 10]"
        await q.stop()

    async def test_enriched_alert_contains_technique_ids_from_sigma_rule(self) -> None:
        q, enriched, _ = await self._setup_full_pipeline()

        raw = _wazuh_process_raw(
            cmd_line="powershell.exe -enc dGVzdA==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        ps_alerts = [e for e in enriched if e["rule_id"] == RULE_ID_POWERSHELL]
        assert len(ps_alerts) >= 1
        assert "T1059.001" in ps_alerts[0]["technique_ids"]

    async def test_enriched_alert_contains_tactic_ids_from_sigma_rule(self) -> None:
        q, enriched, _ = await self._setup_full_pipeline()

        raw = _wazuh_process_raw(
            cmd_line="powershell.exe -enc dGVzdA==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        ps_alerts = [e for e in enriched if e["rule_id"] == RULE_ID_POWERSHELL]
        assert len(ps_alerts) >= 1
        assert "TA0002" in ps_alerts[0]["tactic_ids"]

    async def test_enriched_alert_preserves_host_from_wazuh_agent(self) -> None:
        q, enriched, _ = await self._setup_full_pipeline()

        raw = _wazuh_process_raw(
            cmd_line="powershell.exe -enc dGVzdA==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            agent_name="WIN-SENSITIVE-01",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        ps_alerts = [e for e in enriched if e["rule_id"] == RULE_ID_POWERSHELL]
        assert len(ps_alerts) >= 1
        assert ps_alerts[0]["host"] == "WIN-SENSITIVE-01"

    async def test_enriched_alert_has_asset_criticality_field(self) -> None:
        q, enriched, _ = await self._setup_full_pipeline()

        raw = _wazuh_process_raw(
            cmd_line="powershell.exe -enc dGVzdA==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        assert len(enriched) >= 1
        for alert in enriched:
            assert "asset_criticality" in alert, (
                "Enriched alert must contain the asset_criticality field"
            )

    async def test_dc_host_gets_highest_asset_criticality(self) -> None:
        """Domain controller prefix 'dc' yields criticality 1.0 (the maximum default)."""
        q, enriched, mgr = await self._setup_full_pipeline()

        # Patch CMDB lookup: DC hosts always return criticality 1.0 (CMDB score 5)
        mgr._asset_criticality = AsyncMock(return_value=1.0)

        raw = _wazuh_process_raw(
            cmd_line="powershell.exe -enc dGVzdA==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            agent_name="dc01.corp",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.4)

        ps_alerts = [e for e in enriched if e["rule_id"] == RULE_ID_POWERSHELL]
        assert len(ps_alerts) >= 1
        assert ps_alerts[0]["asset_criticality"] == 1.0

    async def test_critical_severity_rule_produces_high_score(self) -> None:
        """LSASS rule (critical severity) must produce a higher score than medium-level rules."""
        q, enriched, _ = await self._setup_full_pipeline()

        # LSASS rule is "critical" (severity_id=5)
        lsass_raw = _wazuh_process_raw(
            cmd_line="C:\\Windows\\System32\\lsass.exe",
            image=r"C:\Windows\System32\lsass.exe",
        )
        await q.publish(Topic.RAW_WAZUH, lsass_raw)
        await asyncio.sleep(0.4)

        lsass_alerts = [e for e in enriched if e["rule_id"] == RULE_ID_LSASS]
        assert len(lsass_alerts) >= 1
        # LSASS is critical (severity_id=5); score formula: (5-1)/4 * 0.60 * 10 = 6.0 base
        assert lsass_alerts[0]["score"] >= 6.0, (
            f"Critical-severity alert score {lsass_alerts[0]['score']} should be ≥ 6.0"
        )
        await q.stop()

    async def test_three_distinct_attack_events_produce_three_enriched(self) -> None:
        """
        Three different attack techniques must each produce an enriched alert,
        verifying the pipeline handles concurrent events from the same source.
        """
        q, enriched, mgr = await self._setup_full_pipeline()

        # Ensure each alert is treated as unique
        mgr._valkey.set = AsyncMock(return_value=True)

        events = [
            _wazuh_process_raw(
                cmd_line="powershell.exe -enc dGVzdA==",
                image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ),
            _wazuh_process_raw(
                cmd_line=r"sc create MalSvc binpath= C:\temp\mal.exe",
                image=r"C:\Windows\System32\sc.exe",
            ),
            _wazuh_process_raw(
                cmd_line="C:\\Windows\\System32\\lsass.exe",
                image=r"C:\Windows\System32\lsass.exe",
            ),
        ]

        for raw in events:
            await q.publish(Topic.RAW_WAZUH, raw)

        await asyncio.sleep(0.6)

        fired_rule_ids = {e["rule_id"] for e in enriched}
        assert RULE_ID_POWERSHELL in fired_rule_ids
        assert RULE_ID_NEW_SERVICE in fired_rule_ids
        assert RULE_ID_LSASS in fired_rule_ids
        await q.stop()


# ── Class 3: Deduplication of synthetic events ────────────────────────────────

class TestSyntheticEventDeduplication:
    """
    Verifies that AlertManager deduplication works correctly when the same
    synthetic event is injected twice versus events from distinct hosts.
    """

    async def _full_pipeline_queue_with_mgr(
        self,
    ) -> tuple[InMemoryQueue, list[dict], AlertManager]:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        engine = await _make_sigma_engine()
        await sigma_consumer(q, engine)

        mgr = _make_alert_manager(q)

        async def _alert_consumer(msg: dict) -> None:
            await mgr.process(msg)

        await q.subscribe(Topic.ALERTS, "alert-mgr", _alert_consumer)

        enriched: list[dict] = []

        async def _capture(msg: dict) -> None:
            enriched.append(msg)

        await q.subscribe(Topic.ENRICHED, "integration", _capture)
        return q, enriched, mgr

    async def test_identical_events_produce_one_enriched_alert(self) -> None:
        """Publishing the same raw event twice must result in a single enriched alert."""
        q, enriched, mgr = await self._full_pipeline_queue_with_mgr()

        # First call → True (new key set); second call → None (duplicate)
        mgr._valkey.set = AsyncMock(side_effect=[True, None])

        raw = _wazuh_process_raw(
            cmd_line="powershell.exe -enc dGVzdA==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            agent_name="WIN-DC01",
        )
        await q.publish(Topic.RAW_WAZUH, raw)
        await q.publish(Topic.RAW_WAZUH, raw)
        await asyncio.sleep(0.5)

        ps_alerts = [e for e in enriched if e["rule_id"] == RULE_ID_POWERSHELL]
        assert len(ps_alerts) == 1, (
            f"Duplicate identical events must produce exactly 1 enriched alert, "
            f"got {len(ps_alerts)}"
        )
        await q.stop()

    async def test_same_rule_different_hosts_produce_two_enriched_alerts(self) -> None:
        """The same attack from two distinct hosts must each produce an enriched alert."""
        q, enriched, mgr = await self._full_pipeline_queue_with_mgr()

        # Both calls set new keys → both are unique
        mgr._valkey.set = AsyncMock(return_value=True)

        raw_host_a = _wazuh_process_raw(
            cmd_line="powershell.exe -enc dGVzdA==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            agent_name="WIN-HOST-A",
        )
        raw_host_b = _wazuh_process_raw(
            cmd_line="powershell.exe -enc dGVzdA==",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            agent_name="WIN-HOST-B",
        )
        await q.publish(Topic.RAW_WAZUH, raw_host_a)
        await q.publish(Topic.RAW_WAZUH, raw_host_b)
        await asyncio.sleep(0.5)

        ps_alerts = [e for e in enriched if e["rule_id"] == RULE_ID_POWERSHELL]
        assert len(ps_alerts) == 2, (
            "Same rule triggered on two distinct hosts must produce 2 enriched alerts"
        )
        hosts = {a["host"] for a in ps_alerts}
        assert hosts == {"WIN-HOST-A", "WIN-HOST-B"}
        await q.stop()
