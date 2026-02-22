"""Tests for feature 8.21 — Bundled example rules — 5 default detections.

Verifies that every rule in sigma_rules/ is:
  1. Present on disk with the expected filename
  2. Parseable by SigmaEngine.load_rule_yaml()
  3. Carrying correct metadata (id, title, level, status, ATT&CK tags)
  4. Functional — matches events it should detect
  5. Precise — does NOT fire on benign events

Rules under test:
  - powershell_encoded_command.yml   (T1059.001, high)
  - lsass_memory_access.yml          (T1003.001, critical)
  - new_service_creation.yml         (T1543.003, medium)
  - lateral_movement_smb.yml         (T1021.002, high)
  - dns_tunneling_long_query.yml     (T1071.004, medium)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.engine.sigma_engine import SigmaEngine, SigmaRule
from app.services.normalizers.ocsf import (
    Endpoint,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BACKEND_ROOT = Path(__file__).parent.parent.parent
_SIGMA_RULES_DIR = _BACKEND_ROOT / "sigma_rules"

_RULE_FILES = {
    "powershell_encoded_command": _SIGMA_RULES_DIR / "powershell_encoded_command.yml",
    "lsass_memory_access":        _SIGMA_RULES_DIR / "lsass_memory_access.yml",
    "new_service_creation":       _SIGMA_RULES_DIR / "new_service_creation.yml",
    "lateral_movement_smb":       _SIGMA_RULES_DIR / "lateral_movement_smb.yml",
    "dns_tunneling_long_query":   _SIGMA_RULES_DIR / "dns_tunneling_long_query.yml",
}

# Expected rule IDs per file
_EXPECTED_IDS = {
    "powershell_encoded_command": "b6f98540-ed62-4856-b8b7-2a2d7b80f5b7",
    "lsass_memory_access":        "0d894093-71bc-43c3-b7e0-01eb5adf38cd",
    "new_service_creation":       "e4f1b7cc-28b3-47c8-bb8e-c93f6a8e8d7e",
    "lateral_movement_smb":       "c2c02497-17b0-4c2d-a3f7-e5a19cf1b88b",
    "dns_tunneling_long_query":   "d5e0ef77-3bd9-4a4d-b6e2-0b3c8af53a10",
}


# ---------------------------------------------------------------------------
# Helpers — OCSFEvent constructors
# ---------------------------------------------------------------------------

def _proc_event(**overrides) -> OCSFEvent:
    """Minimal Windows process-creation event."""
    kw: dict = dict(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        class_name="Process Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        dst_endpoint=Endpoint(hostname="workstation-01"),
    )
    kw.update(overrides)
    return OCSFEvent(**kw)


def _net_event(**overrides) -> OCSFEvent:
    """Minimal Windows network-connection event."""
    kw: dict = dict(
        class_uid=OCSFClass.NETWORK_ACTIVITY,
        class_name="Network Activity",
        category_uid=OCSFCategory.NETWORK,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        dst_endpoint=Endpoint(hostname="target-host"),
    )
    kw.update(overrides)
    return OCSFEvent(**kw)


def _dns_event(**overrides) -> OCSFEvent:
    """Minimal DNS-query event."""
    kw: dict = dict(
        class_uid=OCSFClass.DNS_ACTIVITY,
        class_name="DNS Activity",
        category_uid=OCSFCategory.NETWORK,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        dst_endpoint=Endpoint(hostname="dns-server"),
    )
    kw.update(overrides)
    return OCSFEvent(**kw)


def _load_rule(key: str) -> SigmaRule:
    """Parse a single bundled rule file and return SigmaRule (assert not None)."""
    engine = SigmaEngine()
    path = _RULE_FILES[key]
    rule = engine.load_rule_yaml(path.read_text())
    assert rule is not None, f"Rule {key!r} failed to parse"
    return rule


async def _alerts(rule: SigmaRule, event: OCSFEvent) -> list:
    engine = SigmaEngine()
    engine.add_rule(rule)
    return [a async for a in engine.evaluate(event)]


# ===========================================================================
# 1 — Disk presence
# ===========================================================================


class TestBundledRulesExist:
    def test_powershell_encoded_command_exists(self) -> None:
        assert _RULE_FILES["powershell_encoded_command"].is_file()

    def test_lsass_memory_access_exists(self) -> None:
        assert _RULE_FILES["lsass_memory_access"].is_file()

    def test_new_service_creation_exists(self) -> None:
        assert _RULE_FILES["new_service_creation"].is_file()

    def test_lateral_movement_smb_exists(self) -> None:
        assert _RULE_FILES["lateral_movement_smb"].is_file()

    def test_dns_tunneling_long_query_exists(self) -> None:
        assert _RULE_FILES["dns_tunneling_long_query"].is_file()

    async def test_sigma_rules_dir_loads_exactly_five(self) -> None:
        engine = SigmaEngine()
        count = await engine.load_rules_from_dir(str(_SIGMA_RULES_DIR))
        assert count == 5, f"Expected 5 bundled rules, got {count}"


# ===========================================================================
# 2 — Parseability & metadata
# ===========================================================================


class TestBundledRulesMetadata:

    # ── powershell_encoded_command ────────────────────────────────────────────

    def test_ps_encoded_parses(self) -> None:
        assert _load_rule("powershell_encoded_command") is not None

    def test_ps_encoded_id(self) -> None:
        rule = _load_rule("powershell_encoded_command")
        assert rule.id == _EXPECTED_IDS["powershell_encoded_command"]

    def test_ps_encoded_title(self) -> None:
        rule = _load_rule("powershell_encoded_command")
        assert "powershell" in rule.title.lower()

    def test_ps_encoded_level_high(self) -> None:
        assert _load_rule("powershell_encoded_command").level == "high"

    def test_ps_encoded_status_stable(self) -> None:
        assert _load_rule("powershell_encoded_command").status == "stable"

    def test_ps_encoded_technique_t1059(self) -> None:
        rule = _load_rule("powershell_encoded_command")
        assert any("T1059" in t for t in rule.technique_ids)

    def test_ps_encoded_tactic_ta0002(self) -> None:
        assert "TA0002" in _load_rule("powershell_encoded_command").tactic_ids

    def test_ps_encoded_has_matcher(self) -> None:
        assert _load_rule("powershell_encoded_command")._matcher is not None

    # ── lsass_memory_access ───────────────────────────────────────────────────

    def test_lsass_parses(self) -> None:
        assert _load_rule("lsass_memory_access") is not None

    def test_lsass_id(self) -> None:
        rule = _load_rule("lsass_memory_access")
        assert rule.id == _EXPECTED_IDS["lsass_memory_access"]

    def test_lsass_level_critical(self) -> None:
        assert _load_rule("lsass_memory_access").level == "critical"

    def test_lsass_technique_t1003(self) -> None:
        rule = _load_rule("lsass_memory_access")
        assert any("T1003" in t for t in rule.technique_ids)

    def test_lsass_tactic_ta0006(self) -> None:
        assert "TA0006" in _load_rule("lsass_memory_access").tactic_ids

    def test_lsass_has_matcher(self) -> None:
        assert _load_rule("lsass_memory_access")._matcher is not None

    # ── new_service_creation ──────────────────────────────────────────────────

    def test_new_service_parses(self) -> None:
        assert _load_rule("new_service_creation") is not None

    def test_new_service_id(self) -> None:
        rule = _load_rule("new_service_creation")
        assert rule.id == _EXPECTED_IDS["new_service_creation"]

    def test_new_service_level_medium(self) -> None:
        assert _load_rule("new_service_creation").level == "medium"

    def test_new_service_technique_t1543(self) -> None:
        rule = _load_rule("new_service_creation")
        assert any("T1543" in t for t in rule.technique_ids)

    def test_new_service_tactic_ta0003(self) -> None:
        assert "TA0003" in _load_rule("new_service_creation").tactic_ids

    def test_new_service_has_matcher(self) -> None:
        assert _load_rule("new_service_creation")._matcher is not None

    # ── lateral_movement_smb ──────────────────────────────────────────────────

    def test_smb_parses(self) -> None:
        assert _load_rule("lateral_movement_smb") is not None

    def test_smb_id(self) -> None:
        rule = _load_rule("lateral_movement_smb")
        assert rule.id == _EXPECTED_IDS["lateral_movement_smb"]

    def test_smb_level_high(self) -> None:
        assert _load_rule("lateral_movement_smb").level == "high"

    def test_smb_technique_t1021(self) -> None:
        rule = _load_rule("lateral_movement_smb")
        assert any("T1021" in t for t in rule.technique_ids)

    def test_smb_tactic_ta0008(self) -> None:
        assert "TA0008" in _load_rule("lateral_movement_smb").tactic_ids

    def test_smb_has_matcher(self) -> None:
        assert _load_rule("lateral_movement_smb")._matcher is not None

    # ── dns_tunneling_long_query ──────────────────────────────────────────────

    def test_dns_tunnel_parses(self) -> None:
        assert _load_rule("dns_tunneling_long_query") is not None

    def test_dns_tunnel_id(self) -> None:
        rule = _load_rule("dns_tunneling_long_query")
        assert rule.id == _EXPECTED_IDS["dns_tunneling_long_query"]

    def test_dns_tunnel_level_medium(self) -> None:
        assert _load_rule("dns_tunneling_long_query").level == "medium"

    def test_dns_tunnel_technique_t1071(self) -> None:
        rule = _load_rule("dns_tunneling_long_query")
        assert any("T1071" in t for t in rule.technique_ids)

    def test_dns_tunnel_tactic_ta0011(self) -> None:
        assert "TA0011" in _load_rule("dns_tunneling_long_query").tactic_ids

    def test_dns_tunnel_has_matcher(self) -> None:
        assert _load_rule("dns_tunneling_long_query")._matcher is not None


# ===========================================================================
# 3 — Detection correctness (match / no-match)
# ===========================================================================


class TestPowerShellEncodedCommandDetection:
    """Rule: cmd_line contains (-enc | -EncodedCommand | '-e ') AND name endswith powershell.exe"""

    async def test_match_enc_flag(self) -> None:
        rule = _load_rule("powershell_encoded_command")
        event = _proc_event(process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc123"))
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_encoded_command_flag(self) -> None:
        rule = _load_rule("powershell_encoded_command")
        event = _proc_event(process=ProcessInfo(name="powershell.exe", cmd_line="powershell -EncodedCommand dGVzdA=="))
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_short_e_flag(self) -> None:
        rule = _load_rule("powershell_encoded_command")
        event = _proc_event(process=ProcessInfo(name="powershell.exe", cmd_line="powershell -e dGVzdA=="))
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_alert_level_high(self) -> None:
        rule = _load_rule("powershell_encoded_command")
        event = _proc_event(process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc"))
        alerts = await _alerts(rule, event)
        assert alerts[0].level == "high"

    async def test_alert_technique_id(self) -> None:
        rule = _load_rule("powershell_encoded_command")
        event = _proc_event(process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc"))
        alerts = await _alerts(rule, event)
        assert any("T1059" in t for t in alerts[0].technique_ids)

    async def test_no_match_wrong_process_name(self) -> None:
        """cmd.exe with -enc flag — name doesn't end with powershell.exe."""
        rule = _load_rule("powershell_encoded_command")
        event = _proc_event(process=ProcessInfo(name="cmd.exe", cmd_line="cmd -enc abc"))
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0

    async def test_no_match_benign_powershell(self) -> None:
        """PowerShell without encoded command flags."""
        rule = _load_rule("powershell_encoded_command")
        event = _proc_event(process=ProcessInfo(name="powershell.exe", cmd_line="powershell -Command Get-Process"))
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0


class TestLsassMemoryAccessDetection:
    """Rule: path endswith \\lsass.exe AND NOT name in [csrss.exe, wininit.exe, wmiprvse.exe]"""

    async def test_match_mimikatz_accessing_lsass(self) -> None:
        rule = _load_rule("lsass_memory_access")
        event = _proc_event(
            process=ProcessInfo(name="mimikatz.exe", path=r"C:\Windows\System32\lsass.exe"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_unknown_process_accessing_lsass(self) -> None:
        rule = _load_rule("lsass_memory_access")
        event = _proc_event(
            process=ProcessInfo(name="explorer.exe", path=r"C:\Windows\System32\lsass.exe"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_alert_level_critical(self) -> None:
        rule = _load_rule("lsass_memory_access")
        event = _proc_event(
            process=ProcessInfo(name="malware.exe", path=r"C:\Windows\System32\lsass.exe"),
        )
        alerts = await _alerts(rule, event)
        assert alerts[0].level == "critical"

    async def test_alert_severity_id_5(self) -> None:
        rule = _load_rule("lsass_memory_access")
        event = _proc_event(
            process=ProcessInfo(name="malware.exe", path=r"C:\Windows\System32\lsass.exe"),
        )
        alerts = await _alerts(rule, event)
        assert alerts[0].severity_id == 5

    async def test_no_match_csrss_filtered(self) -> None:
        """csrss.exe legitimately accesses LSASS — must be filtered out."""
        rule = _load_rule("lsass_memory_access")
        event = _proc_event(
            process=ProcessInfo(name="csrss.exe", path=r"C:\Windows\System32\lsass.exe"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0

    async def test_no_match_wininit_filtered(self) -> None:
        rule = _load_rule("lsass_memory_access")
        event = _proc_event(
            process=ProcessInfo(name="wininit.exe", path=r"C:\Windows\System32\lsass.exe"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0

    async def test_no_match_wmiprvse_filtered(self) -> None:
        rule = _load_rule("lsass_memory_access")
        event = _proc_event(
            process=ProcessInfo(name="wmiprvse.exe", path=r"C:\Windows\System32\lsass.exe"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0

    async def test_no_match_different_path(self) -> None:
        """Process is not targeting lsass.exe."""
        rule = _load_rule("lsass_memory_access")
        event = _proc_event(
            process=ProcessInfo(name="mimikatz.exe", path=r"C:\Windows\System32\services.exe"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0


class TestNewServiceCreationDetection:
    """Rule: cmd_line contains ('sc create' | 'sc.exe create' | 'New-Service')"""

    async def test_match_sc_create(self) -> None:
        rule = _load_rule("new_service_creation")
        event = _proc_event(
            process=ProcessInfo(cmd_line=r"sc create MySvc binPath=C:\evil.exe"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_sc_exe_create(self) -> None:
        rule = _load_rule("new_service_creation")
        event = _proc_event(
            process=ProcessInfo(cmd_line=r"sc.exe create BackdoorSvc binPath=C:\backdoor.exe"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_new_service_powershell(self) -> None:
        rule = _load_rule("new_service_creation")
        event = _proc_event(
            process=ProcessInfo(cmd_line="New-Service -Name EvilSvc -BinaryPathName C:\\evil.exe"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_alert_level_medium(self) -> None:
        rule = _load_rule("new_service_creation")
        event = _proc_event(process=ProcessInfo(cmd_line="sc create TestSvc"))
        alerts = await _alerts(rule, event)
        assert alerts[0].level == "medium"

    async def test_alert_tactic_ta0003(self) -> None:
        rule = _load_rule("new_service_creation")
        event = _proc_event(process=ProcessInfo(cmd_line="sc create TestSvc"))
        alerts = await _alerts(rule, event)
        assert "TA0003" in alerts[0].tactic_ids

    async def test_no_match_sc_query(self) -> None:
        """sc query is benign — not a service creation."""
        rule = _load_rule("new_service_creation")
        event = _proc_event(process=ProcessInfo(cmd_line="sc query state= all"))
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0

    async def test_no_match_net_start(self) -> None:
        """net start is a different command."""
        rule = _load_rule("new_service_creation")
        event = _proc_event(process=ProcessInfo(cmd_line="net start MySvc"))
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0


class TestLateralMovementSMBDetection:
    """Rule: DestinationPort in [445, 139] AND name contains ('psexec'|'smbexec'|'wmiexec')"""

    async def test_match_psexec_port_445(self) -> None:
        rule = _load_rule("lateral_movement_smb")
        event = _net_event(
            process=ProcessInfo(name="psexec.exe"),
            dst_endpoint=Endpoint(port=445, hostname="target-host"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_psexec_port_139(self) -> None:
        rule = _load_rule("lateral_movement_smb")
        event = _net_event(
            process=ProcessInfo(name="psexec.exe"),
            dst_endpoint=Endpoint(port=139, hostname="target-host"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_smbexec(self) -> None:
        rule = _load_rule("lateral_movement_smb")
        event = _net_event(
            process=ProcessInfo(name="smbexec.exe"),
            dst_endpoint=Endpoint(port=445, hostname="target-host"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_wmiexec(self) -> None:
        rule = _load_rule("lateral_movement_smb")
        event = _net_event(
            process=ProcessInfo(name="wmiexec.py"),
            dst_endpoint=Endpoint(port=445, hostname="target-host"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_alert_level_high(self) -> None:
        rule = _load_rule("lateral_movement_smb")
        event = _net_event(
            process=ProcessInfo(name="psexec.exe"),
            dst_endpoint=Endpoint(port=445, hostname="target-host"),
        )
        alerts = await _alerts(rule, event)
        assert alerts[0].level == "high"

    async def test_alert_tactic_ta0008(self) -> None:
        rule = _load_rule("lateral_movement_smb")
        event = _net_event(
            process=ProcessInfo(name="psexec.exe"),
            dst_endpoint=Endpoint(port=445, hostname="target-host"),
        )
        alerts = await _alerts(rule, event)
        assert "TA0008" in alerts[0].tactic_ids

    async def test_no_match_wrong_port(self) -> None:
        """Port 80 (HTTP) should not fire the SMB rule."""
        rule = _load_rule("lateral_movement_smb")
        event = _net_event(
            process=ProcessInfo(name="psexec.exe"),
            dst_endpoint=Endpoint(port=80, hostname="target-host"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0

    async def test_no_match_benign_process_smb_port(self) -> None:
        """A legitimate process using port 445 should not fire."""
        rule = _load_rule("lateral_movement_smb")
        event = _net_event(
            process=ProcessInfo(name="explorer.exe"),
            dst_endpoint=Endpoint(port=445, hostname="fileserver"),
        )
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0

    async def test_no_match_no_process_info(self) -> None:
        """No process information — rule requires name to match."""
        rule = _load_rule("lateral_movement_smb")
        event = _net_event(dst_endpoint=Endpoint(port=445, hostname="target-host"))
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0


class TestDNSTunnelingDetection:
    """Rule: QueryName matches regex .{50,} (query length >= 50 chars)"""

    async def test_match_long_query_exactly_50(self) -> None:
        rule = _load_rule("dns_tunneling_long_query")
        long_query = "a" * 50 + ".evil.com"
        event = _dns_event(network_traffic={"query": long_query})
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_very_long_query(self) -> None:
        rule = _load_rule("dns_tunneling_long_query")
        long_query = "x" * 200 + ".c2.example.com"
        event = _dns_event(network_traffic={"query": long_query})
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_match_base64_encoded_c2_query(self) -> None:
        """Typical DNS tunnel query — base64 encoded data as subdomain."""
        rule = _load_rule("dns_tunneling_long_query")
        query = "aGVsbG8td29ybGQtdGhpcy1pcy1hLWxvbmctZG5zLXF1ZXJ5Lg==.tunnel.example.com"
        event = _dns_event(network_traffic={"query": query})
        alerts = await _alerts(rule, event)
        assert len(alerts) == 1

    async def test_alert_level_medium(self) -> None:
        rule = _load_rule("dns_tunneling_long_query")
        long_query = "b" * 60 + ".evil.com"
        event = _dns_event(network_traffic={"query": long_query})
        alerts = await _alerts(rule, event)
        assert alerts[0].level == "medium"

    async def test_alert_tactic_ta0011(self) -> None:
        rule = _load_rule("dns_tunneling_long_query")
        long_query = "c" * 60 + ".evil.com"
        event = _dns_event(network_traffic={"query": long_query})
        alerts = await _alerts(rule, event)
        assert "TA0011" in alerts[0].tactic_ids

    async def test_no_match_short_query(self) -> None:
        """Normal short DNS query — under 50 chars."""
        rule = _load_rule("dns_tunneling_long_query")
        event = _dns_event(network_traffic={"query": "www.google.com"})
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0

    async def test_no_match_exactly_49_chars(self) -> None:
        """Query of exactly 49 chars — just below the threshold."""
        rule = _load_rule("dns_tunneling_long_query")
        event = _dns_event(network_traffic={"query": "a" * 49})
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0

    async def test_no_match_empty_query(self) -> None:
        """Empty query or missing network_traffic."""
        rule = _load_rule("dns_tunneling_long_query")
        event = _dns_event()  # no network_traffic
        alerts = await _alerts(rule, event)
        assert len(alerts) == 0
