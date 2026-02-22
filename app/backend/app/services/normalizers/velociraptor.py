"""
Velociraptor → OCSF normalizer.

Velociraptor artifact result structure (Windows.EventLogs.*):
{
  "_artifact_name": "Windows.EventLogs.Evtx",
  "_source": "velociraptor",
  "System": {
    "EventID": {"Value": 4688},
    "TimeCreated": {"SystemTime": "2024-01-15T08:30:00.0000000Z"},
    "Computer": "WIN-HOST.domain.com",
    "Provider": {"Name": "Microsoft-Windows-Security-Auditing"}
  },
  "EventData": {
    "SubjectUserName": "SYSTEM",
    "SubjectDomainName": "NT AUTHORITY",
    "NewProcessId": "0x1234",
    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd.exe /c whoami"
  }
}

Linux.Sys.* artifact result structure:
{
  "_artifact_name": "Linux.Sys.Pslist",
  "_source": "velociraptor",
  "Pid": 1234,
  "PPid": 456,
  "Name": "bash",
  "Exe": "/bin/bash",
  "Cmdline": "/bin/bash -c whoami",
  "Username": "root"
}

Generic.* artifact result structure (e.g. Generic.Client.Info/process/network):
{
  "_artifact_name": "Generic.System.Pstree",
  "_source": "velociraptor",
  "Pid": 1234,
  "PPid": 1,
  "Name": "sshd",
  "CommandLine": "/usr/sbin/sshd -D"
}

Default flows query result (no _artifact_name):
{
  "_source": "velociraptor",
  "client_id": "C.abc123",
  "flow_id": "F.001",
  "create_time": 1234567890,
  "artifacts": ["Windows.System.Pslist"],
  "state": "FINISHED"
}

Artifact family routing:
  Windows.EventLogs.*  → SecurityFinding (class_uid 2001, category 2)
  Linux.Sys.*          → ProcessActivity (class_uid 1007, category 1)
  Generic.*            → ProcessActivity (class_uid 1007, category 1)
  (default/flows)      → SecurityFinding (class_uid 2001, category 2)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .ocsf import (
    Analytic,
    AttackInfo,
    AttackTactic,
    AttackTechnique,
    Endpoint,
    FindingInfo,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
    UserInfo,
)

# Windows Event ID → (tech_uid, tech_name, tac_uid, tac_name, severity_id)
# severity_id: 0=unknown, 1=info, 2=low, 3=medium, 4=high, 5=critical
_EVENTID_ATTACK: dict[int, tuple[str, str, str, str, int]] = {
    4624: ("T1078",     "Valid Accounts",                    "TA0001", "Initial Access",       1),
    4625: ("T1110",     "Brute Force",                       "TA0006", "Credential Access",    3),
    4648: ("T1078",     "Valid Accounts",                    "TA0001", "Initial Access",       3),
    4663: ("T1005",     "Data from Local System",            "TA0009", "Collection",           2),
    4688: ("T1059",     "Command and Scripting Interpreter", "TA0002", "Execution",            2),
    4697: ("T1543.003", "Windows Service",                   "TA0003", "Persistence",          4),
    4698: ("T1053.005", "Scheduled Task/Job: Scheduled Task","TA0003", "Persistence",          3),
    4720: ("T1136.001", "Create Account: Local Account",     "TA0003", "Persistence",          3),
    4728: ("T1078",     "Valid Accounts",                    "TA0004", "Privilege Escalation", 3),
    4732: ("T1078",     "Valid Accounts",                    "TA0004", "Privilege Escalation", 3),
    7045: ("T1543.003", "Windows Service",                   "TA0003", "Persistence",          4),
}

# Artifact name (exact) → (tech_uid, tech_name, tac_uid, tac_name)
_ARTIFACT_ATTACK: dict[str, tuple[str, str, str, str]] = {
    "Linux.Sys.Pslist":        ("T1057",    "Process Discovery",                      "TA0007", "Discovery"),
    "Linux.Sys.Users":         ("T1087.001","Account Discovery: Local Account",       "TA0007", "Discovery"),
    "Linux.Sys.BashHistory":   ("T1059.004","Unix Shell",                             "TA0002", "Execution"),
    "Generic.Network.Netstat": ("T1049",    "System Network Connections Discovery",   "TA0007", "Discovery"),
    "Generic.System.Pstree":   ("T1057",    "Process Discovery",                      "TA0007", "Discovery"),
}


def _parse_time(ts: str | None) -> datetime:
    """Parse an ISO 8601 / Velociraptor timestamp string. Returns utcnow() on failure.

    Handles Windows event log timestamps with 7-digit fractional seconds
    (e.g. "2024-01-15T08:30:00.0000000Z") by truncating to 6 digits before parsing.
    """
    if not ts:
        return datetime.now(timezone.utc)
    try:
        # Normalize to UTC offset notation
        s = ts.replace("Z", "+00:00")
        # Truncate fractional seconds >6 digits to 6 (Python fromisoformat limit)
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)
        return datetime.fromisoformat(s)
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


class VelociraptorNormalizer:
    """Transforms a Velociraptor artifact result row into an OCSFEvent."""

    def normalize(self, raw: dict[str, Any]) -> OCSFEvent:
        artifact = raw.get("_artifact_name", "")

        if artifact.startswith("Windows.EventLogs."):
            return self._normalize_windows_eventlog(raw, artifact)
        elif artifact.startswith("Linux.Sys."):
            return self._normalize_linux_sys(raw, artifact)
        elif artifact.startswith("Generic."):
            return self._normalize_generic(raw, artifact)
        else:
            return self._normalize_default(raw, artifact)

    # ── Windows.EventLogs.* ───────────────────────────────────────────────────

    def _normalize_windows_eventlog(
        self, raw: dict[str, Any], artifact: str
    ) -> OCSFEvent:
        system = raw.get("System", {})
        event_data = raw.get("EventData", {})

        # EventID can be nested {"Value": N} or a plain int
        eid_raw = system.get("EventID", raw.get("EventID"))
        event_id: int | None = None
        if isinstance(eid_raw, dict):
            event_id = eid_raw.get("Value")
        elif isinstance(eid_raw, int):
            event_id = eid_raw
        if isinstance(event_id, str):
            try:
                event_id = int(event_id)
            except ValueError:
                event_id = None

        # Timestamp
        time_raw = system.get("TimeCreated", {})
        if isinstance(time_raw, dict):
            time_str = time_raw.get("SystemTime", "")
        else:
            time_str = str(time_raw) if time_raw else ""
        event_time = _parse_time(time_str or raw.get("TimeCreated"))

        # Computer / hostname → dst_endpoint
        computer = system.get("Computer") or raw.get("Computer", "")
        dst = Endpoint(hostname=computer or None)

        # User info from EventData
        subject_user = (
            event_data.get("SubjectUserName")
            or event_data.get("TargetUserName")
            or raw.get("Username")
            or ""
        )
        subject_domain = (
            event_data.get("SubjectDomainName")
            or event_data.get("TargetDomainName")
            or ""
        )
        actor = UserInfo(
            name=subject_user or None,
            domain=subject_domain or None,
        )

        # Process info from EventData (common in process-creation events)
        proc_path = event_data.get("NewProcessName") or raw.get("Exe", "")
        cmd_line = event_data.get("CommandLine") or raw.get("Cmdline", "")
        pid_raw = event_data.get("NewProcessId") or raw.get("Pid")
        ppid_raw = event_data.get("ProcessId") or raw.get("PPid")
        process = ProcessInfo(
            name=proc_path.split("\\")[-1] if proc_path else None,
            path=proc_path or None,
            cmd_line=cmd_line or None,
            pid=self._parse_hex_or_int(pid_raw),
            parent_pid=self._parse_hex_or_int(ppid_raw),
        )

        # ATT&CK + severity from Event ID
        attacks, severity_id = self._attacks_from_event_id(event_id)

        finding = FindingInfo(
            title=self._eventlog_title(event_id, artifact),
            severity_id=severity_id,
            attacks=attacks,
            analytic=Analytic(
                uid=str(event_id) if event_id is not None else None,
                name=artifact,
                type_id=1,
            ),
        )

        unmapped = self._collect_unmapped(raw, ("System", "EventData", "_source"))

        return OCSFEvent(
            class_uid=OCSFClass.SECURITY_FINDING,
            class_name="Security Finding",
            category_uid=OCSFCategory.FINDINGS,
            time=event_time,
            severity_id=severity_id,
            metadata_product="Velociraptor",
            metadata_uid=raw.get("flow_id"),
            dst_endpoint=dst,
            actor_user=actor,
            process=process,
            finding_info=finding,
            raw=raw,
            unmapped=unmapped,
        )

    # ── Linux.Sys.* ───────────────────────────────────────────────────────────

    def _normalize_linux_sys(
        self, raw: dict[str, Any], artifact: str
    ) -> OCSFEvent:
        pid = raw.get("Pid") or raw.get("pid")
        ppid = raw.get("PPid") or raw.get("ppid")
        name = raw.get("Name") or raw.get("name", "")
        exe = raw.get("Exe") or raw.get("exe", "")
        cmd_line = raw.get("Cmdline") or raw.get("cmdline", "")
        username = raw.get("Username") or raw.get("username", "")
        hostname = raw.get("Hostname") or raw.get("hostname", "")

        process = ProcessInfo(
            pid=int(pid) if pid is not None else None,
            parent_pid=int(ppid) if ppid is not None else None,
            name=name or None,
            path=exe or None,
            cmd_line=cmd_line or None,
        )
        actor = UserInfo(name=username or None)
        dst = Endpoint(hostname=hostname or None)

        attacks = self._attacks_from_artifact(artifact)

        finding = FindingInfo(
            title=f"Velociraptor artifact: {artifact}",
            severity_id=1,
            attacks=attacks,
            analytic=Analytic(uid=artifact, name=artifact, type_id=1),
        )

        unmapped = self._collect_unmapped(raw, ("_source",))

        return OCSFEvent(
            class_uid=OCSFClass.PROCESS_ACTIVITY,
            class_name="Process Activity",
            category_uid=OCSFCategory.SYSTEM_ACTIVITY,
            time=self._parse_event_time(raw),
            severity_id=1,
            metadata_product="Velociraptor",
            metadata_uid=raw.get("flow_id"),
            dst_endpoint=dst,
            actor_user=actor,
            process=process,
            finding_info=finding,
            raw=raw,
            unmapped=unmapped,
        )

    # ── Generic.* ─────────────────────────────────────────────────────────────

    def _normalize_generic(
        self, raw: dict[str, Any], artifact: str
    ) -> OCSFEvent:
        pid = raw.get("Pid") or raw.get("pid")
        ppid = raw.get("PPid") or raw.get("ppid")
        name = raw.get("Name") or raw.get("name", "")
        exe = raw.get("Exe") or raw.get("exe") or raw.get("CommandLine", "")
        cmd_line = raw.get("CommandLine") or raw.get("Cmdline") or raw.get("cmdline", "")
        hostname = raw.get("Hostname") or raw.get("hostname", "")
        username = raw.get("Username") or raw.get("username", "")

        process = ProcessInfo(
            pid=int(pid) if pid is not None else None,
            parent_pid=int(ppid) if ppid is not None else None,
            name=name or None,
            path=exe or None,
            cmd_line=cmd_line or None,
        )
        actor = UserInfo(name=username or None)
        dst = Endpoint(hostname=hostname or None)

        attacks = self._attacks_from_artifact(artifact)

        finding = FindingInfo(
            title=f"Velociraptor artifact: {artifact}",
            severity_id=1,
            attacks=attacks,
            analytic=Analytic(uid=artifact, name=artifact, type_id=1),
        )

        unmapped = self._collect_unmapped(raw, ("_source",))

        return OCSFEvent(
            class_uid=OCSFClass.PROCESS_ACTIVITY,
            class_name="Process Activity",
            category_uid=OCSFCategory.SYSTEM_ACTIVITY,
            time=self._parse_event_time(raw),
            severity_id=1,
            metadata_product="Velociraptor",
            metadata_uid=raw.get("flow_id"),
            dst_endpoint=dst,
            actor_user=actor,
            process=process,
            finding_info=finding,
            raw=raw,
            unmapped=unmapped,
        )

    # ── Default (flows metadata) ───────────────────────────────────────────────

    def _normalize_default(
        self, raw: dict[str, Any], artifact: str
    ) -> OCSFEvent:
        client_id = raw.get("client_id", "")
        flow_id = raw.get("flow_id", "")
        artifacts_list = raw.get("artifacts", [])
        state = raw.get("state", "")

        title = f"Velociraptor flow {flow_id}" if flow_id else "Velociraptor event"
        if artifacts_list:
            title += f": {', '.join(str(a) for a in artifacts_list)}"

        finding = FindingInfo(
            title=title,
            severity_id=1,
            attacks=[],
            analytic=Analytic(uid=flow_id or None, name=title, type_id=1),
        )

        src = Endpoint(uid=client_id or None)

        unmapped: dict[str, Any] = {}
        for key in ("state", "artifacts", "create_time"):
            val = raw.get(key)
            if val is not None:
                unmapped[key] = val

        return OCSFEvent(
            class_uid=OCSFClass.SECURITY_FINDING,
            class_name="Security Finding",
            category_uid=OCSFCategory.FINDINGS,
            time=self._parse_create_time(raw.get("create_time")),
            severity_id=1,
            metadata_product="Velociraptor",
            metadata_uid=flow_id or None,
            src_endpoint=src,
            finding_info=finding,
            raw=raw,
            unmapped=unmapped,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _attacks_from_event_id(
        self, event_id: int | None
    ) -> tuple[list[AttackInfo], int]:
        """Return (attacks, severity_id) for a Windows Event ID."""
        if event_id is None or event_id not in _EVENTID_ATTACK:
            return [], 1
        tech_uid, tech_name, tac_uid, tac_name, severity_id = _EVENTID_ATTACK[event_id]
        sub = tech_uid.split(".", 1)[1] if "." in tech_uid else None
        attack = AttackInfo(
            tactic=AttackTactic(uid=tac_uid, name=tac_name),
            technique=AttackTechnique(uid=tech_uid, name=tech_name, sub_technique=sub),
        )
        return [attack], severity_id

    def _attacks_from_artifact(self, artifact: str) -> list[AttackInfo]:
        """Return ATT&CK attacks for an artifact name (exact match only)."""
        entry = _ARTIFACT_ATTACK.get(artifact)
        if entry is None:
            return []
        tech_uid, tech_name, tac_uid, tac_name = entry
        sub = tech_uid.split(".", 1)[1] if "." in tech_uid else None
        return [
            AttackInfo(
                tactic=AttackTactic(uid=tac_uid, name=tac_name),
                technique=AttackTechnique(uid=tech_uid, name=tech_name, sub_technique=sub),
            )
        ]

    def _eventlog_title(self, event_id: int | None, artifact: str) -> str:
        if event_id is None:
            return f"Velociraptor Windows event: {artifact}"
        entry = _EVENTID_ATTACK.get(event_id)
        if entry:
            _, tech_name, _, _, _ = entry
            return f"Windows EventID {event_id}: {tech_name}"
        return f"Windows EventID {event_id}: {artifact}"

    @staticmethod
    def _parse_hex_or_int(value: Any) -> int | None:
        """Parse a hex string (0x...) or numeric value to Python int. Returns None on failure."""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return int(value)
        s = str(value).strip()
        if not s:
            return None
        try:
            return int(s, 16) if s.startswith("0x") or s.startswith("0X") else int(s)
        except ValueError:
            return None

    @staticmethod
    def _parse_event_time(raw: dict[str, Any]) -> datetime:
        """Extract a timestamp from common Velociraptor time fields."""
        for key in ("Timestamp", "timestamp", "TimeCreated", "time"):
            val = raw.get(key)
            if val:
                if isinstance(val, (int, float)):
                    try:
                        return datetime.fromtimestamp(val, tz=timezone.utc)
                    except (OSError, OverflowError, ValueError):
                        pass
                else:
                    result = _parse_time(str(val))
                    if result is not None:
                        return result
        return datetime.now(timezone.utc)

    @staticmethod
    def _parse_create_time(create_time: Any) -> datetime:
        """Parse Velociraptor flow create_time (Unix epoch int or ISO string)."""
        if create_time is None:
            return datetime.now(timezone.utc)
        if isinstance(create_time, (int, float)):
            try:
                return datetime.fromtimestamp(create_time, tz=timezone.utc)
            except (OSError, OverflowError, ValueError):
                return datetime.now(timezone.utc)
        try:
            return _parse_time(str(create_time))
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _collect_unmapped(
        raw: dict[str, Any], exclude: tuple[str, ...]
    ) -> dict[str, Any]:
        """Collect raw keys not in *exclude* that have non-None scalar values."""
        skip = set(exclude) | {"_artifact_name", "System", "EventData"}
        return {
            k: v
            for k, v in raw.items()
            if k not in skip and v is not None and not isinstance(v, dict)
        }
