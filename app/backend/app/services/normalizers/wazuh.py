"""
Wazuh → OCSF normalizer.

Wazuh alert structure (simplified):
{
  "timestamp": "2026-02-19T08:30:00.000Z",
  "id": "1708331400.12345",
  "rule": {
    "id": "100234",
    "description": "LSASS Memory Dump Detected",
    "level": 12,
    "mitre": {"id": ["T1003.001"], "tactic": ["credential-access"]}
  },
  "agent": {"id": "001", "name": "WIN-DC01", "ip": "192.168.1.10"},
  "data": {
    "srcip": "192.168.1.10",
    "dstuser": "SYSTEM",
    "win": {
      "eventdata": {
        "commandLine": "mimikatz.exe sekurlsa::logonpasswords",
        "image": "C:\\mimikatz\\mimikatz.exe",
        "processId": "3456",
        "parentProcessId": "1234"
      }
    }
  }
}
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .ocsf import (
    Analytic, AttackInfo, AttackTactic, AttackTechnique,
    Endpoint, FindingInfo, OCSFCategory, OCSFClass, OCSFEvent,
    ProcessInfo, SEVERITY_MAP, UserInfo,
)

# Wazuh rule level → OCSF severity_id
LEVEL_TO_SEVERITY: list[tuple[int, int]] = [
    (14, 5),   # Critical
    (11, 4),   # High
    (7,  3),   # Medium
    (4,  2),   # Low
    (0,  1),   # Informational
]

# Wazuh MITRE tactic ID → OCSF ATT&CK tactic name + UID
MITRE_TACTIC_MAP: dict[str, tuple[str, str]] = {
    "initial-access":          ("Initial Access",          "TA0001"),
    "execution":               ("Execution",               "TA0002"),
    "persistence":             ("Persistence",             "TA0003"),
    "privilege-escalation":    ("Privilege Escalation",    "TA0004"),
    "defense-evasion":         ("Defense Evasion",         "TA0005"),
    "credential-access":       ("Credential Access",       "TA0006"),
    "discovery":               ("Discovery",               "TA0007"),
    "lateral-movement":        ("Lateral Movement",        "TA0008"),
    "collection":              ("Collection",              "TA0009"),
    "command-and-control":     ("Command and Control",     "TA0011"),
    "exfiltration":            ("Exfiltration",            "TA0010"),
    "impact":                  ("Impact",                  "TA0040"),
    "reconnaissance":          ("Reconnaissance",          "TA0043"),
    "resource-development":    ("Resource Development",    "TA0042"),
}

# Reverse lookup: full tactic name → slug.
# Some Wazuh versions emit "Credential Access" instead of "credential-access".
MITRE_TACTIC_FULL_NAME_MAP: dict[str, str] = {
    name: slug for slug, (name, _) in MITRE_TACTIC_MAP.items()
}


class WazuhNormalizer:
    """Transforms a Wazuh alert dict into an OCSFEvent."""

    def normalize(self, raw: dict[str, Any]) -> OCSFEvent:
        rule     = raw.get("rule", {})
        agent    = raw.get("agent", {})
        data     = raw.get("data", {})
        win_data = data.get("win", {}).get("eventdata", {})

        # Determine event class
        class_uid, class_name, category_uid = self._classify(rule, data)

        # Severity
        level       = int(rule.get("level", 5))
        severity_id = self._level_to_severity(level)

        # ATT&CK
        mitre       = rule.get("mitre", {})
        attacks     = self._build_attacks(mitre)

        # Finding info (always present for Wazuh alerts)
        finding = FindingInfo(
            title=rule.get("description", "Unknown Alert"),
            severity_id=severity_id,
            attacks=attacks,
            analytic=Analytic(
                uid=str(rule.get("id", "")),
                name=rule.get("description", ""),
                type_id=1,
            ),
        )

        # Endpoint (agent = destination host being monitored)
        # Feature 7.4: agent → dst_endpoint (full mapping)
        agent_os = agent.get("os", {})
        dst = Endpoint(
            hostname=agent.get("name"),
            ip=agent.get("ip") or data.get("dstip"),
            os_name=agent_os.get("name"),
        )
        src = Endpoint(ip=data.get("srcip"))

        # Preserve agent.id in unmapped for traceability (no uid field on Endpoint)
        unmapped: dict = {}
        if agent.get("id"):
            unmapped["agent_id"] = agent["id"]

        # User
        user = UserInfo(name=data.get("dstuser") or data.get("srcuser"))

        # Process (Windows event data)
        process = ProcessInfo(
            cmd_line=win_data.get("commandLine") or win_data.get("CommandLine"),
            path=win_data.get("image") or win_data.get("Image"),
            pid=self._safe_int(win_data.get("processId") or win_data.get("ProcessId")),
            parent_pid=self._safe_int(
                win_data.get("parentProcessId") or win_data.get("ParentProcessId")
            ),
            name=self._exe_name(
                win_data.get("image") or win_data.get("Image", "")
            ),
        )

        return OCSFEvent(
            class_uid=class_uid,
            class_name=class_name,
            category_uid=category_uid,
            time=self._parse_time(raw.get("timestamp")),
            severity_id=severity_id,
            metadata_product="Wazuh",
            metadata_uid=raw.get("id"),
            src_endpoint=src,
            dst_endpoint=dst,
            actor_user=user,
            process=process,
            finding_info=finding,
            raw=raw,
            unmapped=unmapped,
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _classify(
        self, rule: dict, data: dict
    ) -> tuple[int, str, int]:
        """Pick the best OCSF class for a Wazuh alert."""
        groups = rule.get("groups", [])
        if any("process" in g or "win_process" in g for g in groups):
            return OCSFClass.PROCESS_ACTIVITY, "Process Activity", OCSFCategory.SYSTEM_ACTIVITY
        if any("network" in g or "firewall" in g or "connection" in g for g in groups):
            return OCSFClass.NETWORK_ACTIVITY, "Network Activity", OCSFCategory.NETWORK
        if any("authentication" in g or "login" in g or "logon" in g for g in groups):
            return OCSFClass.AUTHENTICATION, "Authentication", OCSFCategory.IAM
        if any("file" in g or "syscheck" in g for g in groups):
            return OCSFClass.FILE_ACTIVITY, "File Activity", OCSFCategory.SYSTEM_ACTIVITY
        # Default: security finding
        return OCSFClass.SECURITY_FINDING, "Security Finding", OCSFCategory.FINDINGS

    def _level_to_severity(self, level: int) -> int:
        for min_level, severity_id in LEVEL_TO_SEVERITY:
            if level >= min_level:
                return severity_id
        return 1

    def _build_attacks(self, mitre: dict) -> list[AttackInfo]:
        """Convert Wazuh rule.mitre metadata into OCSF AttackInfo objects.

        Handles:
        - Multiple technique IDs paired with their tactics (1-to-1 or fan-out)
        - Sub-technique IDs (e.g. "T1003.001" → sub_technique="001")
        - Technique names from the optional ``mitre.technique`` name list
        - Both slug format ("credential-access") and full-name format
          ("Credential Access") for tactic values
        """
        attacks: list[AttackInfo] = []
        techniques      = mitre.get("id", [])          # e.g. ["T1003.001"]
        tactic_values   = mitre.get("tactic", [])      # slug or full name
        technique_names = mitre.get("technique", [])   # e.g. ["OS Credential Dumping: LSASS Memory"]

        for i, tech_id in enumerate(techniques):
            # ── Resolve tactic ──────────────────────────────────────────────
            raw_tactic  = tactic_values[i] if i < len(tactic_values) else (
                tactic_values[0] if tactic_values else ""
            )
            # Accept both "credential-access" (slug) and "Credential Access" (full name)
            slug        = MITRE_TACTIC_FULL_NAME_MAP.get(raw_tactic, raw_tactic)
            tactic_info = MITRE_TACTIC_MAP.get(slug, (raw_tactic, ""))

            # ── Parse sub-technique ─────────────────────────────────────────
            _parent_uid, sub_technique = self._parse_technique_id(tech_id)

            # ── Resolve technique name ──────────────────────────────────────
            tech_name = technique_names[i] if i < len(technique_names) else tech_id

            attacks.append(AttackInfo(
                tactic=AttackTactic(name=tactic_info[0], uid=tactic_info[1]),
                technique=AttackTechnique(
                    uid=tech_id,
                    name=tech_name,
                    sub_technique=sub_technique,
                ),
            ))
        return attacks

    def _parse_technique_id(self, tech_id: str) -> tuple[str, str | None]:
        """Split a technique ID into its parent and sub-technique parts.

        Examples::
            "T1003.001" → ("T1003", "001")
            "T1059"     → ("T1059", None)
        """
        if "." in tech_id:
            parent, sub = tech_id.split(".", 1)
            return parent, sub
        return tech_id, None

    def _parse_time(self, ts: str | None) -> datetime:
        if not ts:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc)

    def _safe_int(self, val: Any) -> int | None:
        try:
            return int(val) if val is not None else None
        except (ValueError, TypeError):
            return None

    def _exe_name(self, path: str) -> str | None:
        if not path:
            return None
        return path.replace("\\", "/").split("/")[-1]
