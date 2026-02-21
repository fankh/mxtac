"""Compliance framework mapper — ATT&CK technique to NIST 800-53 / PCI-DSS coverage.

Maps ATT&CK technique IDs to compliance control IDs and calculates coverage
based on active (enabled) Sigma rules' technique_ids.

Frameworks supported:
  - "nist"    — NIST SP 800-53 Rev 5
  - "pci-dss" — PCI-DSS v4.0
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.rule import Rule

# ---------------------------------------------------------------------------
# Static mappings: ATT&CK technique_id → compliance control IDs
# ---------------------------------------------------------------------------

_TECHNIQUE_NIST_MAP: dict[str, list[str]] = {
    # Initial Access
    "T1190":     ["SC-7", "SI-2", "SI-3"],       # Exploit Public-Facing Application
    "T1133":     ["AC-3", "SC-7"],               # External Remote Services
    "T1566":     ["SI-3", "AC-3"],               # Phishing
    "T1566.001": ["SI-3", "AC-3"],               # Spearphishing Attachment
    "T1566.002": ["SI-3", "AC-3"],               # Spearphishing Link
    "T1078":     ["AC-2", "IA-2", "IA-5"],       # Valid Accounts
    "T1078.001": ["AC-2", "IA-2", "IA-5"],       # Default Accounts
    "T1078.003": ["AC-2", "IA-2", "IA-5"],       # Local Accounts
    # Execution
    "T1059":     ["CM-7", "SI-3"],               # Command and Scripting Interpreter
    "T1059.001": ["CM-7", "SI-3"],               # PowerShell
    "T1059.003": ["CM-7", "SI-3"],               # Windows Command Shell
    "T1059.004": ["CM-7", "SI-3"],               # Unix Shell
    "T1053":     ["CM-6", "AC-2"],               # Scheduled Task/Job
    "T1053.005": ["CM-6", "AC-2"],               # Scheduled Task
    "T1204":     ["SI-3", "AC-3"],               # User Execution
    # Persistence
    "T1543":     ["CM-7", "SI-7"],               # Create or Modify System Process
    "T1543.003": ["CM-7", "SI-7"],               # Windows Service
    "T1547":     ["CM-6", "SI-7"],               # Boot or Logon Autostart Execution
    "T1136":     ["AC-2", "CM-6"],               # Create Account
    # Privilege Escalation
    "T1548":     ["AC-6", "IA-2"],               # Abuse Elevation Control Mechanism
    "T1548.002": ["AC-6", "IA-2"],               # Bypass User Account Control
    "T1055":     ["SI-4", "AU-2"],               # Process Injection
    "T1055.001": ["SI-4", "AU-2"],               # DLL Injection
    # Defense Evasion
    "T1562":     ["AU-2", "AU-9", "SI-4"],       # Impair Defenses
    "T1562.001": ["AU-2", "AU-9", "SI-4"],       # Disable or Modify Tools
    "T1027":     ["SI-4", "AU-2"],               # Obfuscated Files or Information
    "T1218":     ["CM-7", "SI-3"],               # System Binary Proxy Execution
    # Credential Access
    "T1003":     ["IA-5", "SC-28", "AC-2"],      # OS Credential Dumping
    "T1003.001": ["IA-5", "SC-28", "AC-2"],      # LSASS Memory
    "T1110":     ["AC-7", "IA-5"],               # Brute Force
    "T1555":     ["IA-5", "SC-28"],              # Credentials from Password Stores
    # Discovery
    "T1082":     ["AC-3", "AU-12"],              # System Information Discovery
    "T1083":     ["AC-3", "AU-12"],              # File and Directory Discovery
    "T1087":     ["AC-3", "AU-12"],              # Account Discovery
    "T1135":     ["AC-3", "SC-7"],               # Network Share Discovery
    # Lateral Movement
    "T1021":     ["AC-4", "SC-7", "SC-8"],       # Remote Services
    "T1021.001": ["AC-4", "SC-7"],               # Remote Desktop Protocol
    "T1021.002": ["AC-4", "SC-7"],               # SMB/Windows Admin Shares
    "T1080":     ["AC-3", "SC-7"],               # Taint Shared Content
    # Collection
    "T1005":     ["AC-3", "MP-2"],               # Data from Local System
    "T1074":     ["AC-3", "MP-2"],               # Data Staged
    "T1113":     ["AC-3", "MP-2"],               # Screen Capture
    # Command and Control
    "T1071":     ["SC-7", "SI-4"],               # Application Layer Protocol
    "T1071.001": ["SC-7", "SI-4"],               # Web Protocols
    "T1095":     ["SC-7", "SI-4"],               # Non-Application Layer Protocol
    "T1572":     ["SC-7", "SI-4"],               # Protocol Tunneling
    # Exfiltration
    "T1041":     ["SC-7", "SC-28"],              # Exfiltration Over C2 Channel
    "T1048":     ["SC-7", "SC-28"],              # Exfiltration Over Alternative Protocol
    "T1567":     ["SC-7", "SC-28"],              # Exfiltration Over Web Service
    # Impact
    "T1486":     ["CP-9", "SI-7"],               # Data Encrypted for Impact
    "T1490":     ["CP-9", "SA-10"],              # Inhibit System Recovery
    "T1498":     ["SC-7", "CP-9"],               # Network Denial of Service
}

_TECHNIQUE_PCI_MAP: dict[str, list[str]] = {
    # Initial Access
    "T1190":     ["Req-1.3", "Req-6.3"],         # Exploit Public-Facing Application
    "T1133":     ["Req-1.3", "Req-8.2"],         # External Remote Services
    "T1566":     ["Req-12.6"],                   # Phishing
    "T1566.001": ["Req-12.6"],                   # Spearphishing Attachment
    "T1566.002": ["Req-12.6"],                   # Spearphishing Link
    "T1078":     ["Req-7.1", "Req-8.2"],         # Valid Accounts
    "T1078.001": ["Req-7.1", "Req-8.2"],         # Default Accounts
    "T1078.003": ["Req-7.1", "Req-8.2"],         # Local Accounts
    # Execution
    "T1059":     ["Req-6.4"],                    # Command and Scripting Interpreter
    "T1059.001": ["Req-6.4"],                    # PowerShell
    "T1059.003": ["Req-6.4"],                    # Windows Command Shell
    "T1059.004": ["Req-6.4"],                    # Unix Shell
    "T1053":     ["Req-6.3"],                    # Scheduled Task/Job
    "T1053.005": ["Req-6.3"],                    # Scheduled Task
    # Persistence
    "T1543":     ["Req-6.3", "Req-10.2"],        # Create or Modify System Process
    "T1543.003": ["Req-6.3", "Req-10.2"],        # Windows Service
    "T1547":     ["Req-6.3", "Req-10.2"],        # Boot or Logon Autostart Execution
    "T1136":     ["Req-8.2", "Req-10.2"],        # Create Account
    # Privilege Escalation
    "T1548":     ["Req-7.1", "Req-8.3"],         # Abuse Elevation Control Mechanism
    "T1548.002": ["Req-7.1", "Req-8.3"],         # Bypass UAC
    "T1055":     ["Req-6.3"],                    # Process Injection
    # Defense Evasion
    "T1562":     ["Req-10.5", "Req-10.7"],       # Impair Defenses
    "T1562.001": ["Req-10.5", "Req-10.7"],       # Disable or Modify Tools
    "T1027":     ["Req-10.7"],                   # Obfuscated Files or Information
    "T1218":     ["Req-6.4"],                    # System Binary Proxy Execution
    # Credential Access
    "T1003":     ["Req-8.4", "Req-8.6"],         # OS Credential Dumping
    "T1003.001": ["Req-8.4", "Req-8.6"],         # LSASS Memory
    "T1110":     ["Req-8.2", "Req-8.6"],         # Brute Force
    "T1555":     ["Req-8.4", "Req-3.4"],         # Credentials from Password Stores
    # Discovery
    "T1082":     ["Req-11.5"],                   # System Information Discovery
    "T1083":     ["Req-11.5"],                   # File and Directory Discovery
    "T1087":     ["Req-7.1", "Req-11.5"],        # Account Discovery
    "T1135":     ["Req-1.3"],                    # Network Share Discovery
    # Lateral Movement
    "T1021":     ["Req-1.3", "Req-7.1"],         # Remote Services
    "T1021.001": ["Req-1.3", "Req-7.1"],         # RDP
    "T1021.002": ["Req-1.3"],                    # SMB/Admin Shares
    # Collection
    "T1005":     ["Req-9.8", "Req-3.4"],         # Data from Local System
    "T1074":     ["Req-9.8"],                    # Data Staged
    # Command and Control
    "T1071":     ["Req-1.3", "Req-11.4"],        # Application Layer Protocol
    "T1071.001": ["Req-1.3", "Req-11.4"],        # Web Protocols
    "T1095":     ["Req-1.3"],                    # Non-Application Layer Protocol
    "T1572":     ["Req-1.3", "Req-11.4"],        # Protocol Tunneling
    # Exfiltration
    "T1041":     ["Req-4.2", "Req-9.8"],         # Exfiltration Over C2
    "T1048":     ["Req-4.2"],                    # Exfiltration Over Alt Protocol
    "T1567":     ["Req-4.2", "Req-9.8"],         # Exfiltration Over Web Service
    # Impact
    "T1486":     ["Req-6.5", "Req-12.10"],       # Data Encrypted for Impact
    "T1490":     ["Req-12.10"],                  # Inhibit System Recovery
    "T1498":     ["Req-11.4"],                   # Network DoS
}

# Human-readable names for NIST 800-53 controls
_NIST_CONTROL_NAMES: dict[str, str] = {
    "AC-2":  "Account Management",
    "AC-3":  "Access Enforcement",
    "AC-4":  "Information Flow Enforcement",
    "AC-6":  "Least Privilege",
    "AC-7":  "Unsuccessful Logon Attempts",
    "AU-2":  "Event Logging",
    "AU-9":  "Protection of Audit Information",
    "AU-12": "Audit Record Generation",
    "CM-6":  "Configuration Settings",
    "CM-7":  "Least Functionality",
    "CP-9":  "System Backup",
    "IA-2":  "Identification and Authentication",
    "IA-5":  "Authenticator Management",
    "MP-2":  "Media Access",
    "SA-10": "Developer Configuration Management",
    "SC-7":  "Boundary Protection",
    "SC-8":  "Transmission Confidentiality and Integrity",
    "SC-28": "Protection of Information at Rest",
    "SI-2":  "Flaw Remediation",
    "SI-3":  "Malicious Code Protection",
    "SI-4":  "System Monitoring",
    "SI-7":  "Software, Firmware, and Information Integrity",
}

# Human-readable names for PCI-DSS requirements
_PCI_REQUIREMENT_NAMES: dict[str, str] = {
    "Req-1.3":   "Restrict Inbound and Outbound Traffic",
    "Req-3.4":   "Protect Stored Cardholder Data",
    "Req-4.2":   "Encrypt Cardholder Data Across Open Networks",
    "Req-6.3":   "Develop Secure Software",
    "Req-6.4":   "Protect Web-Facing Applications",
    "Req-6.5":   "Identify Security Vulnerabilities",
    "Req-7.1":   "Limit Access to System Components",
    "Req-8.2":   "Uniquely Identify Users",
    "Req-8.3":   "Authenticate Access to System Components",
    "Req-8.4":   "Secure Individual Non-Consumer Authentications",
    "Req-8.6":   "Manage System and Application Accounts",
    "Req-9.8":   "Protect Stored Media",
    "Req-10.2":  "Implement Audit Logs",
    "Req-10.5":  "Protect Audit Logs from Destruction and Modification",
    "Req-10.7":  "Failures of Security Controls are Detected",
    "Req-11.4":  "Detect and Alert on Intrusions",
    "Req-11.5":  "Detect and Alert on Unauthorized Changes",
    "Req-12.6":  "Security Awareness Education",
    "Req-12.10": "Respond to Security Incidents",
}


class ComplianceMapper:
    """Maps ATT&CK technique coverage from active Sigma rules to compliance frameworks.

    Coverage is calculated by checking which ATT&CK technique IDs appear in
    enabled Sigma rules. A control is considered 'covered' when at least one
    of its mapped techniques is present in an active rule.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_compliance_status(self, framework: str) -> dict[str, Any]:
        """Return a compliance coverage matrix for the given framework.

        Args:
            framework: "nist" or "pci-dss"

        Returns a dict with:
            framework           — the requested framework name
            controls            — list of control dicts (see below)
            summary             — { total_controls, covered_controls, coverage_pct }

        Each control dict contains:
            id                  — control ID (e.g. "AC-2" or "Req-7.1")
            name                — human-readable control name
            covered             — True if any active rule covers a mapped technique
            techniques          — all ATT&CK technique IDs that map to this control
            covered_techniques  — subset of techniques covered by active rules

        Raises:
            ValueError: if framework is not "nist" or "pci-dss"
        """
        if framework not in ("nist", "pci-dss"):
            raise ValueError(
                f"Unknown framework {framework!r}. Valid: nist, pci-dss"
            )

        active_techniques = await self._get_active_rule_techniques()

        if framework == "nist":
            return self._build_coverage(
                framework="nist",
                technique_map=_TECHNIQUE_NIST_MAP,
                control_names=_NIST_CONTROL_NAMES,
                active_techniques=active_techniques,
            )
        else:
            return self._build_coverage(
                framework="pci-dss",
                technique_map=_TECHNIQUE_PCI_MAP,
                control_names=_PCI_REQUIREMENT_NAMES,
                active_techniques=active_techniques,
            )

    async def _get_active_rule_techniques(self) -> set[str]:
        """Query enabled rules and return the union of all their technique IDs."""
        result = await self._session.execute(
            select(Rule.technique_ids)
            .where(Rule.enabled == True)  # noqa: E712
            .where(Rule.technique_ids.is_not(None))
        )
        rows = result.scalars().all()

        covered: set[str] = set()
        for technique_ids_json in rows:
            try:
                ids = json.loads(technique_ids_json)
                for tid in ids:
                    if isinstance(tid, str) and tid.strip():
                        covered.add(tid.strip())
            except (ValueError, TypeError):
                continue

        return covered

    @staticmethod
    def _build_coverage(
        *,
        framework: str,
        technique_map: dict[str, list[str]],
        control_names: dict[str, str],
        active_techniques: set[str],
    ) -> dict[str, Any]:
        """Build a coverage matrix from a technique→control mapping."""
        # Invert to control→techniques
        control_to_techniques: dict[str, set[str]] = {}
        for technique_id, control_ids in technique_map.items():
            for control_id in control_ids:
                control_to_techniques.setdefault(control_id, set()).add(technique_id)

        controls: list[dict[str, Any]] = []
        for control_id, techniques in sorted(control_to_techniques.items()):
            covered_techniques = sorted(techniques & active_techniques)
            controls.append({
                "id": control_id,
                "name": control_names.get(control_id, control_id),
                "covered": bool(covered_techniques),
                "techniques": sorted(techniques),
                "covered_techniques": covered_techniques,
            })

        covered_count = sum(1 for c in controls if c["covered"])
        total = len(controls)
        coverage_pct = round(covered_count / total * 100, 1) if total else 0.0

        return {
            "framework": framework,
            "controls": controls,
            "summary": {
                "total_controls": total,
                "covered_controls": covered_count,
                "coverage_pct": coverage_pct,
            },
        }


# ---------------------------------------------------------------------------
# Module-level accessors for the static mapping tables (used by tests)
# ---------------------------------------------------------------------------

def get_technique_nist_map() -> dict[str, list[str]]:
    """Return the ATT&CK technique → NIST 800-53 control mapping."""
    return _TECHNIQUE_NIST_MAP


def get_technique_pci_map() -> dict[str, list[str]]:
    """Return the ATT&CK technique → PCI-DSS requirement mapping."""
    return _TECHNIQUE_PCI_MAP
