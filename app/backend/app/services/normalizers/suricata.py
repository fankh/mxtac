"""
Suricata EVE JSON → OCSF normalizer.

EVE JSON event_type: alert, dns, http, tls, flow, ssh, smb, ...

Alert event example:
{
  "timestamp": "2026-02-19T08:30:00.123456+0000",
  "event_type": "alert",
  "src_ip": "192.168.1.200",
  "src_port": 4444,
  "dest_ip": "10.0.0.5",
  "dest_port": 443,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2030358,
    "rev": 1,
    "signature": "ET MALWARE CobaltStrike Beacon Activity",
    "category": "A Network Trojan was detected",
    "severity": 1,
    "metadata": {"mitre_technique_id": ["T1071.001"]}
  }
}
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .ocsf import (
    Analytic, AttackInfo, AttackTactic, AttackTechnique, Endpoint,
    FindingInfo, OCSFCategory, OCSFClass, OCSFEvent, UserInfo,
)

# MITRE ATT&CK technique lookup: uid → (name, primary_tactic_uid, primary_tactic_name)
# Covers techniques commonly referenced in Suricata / Emerging Threats rules.
# Unknown UIDs fall back to using the UID string as the name with no tactic.
_MITRE_TECH: dict[str, tuple[str, str, str]] = {
    # Initial Access (TA0001)
    "T1190":     ("Exploit Public-Facing Application",                         "TA0001", "Initial Access"),
    "T1566":     ("Phishing",                                                  "TA0001", "Initial Access"),
    "T1566.001": ("Phishing: Spearphishing Attachment",                        "TA0001", "Initial Access"),
    "T1566.002": ("Phishing: Spearphishing Link",                              "TA0001", "Initial Access"),
    # Execution (TA0002)
    "T1059":     ("Command and Scripting Interpreter",                         "TA0002", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell",             "TA0002", "Execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell",  "TA0002", "Execution"),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript",             "TA0002", "Execution"),
    "T1203":     ("Exploitation for Client Execution",                         "TA0002", "Execution"),
    # Persistence (TA0003)
    "T1053":     ("Scheduled Task/Job",                                        "TA0003", "Persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task",                        "TA0003", "Persistence"),
    # Credential Access (TA0006)
    "T1003":     ("OS Credential Dumping",                                     "TA0006", "Credential Access"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory",                      "TA0006", "Credential Access"),
    "T1110":     ("Brute Force",                                               "TA0006", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing",                            "TA0006", "Credential Access"),
    # Discovery (TA0007)
    "T1046":     ("Network Service Discovery",                                 "TA0007", "Discovery"),
    "T1082":     ("System Information Discovery",                              "TA0007", "Discovery"),
    "T1083":     ("File and Directory Discovery",                              "TA0007", "Discovery"),
    # Lateral Movement (TA0008)
    "T1021":     ("Remote Services",                                           "TA0008", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol",                  "TA0008", "Lateral Movement"),
    "T1021.006": ("Remote Services: Windows Remote Management",               "TA0008", "Lateral Movement"),
    # Collection (TA0009)
    "T1005":     ("Data from Local System",                                    "TA0009", "Collection"),
    "T1560":     ("Archive Collected Data",                                    "TA0009", "Collection"),
    # Exfiltration (TA0010)
    "T1041":     ("Exfiltration Over C2 Channel",                             "TA0010", "Exfiltration"),
    "T1048":     ("Exfiltration Over Alternative Protocol",                    "TA0010", "Exfiltration"),
    "T1048.003": ("Exfiltration Over Alternative Protocol: Unencrypted",       "TA0010", "Exfiltration"),
    # Command and Control (TA0011)
    "T1071":     ("Application Layer Protocol",                                "TA0011", "Command and Control"),
    "T1071.001": ("Application Layer Protocol: Web Protocols",                 "TA0011", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS",                           "TA0011", "Command and Control"),
    "T1090":     ("Proxy",                                                     "TA0011", "Command and Control"),
    "T1090.001": ("Proxy: Internal Proxy",                                     "TA0011", "Command and Control"),
    "T1090.003": ("Proxy: Multi-hop Proxy",                                    "TA0011", "Command and Control"),
    "T1095":     ("Non-Application Layer Protocol",                            "TA0011", "Command and Control"),
    "T1102":     ("Web Service",                                               "TA0011", "Command and Control"),
    "T1105":     ("Ingress Tool Transfer",                                     "TA0011", "Command and Control"),
    "T1571":     ("Non-Standard Port",                                         "TA0011", "Command and Control"),
    "T1573":     ("Encrypted Channel",                                         "TA0011", "Command and Control"),
    "T1573.001": ("Encrypted Channel: Symmetric Cryptography",                 "TA0011", "Command and Control"),
    "T1573.002": ("Encrypted Channel: Asymmetric Cryptography",                "TA0011", "Command and Control"),
    # Impact (TA0040)
    "T1486":     ("Data Encrypted for Impact",                                 "TA0040", "Impact"),
    "T1489":     ("Service Stop",                                              "TA0040", "Impact"),
    "T1498":     ("Network Denial of Service",                                 "TA0040", "Impact"),
}

# Suricata alert severity (1=high, 2=medium, 3=low, 4=info) → OCSF severity_id
SURICATA_SEV_MAP: dict[int, int] = {
    1: 4,   # High
    2: 3,   # Medium
    3: 2,   # Low
    4: 1,   # Informational
}


class SuricataNormalizer:
    """Transforms a Suricata EVE JSON event into an OCSFEvent."""

    def normalize(self, raw: dict[str, Any]) -> OCSFEvent:
        event_type = raw.get("event_type", "alert")

        if event_type == "alert":
            return self._normalize_alert(raw)
        if event_type == "dns":
            return self._normalize_dns(raw)
        if event_type in ("http", "tls"):
            return self._normalize_network(raw, event_type)

        # Generic network activity fallback
        return self._normalize_network(raw, event_type)

    def _normalize_alert(self, raw: dict[str, Any]) -> OCSFEvent:
        alert = raw.get("alert", {})
        sig_id   = str(alert.get("signature_id", ""))
        sig_name = alert.get("signature", "Unknown Suricata Alert")

        # Severity
        sev_raw     = int(alert.get("severity", 2))
        severity_id = SURICATA_SEV_MAP.get(sev_raw, 3)

        # ATT&CK from Suricata metadata
        attacks = self._build_attacks(alert.get("metadata", {}))

        finding = FindingInfo(
            title=sig_name,
            severity_id=severity_id,
            attacks=attacks,
            analytic=Analytic(uid=sig_id, name=sig_name, type_id=1),
        )

        flow_id = raw.get("flow_id")
        return OCSFEvent(
            class_uid=OCSFClass.SECURITY_FINDING,
            class_name="Security Finding",
            category_uid=OCSFCategory.FINDINGS,
            time=self._parse_time(raw.get("timestamp")),
            severity_id=severity_id,
            metadata_product="Suricata",
            metadata_uid=str(flow_id) if flow_id is not None else None,
            src_endpoint=Endpoint(
                ip=raw.get("src_ip"),
                port=raw.get("src_port"),
            ),
            dst_endpoint=Endpoint(
                ip=raw.get("dest_ip"),
                port=raw.get("dest_port"),
            ),
            finding_info=finding,
            network_traffic={
                "proto":  raw.get("proto"),
                "action": alert.get("action"),
            },
            raw=raw,
        )

    def _normalize_dns(self, raw: dict[str, Any]) -> OCSFEvent:
        dns = raw.get("dns", {})
        flow_id = raw.get("flow_id")
        return OCSFEvent(
            class_uid=OCSFClass.DNS_ACTIVITY,
            class_name="DNS Activity",
            category_uid=OCSFCategory.NETWORK,
            time=self._parse_time(raw.get("timestamp")),
            severity_id=1,
            metadata_product="Suricata",
            metadata_uid=str(flow_id) if flow_id is not None else None,
            src_endpoint=Endpoint(ip=raw.get("src_ip")),
            dst_endpoint=Endpoint(ip=raw.get("dest_ip")),
            network_traffic={
                "query":   dns.get("rrname"),
                "qtype":   dns.get("rrtype"),
                "answers": dns.get("answers", []),
                "rcode":   dns.get("rcode"),
            },
            raw=raw,
        )

    def _normalize_network(self, raw: dict[str, Any], event_type: str) -> OCSFEvent:
        flow_id = raw.get("flow_id")
        return OCSFEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            class_name="Network Activity",
            category_uid=OCSFCategory.NETWORK,
            time=self._parse_time(raw.get("timestamp")),
            severity_id=1,
            metadata_product="Suricata",
            metadata_uid=str(flow_id) if flow_id is not None else None,
            src_endpoint=Endpoint(ip=raw.get("src_ip"), port=raw.get("src_port")),
            dst_endpoint=Endpoint(ip=raw.get("dest_ip"), port=raw.get("dest_port")),
            network_traffic={"event_type": event_type, **raw.get(event_type, {})},
            raw=raw,
        )

    def _build_attacks(self, metadata: dict) -> list[AttackInfo]:
        attacks = []
        for tech_id in metadata.get("mitre_technique_id", []):
            tech_id = tech_id.strip()
            entry = _MITRE_TECH.get(tech_id)
            if entry:
                tech_name, tac_uid, tac_name = entry
                sub = tech_id.split(".", 1)[1] if "." in tech_id else None
                attacks.append(AttackInfo(
                    technique=AttackTechnique(uid=tech_id, name=tech_name, sub_technique=sub),
                    tactic=AttackTactic(uid=tac_uid, name=tac_name),
                ))
            else:
                # Unknown technique: preserve UID as fallback name, no tactic
                attacks.append(AttackInfo(
                    technique=AttackTechnique(uid=tech_id, name=tech_id),
                ))
        return attacks

    def _parse_time(self, ts: str | None) -> datetime:
        if not ts:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(ts.replace("+0000", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc)
