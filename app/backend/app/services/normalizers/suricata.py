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
    Analytic, AttackInfo, AttackTechnique, Endpoint,
    FindingInfo, OCSFCategory, OCSFClass, OCSFEvent, UserInfo,
)

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

        return OCSFEvent(
            class_uid=OCSFClass.SECURITY_FINDING,
            class_name="Security Finding",
            category_uid=OCSFCategory.FINDINGS,
            time=self._parse_time(raw.get("timestamp")),
            severity_id=severity_id,
            metadata_product="Suricata",
            metadata_uid=raw.get("flow_id"),
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
        return OCSFEvent(
            class_uid=OCSFClass.DNS_ACTIVITY,
            class_name="DNS Activity",
            category_uid=OCSFCategory.NETWORK,
            time=self._parse_time(raw.get("timestamp")),
            severity_id=1,
            metadata_product="Suricata",
            metadata_uid=raw.get("flow_id"),
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
        return OCSFEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            class_name="Network Activity",
            category_uid=OCSFCategory.NETWORK,
            time=self._parse_time(raw.get("timestamp")),
            severity_id=1,
            metadata_product="Suricata",
            metadata_uid=raw.get("flow_id"),
            src_endpoint=Endpoint(ip=raw.get("src_ip"), port=raw.get("src_port")),
            dst_endpoint=Endpoint(ip=raw.get("dest_ip"), port=raw.get("dest_port")),
            network_traffic={"event_type": event_type, **raw.get(event_type, {})},
            raw=raw,
        )

    def _build_attacks(self, metadata: dict) -> list[AttackInfo]:
        attacks = []
        for tech_id in metadata.get("mitre_technique_id", []):
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
