"""
NDR Consumer — subscribes to normalized events, runs NDR detection algorithms,
and publishes alerts for network-based threats.

Filters for network_activity class events and feeds them through the
NdrDetectionEngine for behavioral analysis (C2 beaconing, port scan,
lateral movement, exfiltration, DNS anomaly, brute force).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core.logging import get_logger
from ..pipeline.queue import MessageQueue, Topic
from .ndr_detection import FlowRecord, NdrDetectionEngine

logger = get_logger(__name__)

# OCSF class names that indicate network activity
NETWORK_CLASSES = frozenset({
    "network_activity",
    "network_connection",
    "dns_activity",
    "dns_query",
    "http_activity",
    "tls_activity",
    "rdp_activity",
    "smb_activity",
    "ssh_activity",
})


async def ndr_consumer(queue: MessageQueue) -> None:
    """Subscribe to normalized events and run NDR detection algorithms."""

    engine = NdrDetectionEngine()
    event_count = 0
    alert_count = 0

    async def _handle(event_dict: dict[str, Any]) -> None:
        nonlocal event_count, alert_count

        # Only process network events
        class_name = event_dict.get("class_name", "")
        if class_name not in NETWORK_CLASSES:
            return

        try:
            flow = _to_flow_record(event_dict)
            if not flow:
                return

            event_count += 1
            alerts = engine.analyze_flow(flow)

            for alert in alerts:
                alert_dict = {
                    "id": f"ndr-{alert.alert_type.lower()}-{alert.src_ip}-{event_count}",
                    "rule_id": f"ndr.{alert.alert_type.lower()}",
                    "rule_title": f"NDR: {alert.alert_type.replace('_', ' ').title()}",
                    "level": alert.severity,
                    "severity_id": _severity_to_id(alert.severity),
                    "technique_ids": [alert.mitre_technique] if alert.mitre_technique else [],
                    "tactic_ids": [alert.mitre_tactic] if alert.mitre_tactic else [],
                    "host": alert.src_ip,
                    "time": alert.timestamp.isoformat(),
                    "event_snapshot": {
                        "src_ip": alert.src_ip,
                        "dst_ip": alert.dst_ip,
                        "dst_port": alert.dst_port,
                        "description": alert.description,
                        "confidence": alert.confidence,
                        "evidence": alert.evidence,
                    },
                }
                await queue.publish(Topic.ALERTS, alert_dict)
                alert_count += 1
                logger.info(
                    "NDR alert: type=%s src=%s dst=%s confidence=%.2f",
                    alert.alert_type, alert.src_ip, alert.dst_ip, alert.confidence,
                )

            # Periodic stats log
            if event_count % 10000 == 0:
                logger.info(
                    "NDR consumer stats: events=%d, alerts=%d", event_count, alert_count
                )

        except Exception:
            logger.debug("NDR consumer error", exc_info=True)

    await queue.subscribe(Topic.NORMALIZED, "ndr-detection", _handle)
    logger.info("NDR consumer subscribed to %s", Topic.NORMALIZED)


def _to_flow_record(event: dict[str, Any]) -> FlowRecord | None:
    """Convert OCSF event dict to FlowRecord for NDR analysis."""
    raw = event.get("raw", event)

    # Extract endpoints
    src = raw.get("src_endpoint", {}) if isinstance(raw, dict) else {}
    dst = raw.get("dst_endpoint", {}) if isinstance(raw, dict) else {}

    src_ip = src.get("ip") or event.get("src_ip") or ""
    dst_ip = dst.get("ip") or event.get("dst_ip") or ""

    if not src_ip or not dst_ip:
        return None

    src_port = int(src.get("port", 0) or event.get("src_port", 0) or 0)
    dst_port = int(dst.get("port", 0) or event.get("dst_port", 0) or 0)

    # Protocol
    protocol = str(raw.get("protocol", event.get("protocol", "TCP"))).upper()
    if protocol.isdigit():
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(protocol), "OTHER")

    # Traffic
    traffic = raw.get("traffic", {}) if isinstance(raw, dict) else {}
    bytes_in = int(traffic.get("bytes_in", raw.get("bytes_in", 0)) or 0)
    bytes_out = int(traffic.get("bytes_out", raw.get("bytes_out", 0)) or 0)

    # Duration
    duration_ms = int(raw.get("duration_ms", raw.get("duration", 0)) or 0)

    # Timestamp
    time_str = event.get("time") or raw.get("time", "")
    try:
        ts = datetime.fromisoformat(str(time_str).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        ts = datetime.now(timezone.utc)

    return FlowRecord(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        duration_ms=duration_ms,
        timestamp=ts,
    )


def _severity_to_id(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
        severity.lower(), 3
    )
