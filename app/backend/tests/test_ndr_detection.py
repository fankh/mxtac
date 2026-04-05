"""Integration tests for NDR detection engine algorithms."""

import math
import time
from datetime import datetime, timezone

import pytest

from app.services.ndr_detection import (
    FlowRecord,
    NdrDetectionEngine,
)


@pytest.fixture
def engine():
    return NdrDetectionEngine()


def _flow(src="10.0.0.1", dst="192.168.1.1", src_port=12345, dst_port=80,
          proto="TCP", bytes_in=100, bytes_out=100, duration_ms=1000):
    return FlowRecord(
        src_ip=src, dst_ip=dst, src_port=src_port, dst_port=dst_port,
        protocol=proto, bytes_in=bytes_in, bytes_out=bytes_out,
        duration_ms=duration_ms, timestamp=datetime.now(timezone.utc),
    )


class TestPortScan:
    def test_no_alert_below_threshold(self, engine):
        """14 ports should NOT trigger."""
        for port in range(1, 15):
            alerts = engine.analyze_flow(_flow(dst_port=port, dst="10.0.0.100"))
        assert not any(a.alert_type == "PORT_SCAN" for a in alerts)

    def test_alert_at_threshold(self, engine):
        """15 distinct ports should trigger port scan alert."""
        all_alerts = []
        for port in range(1, 20):
            all_alerts.extend(engine.analyze_flow(_flow(dst_port=port, dst="10.0.0.100")))
        scan_alerts = [a for a in all_alerts if a.alert_type == "PORT_SCAN"]
        assert len(scan_alerts) == 1
        assert scan_alerts[0].mitre_technique == "T1046"
        assert scan_alerts[0].severity == "medium"


class TestC2Beaconing:
    def test_regular_interval_triggers(self, engine):
        """10+ connections with <20% jitter should trigger C2 alert."""
        all_alerts = []
        for i in range(12):
            flow = _flow(src="10.0.0.5", dst="1.2.3.4", dst_port=443)
            # Simulate regular intervals by manipulating engine state directly
            key = f"10.0.0.5::1.2.3.4:443"
            engine._beacon_state[key].append(time.monotonic() + i * 60)  # every 60s
            all_alerts.extend(engine.analyze_flow(flow))

        beacon_alerts = [a for a in all_alerts if a.alert_type == "C2_BEACONING"]
        assert len(beacon_alerts) >= 1
        assert beacon_alerts[0].mitre_technique == "T1071"
        assert beacon_alerts[0].severity == "high"


class TestLateralMovement:
    def test_unknown_smb_triggers(self, engine):
        """New internal SMB connection should trigger lateral movement."""
        alerts = engine.analyze_flow(_flow(
            src="192.168.1.10", dst="192.168.1.20", dst_port=445,
        ))
        lat_alerts = [a for a in alerts if a.alert_type == "LATERAL_MOVEMENT"]
        assert len(lat_alerts) == 1
        assert lat_alerts[0].mitre_technique == "T1021"

    def test_known_pair_no_alert(self, engine):
        """Known internal pair should not trigger."""
        engine.add_known_pair("192.168.1.10", "192.168.1.20")
        alerts = engine.analyze_flow(_flow(
            src="192.168.1.10", dst="192.168.1.20", dst_port=445,
        ))
        assert not any(a.alert_type == "LATERAL_MOVEMENT" for a in alerts)


class TestDnsAnomaly:
    def test_large_dns_triggers(self, engine):
        """DNS request >100 bytes should trigger tunneling alert."""
        alerts = engine.analyze_flow(_flow(
            src="10.0.0.1", dst="8.8.8.8", dst_port=53,
            bytes_in=200, bytes_out=50,
        ))
        dns_alerts = [a for a in alerts if a.alert_type == "DNS_ANOMALY"]
        assert len(dns_alerts) == 1
        assert dns_alerts[0].mitre_technique == "T1071.004"

    def test_normal_dns_no_alert(self, engine):
        """Normal DNS (<100 bytes) should not trigger."""
        alerts = engine.analyze_flow(_flow(
            src="10.0.0.1", dst="8.8.8.8", dst_port=53,
            bytes_in=40, bytes_out=30,
        ))
        assert not any(a.alert_type == "DNS_ANOMALY" for a in alerts)


class TestBruteForce:
    def test_multiple_failed_auth_triggers(self, engine):
        """10+ short-duration connections on SSH should trigger brute force."""
        all_alerts = []
        for _ in range(12):
            all_alerts.extend(engine.analyze_flow(_flow(
                src="1.2.3.4", dst="10.0.0.1", dst_port=22,
                duration_ms=500, bytes_in=200, bytes_out=50,
            )))
        bf_alerts = [a for a in all_alerts if a.alert_type == "BRUTE_FORCE"]
        assert len(bf_alerts) >= 1
        assert bf_alerts[0].mitre_technique == "T1110"


class TestExfiltration:
    def test_volume_above_baseline_triggers(self, engine):
        """Outbound volume >2x baseline should trigger exfil alert."""
        engine.set_baseline("outbound_bytes", 1000)
        alerts = engine.analyze_flow(_flow(
            src="10.0.0.5", dst="1.2.3.4",
            bytes_out=3000, bytes_in=100,
        ))
        exfil_alerts = [a for a in alerts if a.alert_type == "DATA_EXFILTRATION"]
        assert len(exfil_alerts) == 1
        assert exfil_alerts[0].severity == "critical"


class TestDomainEntropy:
    def test_normal_domain(self, engine):
        assert NdrDetectionEngine.calculate_domain_entropy("google") < 3.5

    def test_dga_domain(self, engine):
        assert NdrDetectionEngine.calculate_domain_entropy("xk3j9f2mq8p1") > 3.5

    def test_empty_domain(self, engine):
        assert NdrDetectionEngine.calculate_domain_entropy("") == 0.0
