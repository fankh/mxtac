//! OCSF Network Activity (class_uid 4001) serialization.
//!
//! Implements the Open Cybersecurity Schema Framework (OCSF) v1.1.0
//! Network Activity class for MxWatch NDR events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// OCSF building blocks (shared with MxGuard; duplicated here for crate
// independence).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfMetadata {
    pub version: String,
    pub product: OcsfProduct,
}

impl Default for OcsfMetadata {
    fn default() -> Self {
        Self {
            version: "1.1.0".into(),
            product: OcsfProduct::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfProduct {
    pub name: String,
    pub vendor: String,
    pub version: String,
}

impl Default for OcsfProduct {
    fn default() -> Self {
        Self {
            name: "MxWatch".into(),
            vendor: "MxTac".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfDevice {
    pub hostname: String,
    pub ip: String,
    pub os_name: String,
}

impl OcsfDevice {
    pub fn from_current_host() -> Self {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into());
        Self {
            hostname,
            ip: "0.0.0.0".into(),
            os_name: "Linux".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// OCSF Network endpoint (src or dst).
// ---------------------------------------------------------------------------

/// OCSF-compliant network endpoint with IP address and port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OcsfEndpoint {
    pub ip: String,
    pub port: u16,
}

impl OcsfEndpoint {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            ip: ip.to_string(),
            port,
        }
    }
}

// ---------------------------------------------------------------------------
// OCSF Connection info.
// ---------------------------------------------------------------------------

/// OCSF connection direction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
    Unknown,
}

impl ConnectionDirection {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Inbound => "Inbound",
            Self::Outbound => "Outbound",
            Self::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for ConnectionDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// OCSF connection info object embedded in Network Activity events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OcsfConnectionInfo {
    /// Traffic direction relative to the observed device.
    pub direction: String,
    /// Application-layer protocol name (HTTP, DNS, TLS, etc.).
    pub protocol_name: String,
}

impl OcsfConnectionInfo {
    pub fn new(protocol: &str, direction: ConnectionDirection) -> Self {
        Self {
            direction: direction.to_string(),
            protocol_name: protocol.to_uppercase(),
        }
    }

    /// Create with Unknown direction (used when direction cannot be inferred).
    pub fn unknown(protocol: &str) -> Self {
        Self::new(protocol, ConnectionDirection::Unknown)
    }
}

// ---------------------------------------------------------------------------
// Network Activity event (OCSF 4001)
// ---------------------------------------------------------------------------

/// OCSF Network Activity event (class_uid 4001, category_uid 4).
///
/// Serialized `time` is a Unix epoch timestamp in seconds (integer),
/// conforming to the OCSF specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfNetworkEvent {
    pub metadata: OcsfMetadata,
    /// Event timestamp as Unix epoch seconds.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub time: DateTime<Utc>,
    /// OCSF class UID — always 4001 for Network Activity.
    pub class_uid: u32,
    /// OCSF category UID — always 4 (Network Activity).
    pub category_uid: u32,
    /// Human-readable activity label.
    pub activity: String,
    /// OCSF activity_id (5 = Traffic, 99 = Other/Detection).
    pub activity_id: u32,
    /// OCSF severity_id (1–5).
    pub severity_id: u8,
    /// Human-readable severity label.
    pub severity: String,
    /// Human-readable event description.
    pub message: String,
    /// Sensor device that observed the traffic.
    pub device: OcsfDevice,
    /// Source network endpoint.
    pub src_endpoint: OcsfEndpoint,
    /// Destination network endpoint.
    pub dst_endpoint: OcsfEndpoint,
    /// Connection metadata (direction, protocol).
    pub connection_info: OcsfConnectionInfo,
    /// Optional detection detail when a detector has raised an alert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionDetail>,
}

/// Detection context attached to alert-type events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionDetail {
    pub detector: String,
    pub description: String,
    pub evidence: serde_json::Value,
}

impl OcsfNetworkEvent {
    /// Build a standard traffic observation event.
    pub fn traffic(
        device: OcsfDevice,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: &str,
        severity_id: u8,
    ) -> Self {
        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid: 4001,
            category_uid: 4,
            activity: "Traffic".into(),
            // OCSF activity_id 5 = Traffic
            activity_id: 5,
            severity_id,
            severity: severity_name(severity_id).into(),
            message: format!("Network traffic observed on {}", protocol.to_uppercase()),
            device,
            src_endpoint: OcsfEndpoint::new(src_ip, src_port),
            dst_endpoint: OcsfEndpoint::new(dst_ip, dst_port),
            connection_info: OcsfConnectionInfo::unknown(protocol),
            detection: None,
        }
    }

    /// Build a detection-based event from an alert.
    pub fn from_alert(
        device: OcsfDevice,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: &str,
        alert: &crate::detectors::Alert,
    ) -> Self {
        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid: 4001,
            category_uid: 4,
            activity: "Detection".into(),
            // OCSF activity_id 99 = Other (used for custom detection events)
            activity_id: 99,
            severity_id: alert.severity.ocsf_id(),
            severity: severity_name(alert.severity.ocsf_id()).into(),
            message: alert.description.clone(),
            device,
            src_endpoint: OcsfEndpoint::new(src_ip, src_port),
            dst_endpoint: OcsfEndpoint::new(dst_ip, dst_port),
            connection_info: OcsfConnectionInfo::unknown(protocol),
            detection: Some(DetectionDetail {
                detector: alert.detector.clone(),
                description: alert.description.clone(),
                evidence: alert.evidence.clone(),
            }),
        }
    }
}

fn severity_name(id: u8) -> &'static str {
    match id {
        1 => "Informational",
        2 => "Low",
        3 => "Medium",
        4 => "High",
        5 => "Critical",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    use crate::detectors::{Alert, AlertSeverity};

    fn src_ip() -> IpAddr {
        IpAddr::from_str("192.168.1.100").unwrap()
    }

    fn dst_ip() -> IpAddr {
        IpAddr::from_str("203.0.113.50").unwrap()
    }

    fn test_device() -> OcsfDevice {
        OcsfDevice {
            hostname: "test-sensor".into(),
            ip: "192.168.1.1".into(),
            os_name: "Linux".into(),
        }
    }

    // --- traffic() constructor -----------------------------------------------

    #[test]
    fn test_traffic_class_uid() {
        let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 12345, dst_ip(), 80, "HTTP", 1);
        assert_eq!(ev.class_uid, 4001);
        assert_eq!(ev.category_uid, 4);
    }

    #[test]
    fn test_traffic_activity_id() {
        let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 12345, dst_ip(), 80, "HTTP", 1);
        assert_eq!(ev.activity, "Traffic");
        // OCSF activity_id 5 = Traffic
        assert_eq!(ev.activity_id, 5);
    }

    #[test]
    fn test_traffic_endpoints() {
        let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 54321, dst_ip(), 443, "TLS", 1);
        assert_eq!(ev.src_endpoint.ip, "192.168.1.100");
        assert_eq!(ev.src_endpoint.port, 54321);
        assert_eq!(ev.dst_endpoint.ip, "203.0.113.50");
        assert_eq!(ev.dst_endpoint.port, 443);
    }

    #[test]
    fn test_traffic_connection_info() {
        let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 1234, dst_ip(), 53, "dns", 1);
        // protocol_name should be uppercased
        assert_eq!(ev.connection_info.protocol_name, "DNS");
        assert_eq!(ev.connection_info.direction, "Unknown");
    }

    #[test]
    fn test_traffic_no_detection() {
        let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 1234, dst_ip(), 80, "HTTP", 2);
        assert!(ev.detection.is_none());
    }

    // --- from_alert() constructor --------------------------------------------

    #[test]
    fn test_alert_activity_id() {
        let alert = Alert {
            detector: "PortScan".into(),
            severity: AlertSeverity::High,
            description: "Port scan detected".into(),
            evidence: serde_json::json!({}),
        };
        let ev = OcsfNetworkEvent::from_alert(
            test_device(), src_ip(), 9999, dst_ip(), 22, "TCP", &alert,
        );
        assert_eq!(ev.activity, "Detection");
        assert_eq!(ev.activity_id, 99);
    }

    #[test]
    fn test_alert_severity_mapping() {
        let cases = [
            (AlertSeverity::Low, 2u8, "Low"),
            (AlertSeverity::Medium, 3, "Medium"),
            (AlertSeverity::High, 4, "High"),
            (AlertSeverity::Critical, 5, "Critical"),
        ];
        for (sev, expected_id, expected_name) in cases {
            let alert = Alert {
                detector: "Test".into(),
                severity: sev,
                description: "test".into(),
                evidence: serde_json::json!({}),
            };
            let ev = OcsfNetworkEvent::from_alert(
                test_device(), src_ip(), 1, dst_ip(), 1, "TCP", &alert,
            );
            assert_eq!(ev.severity_id, expected_id, "severity_id mismatch for {expected_name}");
            assert_eq!(ev.severity, expected_name, "severity mismatch");
        }
    }

    #[test]
    fn test_alert_message_from_description() {
        let alert = Alert {
            detector: "DnsTunnel".into(),
            severity: AlertSeverity::High,
            description: "DNS tunneling detected via long query".into(),
            evidence: serde_json::json!({"query_len": 200}),
        };
        let ev = OcsfNetworkEvent::from_alert(
            test_device(), src_ip(), 54321, dst_ip(), 53, "DNS", &alert,
        );
        assert_eq!(ev.message, "DNS tunneling detected via long query");
    }

    #[test]
    fn test_alert_detection_detail() {
        let alert = Alert {
            detector: "C2Beacon".into(),
            severity: AlertSeverity::Critical,
            description: "C2 beaconing detected".into(),
            evidence: serde_json::json!({"interval_cv": 0.05, "samples": 20}),
        };
        let ev = OcsfNetworkEvent::from_alert(
            test_device(), src_ip(), 54321, dst_ip(), 443, "TLS", &alert,
        );
        let det = ev.detection.expect("detection should be present");
        assert_eq!(det.detector, "C2Beacon");
        assert_eq!(det.description, "C2 beaconing detected");
        assert_eq!(det.evidence["interval_cv"], 0.05);
        assert_eq!(det.evidence["samples"], 20);
    }

    // --- Severity names ------------------------------------------------------

    #[test]
    fn test_severity_name_all() {
        assert_eq!(severity_name(1), "Informational");
        assert_eq!(severity_name(2), "Low");
        assert_eq!(severity_name(3), "Medium");
        assert_eq!(severity_name(4), "High");
        assert_eq!(severity_name(5), "Critical");
        assert_eq!(severity_name(0), "Unknown");
        assert_eq!(severity_name(99), "Unknown");
    }

    #[test]
    fn test_traffic_severity_levels() {
        for (id, name) in [(1u8, "Informational"), (2, "Low"), (3, "Medium"), (4, "High"), (5, "Critical")] {
            let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 1, dst_ip(), 80, "HTTP", id);
            assert_eq!(ev.severity_id, id);
            assert_eq!(ev.severity, name);
        }
    }

    // --- JSON serialization --------------------------------------------------

    #[test]
    fn test_json_traffic_structure() {
        let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 12345, dst_ip(), 80, "HTTP", 2);
        let json = serde_json::to_string(&ev).expect("serialization failed");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse failed");

        assert_eq!(v["class_uid"], 4001);
        assert_eq!(v["category_uid"], 4);
        assert_eq!(v["activity"], "Traffic");
        assert_eq!(v["activity_id"], 5);
        assert_eq!(v["severity_id"], 2);
        assert_eq!(v["severity"], "Low");

        // Nested endpoint objects
        assert_eq!(v["src_endpoint"]["ip"], "192.168.1.100");
        assert_eq!(v["src_endpoint"]["port"], 12345);
        assert_eq!(v["dst_endpoint"]["ip"], "203.0.113.50");
        assert_eq!(v["dst_endpoint"]["port"], 80);

        // Connection info
        assert_eq!(v["connection_info"]["protocol_name"], "HTTP");
        assert_eq!(v["connection_info"]["direction"], "Unknown");
    }

    #[test]
    fn test_json_time_is_integer() {
        let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 1, dst_ip(), 80, "HTTP", 1);
        let json = serde_json::to_string(&ev).expect("serialization failed");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse failed");

        // OCSF requires time as Unix epoch seconds (integer, not ISO 8601 string)
        assert!(
            v["time"].is_i64() || v["time"].is_u64(),
            "time must be an integer epoch timestamp, got: {}",
            v["time"]
        );
    }

    #[test]
    fn test_json_detection_omitted_for_traffic() {
        let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 1, dst_ip(), 80, "HTTP", 1);
        let json = serde_json::to_string(&ev).expect("serialization failed");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse failed");

        // skip_serializing_if = Option::is_none should exclude the field entirely
        assert!(
            v.get("detection").is_none(),
            "detection field should be absent from traffic events"
        );
    }

    #[test]
    fn test_json_detection_present_for_alert() {
        let alert = Alert {
            detector: "ProtoAnomaly".into(),
            severity: AlertSeverity::Medium,
            description: "Protocol anomaly on port 22".into(),
            evidence: serde_json::json!({"port": 22, "expected": "SSH"}),
        };
        let ev = OcsfNetworkEvent::from_alert(
            test_device(), src_ip(), 50000, dst_ip(), 22, "TCP", &alert,
        );
        let json = serde_json::to_string(&ev).expect("serialization failed");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse failed");

        assert_eq!(v["detection"]["detector"], "ProtoAnomaly");
        assert_eq!(v["detection"]["evidence"]["port"], 22);
    }

    #[test]
    fn test_json_metadata() {
        let ev = OcsfNetworkEvent::traffic(test_device(), src_ip(), 1, dst_ip(), 80, "TCP", 1);
        let json = serde_json::to_string(&ev).expect("serialization failed");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse failed");

        assert_eq!(v["metadata"]["version"], "1.1.0");
        assert_eq!(v["metadata"]["product"]["name"], "MxWatch");
        assert_eq!(v["metadata"]["product"]["vendor"], "MxTac");
    }

    // --- JSON round-trip -----------------------------------------------------

    #[test]
    fn test_roundtrip_traffic() {
        let ev = OcsfNetworkEvent::traffic(
            test_device(), src_ip(), 54321, dst_ip(), 443, "TLS", 3,
        );
        let json = serde_json::to_string(&ev).expect("serialization failed");
        let restored: OcsfNetworkEvent =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(restored.class_uid, ev.class_uid);
        assert_eq!(restored.severity_id, ev.severity_id);
        assert_eq!(restored.src_endpoint, ev.src_endpoint);
        assert_eq!(restored.dst_endpoint, ev.dst_endpoint);
        assert_eq!(restored.connection_info, ev.connection_info);
        assert_eq!(restored.time.timestamp(), ev.time.timestamp());
    }

    #[test]
    fn test_roundtrip_alert() {
        let alert = Alert {
            detector: "DnsTunnel".into(),
            severity: AlertSeverity::High,
            description: "High entropy DNS query".into(),
            evidence: serde_json::json!({"entropy": 4.8, "query": "aabbccdd.evil.com"}),
        };
        let ev = OcsfNetworkEvent::from_alert(
            test_device(), src_ip(), 60000, dst_ip(), 53, "DNS", &alert,
        );
        let json = serde_json::to_string(&ev).expect("serialization failed");
        let restored: OcsfNetworkEvent =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(restored.activity, "Detection");
        assert_eq!(restored.severity_id, 4);
        let det = restored.detection.expect("detection should be present after round-trip");
        assert_eq!(det.detector, "DnsTunnel");
        assert_eq!(det.evidence["entropy"], 4.8);
    }

    // --- OcsfEndpoint --------------------------------------------------------

    #[test]
    fn test_endpoint_ipv4() {
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let ep = OcsfEndpoint::new(ip, 8080);
        assert_eq!(ep.ip, "10.0.0.1");
        assert_eq!(ep.port, 8080);
    }

    #[test]
    fn test_endpoint_ipv6() {
        let ip = IpAddr::from_str("2001:db8::1").unwrap();
        let ep = OcsfEndpoint::new(ip, 443);
        assert_eq!(ep.ip, "2001:db8::1");
        assert_eq!(ep.port, 443);
    }

    // --- OcsfConnectionInfo --------------------------------------------------

    #[test]
    fn test_connection_info_protocol_uppercase() {
        let ci = OcsfConnectionInfo::unknown("https");
        assert_eq!(ci.protocol_name, "HTTPS");
    }

    #[test]
    fn test_connection_info_direction() {
        let ci_in = OcsfConnectionInfo::new("TCP", ConnectionDirection::Inbound);
        assert_eq!(ci_in.direction, "Inbound");

        let ci_out = OcsfConnectionInfo::new("TCP", ConnectionDirection::Outbound);
        assert_eq!(ci_out.direction, "Outbound");

        let ci_unk = OcsfConnectionInfo::unknown("TCP");
        assert_eq!(ci_unk.direction, "Unknown");
    }
}
