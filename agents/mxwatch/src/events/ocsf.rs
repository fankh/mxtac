//! OCSF Network Activity (class_uid 4001) serialization.

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
// Network Activity event (OCSF 4001)
// ---------------------------------------------------------------------------

/// OCSF Network Activity event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfNetworkEvent {
    pub metadata: OcsfMetadata,
    pub time: DateTime<Utc>,
    pub class_uid: u32,
    pub category_uid: u32,
    pub activity: String,
    pub activity_id: u32,
    pub severity_id: u8,
    pub severity: String,
    pub device: OcsfDevice,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: String,
    /// Optional detection detail when a detector has raised an alert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionDetail>,
}

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
            activity_id: 6,
            severity_id,
            severity: severity_name(severity_id).into(),
            device,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol: protocol.into(),
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
            activity_id: 99,
            severity_id: alert.severity.ocsf_id(),
            severity: severity_name(alert.severity.ocsf_id()).into(),
            device,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol: protocol.into(),
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
