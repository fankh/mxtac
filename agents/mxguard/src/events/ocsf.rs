//! OCSF (Open Cybersecurity Schema Framework) event serialization structs.
//!
//! These structures map to OCSF v1.1 event classes relevant to EDR telemetry:
//!   - Process Activity (class_uid 1007)
//!   - File System Activity (class_uid 1001)
//!   - Network Activity (class_uid 4001)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Severity enum
// ---------------------------------------------------------------------------

/// OCSF severity levels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum OcsfSeverity {
    #[default]
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl OcsfSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "Informational",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }

    pub fn id(&self) -> u8 {
        *self as u8
    }
}

// ---------------------------------------------------------------------------
// Common OCSF building blocks
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
            name: "MxGuard".into(),
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
    pub os_version: String,
}

impl OcsfDevice {
    /// Build device info from the current host.
    pub fn from_current_host() -> Self {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into());
        Self {
            hostname,
            ip: "0.0.0.0".into(),
            os_name: "Linux".into(),
            os_version: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Unified OCSF event envelope
// ---------------------------------------------------------------------------

/// A unified OCSF event that wraps all class-specific payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfEvent {
    pub metadata: OcsfMetadata,
    pub time: DateTime<Utc>,
    pub class_uid: u32,
    pub category_uid: u32,
    pub activity: String,
    pub activity_id: u32,
    pub severity_id: u8,
    pub severity: String,
    pub device: OcsfDevice,
    /// Class-specific payload (serialized as a flat JSON merge).
    #[serde(flatten)]
    pub payload: OcsfPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type_name")]
pub enum OcsfPayload {
    #[serde(rename = "process_activity")]
    ProcessActivity(ProcessActivityData),
    #[serde(rename = "file_activity")]
    FileActivity(FileActivityData),
    #[serde(rename = "network_activity")]
    NetworkActivity(NetworkActivityData),
}

// ---------------------------------------------------------------------------
// Process Activity (1007)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessActivityData {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmd_line: String,
    /// Resolved path to the executable binary (from `/proc/{pid}/exe`).
    pub exe_path: Option<String>,
    /// Working directory of the process (from `/proc/{pid}/cwd`).
    pub cwd: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub user: String,
}

// ---------------------------------------------------------------------------
// File System Activity (1001)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileActivityData {
    pub path: String,
    pub action: String,
    pub size: Option<u64>,
    pub hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Network Activity (4001)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkActivityData {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub pid: Option<u32>,
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

impl OcsfEvent {
    /// Create a new Process Activity event.
    pub fn process_activity(
        device: OcsfDevice,
        activity: &str,
        activity_id: u32,
        severity: OcsfSeverity,
        data: ProcessActivityData,
    ) -> Self {
        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid: 1007,
            category_uid: 1,
            activity: activity.into(),
            activity_id,
            severity_id: severity.id(),
            severity: severity.as_str().into(),
            device,
            payload: OcsfPayload::ProcessActivity(data),
        }
    }

    /// Create a new File System Activity event.
    pub fn file_activity(
        device: OcsfDevice,
        activity: &str,
        activity_id: u32,
        severity: OcsfSeverity,
        data: FileActivityData,
    ) -> Self {
        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid: 1001,
            category_uid: 1,
            activity: activity.into(),
            activity_id,
            severity_id: severity.id(),
            severity: severity.as_str().into(),
            device,
            payload: OcsfPayload::FileActivity(data),
        }
    }

    /// Create a new Network Activity event.
    pub fn network_activity(
        device: OcsfDevice,
        activity: &str,
        activity_id: u32,
        severity: OcsfSeverity,
        data: NetworkActivityData,
    ) -> Self {
        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid: 4001,
            category_uid: 4,
            activity: activity.into(),
            activity_id,
            severity_id: severity.id(),
            severity: severity.as_str().into(),
            device,
            payload: OcsfPayload::NetworkActivity(data),
        }
    }
}
