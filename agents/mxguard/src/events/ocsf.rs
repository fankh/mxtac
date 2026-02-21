//! OCSF (Open Cybersecurity Schema Framework) event serialization structs.
//!
//! These structures map to OCSF v1.1 event classes relevant to EDR telemetry:
//!   - Process Activity (class_uid 1007)
//!   - File System Activity (class_uid 1001)
//!   - Network Activity (class_uid 4001)
//!   - Authentication Activity (class_uid 3002)
//!
//! ## OCSF v1.1 Compliance
//!
//! All events include the required OCSF top-level fields:
//!   - `metadata.uid`       — UUID v4 per-event identifier (deduplication)
//!   - `metadata.log_time`  — Timestamp when the event was logged by MxGuard
//!   - `type_uid`           — Derived: `class_uid * 100 + activity_id`
//!   - `class_name`         — Human-readable class name (e.g. "Process Activity")
//!   - `category_name`      — Human-readable category name (e.g. "System Activity")
//!   - `type_name`          — Derived: `"{class_name}: {activity}"`

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// OCSF event metadata — version, product info, and per-event identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfMetadata {
    /// OCSF schema version (always "1.1.0").
    pub version: String,
    /// Product that generated the event.
    pub product: OcsfProduct,
    /// Unique event identifier (UUID v4). Enables deduplication at the backend.
    pub uid: String,
    /// Timestamp at which MxGuard logged/processed this event.
    /// Distinct from `OcsfEvent::time` which records when the OS event occurred.
    pub log_time: DateTime<Utc>,
}

impl Default for OcsfMetadata {
    fn default() -> Self {
        Self {
            version: "1.1.0".into(),
            product: OcsfProduct::default(),
            uid: Uuid::new_v4().to_string(),
            log_time: Utc::now(),
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
///
/// Serializes to a flat JSON object with all OCSF v1.1 required fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfEvent {
    pub metadata: OcsfMetadata,
    /// Timestamp when the OS event occurred (ISO 8601 / RFC 3339).
    pub time: DateTime<Utc>,
    /// OCSF class identifier (e.g. 1007 for Process Activity).
    pub class_uid: u32,
    /// Human-readable class name (e.g. "Process Activity").
    pub class_name: String,
    /// OCSF category identifier.
    pub category_uid: u32,
    /// Human-readable category name (e.g. "System Activity").
    pub category_name: String,
    /// OCSF type identifier: `class_uid * 100 + activity_id`.
    ///
    /// Examples:
    /// - Process Activity Launch   → 100701
    /// - File System Activity Create → 100101
    /// - Network Activity Connect  → 400101
    /// - Authentication Logon      → 300201
    pub type_uid: u32,
    /// Human-readable type name composed as `"{class_name}: {activity}"`.
    /// Example: `"Process Activity: Launch"`.
    pub type_name: String,
    /// Human-readable activity name (e.g. "Launch", "Create", "Connect").
    pub activity: String,
    /// Numeric activity identifier within the class.
    pub activity_id: u32,
    /// Numeric severity level (1–5).
    pub severity_id: u8,
    /// Human-readable severity (e.g. "Informational", "High").
    pub severity: String,
    pub device: OcsfDevice,
    /// MITRE ATT&CK technique IDs applicable to this event (e.g. `["T1059", "T1059.004"]`).
    ///
    /// Populated by the ATT&CK tagger in `crate::attack`.  The field is omitted from
    /// JSON output when empty so that existing serialization round-trip tests are
    /// unaffected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack_techniques: Vec<String>,
    /// Class-specific payload flattened into the top-level JSON object.
    ///
    /// The `_payload_type` discriminator is an internal MxGuard field used
    /// for deserialization. Consumers should use `class_uid` / `type_uid`
    /// to identify the event class.
    #[serde(flatten)]
    pub payload: OcsfPayload,
}

/// Class-specific payload variants for the supported OCSF event classes.
///
/// The `_payload_type` tag is an internal discriminator that does not appear
/// in the OCSF schema; it allows MxGuard to round-trip events through JSON
/// without losing the payload type information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "_payload_type")]
pub enum OcsfPayload {
    #[serde(rename = "process_activity")]
    ProcessActivity(ProcessActivityData),
    #[serde(rename = "file_activity")]
    FileActivity(FileActivityData),
    #[serde(rename = "network_activity")]
    NetworkActivity(NetworkActivityData),
    #[serde(rename = "authentication_activity")]
    AuthenticationActivity(AuthenticationActivityData),
    #[serde(rename = "registry_activity")]
    RegistryActivity(RegistryActivityData),
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
// Authentication Activity (3002)
// ---------------------------------------------------------------------------

/// Data payload for OCSF Authentication Activity events (class_uid 3002).
///
/// Populated by parsing `/var/log/auth.log` or `/var/log/secure` log lines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationActivityData {
    /// Authenticated (or attempted) username.
    pub user: String,
    /// Source IP address extracted from the log line (may be absent for local auth).
    pub source_ip: Option<String>,
    /// Source TCP port extracted from the log line.
    pub source_port: Option<u16>,
    /// Authentication mechanism: `"password"`, `"publickey"`, `"sudo"`, `"su"`,
    /// `"pam"`, `"session"`, or `"unknown"`.
    pub auth_method: String,
    /// `"Success"` or `"Failure"`.
    pub status: String,
    /// High-level outcome used to derive the OCSF activity: `"Logon"` or `"Logoff"`.
    pub outcome: String,
    /// Service that generated the log line (e.g. `"sshd"`, `"sudo"`, `"su"`).
    pub service: String,
}

// ---------------------------------------------------------------------------
// Registry Key Activity (201004) — Windows extension
// ---------------------------------------------------------------------------

/// Data payload for OCSF Windows Registry Key Activity events (class_uid 201004).
///
/// Populated by polling the Windows registry for changes to monitored keys.
/// Only generated on Windows (`#[cfg(target_os = "windows")]`).
///
/// ## OCSF Activity IDs
/// - 1: Create — a new registry key or value was created
/// - 2: Delete — a registry key or value was deleted
/// - 3: Modify — a registry value's data was changed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryActivityData {
    /// Full registry key path, e.g.
    /// `"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"`.
    pub key: String,
    /// Registry value name that changed, or `None` for key-level events (key
    /// created / deleted when no specific value is involved).
    pub value_name: Option<String>,
    /// Windows registry value type, e.g. `"REG_SZ"`, `"REG_DWORD"`, `"REG_BINARY"`.
    /// `None` when the value was deleted and the type cannot be determined.
    pub value_type: Option<String>,
    /// String representation of the current (or new) registry value data.
    /// `None` when the value was deleted.
    pub value_data: Option<String>,
    /// Previous value data before modification, populated only for Modify events.
    pub old_value_data: Option<String>,
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

impl OcsfEvent {
    /// Create a new Process Activity event (class_uid 1007, category 1 — System Activity).
    ///
    /// Sets `type_uid = 1007 * 100 + activity_id` and derives `class_name`,
    /// `category_name`, and `type_name` automatically.
    pub fn process_activity(
        device: OcsfDevice,
        activity: &str,
        activity_id: u32,
        severity: OcsfSeverity,
        data: ProcessActivityData,
    ) -> Self {
        let class_uid: u32 = 1007;
        let class_name = "Process Activity".to_string();
        let category_uid: u32 = 1;
        let category_name = "System Activity".to_string();
        let type_uid = class_uid * 100 + activity_id;
        let type_name = format!("{class_name}: {activity}");

        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid,
            class_name,
            category_uid,
            category_name,
            type_uid,
            type_name,
            activity: activity.into(),
            activity_id,
            severity_id: severity.id(),
            severity: severity.as_str().into(),
            device,
            attack_techniques: vec![],
            payload: OcsfPayload::ProcessActivity(data),
        }
    }

    /// Create a new File System Activity event (class_uid 1001, category 1 — System Activity).
    ///
    /// Sets `type_uid = 1001 * 100 + activity_id` and derives `class_name`,
    /// `category_name`, and `type_name` automatically.
    pub fn file_activity(
        device: OcsfDevice,
        activity: &str,
        activity_id: u32,
        severity: OcsfSeverity,
        data: FileActivityData,
    ) -> Self {
        let class_uid: u32 = 1001;
        let class_name = "File System Activity".to_string();
        let category_uid: u32 = 1;
        let category_name = "System Activity".to_string();
        let type_uid = class_uid * 100 + activity_id;
        let type_name = format!("{class_name}: {activity}");

        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid,
            class_name,
            category_uid,
            category_name,
            type_uid,
            type_name,
            activity: activity.into(),
            activity_id,
            severity_id: severity.id(),
            severity: severity.as_str().into(),
            device,
            attack_techniques: vec![],
            payload: OcsfPayload::FileActivity(data),
        }
    }

    /// Create a new Network Activity event (class_uid 4001, category 4 — Network Activity).
    ///
    /// Sets `type_uid = 4001 * 100 + activity_id` and derives `class_name`,
    /// `category_name`, and `type_name` automatically.
    pub fn network_activity(
        device: OcsfDevice,
        activity: &str,
        activity_id: u32,
        severity: OcsfSeverity,
        data: NetworkActivityData,
    ) -> Self {
        let class_uid: u32 = 4001;
        let class_name = "Network Activity".to_string();
        let category_uid: u32 = 4;
        let category_name = "Network Activity".to_string();
        let type_uid = class_uid * 100 + activity_id;
        let type_name = format!("{class_name}: {activity}");

        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid,
            class_name,
            category_uid,
            category_name,
            type_uid,
            type_name,
            activity: activity.into(),
            activity_id,
            severity_id: severity.id(),
            severity: severity.as_str().into(),
            device,
            attack_techniques: vec![],
            payload: OcsfPayload::NetworkActivity(data),
        }
    }

    /// Create a new Authentication Activity event (class_uid 3002, category 3 — IAM).
    ///
    /// `activity` is typically `"Logon"` (activity_id 1) or `"Logoff"` (activity_id 2).
    /// Sets `type_uid = 3002 * 100 + activity_id` and derives `class_name`,
    /// `category_name`, and `type_name` automatically.
    pub fn authentication_activity(
        device: OcsfDevice,
        activity: &str,
        activity_id: u32,
        severity: OcsfSeverity,
        data: AuthenticationActivityData,
    ) -> Self {
        let class_uid: u32 = 3002;
        let class_name = "Authentication".to_string();
        let category_uid: u32 = 3;
        let category_name = "Identity & Access Management".to_string();
        let type_uid = class_uid * 100 + activity_id;
        let type_name = format!("{class_name}: {activity}");

        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid,
            class_name,
            category_uid,
            category_name,
            type_uid,
            type_name,
            activity: activity.into(),
            activity_id,
            severity_id: severity.id(),
            severity: severity.as_str().into(),
            device,
            attack_techniques: vec![],
            payload: OcsfPayload::AuthenticationActivity(data),
        }
    }

    /// Create a new Windows Registry Key Activity event (class_uid 201004, category 1).
    ///
    /// This is a Windows-specific OCSF extension class. Activity IDs:
    /// - 1 = Create (new key or value)
    /// - 2 = Delete (key or value removed)
    /// - 3 = Modify (value data changed)
    ///
    /// Sets `type_uid = 201004 * 100 + activity_id` and derives `class_name`,
    /// `category_name`, and `type_name` automatically.
    pub fn registry_activity(
        device: OcsfDevice,
        activity: &str,
        activity_id: u32,
        severity: OcsfSeverity,
        data: RegistryActivityData,
    ) -> Self {
        let class_uid: u32 = 201004;
        let class_name = "Windows Registry Key Activity".to_string();
        let category_uid: u32 = 1;
        let category_name = "System Activity".to_string();
        let type_uid = class_uid * 100 + activity_id;
        let type_name = format!("{class_name}: {activity}");

        Self {
            metadata: OcsfMetadata::default(),
            time: Utc::now(),
            class_uid,
            class_name,
            category_uid,
            category_name,
            type_uid,
            type_name,
            activity: activity.into(),
            activity_id,
            severity_id: severity.id(),
            severity: severity.as_str().into(),
            device,
            attack_techniques: vec![],
            payload: OcsfPayload::RegistryActivity(data),
        }
    }

    /// Attach ATT&CK technique IDs to the event (builder pattern).
    ///
    /// Technique IDs are sorted and deduplicated by the tagger; this method
    /// stores them verbatim.  An empty `Vec` is a no-op in terms of JSON
    /// output (the field is skipped when empty).
    pub fn with_attack_techniques(mut self, techniques: Vec<String>) -> Self {
        self.attack_techniques = techniques;
        self
    }
}

// ---------------------------------------------------------------------------
// Unit tests — OCSF event serialization
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn test_device() -> OcsfDevice {
        OcsfDevice {
            hostname: "test-host".into(),
            ip: "192.168.1.1".into(),
            os_name: "Linux".into(),
            os_version: "6.1.0".into(),
        }
    }

    fn process_event() -> OcsfEvent {
        OcsfEvent::process_activity(
            test_device(),
            "Launch",
            1,
            OcsfSeverity::Informational,
            ProcessActivityData {
                pid: 1234,
                ppid: 1000,
                name: "bash".into(),
                cmd_line: "/bin/bash -i".into(),
                exe_path: Some("/bin/bash".into()),
                cwd: Some("/home/user".into()),
                uid: 1000,
                gid: 1000,
                user: "user".into(),
            },
        )
    }

    fn file_event() -> OcsfEvent {
        OcsfEvent::file_activity(
            test_device(),
            "Create",
            1,
            OcsfSeverity::High,
            FileActivityData {
                path: "/tmp/test.sh".into(),
                action: "Create".into(),
                size: Some(512),
                hash: Some(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                ),
            },
        )
    }

    fn network_event() -> OcsfEvent {
        OcsfEvent::network_activity(
            test_device(),
            "Connect",
            1,
            OcsfSeverity::High,
            NetworkActivityData {
                local_addr: "192.168.1.1".into(),
                local_port: 54321,
                remote_addr: "10.0.0.1".into(),
                remote_port: 4444,
                protocol: "TCP".into(),
                state: "ESTABLISHED".into(),
                pid: None,
            },
        )
    }

    fn auth_event() -> OcsfEvent {
        OcsfEvent::authentication_activity(
            test_device(),
            "Logon",
            1,
            OcsfSeverity::Medium,
            AuthenticationActivityData {
                user: "ubuntu".into(),
                source_ip: Some("203.0.113.10".into()),
                source_port: Some(45678),
                auth_method: "publickey".into(),
                status: "Success".into(),
                outcome: "Logon".into(),
                service: "sshd".into(),
            },
        )
    }

    // -----------------------------------------------------------------------
    // type_uid computation
    // -----------------------------------------------------------------------

    #[test]
    fn process_activity_type_uid_is_100701() {
        let ev = process_event();
        // class_uid=1007, activity_id=1 → type_uid = 1007*100 + 1 = 100701
        assert_eq!(ev.type_uid, 100701);
    }

    #[test]
    fn file_activity_type_uid_is_100101() {
        let ev = file_event();
        // class_uid=1001, activity_id=1 → type_uid = 1001*100 + 1 = 100101
        assert_eq!(ev.type_uid, 100101);
    }

    #[test]
    fn network_activity_type_uid_is_400101() {
        let ev = network_event();
        // class_uid=4001, activity_id=1 → type_uid = 4001*100 + 1 = 400101
        assert_eq!(ev.type_uid, 400101);
    }

    #[test]
    fn authentication_activity_type_uid_is_300201() {
        let ev = auth_event();
        // class_uid=3002, activity_id=1 → type_uid = 3002*100 + 1 = 300201
        assert_eq!(ev.type_uid, 300201);
    }

    #[test]
    fn type_uid_reflects_activity_id() {
        // activity_id=2 should shift type_uid by 1
        let ev = OcsfEvent::process_activity(
            test_device(),
            "Terminate",
            2,
            OcsfSeverity::Low,
            ProcessActivityData {
                pid: 1, ppid: 0, name: "init".into(), cmd_line: "".into(),
                exe_path: None, cwd: None, uid: 0, gid: 0, user: "root".into(),
            },
        );
        assert_eq!(ev.type_uid, 1007 * 100 + 2); // 100702
    }

    // -----------------------------------------------------------------------
    // class_name and category_name
    // -----------------------------------------------------------------------

    #[test]
    fn process_activity_class_name() {
        let ev = process_event();
        assert_eq!(ev.class_name, "Process Activity");
        assert_eq!(ev.class_uid, 1007);
        assert_eq!(ev.category_uid, 1);
        assert_eq!(ev.category_name, "System Activity");
    }

    #[test]
    fn file_activity_class_name() {
        let ev = file_event();
        assert_eq!(ev.class_name, "File System Activity");
        assert_eq!(ev.class_uid, 1001);
        assert_eq!(ev.category_uid, 1);
        assert_eq!(ev.category_name, "System Activity");
    }

    #[test]
    fn network_activity_class_name() {
        let ev = network_event();
        assert_eq!(ev.class_name, "Network Activity");
        assert_eq!(ev.class_uid, 4001);
        assert_eq!(ev.category_uid, 4);
        assert_eq!(ev.category_name, "Network Activity");
    }

    #[test]
    fn authentication_activity_class_name() {
        let ev = auth_event();
        assert_eq!(ev.class_name, "Authentication");
        assert_eq!(ev.class_uid, 3002);
        assert_eq!(ev.category_uid, 3);
        assert_eq!(ev.category_name, "Identity & Access Management");
    }

    // -----------------------------------------------------------------------
    // type_name composition
    // -----------------------------------------------------------------------

    #[test]
    fn process_activity_type_name_format() {
        let ev = process_event();
        assert_eq!(ev.type_name, "Process Activity: Launch");
    }

    #[test]
    fn file_activity_type_name_format() {
        let ev = file_event();
        assert_eq!(ev.type_name, "File System Activity: Create");
    }

    #[test]
    fn network_activity_type_name_format() {
        let ev = network_event();
        assert_eq!(ev.type_name, "Network Activity: Connect");
    }

    #[test]
    fn authentication_activity_type_name_format() {
        let ev = auth_event();
        assert_eq!(ev.type_name, "Authentication: Logon");
    }

    // -----------------------------------------------------------------------
    // metadata.uid (UUID v4)
    // -----------------------------------------------------------------------

    #[test]
    fn metadata_uid_is_valid_uuid() {
        let ev = process_event();
        // Must parse as a valid UUID
        let parsed = Uuid::parse_str(&ev.metadata.uid);
        assert!(parsed.is_ok(), "metadata.uid must be a valid UUID, got: {}", ev.metadata.uid);
    }

    #[test]
    fn metadata_uid_is_version_4() {
        let ev = process_event();
        let uuid = Uuid::parse_str(&ev.metadata.uid).unwrap();
        assert_eq!(uuid.get_version_num(), 4, "metadata.uid must be UUID v4");
    }

    #[test]
    fn each_event_gets_unique_metadata_uid() {
        let ev1 = process_event();
        let ev2 = process_event();
        assert_ne!(
            ev1.metadata.uid, ev2.metadata.uid,
            "Every OcsfEvent must have a distinct metadata.uid"
        );
    }

    #[test]
    fn metadata_uid_appears_in_serialized_json() {
        let ev = process_event();
        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let uid = v["metadata"]["uid"].as_str().expect("metadata.uid must be a string");
        assert!(!uid.is_empty());
        Uuid::parse_str(uid).expect("metadata.uid in JSON must be a valid UUID");
    }

    // -----------------------------------------------------------------------
    // metadata.log_time
    // -----------------------------------------------------------------------

    #[test]
    fn metadata_log_time_is_set() {
        let before = Utc::now();
        let ev = process_event();
        let after = Utc::now();
        assert!(ev.metadata.log_time >= before, "log_time must be at or after test start");
        assert!(ev.metadata.log_time <= after, "log_time must be at or before test end");
    }

    #[test]
    fn metadata_log_time_appears_in_json() {
        let ev = process_event();
        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let log_time = v["metadata"]["log_time"].as_str();
        assert!(log_time.is_some(), "metadata.log_time must be present in serialized JSON");
    }

    // -----------------------------------------------------------------------
    // Required OCSF fields in serialized JSON
    // -----------------------------------------------------------------------

    fn assert_required_ocsf_fields(ev: &OcsfEvent) {
        let json = serde_json::to_string(ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Top-level required fields
        assert!(v.get("time").is_some(), "missing: time");
        assert!(v.get("class_uid").is_some(), "missing: class_uid");
        assert!(v.get("class_name").is_some(), "missing: class_name");
        assert!(v.get("category_uid").is_some(), "missing: category_uid");
        assert!(v.get("category_name").is_some(), "missing: category_name");
        assert!(v.get("type_uid").is_some(), "missing: type_uid");
        assert!(v.get("type_name").is_some(), "missing: type_name");
        assert!(v.get("activity").is_some(), "missing: activity");
        assert!(v.get("activity_id").is_some(), "missing: activity_id");
        assert!(v.get("severity_id").is_some(), "missing: severity_id");
        assert!(v.get("severity").is_some(), "missing: severity");
        assert!(v.get("device").is_some(), "missing: device");
        assert!(v.get("metadata").is_some(), "missing: metadata");

        // Metadata sub-fields
        let meta = &v["metadata"];
        assert!(meta.get("version").is_some(), "missing: metadata.version");
        assert!(meta.get("product").is_some(), "missing: metadata.product");
        assert!(meta.get("uid").is_some(), "missing: metadata.uid");
        assert!(meta.get("log_time").is_some(), "missing: metadata.log_time");
    }

    #[test]
    fn process_activity_has_all_required_ocsf_fields() {
        assert_required_ocsf_fields(&process_event());
    }

    #[test]
    fn file_activity_has_all_required_ocsf_fields() {
        assert_required_ocsf_fields(&file_event());
    }

    #[test]
    fn network_activity_has_all_required_ocsf_fields() {
        assert_required_ocsf_fields(&network_event());
    }

    #[test]
    fn authentication_activity_has_all_required_ocsf_fields() {
        assert_required_ocsf_fields(&auth_event());
    }

    // -----------------------------------------------------------------------
    // Payload fields present in serialized JSON
    // -----------------------------------------------------------------------

    #[test]
    fn process_activity_payload_fields_in_json() {
        let ev = process_event();
        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["pid"].as_u64(), Some(1234));
        assert_eq!(v["ppid"].as_u64(), Some(1000));
        assert_eq!(v["name"].as_str(), Some("bash"));
        assert_eq!(v["cmd_line"].as_str(), Some("/bin/bash -i"));
        assert_eq!(v["exe_path"].as_str(), Some("/bin/bash"));
        assert_eq!(v["user"].as_str(), Some("user"));
    }

    #[test]
    fn file_activity_payload_fields_in_json() {
        let ev = file_event();
        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["path"].as_str(), Some("/tmp/test.sh"));
        assert_eq!(v["action"].as_str(), Some("Create"));
        assert_eq!(v["size"].as_u64(), Some(512));
        assert!(v["hash"].as_str().is_some());
    }

    #[test]
    fn network_activity_payload_fields_in_json() {
        let ev = network_event();
        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["local_addr"].as_str(), Some("192.168.1.1"));
        assert_eq!(v["local_port"].as_u64(), Some(54321));
        assert_eq!(v["remote_addr"].as_str(), Some("10.0.0.1"));
        assert_eq!(v["remote_port"].as_u64(), Some(4444));
        assert_eq!(v["protocol"].as_str(), Some("TCP"));
        assert_eq!(v["state"].as_str(), Some("ESTABLISHED"));
    }

    #[test]
    fn auth_activity_payload_fields_in_json() {
        let ev = auth_event();
        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["user"].as_str(), Some("ubuntu"));
        assert_eq!(v["source_ip"].as_str(), Some("203.0.113.10"));
        assert_eq!(v["auth_method"].as_str(), Some("publickey"));
        assert_eq!(v["status"].as_str(), Some("Success"));
        assert_eq!(v["service"].as_str(), Some("sshd"));
    }

    // -----------------------------------------------------------------------
    // Serialization / deserialization round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn process_activity_roundtrip() {
        let original = process_event();
        let json = serde_json::to_string(&original).unwrap();
        let restored: OcsfEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.class_uid, original.class_uid);
        assert_eq!(restored.class_name, original.class_name);
        assert_eq!(restored.category_uid, original.category_uid);
        assert_eq!(restored.category_name, original.category_name);
        assert_eq!(restored.type_uid, original.type_uid);
        assert_eq!(restored.type_name, original.type_name);
        assert_eq!(restored.activity, original.activity);
        assert_eq!(restored.activity_id, original.activity_id);
        assert_eq!(restored.severity_id, original.severity_id);
        assert_eq!(restored.severity, original.severity);
        assert_eq!(restored.metadata.uid, original.metadata.uid);

        if let OcsfPayload::ProcessActivity(d) = &restored.payload {
            assert_eq!(d.pid, 1234);
            assert_eq!(d.name, "bash");
        } else {
            panic!("Expected ProcessActivity payload after round-trip");
        }
    }

    #[test]
    fn file_activity_roundtrip() {
        let original = file_event();
        let json = serde_json::to_string(&original).unwrap();
        let restored: OcsfEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.class_uid, 1001);
        assert_eq!(restored.type_uid, 100101);
        assert_eq!(restored.metadata.uid, original.metadata.uid);

        if let OcsfPayload::FileActivity(d) = &restored.payload {
            assert_eq!(d.path, "/tmp/test.sh");
            assert_eq!(d.action, "Create");
        } else {
            panic!("Expected FileActivity payload after round-trip");
        }
    }

    #[test]
    fn network_activity_roundtrip() {
        let original = network_event();
        let json = serde_json::to_string(&original).unwrap();
        let restored: OcsfEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.class_uid, 4001);
        assert_eq!(restored.type_uid, 400101);
        assert_eq!(restored.metadata.uid, original.metadata.uid);

        if let OcsfPayload::NetworkActivity(d) = &restored.payload {
            assert_eq!(d.remote_port, 4444);
            assert_eq!(d.protocol, "TCP");
        } else {
            panic!("Expected NetworkActivity payload after round-trip");
        }
    }

    #[test]
    fn authentication_activity_roundtrip() {
        let original = auth_event();
        let json = serde_json::to_string(&original).unwrap();
        let restored: OcsfEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.class_uid, 3002);
        assert_eq!(restored.type_uid, 300201);
        assert_eq!(restored.metadata.uid, original.metadata.uid);

        if let OcsfPayload::AuthenticationActivity(d) = &restored.payload {
            assert_eq!(d.user, "ubuntu");
            assert_eq!(d.status, "Success");
        } else {
            panic!("Expected AuthenticationActivity payload after round-trip");
        }
    }

    // -----------------------------------------------------------------------
    // Severity mapping
    // -----------------------------------------------------------------------

    #[test]
    fn severity_informational_maps_to_id_1() {
        assert_eq!(OcsfSeverity::Informational.id(), 1);
        assert_eq!(OcsfSeverity::Informational.as_str(), "Informational");
    }

    #[test]
    fn severity_low_maps_to_id_2() {
        assert_eq!(OcsfSeverity::Low.id(), 2);
        assert_eq!(OcsfSeverity::Low.as_str(), "Low");
    }

    #[test]
    fn severity_medium_maps_to_id_3() {
        assert_eq!(OcsfSeverity::Medium.id(), 3);
        assert_eq!(OcsfSeverity::Medium.as_str(), "Medium");
    }

    #[test]
    fn severity_high_maps_to_id_4() {
        assert_eq!(OcsfSeverity::High.id(), 4);
        assert_eq!(OcsfSeverity::High.as_str(), "High");
    }

    #[test]
    fn severity_critical_maps_to_id_5() {
        assert_eq!(OcsfSeverity::Critical.id(), 5);
        assert_eq!(OcsfSeverity::Critical.as_str(), "Critical");
    }

    #[test]
    fn severity_fields_are_serialized_consistently() {
        let ev = OcsfEvent::file_activity(
            test_device(),
            "Create",
            1,
            OcsfSeverity::Critical,
            FileActivityData {
                path: "/etc/passwd".into(),
                action: "Create".into(),
                size: None,
                hash: None,
            },
        );
        assert_eq!(ev.severity_id, 5);
        assert_eq!(ev.severity, "Critical");

        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["severity_id"].as_u64(), Some(5));
        assert_eq!(v["severity"].as_str(), Some("Critical"));
    }

    // -----------------------------------------------------------------------
    // Metadata product info
    // -----------------------------------------------------------------------

    #[test]
    fn metadata_product_vendor_is_mxtac() {
        let ev = process_event();
        assert_eq!(ev.metadata.product.vendor, "MxTac");
        assert_eq!(ev.metadata.product.name, "MxGuard");
        assert_eq!(ev.metadata.version, "1.1.0");
    }

    #[test]
    fn metadata_product_version_matches_cargo_version() {
        let ev = process_event();
        assert_eq!(ev.metadata.product.version, env!("CARGO_PKG_VERSION"));
    }

    // -----------------------------------------------------------------------
    // Batch serialization (transport sends Vec<OcsfEvent>)
    // -----------------------------------------------------------------------

    #[test]
    fn batch_of_events_serializes_and_deserializes() {
        let events = vec![process_event(), file_event(), network_event(), auth_event()];

        let json = serde_json::to_string(&events).unwrap();
        let restored: Vec<OcsfEvent> = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.len(), 4);
        assert_eq!(restored[0].class_uid, 1007);
        assert_eq!(restored[1].class_uid, 1001);
        assert_eq!(restored[2].class_uid, 4001);
        assert_eq!(restored[3].class_uid, 3002);
    }

    #[test]
    fn all_events_in_batch_have_unique_uids() {
        let events = vec![process_event(), process_event(), process_event()];
        let uids: Vec<&str> = events.iter().map(|e| e.metadata.uid.as_str()).collect();

        // Check all UIDs are distinct
        for i in 0..uids.len() {
            for j in (i + 1)..uids.len() {
                assert_ne!(uids[i], uids[j], "Events {i} and {j} share the same metadata.uid");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Optional fields
    // -----------------------------------------------------------------------

    #[test]
    fn file_activity_null_hash_serializes_as_json_null() {
        let ev = OcsfEvent::file_activity(
            test_device(),
            "Delete",
            3,
            OcsfSeverity::Low,
            FileActivityData {
                path: "/tmp/gone.txt".into(),
                action: "Delete".into(),
                size: None,
                hash: None,
            },
        );

        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["hash"].is_null(), "hash should be null when None");
        assert!(v["size"].is_null(), "size should be null when None");
    }

    #[test]
    fn auth_activity_without_source_ip_serializes_correctly() {
        let ev = OcsfEvent::authentication_activity(
            test_device(),
            "Logon",
            1,
            OcsfSeverity::Informational,
            AuthenticationActivityData {
                user: "root".into(),
                source_ip: None,
                source_port: None,
                auth_method: "session".into(),
                status: "Success".into(),
                outcome: "Logon".into(),
                service: "su".into(),
            },
        );

        let json = serde_json::to_string(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["source_ip"].is_null());
        assert!(v["source_port"].is_null());
    }

    // -----------------------------------------------------------------------
    // Registry Key Activity (201004) tests
    // -----------------------------------------------------------------------

    fn registry_event_create() -> OcsfEvent {
        OcsfEvent::registry_activity(
            test_device(),
            "Create",
            1,
            OcsfSeverity::High,
            RegistryActivityData {
                key: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                    .into(),
                value_name: Some("Malware".into()),
                value_type: Some("REG_SZ".into()),
                value_data: Some("C:\\Windows\\Temp\\malware.exe".into()),
                old_value_data: None,
            },
        )
    }

    fn registry_event_modify() -> OcsfEvent {
        OcsfEvent::registry_activity(
            test_device(),
            "Modify",
            3,
            OcsfSeverity::Medium,
            RegistryActivityData {
                key: "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
                    .into(),
                value_name: Some("EnableDeadGWDetect".into()),
                value_type: Some("REG_DWORD".into()),
                value_data: Some("0".into()),
                old_value_data: Some("1".into()),
            },
        )
    }

    fn registry_event_delete() -> OcsfEvent {
        OcsfEvent::registry_activity(
            test_device(),
            "Delete",
            2,
            OcsfSeverity::High,
            RegistryActivityData {
                key: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                    .into(),
                value_name: Some("SecuritySoftware".into()),
                value_type: None,
                value_data: None,
                old_value_data: None,
            },
        )
    }

    #[test]
    fn registry_activity_type_uid_create_is_20100401() {
        let ev = registry_event_create();
        // class_uid=201004, activity_id=1 → type_uid = 201004*100 + 1 = 20100401
        assert_eq!(ev.type_uid, 20100401);
    }

    #[test]
    fn registry_activity_type_uid_delete_is_20100402() {
        let ev = registry_event_delete();
        // class_uid=201004, activity_id=2 → type_uid = 201004*100 + 2 = 20100402
        assert_eq!(ev.type_uid, 20100402);
    }

    #[test]
    fn registry_activity_type_uid_modify_is_20100403() {
        let ev = registry_event_modify();
        // class_uid=201004, activity_id=3 → type_uid = 201004*100 + 3 = 20100403
        assert_eq!(ev.type_uid, 20100403);
    }

    #[test]
    fn registry_activity_class_uid_is_201004() {
        let ev = registry_event_create();
        assert_eq!(ev.class_uid, 201004);
    }

    #[test]
    fn registry_activity_class_name_is_correct() {
        let ev = registry_event_create();
        assert_eq!(ev.class_name, "Windows Registry Key Activity");
    }

    #[test]
    fn registry_activity_category_is_system_activity() {
        let ev = registry_event_create();
        assert_eq!(ev.category_uid, 1);
        assert_eq!(ev.category_name, "System Activity");
    }

    #[test]
    fn registry_activity_type_name_is_composed() {
        let ev = registry_event_create();
        assert_eq!(ev.type_name, "Windows Registry Key Activity: Create");
    }

    #[test]
    fn registry_activity_modify_type_name() {
        let ev = registry_event_modify();
        assert_eq!(ev.type_name, "Windows Registry Key Activity: Modify");
    }

    #[test]
    fn registry_activity_has_required_ocsf_fields() {
        let ev = registry_event_create();
        assert!(!ev.metadata.uid.is_empty(), "metadata.uid must be set");
        assert_eq!(ev.metadata.version, "1.1.0");
        assert!(ev.time <= Utc::now(), "time must be in the past");
        assert!(ev.metadata.log_time <= Utc::now());
    }

    #[test]
    fn registry_activity_metadata_uid_is_uuid_v4() {
        let ev = registry_event_create();
        let parsed = uuid::Uuid::parse_str(&ev.metadata.uid)
            .expect("metadata.uid must be a valid UUID");
        assert_eq!(parsed.get_version_num(), 4, "must be UUID v4");
    }

    #[test]
    fn registry_activity_create_payload_fields() {
        let ev = registry_event_create();
        if let OcsfPayload::RegistryActivity(data) = &ev.payload {
            assert!(data.key.contains("CurrentVersion\\Run"));
            assert_eq!(data.value_name.as_deref(), Some("Malware"));
            assert_eq!(data.value_type.as_deref(), Some("REG_SZ"));
            assert_eq!(
                data.value_data.as_deref(),
                Some("C:\\Windows\\Temp\\malware.exe")
            );
            assert!(data.old_value_data.is_none());
        } else {
            panic!("Expected RegistryActivity payload");
        }
    }

    #[test]
    fn registry_activity_modify_has_old_value_data() {
        let ev = registry_event_modify();
        if let OcsfPayload::RegistryActivity(data) = &ev.payload {
            assert_eq!(data.old_value_data.as_deref(), Some("1"));
            assert_eq!(data.value_data.as_deref(), Some("0"));
        } else {
            panic!("Expected RegistryActivity payload");
        }
    }

    #[test]
    fn registry_activity_delete_has_no_value_data() {
        let ev = registry_event_delete();
        if let OcsfPayload::RegistryActivity(data) = &ev.payload {
            assert!(data.value_type.is_none());
            assert!(data.value_data.is_none());
            assert_eq!(data.value_name.as_deref(), Some("SecuritySoftware"));
        } else {
            panic!("Expected RegistryActivity payload");
        }
    }

    #[test]
    fn registry_activity_serializes_and_deserializes() {
        let ev = registry_event_create();
        let json = serde_json::to_string(&ev).expect("serialize");
        let ev2: OcsfEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ev2.class_uid, 201004);
        assert_eq!(ev2.activity, "Create");
        if let OcsfPayload::RegistryActivity(data) = &ev2.payload {
            assert!(data.key.contains("CurrentVersion\\Run"));
        } else {
            panic!("Expected RegistryActivity payload after round-trip");
        }
    }

    #[test]
    fn registry_activity_key_field_in_json() {
        let ev = registry_event_create();
        let json = serde_json::to_string(&ev).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert!(v["key"].is_string(), "key field must be present in JSON");
        assert!(
            v["key"].as_str().unwrap().contains("Run"),
            "key field must contain registry path"
        );
    }

    #[test]
    fn registry_activity_severity_high_for_create() {
        let ev = registry_event_create();
        assert_eq!(ev.severity_id, 4);
        assert_eq!(ev.severity, "High");
    }

    #[test]
    fn registry_activity_attack_techniques_attached() {
        let ev = registry_event_create().with_attack_techniques(vec!["T1112".into()]);
        assert_eq!(ev.attack_techniques, vec!["T1112"]);
    }
}
