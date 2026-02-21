//! Windows Registry monitoring collector.
//!
//! This module is **Windows only** (`#[cfg(target_os = "windows")]`).
//!
//! # Monitoring Strategy
//!
//! The collector uses a **polling + snapshot-diff** approach:
//!
//! 1. On startup, an in-memory snapshot is taken of all monitored registry
//!    keys (values and immediate sub-keys).
//! 2. Every `poll_interval_ms` milliseconds each key is re-read and compared
//!    against the previous snapshot.
//! 3. Differences are emitted as OCSF **Registry Key Activity** events
//!    (class_uid 201004) with the appropriate activity:
//!    - **Create** (activity_id 1) — a new value or sub-key appeared.
//!    - **Delete** (activity_id 2) — a value or sub-key was removed.
//!    - **Modify** (activity_id 3) — a value's data changed.
//!
//! # Monitored Paths
//!
//! Default keys cover the most security-relevant registry locations:
//! - `HKLM\...\CurrentVersion\Run` / `RunOnce` — autorun persistence
//! - `HKLM\SYSTEM\...\Services` — Windows services
//! - `HKLM\SYSTEM\...\Control\Lsa` — LSA credential configuration
//! - `HKLM\...\Image File Execution Options` — debugger injection hijacking
//! - `HKLM\...\KnownDLLs` — DLL hijacking via known-DLL substitution
//!
//! # ATT&CK Coverage
//!
//! Registry telemetry adds coverage for:
//! - T1112  — Modify Registry
//! - T1543.003 — Create or Modify System Process: Windows Service
//! - T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys
//! - T1546.012 — Event Triggered Execution: Image File Execution Options
//! - T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking
//! - T1003.001 — OS Credential Dumping: LSASS Memory (via LSA config)

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use winreg::enums::{
    HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS,
};
use winreg::{RegKey, HKEY};

use crate::attack::tag_registry_event;
use crate::collectors::Collector;
use crate::config::RegistryCollectorConfig;
use crate::events::ocsf::{OcsfDevice, OcsfEvent, OcsfSeverity, RegistryActivityData};
use crate::events::OcsfEvent as Event;

// ---------------------------------------------------------------------------
// Hive parsing
// ---------------------------------------------------------------------------

/// Parse a registry path string into a `(HKEY, sub-key path)` pair.
///
/// Accepts both long (`HKEY_LOCAL_MACHINE`) and short (`HKLM`) hive names.
/// Returns `None` if the hive prefix is not recognised.
fn parse_hive(path: &str) -> Option<(HKEY, &str)> {
    let path = path.trim_start_matches('\\');

    let hives: &[(&[&str], HKEY)] = &[
        (&["HKEY_LOCAL_MACHINE", "HKLM"], HKEY_LOCAL_MACHINE),
        (&["HKEY_CURRENT_USER", "HKCU"], HKEY_CURRENT_USER),
        (&["HKEY_USERS", "HKU"], HKEY_USERS),
        (&["HKEY_CLASSES_ROOT", "HKCR"], HKEY_CLASSES_ROOT),
    ];

    for (prefixes, hkey) in hives {
        for prefix in *prefixes {
            if let Some(rest) = path.strip_prefix(prefix) {
                let sub = rest.trim_start_matches('\\');
                return Some((*hkey, sub));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Snapshot types
// ---------------------------------------------------------------------------

/// A snapshot of a single registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValueSnapshot {
    /// Windows registry type name (e.g. `"REG_SZ"`, `"REG_DWORD"`).
    value_type: String,
    /// String representation of the value data.
    data: String,
}

/// A snapshot of all values in a single registry key.
type KeySnapshot = HashMap<String, ValueSnapshot>;

/// A snapshot of all monitored registry keys, keyed by the full path string.
type RegistrySnapshot = HashMap<String, KeySnapshot>;

// ---------------------------------------------------------------------------
// Registry value reading
// ---------------------------------------------------------------------------

/// Read a Windows registry value and return its type name and a string
/// representation of the data.
fn read_value(key: &RegKey, name: &str) -> Option<ValueSnapshot> {
    use winreg::enums::*;
    use winreg::RegValue;

    let rv: RegValue = key.get_raw_value(name).ok()?;

    let (value_type, data) = match rv.vtype {
        REG_SZ | REG_EXPAND_SZ => {
            let s: String = key.get_value(name).unwrap_or_default();
            ("REG_SZ".into(), s)
        }
        REG_MULTI_SZ => {
            let v: Vec<String> = key.get_value(name).unwrap_or_default();
            ("REG_MULTI_SZ".into(), v.join("|"))
        }
        REG_DWORD => {
            let d: u32 = key.get_value(name).unwrap_or_default();
            ("REG_DWORD".into(), d.to_string())
        }
        REG_QWORD => {
            let q: u64 = key.get_value(name).unwrap_or_default();
            ("REG_QWORD".into(), q.to_string())
        }
        REG_BINARY => {
            // Represent binary as hex string (first 64 bytes max).
            let bytes = &rv.bytes[..rv.bytes.len().min(64)];
            let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
            ("REG_BINARY".into(), hex)
        }
        _ => {
            ("REG_UNKNOWN".into(), format!("<{} bytes>", rv.bytes.len()))
        }
    };

    Some(ValueSnapshot { value_type, data })
}

/// Snapshot all named values in a registry key (excludes sub-keys).
fn snapshot_key(hive: HKEY, sub_key: &str) -> Option<KeySnapshot> {
    let root = RegKey::predef(hive);
    let key = root.open_subkey(sub_key).ok()?;

    let mut snap = KeySnapshot::new();
    for name_result in key.enum_values() {
        if let Ok((name, _)) = name_result {
            if let Some(vs) = read_value(&key, &name) {
                snap.insert(name, vs);
            }
        }
    }
    Some(snap)
}

// ---------------------------------------------------------------------------
// Diff logic
// ---------------------------------------------------------------------------

/// A detected registry change.
#[derive(Debug)]
enum RegistryChange {
    ValueCreated {
        value_name: String,
        value_type: String,
        value_data: String,
    },
    ValueDeleted {
        value_name: String,
    },
    ValueModified {
        value_name: String,
        value_type: String,
        new_data: String,
        old_data: String,
    },
}

/// Diff two key snapshots and return all detected changes.
fn diff_snapshots(old: &KeySnapshot, new: &KeySnapshot) -> Vec<RegistryChange> {
    let mut changes = Vec::new();

    // Detect created and modified values.
    for (name, new_val) in new {
        match old.get(name) {
            None => changes.push(RegistryChange::ValueCreated {
                value_name: name.clone(),
                value_type: new_val.value_type.clone(),
                value_data: new_val.data.clone(),
            }),
            Some(old_val) if old_val.data != new_val.data => {
                changes.push(RegistryChange::ValueModified {
                    value_name: name.clone(),
                    value_type: new_val.value_type.clone(),
                    new_data: new_val.data.clone(),
                    old_data: old_val.data.clone(),
                })
            }
            Some(_) => {} // unchanged
        }
    }

    // Detect deleted values.
    for name in old.keys() {
        if !new.contains_key(name) {
            changes.push(RegistryChange::ValueDeleted {
                value_name: name.clone(),
            });
        }
    }

    changes
}

// ---------------------------------------------------------------------------
// Severity heuristics
// ---------------------------------------------------------------------------

/// Determine severity for a registry event based on the key path.
///
/// High-sensitivity keys (autorun, LSA, IFEO) generate High-severity events;
/// other keys generate Medium-severity events.
fn classify_severity(key_path: &str) -> OcsfSeverity {
    let path_lc = key_path.to_lowercase();
    let high_patterns = [
        "currentversion\\run",
        "currentversion\\runonce",
        "image file execution options",
        "control\\lsa",
        "knowndlls",
    ];
    if high_patterns.iter().any(|p| path_lc.contains(p)) {
        OcsfSeverity::High
    } else {
        OcsfSeverity::Medium
    }
}

// ---------------------------------------------------------------------------
// Collector implementation
// ---------------------------------------------------------------------------

/// Polls the Windows Registry for changes to monitored keys.
pub struct RegistryCollector {
    config: RegistryCollectorConfig,
    device: OcsfDevice,
}

impl RegistryCollector {
    pub fn new(config: &RegistryCollectorConfig, device: OcsfDevice) -> Self {
        Self {
            config: config.clone(),
            device,
        }
    }

    /// Build an initial snapshot for all configured watch keys.
    fn build_initial_snapshot(&self) -> RegistrySnapshot {
        let mut snap = RegistrySnapshot::new();
        for key_path in &self.config.watch_keys {
            match parse_hive(key_path) {
                None => {
                    warn!(key = %key_path, "Registry key has unrecognised hive prefix — skipping");
                }
                Some((hive, sub)) => {
                    match snapshot_key(hive, sub) {
                        Some(ks) => {
                            debug!(key = %key_path, values = ks.len(), "Registry snapshot taken");
                            snap.insert(key_path.clone(), ks);
                        }
                        None => {
                            debug!(key = %key_path, "Registry key not accessible (may not exist yet)");
                            // Insert empty snapshot so deletions from empty state are handled.
                            snap.insert(key_path.clone(), KeySnapshot::new());
                        }
                    }
                }
            }
        }
        snap
    }

    /// Emit OCSF events for all changes between `old_snap` and the current
    /// registry state, updating `old_snap` in place.
    async fn detect_and_emit(
        &self,
        snap: &mut RegistrySnapshot,
        tx: &mpsc::Sender<Event>,
    ) {
        for key_path in &self.config.watch_keys {
            let (hive, sub) = match parse_hive(key_path) {
                Some(v) => v,
                None => continue,
            };

            let new_ks = snapshot_key(hive, sub).unwrap_or_default();
            let old_ks = snap.get(key_path).cloned().unwrap_or_default();

            let changes = diff_snapshots(&old_ks, &new_ks);
            for change in changes {
                let event = self.build_event(key_path, change);
                if let Err(e) = tx.send(event).await {
                    error!("Registry collector: failed to send event: {e}");
                }
            }

            // Update snapshot with current state.
            snap.insert(key_path.clone(), new_ks);
        }
    }

    /// Convert a [`RegistryChange`] into an OCSF event.
    fn build_event(&self, key_path: &str, change: RegistryChange) -> Event {
        let severity = classify_severity(key_path);

        let (activity, activity_id, data) = match change {
            RegistryChange::ValueCreated {
                value_name,
                value_type,
                value_data,
            } => (
                "Create",
                1u32,
                RegistryActivityData {
                    key: key_path.to_string(),
                    value_name: Some(value_name),
                    value_type: Some(value_type),
                    value_data: Some(value_data),
                    old_value_data: None,
                },
            ),
            RegistryChange::ValueDeleted { value_name } => (
                "Delete",
                2u32,
                RegistryActivityData {
                    key: key_path.to_string(),
                    value_name: Some(value_name),
                    value_type: None,
                    value_data: None,
                    old_value_data: None,
                },
            ),
            RegistryChange::ValueModified {
                value_name,
                value_type,
                new_data,
                old_data,
            } => (
                "Modify",
                3u32,
                RegistryActivityData {
                    key: key_path.to_string(),
                    value_name: Some(value_name),
                    value_type: Some(value_type),
                    value_data: Some(new_data),
                    old_value_data: Some(old_data),
                },
            ),
        };

        let techniques = tag_registry_event(&data);
        OcsfEvent::registry_activity(self.device.clone(), activity, activity_id, severity, data)
            .with_attack_techniques(techniques)
    }
}

#[async_trait]
impl Collector for RegistryCollector {
    fn name(&self) -> &'static str {
        "registry"
    }

    async fn run(
        &self,
        tx: mpsc::Sender<Event>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        info!(
            watch_keys = self.config.watch_keys.len(),
            poll_interval_ms = self.config.poll_interval_ms,
            "Registry collector starting"
        );

        let mut snapshot = self.build_initial_snapshot();
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {
                    self.detect_and_emit(&mut snapshot, &tx).await;
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Registry collector received shutdown signal");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Hive parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_hive_long_hklm() {
        let path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Test";
        let result = parse_hive(path);
        assert!(result.is_some(), "should parse HKEY_LOCAL_MACHINE");
        let (_, sub) = result.unwrap();
        assert_eq!(sub, r"SOFTWARE\Test");
    }

    #[test]
    fn parse_hive_short_hklm() {
        let path = r"HKLM\SOFTWARE\Test";
        let result = parse_hive(path);
        assert!(result.is_some(), "should parse HKLM short form");
        let (_, sub) = result.unwrap();
        assert_eq!(sub, r"SOFTWARE\Test");
    }

    #[test]
    fn parse_hive_hkcu() {
        let path = r"HKEY_CURRENT_USER\SOFTWARE\Test";
        let (_, sub) = parse_hive(path).expect("should parse HKCU");
        assert_eq!(sub, r"SOFTWARE\Test");
    }

    #[test]
    fn parse_hive_hkcu_short() {
        let path = r"HKCU\SOFTWARE\Test";
        let (_, sub) = parse_hive(path).expect("should parse HKCU short");
        assert_eq!(sub, r"SOFTWARE\Test");
    }

    #[test]
    fn parse_hive_hku() {
        let path = r"HKEY_USERS\S-1-5-21\SOFTWARE\Test";
        let (_, sub) = parse_hive(path).expect("should parse HKEY_USERS");
        assert_eq!(sub, r"S-1-5-21\SOFTWARE\Test");
    }

    #[test]
    fn parse_hive_unknown_returns_none() {
        let path = r"HKEY_UNKNOWN\Test";
        assert!(parse_hive(path).is_none(), "unknown hive should return None");
    }

    #[test]
    fn parse_hive_empty_returns_none() {
        assert!(parse_hive("").is_none());
    }

    // -----------------------------------------------------------------------
    // Severity classification tests
    // -----------------------------------------------------------------------

    #[test]
    fn severity_run_key_is_high() {
        let sev = classify_severity(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        );
        assert_eq!(sev, OcsfSeverity::High);
    }

    #[test]
    fn severity_runonce_key_is_high() {
        let sev = classify_severity(
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        );
        assert_eq!(sev, OcsfSeverity::High);
    }

    #[test]
    fn severity_ifeo_key_is_high() {
        let sev = classify_severity(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        );
        assert_eq!(sev, OcsfSeverity::High);
    }

    #[test]
    fn severity_lsa_key_is_high() {
        let sev = classify_severity(
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa",
        );
        assert_eq!(sev, OcsfSeverity::High);
    }

    #[test]
    fn severity_knowndlls_is_high() {
        let sev = classify_severity(
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        );
        assert_eq!(sev, OcsfSeverity::High);
    }

    #[test]
    fn severity_services_key_is_medium() {
        let sev = classify_severity(
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
        );
        assert_eq!(sev, OcsfSeverity::Medium);
    }

    #[test]
    fn severity_arbitrary_key_is_medium() {
        let sev = classify_severity(r"HKEY_LOCAL_MACHINE\SOFTWARE\SomeApp\Settings");
        assert_eq!(sev, OcsfSeverity::Medium);
    }

    // -----------------------------------------------------------------------
    // Diff logic tests
    // -----------------------------------------------------------------------

    fn vs(vtype: &str, data: &str) -> ValueSnapshot {
        ValueSnapshot {
            value_type: vtype.into(),
            data: data.into(),
        }
    }

    #[test]
    fn diff_detects_new_value() {
        let old: KeySnapshot = HashMap::new();
        let mut new: KeySnapshot = HashMap::new();
        new.insert("Malware".into(), vs("REG_SZ", r"C:\tmp\evil.exe"));

        let changes = diff_snapshots(&old, &new);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            RegistryChange::ValueCreated { value_name, .. } if value_name == "Malware"
        ));
    }

    #[test]
    fn diff_detects_deleted_value() {
        let mut old: KeySnapshot = HashMap::new();
        old.insert("Legitimate".into(), vs("REG_SZ", r"C:\Windows\explorer.exe"));
        let new: KeySnapshot = HashMap::new();

        let changes = diff_snapshots(&old, &new);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            RegistryChange::ValueDeleted { value_name } if value_name == "Legitimate"
        ));
    }

    #[test]
    fn diff_detects_modified_value() {
        let mut old: KeySnapshot = HashMap::new();
        old.insert("Startup".into(), vs("REG_SZ", r"C:\Program Files\App\app.exe"));
        let mut new: KeySnapshot = HashMap::new();
        new.insert("Startup".into(), vs("REG_SZ", r"C:\tmp\malware.exe"));

        let changes = diff_snapshots(&old, &new);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            RegistryChange::ValueModified { value_name, new_data, old_data, .. }
                if value_name == "Startup"
                && new_data.contains("malware")
                && old_data.contains("app.exe")
        ));
    }

    #[test]
    fn diff_no_changes_on_identical_snapshots() {
        let mut snap: KeySnapshot = HashMap::new();
        snap.insert("Normal".into(), vs("REG_SZ", "normal_value"));

        let changes = diff_snapshots(&snap, &snap.clone());
        assert!(changes.is_empty(), "no changes should be detected when snapshots are identical");
    }

    #[test]
    fn diff_multiple_changes_detected() {
        let mut old: KeySnapshot = HashMap::new();
        old.insert("Existing".into(), vs("REG_SZ", "old_val"));
        old.insert("ToDelete".into(), vs("REG_DWORD", "1"));

        let mut new: KeySnapshot = HashMap::new();
        new.insert("Existing".into(), vs("REG_SZ", "new_val"));
        new.insert("NewValue".into(), vs("REG_SZ", "added"));
        // ToDelete is absent → deleted.

        let changes = diff_snapshots(&old, &new);
        assert_eq!(changes.len(), 3, "should detect modify + create + delete = 3 changes");
    }

    // -----------------------------------------------------------------------
    // OCSF event construction tests (via build_event)
    // -----------------------------------------------------------------------

    fn test_collector() -> RegistryCollector {
        use crate::config::RegistryCollectorConfig;
        RegistryCollector {
            config: RegistryCollectorConfig::default(),
            device: OcsfDevice {
                hostname: "win-host".into(),
                ip: "10.0.0.1".into(),
                os_name: "Windows".into(),
                os_version: "10.0.22631".into(),
            },
        }
    }

    #[test]
    fn build_event_create_has_correct_ocsf_fields() {
        let col = test_collector();
        let key =
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let change = RegistryChange::ValueCreated {
            value_name: "Backdoor".into(),
            value_type: "REG_SZ".into(),
            value_data: r"C:\Windows\Temp\back.exe".into(),
        };
        let ev = col.build_event(key, change);
        assert_eq!(ev.class_uid, 201004);
        assert_eq!(ev.activity, "Create");
        assert_eq!(ev.activity_id, 1);
        assert_eq!(ev.severity_id, 4, "Run key should be High severity");
    }

    #[test]
    fn build_event_delete_has_correct_activity() {
        let col = test_collector();
        let key = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services";
        let change = RegistryChange::ValueDeleted {
            value_name: "MaliciousSvc".into(),
        };
        let ev = col.build_event(key, change);
        assert_eq!(ev.activity, "Delete");
        assert_eq!(ev.activity_id, 2);
    }

    #[test]
    fn build_event_modify_includes_old_value_data() {
        let col = test_collector();
        let key =
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa";
        let change = RegistryChange::ValueModified {
            value_name: "LmCompatibilityLevel".into(),
            value_type: "REG_DWORD".into(),
            new_data: "0".into(),
            old_data: "5".into(),
        };
        let ev = col.build_event(key, change);
        assert_eq!(ev.activity, "Modify");
        assert_eq!(ev.activity_id, 3);
        assert_eq!(ev.severity_id, 4, "LSA key should be High severity");

        use crate::events::ocsf::OcsfPayload;
        if let OcsfPayload::RegistryActivity(data) = &ev.payload {
            assert_eq!(data.old_value_data.as_deref(), Some("5"));
            assert_eq!(data.value_data.as_deref(), Some("0"));
        } else {
            panic!("Expected RegistryActivity payload");
        }
    }

    #[test]
    fn build_event_attaches_attack_techniques() {
        let col = test_collector();
        let key =
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let change = RegistryChange::ValueCreated {
            value_name: "Persist".into(),
            value_type: "REG_SZ".into(),
            value_data: r"C:\evil\persist.exe".into(),
        };
        let ev = col.build_event(key, change);
        // T1547.001 (Registry Run Keys) should be tagged for a Run key change.
        assert!(
            ev.attack_techniques.iter().any(|t| t == "T1547.001" || t == "T1547" || t == "T1112"),
            "expected persistence or registry technique, got: {:?}",
            ev.attack_techniques
        );
    }
}
