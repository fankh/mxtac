//! Scheduled task monitoring collector.
//!
//! Polls configured paths (cron directories, systemd timer directories, at
//! spool) to detect additions, modifications, and deletions of scheduled task
//! files. Emits OCSF File System Activity (class_uid 1001) events with
//! MITRE ATT&CK technique tags (T1053, T1053.001, T1053.003, T1543.002).
//!
//! ## Design
//!
//! On startup the collector snapshots all files in the configured paths by
//! computing a SHA-256 hash of each file's contents. On each poll interval it
//! re-scans the paths and compares against the snapshot:
//!
//! - New files     → `Create` event (activity_id 1)
//! - Changed files → `Modify` event (activity_id 2)
//! - Removed files → `Delete` event (activity_id 3)
//!
//! The collector filters systemd directories to only track `.timer` and
//! `.service` unit files, reducing noise from unrelated systemd state files.
//! In at(1) spool directories, hidden files and metadata files (`lastjob`,
//! `lockfile`) are skipped.
//!
//! ## Monitored paths (defaults)
//!
//! | Path                              | ATT&CK technique        |
//! |-----------------------------------|-------------------------|
//! | `/etc/crontab`                    | T1053, T1053.003        |
//! | `/etc/cron.d/`                    | T1053, T1053.003        |
//! | `/etc/cron.{hourly,daily,…}/`     | T1053, T1053.003        |
//! | `/var/spool/cron/crontabs/`       | T1053, T1053.003        |
//! | `/var/spool/at/`                  | T1053, T1053.001        |
//! | `/etc/systemd/system/` (*.timer)  | T1543, T1543.002        |

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::ScheduledTaskCollectorConfig;
use crate::events::ocsf::{FileActivityData, OcsfDevice, OcsfEvent, OcsfSeverity};

// ---------------------------------------------------------------------------
// Collector struct
// ---------------------------------------------------------------------------

/// Collector that polls scheduled task locations for file changes.
pub struct ScheduledTaskCollector {
    config: ScheduledTaskCollectorConfig,
    device: OcsfDevice,
}

impl ScheduledTaskCollector {
    pub fn new(config: &ScheduledTaskCollectorConfig, device: OcsfDevice) -> Self {
        Self {
            config: config.clone(),
            device,
        }
    }
}

// ---------------------------------------------------------------------------
// Collector impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Collector for ScheduledTaskCollector {
    fn name(&self) -> &'static str {
        "scheduled_task"
    }

    async fn run(
        &self,
        tx: mpsc::Sender<OcsfEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        info!(
            "Scheduled task collector started (interval={}ms, paths={:?})",
            self.config.poll_interval_ms, self.config.watch_paths
        );
        let interval = Duration::from_millis(self.config.poll_interval_ms);

        // Build initial snapshot — do not emit events for pre-existing files.
        let mut snapshot: HashMap<PathBuf, String> = HashMap::new();
        for path in &self.config.watch_paths {
            scan_path(Path::new(path), &mut snapshot);
        }
        debug!(
            "Scheduled task collector snapshot: {} files indexed",
            snapshot.len()
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    info!("Scheduled task collector shutting down");
                    return Ok(());
                }
            }

            let mut current: HashMap<PathBuf, String> = HashMap::new();
            for path in &self.config.watch_paths {
                scan_path(Path::new(path), &mut current);
            }

            // Detect new and modified files.
            for (path, hash) in &current {
                match snapshot.get(path) {
                    None => {
                        // New file — emit Create event.
                        if let Some(event) =
                            build_event(self.device.clone(), path, "Create", 1, hash)
                        {
                            if tx.send(event).await.is_err() {
                                debug!(
                                    "Event channel closed, stopping scheduled task collector"
                                );
                                return Ok(());
                            }
                        }
                    }
                    Some(old_hash) if old_hash != hash => {
                        // Content changed — emit Modify event.
                        if let Some(event) =
                            build_event(self.device.clone(), path, "Modify", 2, hash)
                        {
                            if tx.send(event).await.is_err() {
                                debug!(
                                    "Event channel closed, stopping scheduled task collector"
                                );
                                return Ok(());
                            }
                        }
                    }
                    _ => {} // unchanged
                }
            }

            // Detect deleted files.
            for path in snapshot.keys() {
                if !current.contains_key(path) {
                    let path_str = path.to_string_lossy().into_owned();
                    let data = FileActivityData {
                        path: path_str,
                        action: "Delete".into(),
                        size: None,
                        hash: None,
                    };
                    let techniques = crate::attack::tag_file_event(&data);
                    let event = OcsfEvent::file_activity(
                        self.device.clone(),
                        "Delete",
                        3,
                        OcsfSeverity::Medium,
                        data,
                    )
                    .with_attack_techniques(techniques);

                    if tx.send(event).await.is_err() {
                        debug!("Event channel closed, stopping scheduled task collector");
                        return Ok(());
                    }
                }
            }

            snapshot = current;
        }
    }
}

// ---------------------------------------------------------------------------
// Path filtering
// ---------------------------------------------------------------------------

/// Determine whether a file at `path` should be monitored.
///
/// - In systemd directories: only `.timer` and `.service` files.
/// - In at(1) spool directories: skip hidden files and metadata entries.
/// - Everywhere else: all regular files.
pub(crate) fn should_monitor(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    if path_str.contains("/systemd/") {
        // Only track unit files relevant to persistence / scheduled tasks.
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("timer") | Some("service")
        )
    } else if path_str.contains("/var/spool/at/") {
        // at(1) job files are short alphanumeric names.
        // Skip hidden files and well-known metadata files.
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        !fname.starts_with('.') && fname != "lastjob" && fname != "lockfile"
    } else {
        true
    }
}

// ---------------------------------------------------------------------------
// File hashing
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of `path` and return it as a lowercase hex string.
///
/// Returns `None` if the file cannot be opened or read (e.g. permission
/// denied, file disappeared between directory scan and open).
pub(crate) fn hash_file(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Directory scanning
// ---------------------------------------------------------------------------

/// Scan `path` (file or one-level-deep directory) and populate `snapshot`
/// with `(absolute_path → sha256_hash)` entries for every monitored file.
///
/// Directories are scanned one level deep only. Subdirectories within
/// scanned directories are not recursed into; this prevents accidental
/// traversal of deep symlink trees found in some systemd pool directories.
pub(crate) fn scan_path(path: &Path, snapshot: &mut HashMap<PathBuf, String>) {
    if !path.exists() {
        return;
    }

    if path.is_file() {
        if should_monitor(path) {
            if let Some(hash) = hash_file(path) {
                snapshot.insert(path.to_path_buf(), hash);
            }
        }
        return;
    }

    if path.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(err) => {
                warn!("Failed to read directory {:?}: {err}", path);
                return;
            }
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() && should_monitor(&p) {
                if let Some(hash) = hash_file(&p) {
                    snapshot.insert(p, hash);
                }
            }
            // Do not recurse into subdirectories.
        }
    }
}

// ---------------------------------------------------------------------------
// Event builder
// ---------------------------------------------------------------------------

/// Build an OCSF File System Activity event for a detected scheduled task
/// file change, attaching ATT&CK technique tags from the attack module.
///
/// Returns `None` only if the path string cannot be represented as UTF-8,
/// which is vanishingly rare on Linux.
fn build_event(
    device: OcsfDevice,
    path: &Path,
    activity: &str,
    activity_id: u32,
    hash: &str,
) -> Option<OcsfEvent> {
    let path_str = path.to_string_lossy().into_owned();
    let size = fs::metadata(path).ok().map(|m| m.len());

    let data = FileActivityData {
        path: path_str,
        action: activity.to_string(),
        size,
        hash: Some(hash.to_string()),
    };

    let techniques = crate::attack::tag_file_event(&data);
    let event = OcsfEvent::file_activity(
        device,
        activity,
        activity_id,
        OcsfSeverity::Medium,
        data,
    )
    .with_attack_techniques(techniques);

    Some(event)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // should_monitor
    // -----------------------------------------------------------------------

    #[test]
    fn monitor_cron_file_in_cron_d() {
        let p = Path::new("/etc/cron.d/my_job");
        assert!(should_monitor(p), "cron.d files must be monitored");
    }

    #[test]
    fn monitor_crontab_file() {
        let p = Path::new("/etc/crontab");
        assert!(should_monitor(p));
    }

    #[test]
    fn monitor_user_crontab() {
        let p = Path::new("/var/spool/cron/crontabs/alice");
        assert!(should_monitor(p));
    }

    #[test]
    fn monitor_at_job_file() {
        let p = Path::new("/var/spool/at/a0001f12345678");
        assert!(should_monitor(p));
    }

    #[test]
    fn skip_at_spool_hidden_file() {
        let p = Path::new("/var/spool/at/.seq");
        assert!(!should_monitor(p), "hidden files in at spool must be skipped");
    }

    #[test]
    fn skip_at_spool_lastjob() {
        let p = Path::new("/var/spool/at/lastjob");
        assert!(!should_monitor(p));
    }

    #[test]
    fn skip_at_spool_lockfile() {
        let p = Path::new("/var/spool/at/lockfile");
        assert!(!should_monitor(p));
    }

    #[test]
    fn monitor_systemd_timer_file() {
        let p = Path::new("/etc/systemd/system/backup.timer");
        assert!(should_monitor(p), ".timer files must be monitored");
    }

    #[test]
    fn monitor_systemd_service_file() {
        let p = Path::new("/etc/systemd/system/backdoor.service");
        assert!(should_monitor(p), ".service files must be monitored");
    }

    #[test]
    fn skip_systemd_socket_file() {
        // .socket is not a timer or service — not relevant for this collector
        let p = Path::new("/etc/systemd/system/foo.socket");
        assert!(!should_monitor(p), ".socket files in systemd must be skipped");
    }

    #[test]
    fn skip_systemd_dir_without_timer_or_service_extension() {
        // Paths inside a systemd directory that lack .timer/.service extensions
        // (e.g. .wants/ directories, .conf files) must NOT be monitored.
        // In practice scan_path only calls should_monitor on regular files
        // (p.is_file()), so .wants directories never reach this function, but
        // the extension filter still correctly handles them.
        let p = Path::new("/etc/systemd/system/multi-user.target.wants");
        // "wants" is the extension from Path::extension()'s perspective → not monitored.
        assert!(!should_monitor(p));
    }

    // -----------------------------------------------------------------------
    // hash_file
    // -----------------------------------------------------------------------

    #[test]
    fn hash_file_returns_some_for_readable_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "* * * * * root /usr/bin/true").unwrap();
        let hash = hash_file(f.path());
        assert!(hash.is_some(), "hash_file must return Some for a readable file");
    }

    #[test]
    fn hash_file_returns_64_hex_chars() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "0 * * * * root /usr/bin/backup").unwrap();
        let hash = hash_file(f.path()).unwrap();
        assert_eq!(hash.len(), 64, "SHA-256 hex must be 64 characters");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "must be hex");
    }

    #[test]
    fn hash_file_is_deterministic() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "30 4 * * * root /sbin/logrotate").unwrap();
        let h1 = hash_file(f.path()).unwrap();
        let h2 = hash_file(f.path()).unwrap();
        assert_eq!(h1, h2, "hash must be deterministic");
    }

    #[test]
    fn hash_file_differs_for_different_content() {
        let mut f1 = tempfile::NamedTempFile::new().unwrap();
        let mut f2 = tempfile::NamedTempFile::new().unwrap();
        writeln!(f1, "content A").unwrap();
        writeln!(f2, "content B").unwrap();
        assert_ne!(hash_file(f1.path()), hash_file(f2.path()));
    }

    #[test]
    fn hash_file_returns_none_for_nonexistent_path() {
        let hash = hash_file(Path::new("/nonexistent/path/to/file.txt"));
        assert!(hash.is_none(), "hash_file must return None for missing file");
    }

    // -----------------------------------------------------------------------
    // scan_path
    // -----------------------------------------------------------------------

    fn make_temp_cron_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        // Write two cron job files
        std::fs::write(dir.path().join("job_a"), "* * * * * user /usr/bin/cmd_a\n").unwrap();
        std::fs::write(dir.path().join("job_b"), "0 2 * * * user /usr/bin/cmd_b\n").unwrap();
        dir
    }

    #[test]
    fn scan_path_indexes_files_in_directory() {
        let dir = make_temp_cron_dir();
        let mut snapshot = HashMap::new();
        scan_path(dir.path(), &mut snapshot);
        assert_eq!(snapshot.len(), 2, "should index both cron files");
    }

    #[test]
    fn scan_path_indexes_single_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "* * * * * root /usr/bin/true").unwrap();
        let mut snapshot = HashMap::new();
        scan_path(f.path(), &mut snapshot);
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.contains_key(f.path()));
    }

    #[test]
    fn scan_path_skips_nonexistent_path() {
        let mut snapshot = HashMap::new();
        scan_path(Path::new("/nonexistent/path"), &mut snapshot);
        assert!(snapshot.is_empty(), "should not panic on missing path");
    }

    #[test]
    fn scan_path_filters_systemd_non_timer_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("backup.timer"), "[Timer]\nOnCalendar=daily\n").unwrap();
        std::fs::write(dir.path().join("backup.service"), "[Service]\n").unwrap();
        std::fs::write(dir.path().join("backup.socket"), "[Socket]\n").unwrap();
        // Fake a systemd path by creating a subdirectory named "systemd" and using it
        let systemd_dir = dir.path().join("systemd");
        std::fs::create_dir(&systemd_dir).unwrap();
        std::fs::write(systemd_dir.join("backup.timer"), "[Timer]\nOnCalendar=daily\n").unwrap();
        std::fs::write(systemd_dir.join("backup.service"), "[Service]\n").unwrap();
        std::fs::write(systemd_dir.join("backup.socket"), "[Socket]\n").unwrap();

        let mut snapshot = HashMap::new();
        scan_path(&systemd_dir, &mut snapshot);
        // Only .timer and .service should be indexed; .socket must be skipped.
        assert_eq!(snapshot.len(), 2, "only .timer and .service must be indexed");
        assert!(snapshot.keys().any(|p| p.to_string_lossy().ends_with(".timer")));
        assert!(snapshot.keys().any(|p| p.to_string_lossy().ends_with(".service")));
        assert!(
            !snapshot.keys().any(|p| p.to_string_lossy().ends_with(".socket")),
            ".socket must be excluded"
        );
    }

    // -----------------------------------------------------------------------
    // Change detection logic (unit-level simulation)
    // -----------------------------------------------------------------------

    #[test]
    fn detect_new_file_as_create() {
        // Simulate: snapshot has no files, current has one → Create
        let dir = TempDir::new().unwrap();
        let job_path = dir.path().join("new_job");
        std::fs::write(&job_path, "* * * * * root /usr/bin/true\n").unwrap();

        let snapshot: HashMap<PathBuf, String> = HashMap::new();
        let mut current = HashMap::new();
        scan_path(dir.path(), &mut current);

        let new_files: Vec<&PathBuf> = current
            .keys()
            .filter(|p| !snapshot.contains_key(*p))
            .collect();
        assert_eq!(new_files.len(), 1, "one new file should be detected");
    }

    #[test]
    fn detect_modified_file_as_modify() {
        let dir = TempDir::new().unwrap();
        let job_path = dir.path().join("existing_job");
        std::fs::write(&job_path, "* * * * * root /usr/bin/true\n").unwrap();

        // Take initial snapshot
        let mut snapshot = HashMap::new();
        scan_path(dir.path(), &mut snapshot);

        // Modify the file
        std::fs::write(&job_path, "0 3 * * * root /usr/bin/modified\n").unwrap();

        let mut current = HashMap::new();
        scan_path(dir.path(), &mut current);

        // The hash should differ
        let old_hash = snapshot.get(&job_path).unwrap();
        let new_hash = current.get(&job_path).unwrap();
        assert_ne!(old_hash, new_hash, "modified file must produce different hash");
    }

    #[test]
    fn detect_deleted_file_as_delete() {
        let dir = TempDir::new().unwrap();
        let job_path = dir.path().join("gone_job");
        std::fs::write(&job_path, "* * * * * root /usr/bin/true\n").unwrap();

        let mut snapshot = HashMap::new();
        scan_path(dir.path(), &mut snapshot);

        // Delete the file
        std::fs::remove_file(&job_path).unwrap();

        let mut current = HashMap::new();
        scan_path(dir.path(), &mut current);

        let deleted: Vec<&PathBuf> = snapshot
            .keys()
            .filter(|p| !current.contains_key(*p))
            .collect();
        assert_eq!(deleted.len(), 1, "deleted file must be detected");
    }

    #[test]
    fn unchanged_file_not_flagged() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("stable_job"), "* * * * * root /usr/bin/true\n").unwrap();

        let mut snapshot = HashMap::new();
        scan_path(dir.path(), &mut snapshot);

        let mut current = HashMap::new();
        scan_path(dir.path(), &mut current);

        // All files should match
        for (path, hash) in &current {
            assert_eq!(
                snapshot.get(path),
                Some(hash),
                "unchanged file must not trigger event"
            );
        }
    }

    // -----------------------------------------------------------------------
    // build_event — ATT&CK technique tagging
    // -----------------------------------------------------------------------

    fn make_device() -> OcsfDevice {
        OcsfDevice {
            hostname: "test-host".into(),
            ip: "127.0.0.1".into(),
            os_name: "Linux".into(),
            os_version: "6.1.0".into(),
        }
    }

    #[test]
    fn cron_file_event_has_t1053_tag() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // Use a path within /etc/cron.d naming convention
        writeln!(f, "* * * * * root /usr/bin/true").unwrap();
        let hash = hash_file(f.path()).unwrap();

        // Manually build data with a cron path to trigger the tagger.
        let data = FileActivityData {
            path: "/etc/cron.d/test_job".into(),
            action: "Create".into(),
            size: Some(30),
            hash: Some(hash.clone()),
        };
        let techniques = crate::attack::tag_file_event(&data);
        assert!(
            techniques.iter().any(|t| t == "T1053"),
            "cron file event must be tagged T1053; got {techniques:?}"
        );
        assert!(
            techniques.iter().any(|t| t == "T1053.003"),
            "cron file event must be tagged T1053.003 (Cron)"
        );
    }

    #[test]
    fn systemd_timer_event_has_t1543_tag() {
        let data = FileActivityData {
            path: "/etc/systemd/system/persistence.timer".into(),
            action: "Create".into(),
            size: Some(64),
            hash: Some("abc123".into()),
        };
        let techniques = crate::attack::tag_file_event(&data);
        assert!(
            techniques.iter().any(|t| t == "T1543"),
            "systemd timer event must be tagged T1543"
        );
        assert!(
            techniques.iter().any(|t| t == "T1543.002"),
            "systemd timer event must be tagged T1543.002"
        );
    }

    #[test]
    fn at_spool_event_has_t1053_001_tag() {
        let data = FileActivityData {
            path: "/var/spool/at/a0001f12345678".into(),
            action: "Create".into(),
            size: Some(128),
            hash: Some("deadbeef".into()),
        };
        let techniques = crate::attack::tag_file_event(&data);
        assert!(
            techniques.iter().any(|t| t == "T1053"),
            "at spool event must be tagged T1053; got {techniques:?}"
        );
        assert!(
            techniques.iter().any(|t| t == "T1053.001"),
            "at spool event must be tagged T1053.001 (At)"
        );
    }

    #[test]
    fn build_event_returns_file_activity_event() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "* * * * * root /usr/bin/true").unwrap();
        let hash = hash_file(f.path()).unwrap();

        let event = build_event(make_device(), f.path(), "Create", 1, &hash);
        assert!(event.is_some(), "build_event must return Some for a readable file");

        let ev = event.unwrap();
        assert_eq!(ev.class_uid, 1001, "must be File System Activity class");
        assert_eq!(ev.activity, "Create");
        assert_eq!(ev.activity_id, 1);
        assert_eq!(ev.severity_id, 3, "severity must be Medium (3)");
    }

    #[test]
    fn build_event_delete_has_medium_severity() {
        let data = FileActivityData {
            path: "/etc/cron.d/important".into(),
            action: "Delete".into(),
            size: None,
            hash: None,
        };
        let ev = OcsfEvent::file_activity(
            make_device(),
            "Delete",
            3,
            OcsfSeverity::Medium,
            data,
        );
        assert_eq!(ev.severity_id, 3);
        assert_eq!(ev.activity_id, 3);
    }
}
