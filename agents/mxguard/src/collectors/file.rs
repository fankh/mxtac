//! File integrity monitoring collector using Linux inotify.
//!
//! Watches configured directories for create / modify / delete events and emits
//! OCSF File System Activity (class_uid 1001) events.  SHA-256 hashes are
//! computed for created and modified files so that downstream consumers can
//! verify file integrity.
//!
//! # Design
//! * Uses `inotify.into_event_stream()` for a fully async, non-blocking event
//!   loop (no busy-polling or spawn_blocking overhead).
//! * Integrates with tokio's `select!` so the collector shuts down cleanly when
//!   the watch channel signals shutdown.
//! * Files larger than [`MAX_HASH_SIZE`] are not hashed to bound I/O cost.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

use crate::collectors::Collector;
use crate::config::FileCollectorConfig;
use crate::events::ocsf::{FileActivityData, OcsfDevice, OcsfEvent, OcsfSeverity};

/// Files larger than this will not be SHA-256 hashed (16 MiB).
const MAX_HASH_SIZE: u64 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// FileCollector
// ---------------------------------------------------------------------------

/// Collector that monitors file system changes via Linux inotify.
pub struct FileCollector {
    config: FileCollectorConfig,
    device: OcsfDevice,
}

impl FileCollector {
    pub fn new(config: &FileCollectorConfig, device: OcsfDevice) -> Self {
        Self {
            config: config.clone(),
            device,
        }
    }

    /// Returns `true` if `name` matches any configured exclude pattern.
    ///
    /// Pattern semantics:
    /// * `*.log` — suffix glob: matches any name ending with `.log`
    /// * `temp`  — exact name match
    fn is_excluded(&self, name: &str) -> bool {
        for pattern in &self.config.exclude_patterns {
            if let Some(suffix) = pattern.strip_prefix('*') {
                if name.ends_with(suffix) {
                    return true;
                }
            } else if name == pattern {
                return true;
            }
        }
        false
    }

    /// Classify the OCSF severity of an event based on the affected path.
    ///
    /// Changes to sensitive system paths are elevated to `High`; everything
    /// else defaults to `Low`.
    fn classify_severity(&self, path: &str) -> OcsfSeverity {
        const SENSITIVE_PATHS: &[&str] = &[
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/",
            "/usr/bin/",
            "/usr/sbin/",
        ];
        for prefix in SENSITIVE_PATHS {
            if path.starts_with(prefix) {
                return OcsfSeverity::High;
            }
        }
        OcsfSeverity::Low
    }

    /// Compute the SHA-256 digest of a file, returned as a lowercase hex string.
    ///
    /// Returns `None` when:
    /// * The file does not exist or cannot be read.
    /// * The file exceeds [`MAX_HASH_SIZE`] (to avoid excessive I/O).
    fn compute_hash(path: &Path) -> Option<String> {
        let metadata = std::fs::metadata(path).ok()?;
        if metadata.len() > MAX_HASH_SIZE {
            return None;
        }
        let data = std::fs::read(path).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        Some(result.iter().map(|b| format!("{b:02x}")).collect())
    }
}

// ---------------------------------------------------------------------------
// Collector impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Collector for FileCollector {
    fn name(&self) -> &'static str {
        "file"
    }

    async fn run(
        &self,
        tx: mpsc::Sender<OcsfEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        info!(
            "File collector started, watching {:?}",
            self.config.watch_paths
        );

        let inotify = Inotify::init()?;

        // Map watch descriptor → base directory so we can reconstruct the full path.
        let mut wd_map: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

        let mask = WatchMask::CREATE
            | WatchMask::MODIFY
            | WatchMask::DELETE
            | WatchMask::MOVED_TO
            | WatchMask::MOVED_FROM;

        for dir in &self.config.watch_paths {
            let path = Path::new(dir);
            if !path.exists() {
                warn!("Watch path does not exist, skipping: {dir}");
                continue;
            }
            match inotify.watches().add(path, mask) {
                Ok(wd) => {
                    wd_map.insert(wd, path.to_path_buf());
                    debug!("Watching directory: {dir}");
                }
                Err(e) => {
                    error!("Failed to add inotify watch for {dir}: {e}");
                }
            }
        }

        info!(
            "File collector: inotify watching {} path(s)",
            wd_map.len()
        );

        // Convert inotify into a fully async event stream (sets O_NONBLOCK internally).
        let buffer = vec![0u8; 4096];
        let mut stream = inotify.into_event_stream(buffer)?;

        loop {
            tokio::select! {
                biased;

                _ = shutdown.changed() => {
                    info!("File collector shutting down");
                    return Ok(());
                }

                event_result = stream.next() => {
                    let Some(result) = event_result else {
                        warn!("inotify event stream ended unexpectedly");
                        return Ok(());
                    };

                    let event = match result {
                        Ok(e) => e,
                        Err(e) => {
                            error!("inotify read error: {e}");
                            return Err(e.into());
                        }
                    };

                    // Skip subdirectory events; we only monitor files inside watched dirs.
                    if event.mask.contains(EventMask::ISDIR) {
                        continue;
                    }

                    // Events without a filename are directory-level notifications; skip.
                    let file_name = match event.name {
                        Some(n) => n.to_string_lossy().into_owned(),
                        None => continue,
                    };

                    if self.is_excluded(&file_name) {
                        debug!("Skipping excluded file: {file_name}");
                        continue;
                    }

                    let base = match wd_map.get(&event.wd) {
                        Some(p) => p.clone(),
                        None => {
                            debug!("Unknown watch descriptor, skipping event");
                            continue;
                        }
                    };

                    let full_path = base.join(&file_name);
                    let path_str = full_path.to_string_lossy().into_owned();

                    let (action, activity_id) =
                        if event.mask.contains(EventMask::CREATE)
                            || event.mask.contains(EventMask::MOVED_TO)
                        {
                            ("Create", 1u32)
                        } else if event.mask.contains(EventMask::MODIFY) {
                            ("Update", 2u32)
                        } else if event.mask.contains(EventMask::DELETE)
                            || event.mask.contains(EventMask::MOVED_FROM)
                        {
                            ("Delete", 3u32)
                        } else {
                            ("Other", 99u32)
                        };

                    // File metadata is not available for deleted files.
                    let size = std::fs::metadata(&full_path).ok().map(|m| m.len());

                    // Compute SHA-256 for new/modified files (file integrity monitoring).
                    let hash = if action == "Create" || action == "Update" {
                        Self::compute_hash(&full_path)
                    } else {
                        None
                    };

                    let severity = self.classify_severity(&path_str);

                    debug!(
                        action,
                        path = path_str,
                        severity = ?severity,
                        "File event"
                    );

                    let data = FileActivityData {
                        path: path_str,
                        action: action.to_string(),
                        size,
                        hash,
                    };

                    let ocsf_event = OcsfEvent::file_activity(
                        self.device.clone(),
                        action,
                        activity_id,
                        severity,
                        data,
                    );

                    if tx.send(ocsf_event).await.is_err() {
                        debug!("Event channel closed, stopping file collector");
                        return Ok(());
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_collector_with_patterns(
        watch_paths: Vec<String>,
        exclude_patterns: Vec<String>,
    ) -> FileCollector {
        let config = FileCollectorConfig {
            enabled: true,
            watch_paths,
            exclude_patterns,
        };
        let device = OcsfDevice {
            hostname: "test-host".to_string(),
            ip: "127.0.0.1".to_string(),
            os_name: "Linux".to_string(),
            os_version: "6.0".to_string(),
        };
        FileCollector::new(&config, device)
    }

    fn make_collector() -> FileCollector {
        make_collector_with_patterns(
            vec!["/tmp".to_string()],
            vec!["*.log".to_string(), "temp".to_string()],
        )
    }

    // ── is_excluded ──────────────────────────────────────────────────────────

    #[test]
    fn is_excluded_suffix_glob_matches() {
        let c = make_collector();
        assert!(c.is_excluded("debug.log"));
        assert!(c.is_excluded("app.error.log"));
    }

    #[test]
    fn is_excluded_suffix_glob_no_match() {
        let c = make_collector();
        assert!(!c.is_excluded("config.toml"));
        assert!(!c.is_excluded("logfile")); // doesn't end with ".log"
    }

    #[test]
    fn is_excluded_exact_match() {
        let c = make_collector();
        assert!(c.is_excluded("temp"));
    }

    #[test]
    fn is_excluded_no_partial_match_on_exact_pattern() {
        let c = make_collector();
        assert!(!c.is_excluded("temporary")); // "temp" pattern is exact, not prefix
        assert!(!c.is_excluded("tempfile"));
    }

    #[test]
    fn is_excluded_empty_name_not_excluded() {
        let c = make_collector();
        assert!(!c.is_excluded(""));
    }

    #[test]
    fn is_excluded_no_patterns_allows_everything() {
        let c = make_collector_with_patterns(vec!["/tmp".to_string()], vec![]);
        assert!(!c.is_excluded("anything.log"));
        assert!(!c.is_excluded("temp"));
    }

    #[test]
    fn is_excluded_multiple_patterns() {
        let c = make_collector_with_patterns(
            vec!["/tmp".to_string()],
            vec!["*.tmp".to_string(), "*.swp".to_string(), "lock".to_string()],
        );
        assert!(c.is_excluded("file.tmp"));
        assert!(c.is_excluded("vim.swp"));
        assert!(c.is_excluded("lock"));
        assert!(!c.is_excluded("important.txt"));
    }

    // ── classify_severity ────────────────────────────────────────────────────

    #[test]
    fn classify_severity_high_for_etc_passwd() {
        let c = make_collector();
        assert_eq!(c.classify_severity("/etc/passwd"), OcsfSeverity::High);
    }

    #[test]
    fn classify_severity_high_for_etc_shadow() {
        let c = make_collector();
        assert_eq!(c.classify_severity("/etc/shadow"), OcsfSeverity::High);
    }

    #[test]
    fn classify_severity_high_for_etc_sudoers() {
        let c = make_collector();
        assert_eq!(c.classify_severity("/etc/sudoers"), OcsfSeverity::High);
    }

    #[test]
    fn classify_severity_high_for_ssh_configs() {
        let c = make_collector();
        assert_eq!(
            c.classify_severity("/etc/ssh/sshd_config"),
            OcsfSeverity::High
        );
        assert_eq!(
            c.classify_severity("/etc/ssh/ssh_host_rsa_key"),
            OcsfSeverity::High
        );
    }

    #[test]
    fn classify_severity_high_for_usr_bin() {
        let c = make_collector();
        assert_eq!(c.classify_severity("/usr/bin/ls"), OcsfSeverity::High);
        assert_eq!(c.classify_severity("/usr/bin/python3"), OcsfSeverity::High);
    }

    #[test]
    fn classify_severity_high_for_usr_sbin() {
        let c = make_collector();
        assert_eq!(
            c.classify_severity("/usr/sbin/iptables"),
            OcsfSeverity::High
        );
    }

    #[test]
    fn classify_severity_low_for_tmp() {
        let c = make_collector();
        assert_eq!(c.classify_severity("/tmp/test.txt"), OcsfSeverity::Low);
    }

    #[test]
    fn classify_severity_low_for_home() {
        let c = make_collector();
        assert_eq!(
            c.classify_severity("/home/user/document.txt"),
            OcsfSeverity::Low
        );
    }

    #[test]
    fn classify_severity_low_for_var_log() {
        let c = make_collector();
        assert_eq!(c.classify_severity("/var/log/syslog"), OcsfSeverity::Low);
    }

    // ── compute_hash ─────────────────────────────────────────────────────────

    #[test]
    fn compute_hash_nonexistent_file_returns_none() {
        let path = Path::new("/nonexistent/path/file_that_does_not_exist_xyz.txt");
        assert!(FileCollector::compute_hash(path).is_none());
    }

    #[test]
    fn compute_hash_empty_file_known_value() {
        // SHA-256 of zero bytes is a well-known constant.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("mxguard_fim_test_empty_{}.bin", std::process::id()));
        std::fs::File::create(&path).expect("create temp file");

        let hash = FileCollector::compute_hash(&path);
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            hash.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn compute_hash_produces_64_lowercase_hex_chars() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("mxguard_fim_test_content_{}.txt", std::process::id()));
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(b"MxGuard file integrity test content")
            .expect("write content");
        drop(f);

        let hash = FileCollector::compute_hash(&path);
        let _ = std::fs::remove_file(&path);

        let hash_str = hash.expect("hash should succeed for a readable file");
        assert_eq!(hash_str.len(), 64, "SHA-256 hex digest must be 64 characters");
        assert!(
            hash_str.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must contain only lowercase hex digits"
        );
    }

    #[test]
    fn compute_hash_different_content_different_hash() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();

        let path_a = dir.join(format!("mxguard_fim_a_{pid}.txt"));
        let path_b = dir.join(format!("mxguard_fim_b_{pid}.txt"));

        std::fs::write(&path_a, b"content alpha").expect("write file a");
        std::fs::write(&path_b, b"content beta").expect("write file b");

        let hash_a = FileCollector::compute_hash(&path_a).expect("hash a");
        let hash_b = FileCollector::compute_hash(&path_b).expect("hash b");

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);

        assert_ne!(hash_a, hash_b, "different content must produce different hashes");
    }

    #[test]
    fn compute_hash_same_content_same_hash() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();

        let path_a = dir.join(format!("mxguard_fim_same_a_{pid}.txt"));
        let path_b = dir.join(format!("mxguard_fim_same_b_{pid}.txt"));

        let content = b"identical content for determinism test";
        std::fs::write(&path_a, content).expect("write file a");
        std::fs::write(&path_b, content).expect("write file b");

        let hash_a = FileCollector::compute_hash(&path_a).expect("hash a");
        let hash_b = FileCollector::compute_hash(&path_b).expect("hash b");

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);

        assert_eq!(hash_a, hash_b, "identical content must produce the same hash");
    }
}
