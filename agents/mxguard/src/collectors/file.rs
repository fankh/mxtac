//! File integrity monitoring collector using Linux inotify.
//!
//! Watches configured directories for create / modify / delete / rename /
//! attribute-change events and emits OCSF File System Activity (class_uid 1001)
//! events.  SHA-256 hashes are computed for created and modified files so that
//! downstream consumers can verify file integrity.
//!
//! # Design
//! * Uses `inotify.into_event_stream()` for a fully async, non-blocking event
//!   loop (no busy-polling or spawn_blocking overhead).
//! * Integrates with tokio's `select!` so the collector shuts down cleanly when
//!   the watch channel signals shutdown.
//! * Files larger than [`MAX_HASH_SIZE`] are not hashed to bound I/O cost.
//! * New subdirectories are automatically watched when they are created inside
//!   an already-watched directory.
//! * Events are rate-limited to [`RATE_LIMIT_PER_FILE`] events per second per
//!   file path to suppress noise from editors and build tools that write the
//!   same file many times in rapid succession.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

/// Minimum interval between events for the same file path.
/// Enforces a maximum of 100 events per second per file.
const RATE_LIMIT_PER_FILE: Duration = Duration::from_millis(10);

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

    /// Map an inotify `EventMask` to an OCSF `(activity_name, activity_id)` pair.
    ///
    /// OCSF File System Activity activity IDs (class_uid 1001):
    /// - 1 = Create
    /// - 2 = Delete
    /// - 4 = Modify
    /// - 5 = Rename
    /// - 7 = Set Attributes
    /// - 99 = Other (unmapped)
    fn event_to_action(mask: EventMask) -> (&'static str, u32) {
        if mask.contains(EventMask::CREATE) {
            ("Create", 1)
        } else if mask.contains(EventMask::DELETE) {
            ("Delete", 2)
        } else if mask.contains(EventMask::MODIFY) {
            ("Modify", 4)
        } else if mask.contains(EventMask::MOVED_TO) || mask.contains(EventMask::MOVED_FROM) {
            ("Rename", 5)
        } else if mask.contains(EventMask::ATTRIB) {
            ("Set Attributes", 7)
        } else {
            ("Other", 99)
        }
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
            | WatchMask::MOVED_FROM
            | WatchMask::ATTRIB;

        // Save the Watches handle *before* consuming inotify via into_event_stream.
        // Both Watches and EventStream share an Arc<OwnedFd> internally, so adding
        // watches via this handle after into_event_stream is safe.
        let mut watches = inotify.watches();

        for dir in &self.config.watch_paths {
            let path = Path::new(dir);
            if !path.exists() {
                warn!("Watch path does not exist, skipping: {dir}");
                continue;
            }
            match watches.add(path, mask) {
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

        // Rate-limit state: tracks the last event timestamp per file path.
        // Enforces at most 100 events/second per distinct path.
        let mut last_event: HashMap<String, Instant> = HashMap::new();

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

                    // Directory events: add a watch for newly created subdirectories;
                    // skip all other directory notifications (we only emit file events).
                    if event.mask.contains(EventMask::ISDIR) {
                        if event.mask.contains(EventMask::CREATE) {
                            if let Some(ref dir_name) = event.name {
                                if let Some(base) = wd_map.get(&event.wd).cloned() {
                                    let new_dir = base.join(dir_name.to_string_lossy().as_ref());
                                    match watches.add(&new_dir, mask) {
                                        Ok(wd) => {
                                            wd_map.insert(wd, new_dir.clone());
                                            debug!(
                                                "Added inotify watch for new directory: {}",
                                                new_dir.display()
                                            );
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Failed to add watch for new directory {}: {e}",
                                                new_dir.display()
                                            );
                                        }
                                    }
                                }
                            }
                        }
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

                    // Rate limiting: suppress events that arrive faster than
                    // RATE_LIMIT_PER_FILE (i.e. more than 100/sec) for the same path.
                    let now = Instant::now();
                    if let Some(&last) = last_event.get(&path_str) {
                        if now.duration_since(last) < RATE_LIMIT_PER_FILE {
                            debug!("Rate limiting event for {path_str}");
                            continue;
                        }
                    }
                    last_event.insert(path_str.clone(), now);

                    let (action, activity_id) = Self::event_to_action(event.mask);

                    // File metadata is not available for deleted/renamed-away files.
                    let size = std::fs::metadata(&full_path).ok().map(|m| m.len());

                    // Compute SHA-256 for new/modified files (file integrity monitoring).
                    let hash = if action == "Create" || action == "Modify" {
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

                    let techniques = crate::attack::tag_file_event(&data);
                    let ocsf_event = OcsfEvent::file_activity(
                        self.device.clone(),
                        action,
                        activity_id,
                        severity,
                        data,
                    )
                    .with_attack_techniques(techniques);

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

    // ── event_to_action ──────────────────────────────────────────────────────

    #[test]
    fn event_to_action_create_returns_id_1() {
        let (action, id) = FileCollector::event_to_action(EventMask::CREATE);
        assert_eq!(action, "Create");
        assert_eq!(id, 1);
    }

    #[test]
    fn event_to_action_delete_returns_id_2() {
        let (action, id) = FileCollector::event_to_action(EventMask::DELETE);
        assert_eq!(action, "Delete");
        assert_eq!(id, 2);
    }

    #[test]
    fn event_to_action_modify_returns_id_4() {
        let (action, id) = FileCollector::event_to_action(EventMask::MODIFY);
        assert_eq!(action, "Modify");
        assert_eq!(id, 4);
    }

    #[test]
    fn event_to_action_moved_to_returns_id_5() {
        let (action, id) = FileCollector::event_to_action(EventMask::MOVED_TO);
        assert_eq!(action, "Rename");
        assert_eq!(id, 5);
    }

    #[test]
    fn event_to_action_moved_from_returns_id_5() {
        let (action, id) = FileCollector::event_to_action(EventMask::MOVED_FROM);
        assert_eq!(action, "Rename");
        assert_eq!(id, 5);
    }

    #[test]
    fn event_to_action_attrib_returns_id_7() {
        let (action, id) = FileCollector::event_to_action(EventMask::ATTRIB);
        assert_eq!(action, "Set Attributes");
        assert_eq!(id, 7);
    }

    #[test]
    fn event_to_action_unknown_mask_returns_other() {
        // ACCESS is not in our watch mask but let's verify the fallback
        let (action, id) = FileCollector::event_to_action(EventMask::ACCESS);
        assert_eq!(action, "Other");
        assert_eq!(id, 99);
    }

    #[test]
    fn event_to_action_create_priority_over_modify() {
        // When multiple flags are set, CREATE takes precedence
        let (action, id) = FileCollector::event_to_action(EventMask::CREATE | EventMask::MODIFY);
        assert_eq!(action, "Create");
        assert_eq!(id, 1);
    }

    #[test]
    fn event_to_action_delete_priority_over_attrib() {
        let (action, id) = FileCollector::event_to_action(EventMask::DELETE | EventMask::ATTRIB);
        assert_eq!(action, "Delete");
        assert_eq!(id, 2);
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

    // ── integration: real inotify events ─────────────────────────────────────

    /// Extract the file path from an OcsfEvent's FileActivity payload.
    fn event_file_path(ev: &crate::events::ocsf::OcsfEvent) -> &str {
        match &ev.payload {
            crate::events::ocsf::OcsfPayload::FileActivity(d) => d.path.as_str(),
            _ => "",
        }
    }

    /// Verify that the collector emits correct OCSF events for real file
    /// operations (create, modify, delete, rename) on a watched directory.
    #[tokio::test]
    async fn integration_file_events_create_modify_delete_rename() {
        use tempfile::TempDir;
        use tokio::sync::watch;

        let tmp = TempDir::new().expect("create temp dir");
        let watch_dir = tmp.path().to_str().unwrap().to_string();

        let config = FileCollectorConfig {
            enabled: true,
            watch_paths: vec![watch_dir.clone()],
            exclude_patterns: vec![],
        };
        let device = OcsfDevice {
            hostname: "test-host".into(),
            ip: "127.0.0.1".into(),
            os_name: "Linux".into(),
            os_version: "6.0".into(),
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let collector = FileCollector::new(&config, device);

        // Run collector in background.
        let handle = tokio::spawn(async move { collector.run(tx, shutdown_rx).await });

        // Give inotify a moment to initialise.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let test_file = tmp.path().join("test_fim.txt");

        // --- Create ---
        std::fs::write(&test_file, b"initial").expect("create file");

        let ev = tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for create event")
            .expect("channel closed");

        assert_eq!(ev.activity, "Create", "create event activity");
        assert_eq!(ev.activity_id, 1, "create activity_id must be 1");
        assert!(
            event_file_path(&ev).ends_with("test_fim.txt"),
            "path should end with test_fim.txt, got: {}",
            event_file_path(&ev)
        );

        // Wait past the rate-limit window (RATE_LIMIT_PER_FILE = 10ms).
        // The initial fs::write may generate IN_CREATE + IN_MODIFY in rapid succession;
        // we need the rate limit window to expire before triggering the next operation.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Drain any additional events (e.g. IN_MODIFY from the initial write).
        while let Ok(Some(_)) = tokio::time::timeout(
            tokio::time::Duration::from_millis(20),
            rx.recv(),
        )
        .await
        {}

        // --- Modify ---
        std::fs::write(&test_file, b"modified").expect("modify file");

        let ev = tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for modify event")
            .expect("channel closed");

        assert_eq!(ev.activity, "Modify", "modify event activity");
        assert_eq!(ev.activity_id, 4, "modify activity_id must be 4");

        // Wait past the rate-limit window before rename.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        while let Ok(Some(_)) = tokio::time::timeout(
            tokio::time::Duration::from_millis(20),
            rx.recv(),
        )
        .await
        {}

        // --- Rename (MOVED_FROM) ---
        let renamed = tmp.path().join("renamed_fim.txt");
        std::fs::rename(&test_file, &renamed).expect("rename file");

        // Expect a MOVED_FROM (Rename) event for the source path.
        let ev = tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for rename event")
            .expect("channel closed");

        assert_eq!(ev.activity, "Rename", "rename event activity");
        assert_eq!(ev.activity_id, 5, "rename activity_id must be 5");

        // Wait past the rate-limit window before delete, and drain the
        // MOVED_TO event (for the destination path) emitted by the rename.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        while let Ok(Some(_)) = tokio::time::timeout(
            tokio::time::Duration::from_millis(20),
            rx.recv(),
        )
        .await
        {}

        // --- Delete ---
        std::fs::remove_file(&renamed).expect("delete file");

        let ev = tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for delete event")
            .expect("channel closed");

        assert_eq!(ev.activity, "Delete", "delete event activity");
        assert_eq!(ev.activity_id, 2, "delete activity_id must be 2");

        // Shutdown the collector.
        shutdown_tx.send(true).expect("send shutdown");
        handle
            .await
            .expect("collector task panicked")
            .expect("collector error");
    }

    /// Verify that the collector watches newly created subdirectories
    /// and emits events for files created inside them.
    #[tokio::test]
    async fn integration_new_subdirectory_gets_watched() {
        use tempfile::TempDir;
        use tokio::sync::watch;

        let tmp = TempDir::new().expect("create temp dir");
        let watch_dir = tmp.path().to_str().unwrap().to_string();

        let config = FileCollectorConfig {
            enabled: true,
            watch_paths: vec![watch_dir.clone()],
            exclude_patterns: vec![],
        };
        let device = OcsfDevice {
            hostname: "test-host".into(),
            ip: "127.0.0.1".into(),
            os_name: "Linux".into(),
            os_version: "6.0".into(),
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let collector = FileCollector::new(&config, device);
        let handle = tokio::spawn(async move { collector.run(tx, shutdown_rx).await });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Create a subdirectory — no event emitted for the directory itself.
        let subdir = tmp.path().join("subdir");
        std::fs::create_dir(&subdir).expect("create subdir");

        // Give the collector time to register the new directory watch.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Create a file inside the newly-created subdirectory.
        let subfile = subdir.join("subfile.txt");
        std::fs::write(&subfile, b"hello").expect("create file in subdir");

        let ev = tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for subdir file event")
            .expect("channel closed");

        assert_eq!(ev.activity, "Create");
        assert_eq!(ev.activity_id, 1);
        assert!(
            event_file_path(&ev).ends_with("subfile.txt"),
            "path should end with subfile.txt, got: {}",
            event_file_path(&ev)
        );

        shutdown_tx.send(true).expect("send shutdown");
        handle
            .await
            .expect("collector task panicked")
            .expect("collector error");
    }

    /// Verify that the exclude pattern filters suppress events for matching files.
    #[tokio::test]
    async fn integration_excluded_files_produce_no_events() {
        use tempfile::TempDir;
        use tokio::sync::watch;

        let tmp = TempDir::new().expect("create temp dir");
        let watch_dir = tmp.path().to_str().unwrap().to_string();

        let config = FileCollectorConfig {
            enabled: true,
            watch_paths: vec![watch_dir.clone()],
            exclude_patterns: vec!["*.log".to_string()],
        };
        let device = OcsfDevice {
            hostname: "test-host".into(),
            ip: "127.0.0.1".into(),
            os_name: "Linux".into(),
            os_version: "6.0".into(),
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let collector = FileCollector::new(&config, device);
        let handle = tokio::spawn(async move { collector.run(tx, shutdown_rx).await });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Create an excluded file — should produce NO event.
        let log_file = tmp.path().join("app.log");
        std::fs::write(&log_file, b"log line").expect("create excluded file");

        // Create a non-excluded file — SHOULD produce an event.
        let txt_file = tmp.path().join("data.txt");
        std::fs::write(&txt_file, b"data").expect("create included file");

        // Wait for and check only the non-excluded event.
        let ev = tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for non-excluded event")
            .expect("channel closed");

        // The event must be for data.txt, not app.log.
        let path = event_file_path(&ev);
        assert!(
            path.ends_with("data.txt"),
            "Expected event for data.txt, got: {path}"
        );
        assert!(
            !path.ends_with("app.log"),
            "Excluded .log file should not produce events"
        );

        shutdown_tx.send(true).expect("send shutdown");
        handle
            .await
            .expect("collector task panicked")
            .expect("collector error");
    }
}
