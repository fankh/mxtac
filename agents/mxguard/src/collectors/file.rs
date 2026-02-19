//! File modification collector using Linux inotify.
//!
//! Watches configured directories for create / modify / delete events
//! and emits OCSF File System Activity (class_uid 1001) events.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::collectors::Collector;
use crate::config::FileCollectorConfig;
use crate::events::ocsf::{
    FileActivityData, OcsfDevice, OcsfEvent, OcsfSeverity,
};

/// Collector that monitors file system changes via inotify.
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

    /// Check if a filename matches any of the exclude patterns (simple suffix match).
    fn is_excluded(&self, name: &str) -> bool {
        for pattern in &self.config.exclude_patterns {
            // Simple glob: "*.log" means ends with ".log"
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

    /// Determine OCSF severity based on path heuristics.
    fn classify_severity(&self, path: &str) -> OcsfSeverity {
        let suspicious = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/",
            "/usr/bin/",
            "/usr/sbin/",
        ];
        for prefix in &suspicious {
            if path.starts_with(prefix) {
                return OcsfSeverity::High;
            }
        }
        OcsfSeverity::Low
    }
}

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
        info!("File collector started, watching {:?}", self.config.watch_paths);

        let inotify = Inotify::init()?;

        // Map from watch descriptor to base directory path.
        let mut wd_map: HashMap<WatchDescriptor, PathBuf> = HashMap::new();

        let mask = WatchMask::CREATE | WatchMask::MODIFY | WatchMask::DELETE | WatchMask::MOVED_TO | WatchMask::MOVED_FROM;

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

        let _buffer = [0u8; 4096];

        loop {
            tokio::select! {
                result = tokio::task::spawn_blocking({
                    // We need to clone the inotify fd concept — but inotify is not
                    // Clone. Instead we rely on a short read timeout via the
                    // blocking thread approach. In production this would use
                    // `inotify.into_event_stream()` with tokio. For the skeleton
                    // we use a polling approach with spawn_blocking.
                    let fd = inotify.as_fd();
                    // Safety: We know inotify lives long enough.
                    let raw_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(std::os::fd::AsRawFd::as_raw_fd(&fd)) };
                    let _ = raw_fd; // Just to keep the borrow alive conceptually.

                    // In a real implementation we would use `inotify.into_event_stream()`.
                    // For the skeleton, we simply yield control briefly.
                    || -> Vec<(WatchDescriptor, EventMask, Option<OsString>)> {
                        // Placeholder: In production, read events from inotify fd.
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        Vec::new()
                    }
                }) => {
                    if let Ok(events) = result {
                        for (wd, mask, name) in events {
                            let base = match wd_map.get(&wd) {
                                Some(p) => p.clone(),
                                None => continue,
                            };

                            let file_name = match name {
                                Some(n) => n.to_string_lossy().to_string(),
                                None => continue,
                            };

                            if self.is_excluded(&file_name) {
                                continue;
                            }

                            let full_path = base.join(&file_name);
                            let path_str = full_path.to_string_lossy().to_string();

                            let action = if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
                                "Create"
                            } else if mask.contains(EventMask::MODIFY) {
                                "Update"
                            } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM) {
                                "Delete"
                            } else {
                                "Other"
                            };

                            let size = std::fs::metadata(&full_path).ok().map(|m| m.len());

                            let severity = self.classify_severity(&path_str);

                            let data = FileActivityData {
                                path: path_str,
                                action: action.into(),
                                size,
                                hash: None, // Hashing deferred to keep skeleton simple.
                            };

                            let event = OcsfEvent::file_activity(
                                self.device.clone(),
                                action,
                                match action {
                                    "Create" => 1,
                                    "Update" => 2,
                                    "Delete" => 3,
                                    _ => 99,
                                },
                                severity,
                                data,
                            );

                            if tx.send(event).await.is_err() {
                                debug!("Event channel closed, stopping file collector");
                                return Ok(());
                            }
                        }
                    }
                }
                _ = shutdown.changed() => {
                    info!("File collector shutting down");
                    return Ok(());
                }
            }
        }
    }
}

// Make `as_fd` available.
use std::os::fd::AsFd;
