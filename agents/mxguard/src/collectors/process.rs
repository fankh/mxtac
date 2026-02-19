//! Process creation collector.
//!
//! Periodically scans `/proc` to discover new processes and emits
//! OCSF Process Activity (class_uid 1007) events.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::ProcessCollectorConfig;
use crate::events::ocsf::{
    OcsfDevice, OcsfEvent, OcsfSeverity, ProcessActivityData,
};

/// Collector that monitors process creation via `/proc`.
pub struct ProcessCollector {
    config: ProcessCollectorConfig,
    device: OcsfDevice,
}

impl ProcessCollector {
    pub fn new(config: &ProcessCollectorConfig, device: OcsfDevice) -> Self {
        Self {
            config: config.clone(),
            device,
        }
    }
}

#[async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn run(
        &self,
        tx: mpsc::Sender<OcsfEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        info!("Process collector started (interval={}ms)", self.config.scan_interval_ms);
        let interval = Duration::from_millis(self.config.scan_interval_ms);
        let mut known_pids: HashSet<u32> = HashSet::new();

        // Seed with current process list so we only report *new* ones.
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Some(pid) = parse_pid(&entry.file_name().to_string_lossy()) {
                    known_pids.insert(pid);
                }
            }
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    info!("Process collector shutting down");
                    return Ok(());
                }
            }

            let entries = match fs::read_dir("/proc") {
                Ok(e) => e,
                Err(err) => {
                    warn!("Failed to read /proc: {err}");
                    continue;
                }
            };

            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                let pid = match parse_pid(&name_str) {
                    Some(p) => p,
                    None => continue,
                };

                if known_pids.contains(&pid) {
                    continue;
                }
                known_pids.insert(pid);

                // Read process metadata from /proc/<pid>/status and /proc/<pid>/cmdline.
                let proc_data = match read_process_info(pid) {
                    Some(d) => d,
                    None => continue,
                };

                let event = OcsfEvent::process_activity(
                    self.device.clone(),
                    "Launch",
                    1, // activity_id: Launch
                    OcsfSeverity::Informational,
                    proc_data,
                );

                if tx.send(event).await.is_err() {
                    debug!("Event channel closed, stopping process collector");
                    return Ok(());
                }
            }

            // Prune dead PIDs to keep memory bounded.
            known_pids.retain(|pid| Path::new(&format!("/proc/{pid}")).exists());
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_pid(s: &str) -> Option<u32> {
    s.parse::<u32>().ok()
}

/// Read basic process information from procfs.
fn read_process_info(pid: u32) -> Option<ProcessActivityData> {
    let status_path = format!("/proc/{pid}/status");
    let status_text = fs::read_to_string(&status_path).ok()?;

    let mut name = String::new();
    let mut ppid: u32 = 0;
    let mut uid: u32 = 0;

    for line in status_text.lines() {
        if let Some(val) = line.strip_prefix("Name:\t") {
            name = val.to_string();
        } else if let Some(val) = line.strip_prefix("PPid:\t") {
            ppid = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("Uid:\t") {
            // Format: real effective saved filesystem — take the first (real).
            uid = val.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }

    let cmdline_path = format!("/proc/{pid}/cmdline");
    let cmd_line = fs::read_to_string(&cmdline_path)
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string();

    // Resolve username best-effort (fallback to uid string).
    let user = uid.to_string();

    Some(ProcessActivityData {
        pid,
        ppid,
        name,
        cmd_line,
        uid,
        user,
    })
}
