//! Process creation collector.
//!
//! Periodically scans `/proc` to discover new processes and emits
//! OCSF Process Activity (class_uid 1007) events.
//!
//! ## Design
//!
//! The collector maintains a `HashSet<u32>` of known PIDs. On each scan
//! interval it reads `/proc` for new numeric directory entries. For each
//! newly seen PID it reads:
//!
//! - `/proc/{pid}/status`  — name, ppid, uid, gid
//! - `/proc/{pid}/cmdline` — full command-line arguments
//! - `/proc/{pid}/exe`     — resolved path to the executable (symlink)
//! - `/proc/{pid}/cwd`     — working directory (symlink)
//!
//! Username is resolved from `/etc/passwd` by UID; falls back to the
//! numeric UID string when the user is not found.
//!
//! Stale PIDs are pruned each cycle so the HashSet stays bounded.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::ProcessCollectorConfig;
use crate::events::ocsf::{OcsfDevice, OcsfEvent, OcsfSeverity, ProcessActivityData};

// ---------------------------------------------------------------------------
// Collector struct
// ---------------------------------------------------------------------------

/// Collector that monitors process creation via `/proc` polling.
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
        info!(
            "Process collector started (interval={}ms)",
            self.config.scan_interval_ms
        );
        let interval = Duration::from_millis(self.config.scan_interval_ms);
        let mut known_pids: HashSet<u32> = HashSet::new();

        // Seed the set with already-running PIDs so we only report *new* ones.
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
                let fname = entry.file_name();
                let pid = match parse_pid(&fname.to_string_lossy()) {
                    Some(p) => p,
                    None => continue,
                };

                if known_pids.contains(&pid) {
                    continue;
                }
                known_pids.insert(pid);

                // Read process metadata from procfs. The process may have exited
                // between discovery and reading — treat any failure as "skip".
                let proc_data = match read_process_info(pid) {
                    Some(d) => d,
                    None => continue,
                };

                let event = OcsfEvent::process_activity(
                    self.device.clone(),
                    "Launch",
                    1, // activity_id 1 = Launch
                    OcsfSeverity::Informational,
                    proc_data,
                );

                if tx.send(event).await.is_err() {
                    debug!("Event channel closed, stopping process collector");
                    return Ok(());
                }
            }

            // Prune PIDs whose /proc entry no longer exists to keep memory bounded.
            known_pids.retain(|pid| Path::new(&format!("/proc/{pid}")).exists());
        }
    }
}

// ---------------------------------------------------------------------------
// Procfs helpers (pub(crate) so unit tests can call them directly)
// ---------------------------------------------------------------------------

/// Parse a decimal PID from a `/proc` directory name.
/// Returns `None` for non-numeric names like "self", "net", "sys", etc.
pub(crate) fn parse_pid(s: &str) -> Option<u32> {
    s.parse::<u32>().ok()
}

/// Fields extracted from `/proc/{pid}/status`.
pub(crate) struct StatusFields {
    pub name: String,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Parse the key fields we need from the `/proc/{pid}/status` text.
///
/// The status file uses tab-separated `Key:\tvalue` lines. The UID and GID
/// lines contain four space-separated values (real, effective, saved, fs);
/// we take the first (real) UID/GID.
pub(crate) fn parse_status_fields(status_text: &str) -> StatusFields {
    let mut name = String::new();
    let mut ppid: u32 = 0;
    let mut uid: u32 = 0;
    let mut gid: u32 = 0;

    for line in status_text.lines() {
        if let Some(val) = line.strip_prefix("Name:\t") {
            name = val.to_string();
        } else if let Some(val) = line.strip_prefix("PPid:\t") {
            ppid = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("Uid:\t") {
            uid = val
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("Gid:\t") {
            gid = val
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }

    StatusFields {
        name,
        ppid,
        uid,
        gid,
    }
}

/// Resolve a UID to a username by scanning the provided `/etc/passwd` contents.
///
/// Accepts the file contents as a `&str` so callers (and tests) can pass
/// any string without touching the filesystem.
///
/// Returns `None` when no matching entry is found.
pub(crate) fn resolve_username_from_contents(uid: u32, passwd_contents: &str) -> Option<String> {
    for line in passwd_contents.lines() {
        // passwd format: username:password:uid:gid:gecos:home:shell
        let mut fields = line.splitn(7, ':');
        let username = fields.next()?;
        fields.next(); // password
        let file_uid: u32 = fields.next()?.parse().ok()?;
        if file_uid == uid {
            return Some(username.to_string());
        }
    }
    None
}

/// Resolve a UID to a username from `/etc/passwd`.
/// Falls back to `None` on any I/O error.
fn resolve_username(uid: u32) -> Option<String> {
    let contents = fs::read_to_string("/etc/passwd").ok()?;
    resolve_username_from_contents(uid, &contents)
}

/// Collect all available information about a process from procfs.
///
/// Returns `None` if the process has already exited (status file unreadable).
pub(crate) fn read_process_info(pid: u32) -> Option<ProcessActivityData> {
    // /proc/{pid}/status is the authoritative source for name/ppid/uid/gid.
    // If it's unreadable the process has likely already exited.
    let status_text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let fields = parse_status_fields(&status_text);

    // /proc/{pid}/cmdline — NUL-separated argument list.
    let cmd_line = fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string();

    // /proc/{pid}/exe — symlink to the executable on disk.
    let exe_path = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    // /proc/{pid}/cwd — symlink to the current working directory.
    let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    // Resolve UID → username; fall back to the numeric UID string.
    let user = resolve_username(fields.uid)
        .unwrap_or_else(|| fields.uid.to_string());

    Some(ProcessActivityData {
        pid,
        ppid: fields.ppid,
        name: fields.name,
        cmd_line,
        exe_path,
        cwd,
        uid: fields.uid,
        gid: fields.gid,
        user,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_pid
    // -----------------------------------------------------------------------

    #[test]
    fn parse_pid_accepts_valid_numbers() {
        assert_eq!(parse_pid("1"), Some(1));
        assert_eq!(parse_pid("1234"), Some(1234));
        assert_eq!(parse_pid("65535"), Some(65535));
        assert_eq!(parse_pid("4194304"), Some(4_194_304)); // typical max PID
    }

    #[test]
    fn parse_pid_rejects_non_numeric_entries() {
        assert_eq!(parse_pid("self"), None);
        assert_eq!(parse_pid("net"), None);
        assert_eq!(parse_pid("sys"), None);
        assert_eq!(parse_pid("tty"), None);
        assert_eq!(parse_pid(""), None);
    }

    #[test]
    fn parse_pid_rejects_negative_and_float() {
        assert_eq!(parse_pid("-1"), None);
        assert_eq!(parse_pid("1.5"), None);
    }

    // -----------------------------------------------------------------------
    // parse_status_fields
    // -----------------------------------------------------------------------

    const SAMPLE_STATUS: &str = "\
Name:\tbash
Umask:\t0022
State:\tS (sleeping)
Tgid:\t1234
Ngid:\t0
Pid:\t1234
PPid:\t1000
TracerPid:\t0
Uid:\t1001\t1001\t1001\t1001
Gid:\t1002\t1002\t1002\t1002
FDSize:\t256
";

    #[test]
    fn parse_status_extracts_all_fields() {
        let fields = parse_status_fields(SAMPLE_STATUS);
        assert_eq!(fields.name, "bash");
        assert_eq!(fields.ppid, 1000);
        assert_eq!(fields.uid, 1001);
        assert_eq!(fields.gid, 1002);
    }

    #[test]
    fn parse_status_handles_minimal_input() {
        let status = "Name:\tinit\nPPid:\t0\n";
        let fields = parse_status_fields(status);
        assert_eq!(fields.name, "init");
        assert_eq!(fields.ppid, 0);
        assert_eq!(fields.uid, 0); // defaults to 0
        assert_eq!(fields.gid, 0);
    }

    #[test]
    fn parse_status_handles_empty_input() {
        let fields = parse_status_fields("");
        assert_eq!(fields.name, "");
        assert_eq!(fields.ppid, 0);
        assert_eq!(fields.uid, 0);
        assert_eq!(fields.gid, 0);
    }

    #[test]
    fn parse_status_takes_real_uid_not_effective() {
        // Uid line: real effective saved fs
        let status = "Name:\tsu\nPPid:\t500\nUid:\t1000\t0\t0\t0\nGid:\t1000\t0\t0\t0\n";
        let fields = parse_status_fields(status);
        assert_eq!(fields.uid, 1000); // real uid, not 0 (effective)
        assert_eq!(fields.gid, 1000);
    }

    // -----------------------------------------------------------------------
    // resolve_username_from_contents
    // -----------------------------------------------------------------------

    const SAMPLE_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
service:x:1001:1001::/srv:/bin/sh
";

    #[test]
    fn resolve_username_finds_root() {
        assert_eq!(
            resolve_username_from_contents(0, SAMPLE_PASSWD).as_deref(),
            Some("root")
        );
    }

    #[test]
    fn resolve_username_finds_regular_user() {
        assert_eq!(
            resolve_username_from_contents(1000, SAMPLE_PASSWD).as_deref(),
            Some("ubuntu")
        );
    }

    #[test]
    fn resolve_username_finds_high_uid() {
        assert_eq!(
            resolve_username_from_contents(65534, SAMPLE_PASSWD).as_deref(),
            Some("nobody")
        );
    }

    #[test]
    fn resolve_username_returns_none_for_unknown_uid() {
        assert_eq!(resolve_username_from_contents(9999, SAMPLE_PASSWD), None);
    }

    #[test]
    fn resolve_username_returns_none_for_empty_passwd() {
        assert_eq!(resolve_username_from_contents(0, ""), None);
    }

    // -----------------------------------------------------------------------
    // read_process_info — live process tests
    // -----------------------------------------------------------------------

    #[test]
    fn read_process_info_succeeds_for_current_process() {
        let pid = std::process::id();
        let info = read_process_info(pid).expect("Should read own process info");

        assert_eq!(info.pid, pid);
        assert!(!info.name.is_empty(), "Process name must not be empty");
        // The process should have a valid exe path (test binary).
        assert!(
            info.exe_path.is_some(),
            "exe_path should be populated for our own process"
        );
        // cwd should also be readable.
        assert!(
            info.cwd.is_some(),
            "cwd should be populated for our own process"
        );
    }

    #[test]
    fn read_process_info_returns_none_for_nonexistent_pid() {
        // u32::MAX is astronomically unlikely to be a running PID.
        assert!(
            read_process_info(u32::MAX).is_none(),
            "Should return None for a PID that does not exist"
        );
    }

    #[test]
    fn read_process_info_uid_matches_current_user() {
        let pid = std::process::id();
        let info = read_process_info(pid).unwrap();
        // Our own UID in the event should match what the OS reports.
        let expected_uid = unsafe { libc::getuid() };
        assert_eq!(info.uid, expected_uid);
    }
}
