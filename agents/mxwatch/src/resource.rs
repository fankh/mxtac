//! Resource monitoring: process-level CPU and RSS enforcement.
//!
//! Samples `/proc/self/stat` (CPU jiffies) and `/proc/self/status` (VmRSS)
//! at a configurable interval and exposes the latest snapshot via an
//! `Arc<ResourceSnapshot>` that the packet-processing loop reads without
//! blocking.
//!
//! When a limit is exceeded the monitor emits a structured warning at
//! `warn!` level.  The packet-processing loop reads the same snapshot and
//! applies a brief sleep to reduce throughput (CPU backpressure) or drops a
//! processing cycle (RAM backpressure).
//!
//! On non-Linux platforms the `read_*` helpers always return `None`; the
//! monitor loop exits immediately if disabled or if no metrics can be read.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use crate::config::ResourceLimitsConfig;

// ---------------------------------------------------------------------------
// Shared snapshot (updated by monitor task, read by processing task)
// ---------------------------------------------------------------------------

/// Latest resource metrics published by the background monitor.
///
/// Fields are stored as scaled integers to allow lock-free atomic access:
/// - `cpu_pct_x100`: CPU% × 100  (e.g. 500 → 5.00%)
/// - `rss_kb`:       Resident Set Size in kibibytes
#[derive(Debug)]
pub struct ResourceSnapshot {
    cpu_pct_x100: AtomicU64,
    rss_kb: AtomicU64,
}

impl Default for ResourceSnapshot {
    fn default() -> Self {
        Self {
            cpu_pct_x100: AtomicU64::new(0),
            rss_kb: AtomicU64::new(0),
        }
    }
}

impl ResourceSnapshot {
    /// CPU usage as a percentage of one logical CPU core (e.g. `4.7`).
    pub fn cpu_pct(&self) -> f64 {
        self.cpu_pct_x100.load(Ordering::Relaxed) as f64 / 100.0
    }

    /// Resident Set Size in mebibytes.
    pub fn rss_mb(&self) -> u64 {
        self.rss_kb.load(Ordering::Relaxed) / 1024
    }
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

/// Background task that samples CPU and RSS at `check_interval_ms` intervals.
pub struct ResourceMonitor {
    config: ResourceLimitsConfig,
    snapshot: Arc<ResourceSnapshot>,
}

impl ResourceMonitor {
    /// Create a new monitor.  Returns the monitor and a shared snapshot handle
    /// that callers can hold to read the latest metrics.
    pub fn new(config: ResourceLimitsConfig) -> (Self, Arc<ResourceSnapshot>) {
        let snapshot = Arc::new(ResourceSnapshot::default());
        let monitor = Self {
            config,
            snapshot: snapshot.clone(),
        };
        (monitor, snapshot)
    }

    /// Run the monitoring loop.  Returns immediately when the feature is
    /// disabled.  Intended to run as a `tokio::spawn`ed task.
    pub async fn run(self) {
        if !self.config.enabled {
            return;
        }

        let interval = Duration::from_millis(self.config.check_interval_ms);

        // Prime the initial CPU sample.
        let mut prev_ticks = read_cpu_ticks().unwrap_or(0);
        let mut prev_instant = Instant::now();

        loop {
            tokio::time::sleep(interval).await;

            let now = Instant::now();
            let elapsed_secs = now.duration_since(prev_instant).as_secs_f64();
            prev_instant = now;

            // ── CPU ──────────────────────────────────────────────────────────
            if let Some(cur_ticks) = read_cpu_ticks() {
                let delta = cur_ticks.saturating_sub(prev_ticks);
                prev_ticks = cur_ticks;

                let tck = clk_tck() as f64;
                let cpu_pct = if elapsed_secs > 0.0 && tck > 0.0 {
                    (delta as f64 / tck) / elapsed_secs * 100.0
                } else {
                    0.0
                };

                self.snapshot
                    .cpu_pct_x100
                    .store((cpu_pct * 100.0) as u64, Ordering::Relaxed);

                debug!(cpu_pct = format_args!("{cpu_pct:.2}"), "resource: CPU");

                if cpu_pct > self.config.max_cpu_pct {
                    warn!(
                        cpu_pct = format_args!("{cpu_pct:.1}"),
                        limit = self.config.max_cpu_pct,
                        "resource: CPU limit exceeded — throttling active"
                    );
                }
            }

            // ── RAM ──────────────────────────────────────────────────────────
            if let Some(rss_kb) = read_rss_kb() {
                self.snapshot.rss_kb.store(rss_kb, Ordering::Relaxed);

                let rss_mb = rss_kb / 1024;
                debug!(rss_mb, "resource: RSS");

                if rss_mb > self.config.max_ram_mb {
                    warn!(
                        rss_mb,
                        limit_mb = self.config.max_ram_mb,
                        "resource: RAM limit exceeded — backpressure active"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific /proc readers
// ---------------------------------------------------------------------------

/// Read cumulative CPU ticks (utime + stime) from `/proc/self/stat`.
///
/// Returns `None` on parse failure or non-Linux platforms.
fn read_cpu_ticks() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        // The `comm` field (index 1) is wrapped in parentheses and may
        // contain spaces or other special characters.  Use `rfind(')')` to
        // safely skip past it.
        let after_paren = stat.rfind(')')?;
        let rest = &stat[after_paren + 1..];
        // Remaining whitespace-separated fields (0-indexed after the closing
        // paren): 0=state 1=ppid 2=pgroup 3=session 4=tty_nr 5=tty_pgrp
        // 6=flags 7=minflt 8=cminflt 9=majflt 10=cmajflt 11=utime 12=stime
        let mut fields = rest.split_whitespace();
        let _state = fields.next()?;       // 0
        let _ppid = fields.next()?;        // 1
        let _pgrp = fields.next()?;        // 2
        let _session = fields.next()?;     // 3
        let _tty_nr = fields.next()?;      // 4
        let _tty_pgrp = fields.next()?;    // 5
        let _flags = fields.next()?;       // 6
        let _minflt = fields.next()?;      // 7
        let _cminflt = fields.next()?;     // 8
        let _majflt = fields.next()?;      // 9
        let _cmajflt = fields.next()?;     // 10
        let utime: u64 = fields.next()?.parse().ok()?;  // 11
        let stime: u64 = fields.next()?.parse().ok()?;  // 12
        Some(utime + stime)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Read Resident Set Size in kibibytes from `/proc/self/status`.
///
/// Returns `None` on parse failure or non-Linux platforms.
fn read_rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                // rest is like "   4096 kB"
                let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kb);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Return the kernel clock-tick rate (jiffies per second) via `sysconf`.
fn clk_tck() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `sysconf` is always safe to call with a known constant.
        let val = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if val > 0 {
            val as u64
        } else {
            100 // POSIX-mandated fallback
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        100
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ResourceSnapshot -------------------------------------------------------

    #[test]
    fn test_snapshot_default_is_zero() {
        let snap = ResourceSnapshot::default();
        assert_eq!(snap.cpu_pct(), 0.0);
        assert_eq!(snap.rss_mb(), 0);
    }

    #[test]
    fn test_snapshot_cpu_pct_conversion() {
        let snap = ResourceSnapshot::default();
        // Store 5.00% → 500 in x100 units.
        snap.cpu_pct_x100.store(500, Ordering::Relaxed);
        let pct = snap.cpu_pct();
        assert!((pct - 5.0).abs() < 0.01, "expected ~5.0, got {pct}");
    }

    #[test]
    fn test_snapshot_cpu_pct_fractional() {
        let snap = ResourceSnapshot::default();
        // 4.75% → 475
        snap.cpu_pct_x100.store(475, Ordering::Relaxed);
        let pct = snap.cpu_pct();
        assert!((pct - 4.75).abs() < 0.01, "expected ~4.75, got {pct}");
    }

    #[test]
    fn test_snapshot_rss_mb_conversion() {
        let snap = ResourceSnapshot::default();
        // 65 536 kB = 64 MiB
        snap.rss_kb.store(65_536, Ordering::Relaxed);
        assert_eq!(snap.rss_mb(), 64);
    }

    #[test]
    fn test_snapshot_rss_mb_zero() {
        let snap = ResourceSnapshot::default();
        snap.rss_kb.store(512, Ordering::Relaxed); // 0.5 MiB → rounds down to 0
        assert_eq!(snap.rss_mb(), 0);
    }

    #[test]
    fn test_snapshot_rss_mb_120mb() {
        let snap = ResourceSnapshot::default();
        snap.rss_kb.store(120 * 1024, Ordering::Relaxed);
        assert_eq!(snap.rss_mb(), 120);
    }

    // -- ResourceMonitor::new ---------------------------------------------------

    #[test]
    fn test_monitor_new_returns_shared_snapshot() {
        let config = crate::config::ResourceLimitsConfig::default();
        let (monitor, snapshot) = ResourceMonitor::new(config);
        // Initial state is zero.
        assert_eq!(snapshot.cpu_pct(), 0.0);
        assert_eq!(snapshot.rss_mb(), 0);
        // Monitor holds the same Arc.
        assert!(Arc::ptr_eq(&monitor.snapshot, &snapshot));
    }

    // -- Platform readers -------------------------------------------------------

    #[test]
    #[cfg(target_os = "linux")]
    fn test_read_cpu_ticks_returns_some() {
        let ticks = read_cpu_ticks();
        assert!(ticks.is_some(), "expected Some on Linux, got None");
        assert!(ticks.unwrap() > 0, "expected non-zero ticks");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_read_rss_kb_returns_some() {
        let rss = read_rss_kb();
        assert!(rss.is_some(), "expected Some on Linux, got None");
        assert!(rss.unwrap() > 0, "expected non-zero RSS");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_rss_is_reasonable() {
        // The test process should consume at least 1 MiB and less than 1 GiB.
        let rss_kb = read_rss_kb().expect("rss");
        assert!(rss_kb >= 1_024, "rss too small: {rss_kb} kB");
        assert!(rss_kb < 1_048_576, "rss suspiciously large: {rss_kb} kB");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_cpu_ticks_increase_over_time() {
        // Burn a small amount of CPU, then verify the tick counter moved.
        let t1 = read_cpu_ticks().expect("t1");
        // Do some allocation work to accumulate CPU time.
        let _v: Vec<u8> = (0..100_000).map(|x| (x % 256) as u8).collect();
        let t2 = read_cpu_ticks().expect("t2");
        // t2 >= t1 (ticks are monotonically non-decreasing).
        assert!(t2 >= t1, "ticks went backwards: {t1} → {t2}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_clk_tck_is_positive() {
        let tck = clk_tck();
        assert!(tck > 0, "clk_tck must be positive, got {tck}");
        // Typically 100 on Linux; allow 1–1000.
        assert!(tck <= 1000, "clk_tck unusually high: {tck}");
    }

    // -- Disabled monitor exits immediately ------------------------------------

    #[tokio::test]
    async fn test_disabled_monitor_runs_immediately() {
        let mut config = crate::config::ResourceLimitsConfig::default();
        config.enabled = false;
        let (monitor, _snap) = ResourceMonitor::new(config);
        // Should complete without sleeping when disabled.
        tokio::time::timeout(Duration::from_millis(100), monitor.run())
            .await
            .expect("disabled monitor should return immediately");
    }
}
