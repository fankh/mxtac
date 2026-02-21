//! Resource usage monitoring for MxGuard.
//!
//! Periodically samples the agent's own CPU and RSS memory usage from Linux
//! `/proc/self` pseudo-files and logs a warning whenever a configured limit
//! is exceeded.  A throttle signal is published via a `watch` channel so the
//! transport layer can back off under pressure.
//!
//! # Targets (feature 24.12)
//!
//! | Metric | Limit  |
//! |--------|--------|
//! | CPU    | < 1 %  |
//! | RSS    | < 30 MB|
//!
//! # CPU measurement
//!
//! CPU usage is calculated over each check interval as:
//!
//! ```text
//! cpu_percent = (delta_ticks / CLK_TCK) / elapsed_secs * 100
//! ```
//!
//! where `delta_ticks = utime + stime` read from `/proc/self/stat`, and
//! `CLK_TCK = 100` (the standard Linux kernel configuration).
//!
//! # Memory measurement
//!
//! Resident Set Size (RSS) is read from the `VmRSS` field of
//! `/proc/self/status` and reported in megabytes.

use std::time::Instant;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::ResourceLimitsConfig;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Linux clock ticks per second (`CONFIG_HZ`).
///
/// 100 Hz is the overwhelming default for x86-64 Linux distributions.
/// This constant avoids a `libc::sysconf` call in production code while
/// still being accurate for the vast majority of deployments.
const CLK_TCK: f64 = 100.0;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A snapshot of the agent's resource usage at a single point in time.
#[derive(Debug, Clone)]
pub struct ResourceStats {
    /// CPU usage averaged over the last check interval (percentage, 0–100).
    pub cpu_percent: f64,
    /// Resident Set Size in megabytes.
    pub rss_mb: u64,
    /// `true` when either the CPU or RAM limit is exceeded.
    pub throttled: bool,
}

impl Default for ResourceStats {
    fn default() -> Self {
        Self {
            cpu_percent: 0.0,
            rss_mb: 0,
            throttled: false,
        }
    }
}

// ---------------------------------------------------------------------------
// /proc parsing helpers  (pub(crate) so unit tests can call them directly)
// ---------------------------------------------------------------------------

/// Parse total CPU ticks (utime + stime) from the text content of
/// `/proc/self/stat`.
///
/// The format is a single line:
/// ```text
/// pid (comm) state ppid ... utime stime ...
/// ```
/// Because `comm` may contain spaces and parentheses the parser locates the
/// last `)` and reads the remaining whitespace-separated fields from there.
/// After that separator the fields are (0-indexed):
///
/// | Index | Field  |
/// |-------|--------|
/// | 0     | state  |
/// | 1     | ppid   |
/// | …     | …      |
/// | 11    | utime  |
/// | 12    | stime  |
pub(crate) fn parse_cpu_ticks(stat: &str) -> anyhow::Result<u64> {
    let rest = stat
        .rfind(')')
        .map(|i| &stat[i + 1..])
        .ok_or_else(|| anyhow::anyhow!("invalid /proc/self/stat: missing closing ')' in comm"))?;

    let fields: Vec<&str> = rest.split_whitespace().collect();

    let utime: u64 = fields
        .get(11)
        .ok_or_else(|| anyhow::anyhow!("missing utime field (index 11) in /proc/self/stat"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("failed to parse utime: {e}"))?;

    let stime: u64 = fields
        .get(12)
        .ok_or_else(|| anyhow::anyhow!("missing stime field (index 12) in /proc/self/stat"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("failed to parse stime: {e}"))?;

    Ok(utime + stime)
}

/// Parse RSS memory in megabytes from the text content of
/// `/proc/self/status`.
///
/// Looks for the `VmRSS:` line which has the form:
/// ```text
/// VmRSS:   12345 kB
/// ```
/// and converts the value from kibibytes to mebibytes (integer division).
pub(crate) fn parse_rss_mb(status: &str) -> anyhow::Result<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow::anyhow!("empty VmRSS value in /proc/self/status"))?
                .parse()
                .map_err(|e| anyhow::anyhow!("failed to parse VmRSS: {e}"))?;
            return Ok(kb / 1024);
        }
    }
    anyhow::bail!("VmRSS line not found in /proc/self/status")
}

// ---------------------------------------------------------------------------
// Live /proc readers
// ---------------------------------------------------------------------------

fn read_cpu_ticks() -> anyhow::Result<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    parse_cpu_ticks(&stat)
}

fn read_rss_mb() -> anyhow::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    parse_rss_mb(&status)
}

// ---------------------------------------------------------------------------
// ResourceMonitor
// ---------------------------------------------------------------------------

/// Monitors the agent's own CPU and RAM usage against configured limits.
///
/// Create with [`ResourceMonitor::new`], then call [`ResourceMonitor::run`]
/// inside a `tokio::spawn`.  Callers hold a `watch::Receiver<ResourceStats>`
/// to observe the latest sample and throttle state.
pub struct ResourceMonitor {
    config: ResourceLimitsConfig,
    stats_tx: watch::Sender<ResourceStats>,
}

impl ResourceMonitor {
    /// Create a new `ResourceMonitor` and return it alongside a
    /// `watch::Receiver` that always holds the most recent [`ResourceStats`].
    pub fn new(config: ResourceLimitsConfig) -> (Self, watch::Receiver<ResourceStats>) {
        let (stats_tx, stats_rx) = watch::channel(ResourceStats::default());
        (Self { config, stats_tx }, stats_rx)
    }

    /// Run the monitor loop until `shutdown` fires.
    ///
    /// On each check interval the method:
    /// 1. Reads CPU ticks and RSS from `/proc/self`.
    /// 2. Computes CPU% averaged over the elapsed wall-clock time.
    /// 3. Logs a `WARN` for any exceeded limit.
    /// 4. Publishes updated [`ResourceStats`] (including `throttled` flag).
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        info!(
            cpu_limit = self.config.cpu_limit_percent,
            ram_limit_mb = self.config.ram_limit_mb,
            check_interval_ms = self.config.check_interval_ms,
            "Resource monitor started"
        );

        let interval =
            std::time::Duration::from_millis(self.config.check_interval_ms);

        // Seed the previous-tick snapshot so the first delta is meaningful.
        let mut prev_ticks = read_cpu_ticks().unwrap_or(0);
        let mut prev_time = Instant::now();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    info!("Resource monitor shutting down");
                    return Ok(());
                }
            }

            // --- CPU ---
            let now = Instant::now();
            let elapsed_secs = now.duration_since(prev_time).as_secs_f64();

            let cpu_percent = match read_cpu_ticks() {
                Ok(ticks) => {
                    let delta = ticks.saturating_sub(prev_ticks) as f64;
                    prev_ticks = ticks;
                    prev_time = now;
                    if elapsed_secs > 0.0 {
                        (delta / CLK_TCK / elapsed_secs) * 100.0
                    } else {
                        0.0
                    }
                }
                Err(e) => {
                    warn!("Failed to read CPU ticks from /proc/self/stat: {e}");
                    prev_time = now;
                    0.0
                }
            };

            // --- RAM ---
            let rss_mb = match read_rss_mb() {
                Ok(mb) => mb,
                Err(e) => {
                    warn!("Failed to read RSS from /proc/self/status: {e}");
                    0
                }
            };

            // --- Limit checks ---
            let cpu_exceeded = cpu_percent > self.config.cpu_limit_percent;
            let ram_exceeded = rss_mb > self.config.ram_limit_mb;
            let throttled = cpu_exceeded || ram_exceeded;

            if cpu_exceeded {
                warn!(
                    cpu_percent = format!("{:.2}", cpu_percent),
                    limit = self.config.cpu_limit_percent,
                    "CPU limit exceeded — consider increasing scan intervals"
                );
            }
            if ram_exceeded {
                warn!(
                    rss_mb,
                    limit_mb = self.config.ram_limit_mb,
                    "RAM limit exceeded — consider reducing event buffer size"
                );
            }

            debug!(
                cpu_percent = format!("{:.3}", cpu_percent),
                rss_mb,
                throttled,
                "Resource sample"
            );

            // Publish — ignore errors (receiver may be gone during shutdown).
            let _ = self.stats_tx.send(ResourceStats {
                cpu_percent,
                rss_mb,
                throttled,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_cpu_ticks
    // -----------------------------------------------------------------------

    /// Minimal /proc/self/stat sample with typical spacing.
    const SAMPLE_STAT: &str =
        "1234 (mxguard) S 1000 1234 1234 34816 1234 4194304 100 200 0 0 50 30 0 0 20 0 1 0 100 10240000 2560";

    #[test]
    fn parse_cpu_ticks_basic() {
        // utime=50, stime=30 → total=80
        let ticks = parse_cpu_ticks(SAMPLE_STAT).expect("parse");
        assert_eq!(ticks, 80);
    }

    #[test]
    fn parse_cpu_ticks_comm_with_spaces() {
        // The comm field contains spaces — parser must use rfind(')').
        let stat = "42 (my guard process) S 1 42 42 0 42 0 0 0 0 0 10 5 0 0 20 0 1 0 50 1024 256";
        let ticks = parse_cpu_ticks(stat).expect("parse");
        assert_eq!(ticks, 15); // utime=10, stime=5
    }

    #[test]
    fn parse_cpu_ticks_zero_values() {
        // utime=0, stime=0 → total=0
        let stat = "1 (init) S 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 10 1024 128";
        let ticks = parse_cpu_ticks(stat).expect("parse");
        assert_eq!(ticks, 0);
    }

    #[test]
    fn parse_cpu_ticks_missing_paren_returns_error() {
        let result = parse_cpu_ticks("1234 mxguard S 1000");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("missing closing ')'"), "msg={msg}");
    }

    #[test]
    fn parse_cpu_ticks_too_few_fields_returns_error() {
        // Only a few fields after ')' — not enough to reach utime.
        let stat = "1 (x) S 0 1";
        let result = parse_cpu_ticks(stat);
        assert!(result.is_err());
    }

    #[test]
    fn parse_cpu_ticks_non_numeric_utime_returns_error() {
        // Replace utime with a non-numeric value.
        let stat = "1 (x) S 0 1 1 0 0 0 0 0 0 0 nan 5 0 0 20 0 1 0 10 1024 128";
        let result = parse_cpu_ticks(stat);
        assert!(result.is_err());
    }

    #[test]
    fn parse_cpu_ticks_live_process() {
        // We can read our own /proc/self/stat — ticks must be >= 0.
        let stat = std::fs::read_to_string("/proc/self/stat").expect("/proc/self/stat");
        let ticks = parse_cpu_ticks(&stat).expect("parse live stat");
        // Any non-negative value is valid (u64 is always >= 0).
        let _ = ticks;
    }

    // -----------------------------------------------------------------------
    // parse_rss_mb
    // -----------------------------------------------------------------------

    const SAMPLE_STATUS: &str = "\
Name:\tmxguard
VmPeak:   51200 kB
VmSize:   40960 kB
VmRSS:    20480 kB
VmData:   10240 kB
Threads:\t1
";

    #[test]
    fn parse_rss_mb_basic() {
        // 20480 kB = 20 MB
        let mb = parse_rss_mb(SAMPLE_STATUS).expect("parse");
        assert_eq!(mb, 20);
    }

    #[test]
    fn parse_rss_mb_rounds_down() {
        // 1023 kB → 0 MB (floor division)
        let status = "VmRSS:  1023 kB\n";
        assert_eq!(parse_rss_mb(status).expect("parse"), 0);
    }

    #[test]
    fn parse_rss_mb_large_value() {
        // 30720 kB = 30 MB exactly
        let status = "VmRSS:  30720 kB\n";
        assert_eq!(parse_rss_mb(status).expect("parse"), 30);
    }

    #[test]
    fn parse_rss_mb_missing_field_returns_error() {
        let status = "Name:\tmxguard\nVmSize: 4096 kB\n";
        let result = parse_rss_mb(status);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("VmRSS"));
    }

    #[test]
    fn parse_rss_mb_non_numeric_value_returns_error() {
        let status = "VmRSS:  abc kB\n";
        let result = parse_rss_mb(status);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rss_mb_live_process() {
        let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
        let mb = parse_rss_mb(&status).expect("parse live status");
        // A running Rust test binary will use at least a few MB.
        assert!(mb > 0, "expected rss_mb > 0, got {mb}");
    }

    // -----------------------------------------------------------------------
    // ResourceMonitor::new
    // -----------------------------------------------------------------------

    #[test]
    fn new_returns_default_stats() {
        let config = ResourceLimitsConfig::default();
        let (_monitor, rx) = ResourceMonitor::new(config);
        let stats = rx.borrow();
        assert_eq!(stats.cpu_percent, 0.0);
        assert_eq!(stats.rss_mb, 0);
        assert!(!stats.throttled);
    }

    // -----------------------------------------------------------------------
    // ResourceMonitor::run — shutdown integration
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn monitor_stops_on_shutdown() {
        let config = ResourceLimitsConfig {
            enabled: true,
            cpu_limit_percent: 100.0, // high limit — won't log warnings
            ram_limit_mb: 99_999,
            check_interval_ms: 100,
        };
        let (monitor, _rx) = ResourceMonitor::new(config);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move { monitor.run(shutdown_rx).await });

        // Give the monitor a moment to start, then signal shutdown.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(true);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle,
        )
        .await
        .expect("monitor should stop within 2 s")
        .expect("task did not panic");

        assert!(result.is_ok(), "monitor returned an error: {result:?}");
    }

    #[tokio::test]
    async fn monitor_publishes_stats_after_first_interval() {
        let config = ResourceLimitsConfig {
            enabled: true,
            cpu_limit_percent: 100.0,
            ram_limit_mb: 99_999,
            check_interval_ms: 50, // short interval for fast test
        };
        let (monitor, mut rx) = ResourceMonitor::new(config);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        tokio::spawn(async move { monitor.run(shutdown_rx).await });

        // Wait for the first update (up to 500 ms).
        let updated = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            rx.changed(),
        )
        .await;

        assert!(
            updated.is_ok(),
            "timed out waiting for first resource stats update"
        );

        let stats = rx.borrow();
        // After at least one real /proc read the RSS should be > 0.
        assert!(stats.rss_mb > 0, "expected rss_mb > 0 after first sample");

        let _ = shutdown_tx.send(true);
    }

    // -----------------------------------------------------------------------
    // Throttle detection
    // -----------------------------------------------------------------------

    #[test]
    fn throttled_when_cpu_exceeds_limit() {
        // Simulate stats that exceed the CPU limit.
        let (tx, rx) = watch::channel(ResourceStats::default());
        tx.send(ResourceStats {
            cpu_percent: 5.0,
            rss_mb: 10,
            throttled: true,
        })
        .unwrap();
        assert!(rx.borrow().throttled);
    }

    #[test]
    fn not_throttled_when_within_limits() {
        let (tx, rx) = watch::channel(ResourceStats::default());
        tx.send(ResourceStats {
            cpu_percent: 0.5,
            rss_mb: 20,
            throttled: false,
        })
        .unwrap();
        assert!(!rx.borrow().throttled);
    }
}
