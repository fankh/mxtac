//! Port scan detector.
//!
//! Identifies hosts performing port scans by tracking distinct destination
//! ports per source IP within a sliding time window.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use tracing::debug;

use crate::config::PortScanDetectorConfig;
use crate::detectors::{Alert, AlertSeverity};

/// Per-source tracking data.
struct SourceState {
    /// Set of distinct destination ports observed.
    ports: HashSet<u16>,
    /// Timestamp of the first packet in the current window.
    window_start: Instant,
}

/// Stateful port scan detector.
pub struct PortScanDetector {
    config: PortScanDetectorConfig,
    /// Keyed by source IP address string.
    sources: HashMap<String, SourceState>,
}

impl PortScanDetector {
    pub fn new(config: &PortScanDetectorConfig) -> Self {
        Self {
            config: config.clone(),
            sources: HashMap::new(),
        }
    }

    /// Record a connection attempt and check for port scan behaviour.
    ///
    /// `src_ip` and `dst_port` describe the connection. If the source has
    /// contacted more distinct ports than the configured threshold within
    /// the window, an alert is returned.
    pub fn record(&mut self, src_ip: &str, dst_port: u16) -> Option<Alert> {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs);

        let state = self.sources.entry(src_ip.to_string()).or_insert_with(|| SourceState {
            ports: HashSet::new(),
            window_start: now,
        });

        // Reset the window if it has expired.
        if now.duration_since(state.window_start) > window {
            state.ports.clear();
            state.window_start = now;
        }

        state.ports.insert(dst_port);

        if state.ports.len() >= self.config.threshold_ports {
            let port_count = state.ports.len();
            debug!(
                "Port scan detected from {src_ip}: {port_count} distinct ports in {}s",
                self.config.window_secs
            );
            // Reset to avoid repeated alerts for the same burst.
            state.ports.clear();
            state.window_start = now;

            return Some(Alert {
                detector: "port_scan".into(),
                severity: AlertSeverity::High,
                description: format!(
                    "Port scan from {src_ip}: {port_count} distinct ports in {}s window",
                    self.config.window_secs
                ),
                evidence: serde_json::json!({
                    "src_ip": src_ip,
                    "distinct_ports": port_count,
                    "window_secs": self.config.window_secs,
                }),
            });
        }

        None
    }

    /// Periodic cleanup of stale entries.
    pub fn cleanup(&mut self) {
        let window = Duration::from_secs(self.config.window_secs * 2);
        let now = Instant::now();
        self.sources
            .retain(|_, state| now.duration_since(state.window_start) < window);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PortScanDetectorConfig;
    use crate::detectors::AlertSeverity;

    fn make_detector(threshold_ports: usize, window_secs: u64) -> PortScanDetector {
        PortScanDetector::new(&PortScanDetectorConfig {
            enabled: true,
            threshold_ports,
            window_secs,
        })
    }

    // -----------------------------------------------------------------------
    // record — below threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_alert_below_threshold() {
        let mut det = make_detector(5, 60);
        // Record 4 distinct ports — one below the threshold.
        for port in 80..84 {
            let alert = det.record("192.168.1.1", port);
            assert!(alert.is_none(), "unexpected alert at port {port}");
        }
    }

    // -----------------------------------------------------------------------
    // record — at threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_fires_at_threshold() {
        let mut det = make_detector(3, 60);
        // First 2 ports: no alert.
        assert!(det.record("10.0.0.1", 80).is_none());
        assert!(det.record("10.0.0.1", 443).is_none());
        // 3rd distinct port crosses the threshold.
        let alert = det.record("10.0.0.1", 8080);
        assert!(alert.is_some(), "expected alert at threshold");
        let alert = alert.unwrap();
        assert_eq!(alert.detector, "port_scan");
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.description.contains("10.0.0.1"));
    }

    // -----------------------------------------------------------------------
    // record — counter resets after alert
    // -----------------------------------------------------------------------

    #[test]
    fn test_counter_resets_after_alert() {
        let mut det = make_detector(3, 60);
        // Trigger an alert.
        det.record("10.0.0.2", 1);
        det.record("10.0.0.2", 2);
        let _ = det.record("10.0.0.2", 3); // alert fires, counter resets

        // After reset, 2 more ports should NOT trigger another alert.
        assert!(det.record("10.0.0.2", 4).is_none());
        assert!(det.record("10.0.0.2", 5).is_none());
    }

    // -----------------------------------------------------------------------
    // record — different source IPs are independent
    // -----------------------------------------------------------------------

    #[test]
    fn test_different_sources_are_independent() {
        let mut det = make_detector(3, 60);
        // Each IP contacts 2 ports — below threshold individually.
        det.record("10.0.0.1", 80);
        det.record("10.0.0.1", 443);
        det.record("10.0.0.2", 80);
        det.record("10.0.0.2", 443);

        // Neither source should have triggered an alert yet.
        // A 3rd port on one source should trigger only for that source.
        let alert = det.record("10.0.0.1", 8080);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert!(alert.description.contains("10.0.0.1"));
    }

    // -----------------------------------------------------------------------
    // record — duplicate ports don't inflate count
    // -----------------------------------------------------------------------

    #[test]
    fn test_duplicate_ports_not_counted_twice() {
        let mut det = make_detector(3, 60);
        // Record same port multiple times.
        for _ in 0..10 {
            assert!(det.record("10.0.0.3", 80).is_none());
        }
        // Only 1 distinct port — should not trigger.
        assert!(det.record("10.0.0.3", 443).is_none()); // 2 distinct
        // Still below threshold of 3.
        let alert = det.record("10.0.0.3", 8080); // 3rd distinct → alert
        assert!(alert.is_some());
    }
}
