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
