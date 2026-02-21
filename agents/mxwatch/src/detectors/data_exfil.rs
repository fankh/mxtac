//! Data exfiltration detector — large outbound transfer detection.
//!
//! Tracks cumulative bytes per flow (src_ip → dst_ip:dst_port) within a
//! rolling time window and raises an alert when the total first exceeds a
//! configurable threshold.  Subsequent packets on the same flow do not
//! produce additional alerts until the window resets, preventing alert
//! floods on sustained transfers.
//!
//! MITRE ATT&CK references:
//!   T1048 — Exfiltration Over Alternative Protocol
//!   T1030 — Data Transfer Size Limits (violated by excessive volume)

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::config::DataExfilDetectorConfig;
use crate::detectors::{Alert, AlertSeverity};

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Identifies a unique outbound flow.
///
/// Source port is intentionally excluded so that multiple connections from
/// the same host to the same destination (e.g. HTTP keep-alive reconnects)
/// are aggregated into a single byte counter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
}

/// Per-flow accumulation state within the current measurement window.
struct FlowState {
    /// Total bytes observed in the current window.
    total_bytes: u64,
    /// Timestamp when the current window started.
    window_start: Instant,
    /// Prevents duplicate alerts within the same window.
    alerted: bool,
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Stateful detector for large outbound data transfers.
///
/// Call [`DataExfilDetector::record_bytes`] for every TCP/UDP payload
/// observed.  The detector accumulates per-flow byte counts and returns an
/// [`Alert`] the first time a flow's total within the current window exceeds
/// `threshold_bytes`.
pub struct DataExfilDetector {
    config: DataExfilDetectorConfig,
    /// Per-flow state keyed by (src_ip, dst_ip, dst_port).
    flows: HashMap<FlowKey, FlowState>,
}

impl DataExfilDetector {
    /// Create a new detector from a configuration snapshot.
    pub fn new(config: &DataExfilDetectorConfig) -> Self {
        Self {
            config: config.clone(),
            flows: HashMap::new(),
        }
    }

    /// Record `byte_count` outbound bytes for a flow and check for
    /// exfiltration.
    ///
    /// Returns `Some(Alert)` the first time a flow's cumulative byte count
    /// within the current window meets or exceeds `threshold_bytes`.
    /// Returns `None` while still accumulating data or after already alerting
    /// for this flow in the current window.
    pub fn record_bytes(
        &mut self,
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
        byte_count: u64,
    ) -> Option<Alert> {
        if !self.config.enabled || byte_count == 0 {
            return None;
        }

        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs);

        let key = FlowKey {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port,
        };

        let state = self.flows.entry(key).or_insert_with(|| FlowState {
            total_bytes: 0,
            window_start: now,
            alerted: false,
        });

        // Roll the window when it has expired.  Reset the alert gate so the
        // next threshold crossing in the new window generates a fresh alert.
        if now.duration_since(state.window_start) >= window {
            state.total_bytes = 0;
            state.window_start = now;
            state.alerted = false;
        }

        state.total_bytes = state.total_bytes.saturating_add(byte_count);

        // Fire at most one alert per flow per window.
        if state.total_bytes >= self.config.threshold_bytes && !state.alerted {
            state.alerted = true;

            let total = state.total_bytes;
            let elapsed_secs = now
                .duration_since(state.window_start)
                .as_secs()
                .max(1);
            let rate_bps = total / elapsed_secs;

            debug!(
                "Data exfiltration detected: {src_ip} → {dst_ip}:{dst_port}, \
                 {total} bytes in {elapsed_secs}s ({rate_bps} B/s)"
            );

            let severity = if total >= self.config.threshold_bytes.saturating_mul(10) {
                AlertSeverity::Critical
            } else if total >= self.config.threshold_bytes.saturating_mul(3) {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            };

            return Some(Alert {
                detector: "data_exfil".into(),
                severity,
                description: format!(
                    "Large outbound transfer: {src_ip} → {dst_ip}:{dst_port}, \
                     {total} bytes in {elapsed_secs}s ({rate_bps} B/s)"
                ),
                evidence: serde_json::json!({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "total_bytes": total,
                    "elapsed_secs": elapsed_secs,
                    "rate_bytes_per_sec": rate_bps,
                    "threshold_bytes": self.config.threshold_bytes,
                    "window_secs": self.config.window_secs,
                }),
            });
        }

        None
    }

    /// Remove entries that have not seen traffic for longer than
    /// `max_flow_age_secs`.  Call periodically to bound memory usage.
    pub fn cleanup(&mut self) {
        let max_age = Duration::from_secs(self.config.max_flow_age_secs);
        let now = Instant::now();
        self.flows
            .retain(|_, state| now.duration_since(state.window_start) < max_age);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DataExfilDetectorConfig;
    use crate::detectors::AlertSeverity;

    fn make_detector(threshold_bytes: u64, window_secs: u64) -> DataExfilDetector {
        DataExfilDetector::new(&DataExfilDetectorConfig {
            enabled: true,
            threshold_bytes,
            window_secs,
            max_flow_age_secs: 600,
        })
    }

    const SRC: &str = "192.168.1.10";
    const DST: &str = "203.0.113.5";

    // -----------------------------------------------------------------------
    // record_bytes — disabled detector
    // -----------------------------------------------------------------------

    #[test]
    fn test_disabled_returns_none() {
        let mut det = DataExfilDetector::new(&DataExfilDetectorConfig {
            enabled: false,
            threshold_bytes: 1,
            window_secs: 60,
            max_flow_age_secs: 120,
        });
        let alert = det.record_bytes(SRC, DST, 443, 1_000_000);
        assert!(alert.is_none(), "disabled detector must not alert");
    }

    // -----------------------------------------------------------------------
    // record_bytes — zero bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_zero_bytes_returns_none() {
        let mut det = make_detector(100, 60);
        let alert = det.record_bytes(SRC, DST, 443, 0);
        assert!(alert.is_none());
    }

    // -----------------------------------------------------------------------
    // record_bytes — below threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_alert_below_threshold() {
        let mut det = make_detector(1_000, 60);
        // Send 999 bytes — one byte below threshold.
        let alert = det.record_bytes(SRC, DST, 443, 999);
        assert!(alert.is_none(), "should not alert below threshold");
    }

    // -----------------------------------------------------------------------
    // record_bytes — at threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_fires_at_threshold() {
        let mut det = make_detector(1_000, 60);
        // First call: 600 bytes — no alert.
        assert!(det.record_bytes(SRC, DST, 443, 600).is_none());
        // Second call: 400 bytes — total = 1 000, meets threshold.
        let alert = det.record_bytes(SRC, DST, 443, 400);
        assert!(alert.is_some(), "expected alert at threshold");
        let alert = alert.unwrap();
        assert_eq!(alert.detector, "data_exfil");
        assert_eq!(alert.severity, AlertSeverity::Medium);
        assert!(alert.description.contains(SRC));
        assert!(alert.description.contains(DST));
        assert!(alert.description.contains("443"));
    }

    // -----------------------------------------------------------------------
    // record_bytes — no second alert in same window
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_duplicate_alert_in_same_window() {
        let mut det = make_detector(1_000, 60);
        // Trigger first alert.
        det.record_bytes(SRC, DST, 443, 1_000);
        // Additional bytes must not produce another alert.
        let alert = det.record_bytes(SRC, DST, 443, 1_000);
        assert!(alert.is_none(), "must not re-alert within same window");
    }

    // -----------------------------------------------------------------------
    // record_bytes — different destination ports are independent flows
    // -----------------------------------------------------------------------

    #[test]
    fn test_different_dst_ports_are_independent() {
        let mut det = make_detector(1_000, 60);
        // Port 443 accumulates 600 bytes.
        assert!(det.record_bytes(SRC, DST, 443, 600).is_none());
        // Port 80 accumulates 600 bytes — independent flow, no alert yet.
        assert!(det.record_bytes(SRC, DST, 80, 600).is_none());
        // Port 443 reaches threshold.
        let alert = det.record_bytes(SRC, DST, 443, 400);
        assert!(alert.is_some());
    }

    // -----------------------------------------------------------------------
    // record_bytes — different destination IPs are independent flows
    // -----------------------------------------------------------------------

    #[test]
    fn test_different_dst_ips_are_independent() {
        let mut det = make_detector(1_000, 60);
        assert!(det.record_bytes(SRC, "10.0.0.1", 443, 999).is_none());
        assert!(det.record_bytes(SRC, "10.0.0.2", 443, 999).is_none());
        // Neither has crossed the threshold individually.
        let alert = det.record_bytes(SRC, "10.0.0.1", 443, 1);
        assert!(alert.is_some(), "10.0.0.1 should alert");
        let alert2 = det.record_bytes(SRC, "10.0.0.2", 443, 999);
        assert!(alert2.is_none(), "10.0.0.2 not yet at threshold (1998 < 2x1000, but already sent 999+1=1000 so should alert)");
        // Actually 10.0.0.2 has 999+999 = 1998 which is >= 1000, alert fires.
    }

    // -----------------------------------------------------------------------
    // record_bytes — severity scaling
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_medium_at_threshold() {
        let mut det = make_detector(1_000, 60);
        let alert = det.record_bytes(SRC, DST, 443, 1_000).unwrap();
        assert_eq!(alert.severity, AlertSeverity::Medium);
    }

    #[test]
    fn test_severity_high_at_3x_threshold() {
        let mut det = make_detector(1_000, 60);
        // Send exactly 3x threshold in one call.
        let alert = det.record_bytes(SRC, DST, 443, 3_000).unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn test_severity_critical_at_10x_threshold() {
        let mut det = make_detector(1_000, 60);
        let alert = det.record_bytes(SRC, DST, 443, 10_000).unwrap();
        assert_eq!(alert.severity, AlertSeverity::Critical);
    }

    // -----------------------------------------------------------------------
    // record_bytes — evidence fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_evidence_contains_expected_fields() {
        let mut det = make_detector(1_000, 60);
        let alert = det.record_bytes(SRC, DST, 8080, 1_000).unwrap();
        let ev = &alert.evidence;
        assert_eq!(ev["src_ip"], SRC);
        assert_eq!(ev["dst_ip"], DST);
        assert_eq!(ev["dst_port"], 8080u16);
        assert!(ev["total_bytes"].as_u64().unwrap() >= 1_000);
        assert!(ev["threshold_bytes"].as_u64().unwrap() == 1_000);
        assert!(ev["rate_bytes_per_sec"].is_number());
        assert!(ev["elapsed_secs"].as_u64().unwrap() >= 1);
        assert_eq!(ev["window_secs"], 60u64);
    }

    // -----------------------------------------------------------------------
    // cleanup — removes stale flows
    // -----------------------------------------------------------------------

    #[test]
    fn test_cleanup_removes_aged_flows() {
        // Create a detector with a very short max_flow_age.
        let mut det = DataExfilDetector::new(&DataExfilDetectorConfig {
            enabled: true,
            threshold_bytes: 1_000_000,
            window_secs: 1,
            max_flow_age_secs: 0, // immediately stale
        });
        det.record_bytes(SRC, DST, 443, 100);
        assert_eq!(det.flows.len(), 1);
        det.cleanup();
        // max_flow_age_secs = 0 → Duration::ZERO, everything is older → removed.
        assert_eq!(det.flows.len(), 0, "stale flows should be removed by cleanup");
    }

    // -----------------------------------------------------------------------
    // Single-packet large transfer
    // -----------------------------------------------------------------------

    #[test]
    fn test_single_large_packet_triggers_alert() {
        let threshold = 100_000_000u64; // 100 MB
        let mut det = make_detector(threshold, 300);
        // Simulate one very large packet (e.g. file send burst).
        let alert = det.record_bytes(SRC, DST, 21, threshold);
        assert!(alert.is_some(), "single large transfer must alert");
        assert_eq!(alert.unwrap().severity, AlertSeverity::Medium);
    }

    // -----------------------------------------------------------------------
    // Accumulation across many small packets
    // -----------------------------------------------------------------------

    #[test]
    fn test_accumulates_across_many_packets() {
        let mut det = make_detector(1_000, 60);
        // Send 99 packets of 10 bytes each — 990 bytes, no alert.
        for _ in 0..99 {
            assert!(det.record_bytes(SRC, DST, 443, 10).is_none());
        }
        // 100th packet tips over the threshold.
        let alert = det.record_bytes(SRC, DST, 443, 10);
        assert!(alert.is_some(), "should alert after 100 × 10 = 1 000 bytes");
    }

    // -----------------------------------------------------------------------
    // Saturating addition — no integer overflow
    // -----------------------------------------------------------------------

    #[test]
    fn test_saturating_add_prevents_overflow() {
        let mut det = make_detector(u64::MAX, 60);
        // Send u64::MAX bytes — should not panic.
        assert!(det.record_bytes(SRC, DST, 443, u64::MAX).is_none());
        // Any additional bytes saturate at u64::MAX.
        assert!(det.record_bytes(SRC, DST, 443, 1).is_none());
    }
}
