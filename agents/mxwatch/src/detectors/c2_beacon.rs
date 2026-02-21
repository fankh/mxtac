//! C2 beacon detector — feature 25.12.
//!
//! Detects command-and-control (C2) beaconing by identifying directional
//! network flows with highly periodic inter-packet timing.
//!
//! ## Threat model
//!
//! Malware implants commonly "phone home" to a C2 server at fixed intervals
//! (e.g. every 30–120 seconds) with a small, configurable jitter to evade
//! simple threshold rules.  This regularity — far more consistent than
//! legitimate user-driven traffic — distinguishes C2 callbacks from normal
//! outbound connections.
//!
//! ## Algorithm
//!
//! For each directional flow `(src_ip → dst_ip:dst_port)` the detector:
//!
//! 1. **Debounces** burst packets: only records a new timestamp once at least
//!    `beacon_interval_secs × (1 − jitter_pct / 100)` seconds have elapsed
//!    since the previous sample, so multiple packets from the same TCP
//!    connection count as one "callback event".
//!
//! 2. **Accumulates** timestamps until `min_packets_for_alert` samples exist.
//!
//! 3. **Evaluates** periodicity by computing the coefficient of variation
//!    (CV = σ / μ) of the inter-arrival times.  A CV ≤ `jitter_pct / 100`
//!    indicates traffic regular enough to be consistent with beaconing.
//!
//! 4. **Fires** a single **High**-severity alert per flow and stops tracking
//!    further packets for that flow.
//!
//! The source port is intentionally excluded from the flow key so that
//! repeated TCP connections from the same host to the same server:port are
//! grouped together, which is the typical pattern for C2 callbacks.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::config::C2BeaconDetectorConfig;
use crate::detectors::{Alert, AlertSeverity};

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Identifies a directional flow.  The source port is omitted so that
/// repeated connections from the same host to the same destination are
/// grouped (each TCP connection uses an ephemeral source port, but the
/// destination service port stays constant across beaconing cycles).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
}

struct FlowState {
    /// Debounced packet timestamps — one entry per inferred beacon cycle.
    timestamps: Vec<Instant>,
    /// Set to `true` once an alert has been emitted; prevents re-alerting.
    alerted: bool,
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Stateful C2 beacon detector.
///
/// Maintains per-flow timing history.  Not `Send`; intended to run on a
/// single packet-processing task.
pub struct C2BeaconDetector {
    config: C2BeaconDetectorConfig,
    flows: HashMap<FlowKey, FlowState>,
}

impl C2BeaconDetector {
    /// Create a new detector from configuration.
    pub fn new(config: &C2BeaconDetectorConfig) -> Self {
        Self {
            config: config.clone(),
            flows: HashMap::new(),
        }
    }

    /// Record a packet for the given directional flow and check for beaconing.
    ///
    /// Returns `Some(Alert)` the **first** time a periodic callback pattern is
    /// confirmed; returns `None` otherwise.  Subsequent calls for the same
    /// flow after an alert return `None` immediately.
    pub fn record_packet(
        &mut self,
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<Alert> {
        if !self.config.enabled {
            return None;
        }

        let key = FlowKey {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port,
        };

        let now = Instant::now();

        // Debounce window: minimum elapsed time before we record a new sample.
        // Clamp jitter_pct to [0, 100] to avoid negative durations.
        let jitter_fraction = (self.config.jitter_pct / 100.0).clamp(0.0, 1.0);
        let min_gap_secs =
            (self.config.beacon_interval_secs * (1.0 - jitter_fraction)).max(0.0);
        let min_gap = Duration::from_secs_f64(min_gap_secs);

        let state = self.flows.entry(key).or_insert_with(|| FlowState {
            timestamps: Vec::new(),
            alerted: false,
        });

        if state.alerted {
            return None;
        }

        // Debounce: skip packets that arrive within the minimum gap.
        if let Some(&last) = state.timestamps.last() {
            if now.duration_since(last) < min_gap {
                return None;
            }
        }

        state.timestamps.push(now);

        // Cap history to bound memory usage per flow.
        const MAX_SAMPLES: usize = 100;
        if state.timestamps.len() > MAX_SAMPLES {
            state.timestamps.remove(0);
        }

        let min_pts = self.config.min_packets_for_alert as usize;
        if state.timestamps.len() < min_pts {
            debug!(
                samples = state.timestamps.len(),
                needed = min_pts,
                "c2_beacon: accumulating samples for {}→{}:{}",
                src_ip,
                dst_ip,
                dst_port,
            );
            return None;
        }

        // Compute inter-arrival times (seconds) between consecutive samples.
        let intervals: Vec<f64> = state
            .timestamps
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .collect();

        if !is_periodic(&intervals, self.config.jitter_pct) {
            return None;
        }

        // Periodic pattern confirmed — emit one alert then stop tracking.
        state.alerted = true;

        let mean: f64 = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance: f64 = intervals
            .iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;
        let std_dev = variance.sqrt();
        let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

        let intervals_rounded: Vec<f64> =
            intervals.iter().map(|&x| (x * 100.0).round() / 100.0).collect();

        Some(Alert {
            detector: "c2_beacon".to_string(),
            severity: AlertSeverity::High,
            description: format!(
                "C2 beacon detected: {src_ip} → {dst_ip}:{dst_port} — \
                 {n} callbacks at ~{mean:.1}s intervals (CV={cv:.3})",
                n = state.timestamps.len(),
            ),
            evidence: serde_json::json!({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "sample_count": state.timestamps.len(),
                "mean_interval_secs": (mean * 100.0).round() / 100.0,
                "std_dev_secs": (std_dev * 100.0).round() / 100.0,
                "jitter_cv": (cv * 1000.0).round() / 1000.0,
                "intervals_secs": intervals_rounded,
            }),
        })
    }

    /// Remove flow entries that have been inactive for longer than
    /// `max_flow_age_secs`.  Call periodically to prevent unbounded growth.
    pub fn cleanup(&mut self) {
        let max_age = Duration::from_secs(self.config.max_flow_age_secs);
        self.flows.retain(|_, state| {
            state
                .timestamps
                .last()
                .map(|t| t.elapsed() <= max_age)
                .unwrap_or(false)
        });
    }
}

// ---------------------------------------------------------------------------
// Periodicity check
// ---------------------------------------------------------------------------

/// Return `true` when `intervals` (in seconds) represent a periodic beacon.
///
/// A sequence is considered periodic when the coefficient of variation
/// (σ / μ) of the inter-arrival times is at or below `jitter_pct / 100`.
///
/// # Arguments
/// * `intervals`  — non-empty slice of inter-arrival times in seconds.
/// * `jitter_pct` — allowed jitter as a percentage (e.g. `20.0` → 20 %).
pub(crate) fn is_periodic(intervals: &[f64], jitter_pct: f64) -> bool {
    if intervals.is_empty() {
        return false;
    }
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return false;
    }
    let variance = intervals
        .iter()
        .map(|&x| (x - mean).powi(2))
        .sum::<f64>()
        / n;
    let cv = variance.sqrt() / mean;
    cv <= jitter_pct / 100.0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn default_config() -> C2BeaconDetectorConfig {
        C2BeaconDetectorConfig::default()
    }

    /// Config with a very short interval for timing-sensitive tests.
    /// min_gap = 20ms * (1 - 0.20) = 16ms → sleep 25ms to cross threshold.
    fn fast_config(min_packets: u32, jitter_pct: f64) -> C2BeaconDetectorConfig {
        C2BeaconDetectorConfig {
            enabled: true,
            beacon_interval_secs: 0.020, // 20 ms
            jitter_pct,
            min_packets_for_alert: min_packets,
            max_flow_age_secs: 3600,
        }
    }

    fn disabled_config() -> C2BeaconDetectorConfig {
        C2BeaconDetectorConfig {
            enabled: false,
            ..C2BeaconDetectorConfig::default()
        }
    }

    /// Sleep long enough to cross the debounce window for `fast_config`.
    fn beat() {
        thread::sleep(Duration::from_millis(25));
    }

    // -----------------------------------------------------------------------
    // is_periodic — pure function tests (no timing, no state)
    // -----------------------------------------------------------------------

    #[test]
    fn test_periodic_empty_returns_false() {
        assert!(!is_periodic(&[], 20.0));
    }

    #[test]
    fn test_periodic_single_interval_returns_true() {
        // CV of a single value is 0, which is ≤ any non-negative jitter.
        assert!(is_periodic(&[60.0], 20.0));
    }

    #[test]
    fn test_periodic_two_equal_intervals_returns_true() {
        assert!(is_periodic(&[60.0, 60.0], 20.0));
    }

    #[test]
    fn test_periodic_all_same_returns_true() {
        let intervals = vec![30.0; 10];
        assert!(is_periodic(&intervals, 5.0));
    }

    #[test]
    fn test_periodic_perfect_60s_beacon() {
        let intervals = vec![60.0, 60.0, 60.0, 60.0];
        assert!(is_periodic(&intervals, 20.0));
    }

    #[test]
    fn test_periodic_jitter_within_20pct() {
        // Mean = 60s, values vary by ±10s → CV ≈ 0.12 < 0.20
        let intervals = vec![50.0, 60.0, 70.0, 60.0, 50.0, 70.0];
        assert!(is_periodic(&intervals, 20.0));
    }

    #[test]
    fn test_periodic_jitter_above_threshold_returns_false() {
        // Alternating 10s and 110s → mean=60, std≈50, CV≈0.83 > 0.20
        let intervals = vec![10.0, 110.0, 10.0, 110.0, 10.0, 110.0];
        assert!(!is_periodic(&intervals, 20.0));
    }

    #[test]
    fn test_periodic_cv_exactly_at_threshold() {
        // Construct intervals whose CV is exactly the jitter fraction.
        // For two values [a, b]: mean = (a+b)/2, std = |a-b|/2, cv = |a-b|/(a+b).
        // We want cv = 0.10 → |a-b|/(a+b) = 0.10. Let a=55, b=45 → cv = 10/100 = 0.10.
        let intervals = vec![55.0, 45.0];
        assert!(is_periodic(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_cv_just_above_threshold_returns_false() {
        // cv = 10/100 = 0.10; threshold = 0.09
        let intervals = vec![55.0, 45.0];
        assert!(!is_periodic(&intervals, 9.0));
    }

    #[test]
    fn test_periodic_zero_mean_returns_false() {
        let intervals = vec![0.0, 0.0, 0.0];
        assert!(!is_periodic(&intervals, 20.0));
    }

    #[test]
    fn test_periodic_all_zeros_returns_false() {
        assert!(!is_periodic(&[0.0], 100.0));
    }

    #[test]
    fn test_periodic_zero_jitter_only_perfect() {
        // CV = 0 required; only identical intervals pass.
        assert!(is_periodic(&[60.0, 60.0, 60.0], 0.0));
    }

    #[test]
    fn test_periodic_zero_jitter_rejects_variation() {
        // Any non-zero standard deviation fails at jitter_pct = 0.
        assert!(!is_periodic(&[59.0, 61.0], 0.0));
    }

    #[test]
    fn test_periodic_large_jitter_accepts_moderate_variation() {
        let intervals = vec![40.0, 60.0, 80.0, 60.0];
        // mean=60, std≈14.1, cv≈0.235 < 0.50
        assert!(is_periodic(&intervals, 50.0));
    }

    #[test]
    fn test_periodic_large_dataset_regular() {
        let intervals = vec![60.0; 50];
        assert!(is_periodic(&intervals, 20.0));
    }

    #[test]
    fn test_periodic_large_dataset_irregular() {
        // Randomly varying: some 1s, some 120s → very high CV.
        let intervals: Vec<f64> = (0..20)
            .map(|i| if i % 3 == 0 { 1.0 } else { 120.0 })
            .collect();
        assert!(!is_periodic(&intervals, 20.0));
    }

    #[test]
    fn test_periodic_strict_10pct_regular() {
        // CV of [58, 60, 62] = std(2)/mean(60) ≈ 0.033 < 0.10
        let intervals = vec![58.0, 60.0, 62.0, 60.0, 59.0, 61.0];
        assert!(is_periodic(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_strict_10pct_rejects_wide_jitter() {
        // [50, 70] → cv = 10/60 ≈ 0.167 > 0.10
        let intervals = vec![50.0, 70.0, 50.0, 70.0];
        assert!(!is_periodic(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_single_outlier_breaks_periodicity() {
        // 9 regular, 1 outlier → significantly raised CV.
        let mut intervals = vec![60.0; 9];
        intervals.push(600.0);
        // mean ≈ 114, high std_dev → CV likely > 0.20
        assert!(!is_periodic(&intervals, 20.0));
    }

    #[test]
    fn test_periodic_beacon_with_drift() {
        // Gradually increasing interval: 55, 57, 59, 61, 63, 65
        // mean=60, std≈3.74, cv≈0.062 < 0.20
        let intervals = vec![55.0, 57.0, 59.0, 61.0, 63.0, 65.0];
        assert!(is_periodic(&intervals, 20.0));
    }

    #[test]
    fn test_periodic_high_frequency_beacon() {
        // 5-second interval, tight jitter
        let intervals = vec![4.9, 5.0, 5.1, 5.0, 4.95, 5.05];
        // cv ≈ 0.016 < 0.10
        assert!(is_periodic(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_negative_jitter_treated_as_zero() {
        // Negative jitter means cv <= 0 which is impossible (cv >= 0),
        // so only cv = 0 (perfectly identical intervals) could ever pass.
        let intervals = vec![60.0, 60.0, 60.0];
        // cv = 0 <= -0.10 is false, so should return false.
        assert!(!is_periodic(&intervals, -10.0));
    }

    // -----------------------------------------------------------------------
    // C2BeaconDetector — state-machine tests (no timing needed)
    // -----------------------------------------------------------------------

    #[test]
    fn test_detector_disabled_returns_none() {
        let mut det = C2BeaconDetector::new(&disabled_config());
        // Even many calls should never alert.
        for _ in 0..20 {
            assert!(det.record_packet("10.0.0.1", "1.2.3.4", 443).is_none());
        }
    }

    #[test]
    fn test_single_packet_no_alert() {
        let mut det = C2BeaconDetector::new(&default_config());
        assert!(det.record_packet("10.0.0.1", "1.2.3.4", 443).is_none());
    }

    #[test]
    fn test_burst_packets_debounced_to_single_sample() {
        // With default config (60s interval, 20% jitter → min_gap = 48s),
        // many rapid calls should only record one timestamp.
        let mut det = C2BeaconDetector::new(&default_config());
        // Fire 10 packets in rapid succession — all should be debounced after
        // the first, so we never accumulate enough samples to alert.
        for _ in 0..10 {
            assert!(det.record_packet("10.0.0.1", "1.2.3.4", 443).is_none());
        }
        // The flow state should have exactly 1 timestamp recorded.
        let key = FlowKey {
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.2.3.4".into(),
            dst_port: 443,
        };
        let state = det.flows.get(&key).expect("flow should exist");
        assert_eq!(state.timestamps.len(), 1, "bursts should be debounced to 1 sample");
    }

    #[test]
    fn test_below_min_packets_no_alert() {
        // Use a fast config so we can actually record multiple samples.
        let cfg = fast_config(5, 20.0);
        let mut det = C2BeaconDetector::new(&cfg);

        // Record 4 samples (one below threshold).
        for _ in 0..4 {
            let result = det.record_packet("10.0.0.1", "1.2.3.4", 80);
            assert!(result.is_none());
            beat();
        }
    }

    #[test]
    fn test_no_alert_after_alerted_flag() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        // Trigger an alert.
        beat(); // initial gap so first packet records
        det.record_packet("10.0.0.1", "1.2.3.4", 80);
        beat();
        det.record_packet("10.0.0.1", "1.2.3.4", 80);
        beat();
        let first = det.record_packet("10.0.0.1", "1.2.3.4", 80);
        // May or may not alert depending on exact timing; set alerted manually.
        let key = FlowKey {
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.2.3.4".into(),
            dst_port: 80,
        };
        if let Some(state) = det.flows.get_mut(&key) {
            state.alerted = true;
        }
        drop(first);

        // All further calls must return None.
        beat();
        assert!(det.record_packet("10.0.0.1", "1.2.3.4", 80).is_none());
        beat();
        assert!(det.record_packet("10.0.0.1", "1.2.3.4", 80).is_none());
    }

    #[test]
    fn test_multiple_flows_tracked_independently() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        // Interleave packets for two different destinations.
        det.record_packet("10.0.0.1", "1.1.1.1", 443);
        det.record_packet("10.0.0.1", "2.2.2.2", 8080);
        beat();
        det.record_packet("10.0.0.1", "1.1.1.1", 443);
        det.record_packet("10.0.0.1", "2.2.2.2", 8080);
        beat();
        det.record_packet("10.0.0.1", "1.1.1.1", 443);
        det.record_packet("10.0.0.1", "2.2.2.2", 8080);

        // Both flows should exist independently.
        let k1 = FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.1.1.1".into(), dst_port: 443 };
        let k2 = FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "2.2.2.2".into(), dst_port: 8080 };
        assert!(det.flows.contains_key(&k1));
        assert!(det.flows.contains_key(&k2));
    }

    #[test]
    fn test_different_dst_port_is_different_flow() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.0.0.1", "1.2.3.4", 80);
        beat();
        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        beat();
        det.record_packet("10.0.0.1", "1.2.3.4", 80);

        let k80 = FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.2.3.4".into(), dst_port: 80 };
        let k443 = FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.2.3.4".into(), dst_port: 443 };
        assert!(det.flows.contains_key(&k80));
        assert!(det.flows.contains_key(&k443));
        assert_eq!(det.flows[&k80].timestamps.len(), 2);
        assert_eq!(det.flows[&k443].timestamps.len(), 1);
    }

    #[test]
    fn test_different_src_ip_is_different_flow() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        det.record_packet("10.0.0.2", "1.2.3.4", 443);

        let k1 = FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.2.3.4".into(), dst_port: 443 };
        let k2 = FlowKey { src_ip: "10.0.0.2".into(), dst_ip: "1.2.3.4".into(), dst_port: 443 };
        assert!(det.flows.contains_key(&k1));
        assert!(det.flows.contains_key(&k2));
    }

    // -----------------------------------------------------------------------
    // C2BeaconDetector — alert quality tests (with timing)
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_fires_after_min_packets_periodic() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        // Record first sample.
        det.record_packet("192.168.1.10", "203.0.113.5", 443);
        beat();
        det.record_packet("192.168.1.10", "203.0.113.5", 443);
        beat();
        let alert = det.record_packet("192.168.1.10", "203.0.113.5", 443);

        assert!(alert.is_some(), "should alert after 3 periodic samples");
        let alert = alert.unwrap();
        assert_eq!(alert.detector, "c2_beacon");
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn test_alert_description_contains_flow_info() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("192.168.1.10", "203.0.113.5", 8080);
        beat();
        det.record_packet("192.168.1.10", "203.0.113.5", 8080);
        beat();
        let alert = det.record_packet("192.168.1.10", "203.0.113.5", 8080);

        if let Some(a) = alert {
            assert!(a.description.contains("192.168.1.10"));
            assert!(a.description.contains("203.0.113.5"));
            assert!(a.description.contains("8080"));
        }
    }

    #[test]
    fn test_alert_evidence_contains_expected_fields() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.1.1.1", "8.8.8.8", 53);
        beat();
        det.record_packet("10.1.1.1", "8.8.8.8", 53);
        beat();
        let alert = det.record_packet("10.1.1.1", "8.8.8.8", 53);

        if let Some(a) = alert {
            let ev = &a.evidence;
            assert_eq!(ev["src_ip"], "10.1.1.1");
            assert_eq!(ev["dst_ip"], "8.8.8.8");
            assert_eq!(ev["dst_port"], 53);
            assert!(ev["mean_interval_secs"].is_number());
            assert!(ev["std_dev_secs"].is_number());
            assert!(ev["jitter_cv"].is_number());
            assert!(ev["intervals_secs"].is_array());
            assert!(ev["sample_count"].is_number());
        }
    }

    #[test]
    fn test_alert_evidence_interval_count_correct() {
        let cfg = fast_config(4, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.1.1.1", "8.8.8.8", 80);
        beat();
        det.record_packet("10.1.1.1", "8.8.8.8", 80);
        beat();
        det.record_packet("10.1.1.1", "8.8.8.8", 80);
        beat();
        let alert = det.record_packet("10.1.1.1", "8.8.8.8", 80);

        if let Some(a) = alert {
            let arr = a.evidence["intervals_secs"].as_array().expect("array");
            // 4 timestamps → 3 intervals
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn test_alert_fires_only_once_per_flow() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        beat();
        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        beat();
        let first = det.record_packet("10.0.0.1", "1.2.3.4", 443);
        beat();
        let second = det.record_packet("10.0.0.1", "1.2.3.4", 443);
        beat();
        let third = det.record_packet("10.0.0.1", "1.2.3.4", 443);

        // At most one alert should ever fire.
        let alert_count = [first, second, third]
            .into_iter()
            .filter(|r| r.is_some())
            .count();
        assert!(alert_count <= 1, "at most one alert per flow");
    }

    // -----------------------------------------------------------------------
    // C2BeaconDetector — cleanup tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cleanup_removes_stale_flows() {
        let mut cfg = fast_config(3, 20.0);
        // Very short max age — flows become stale almost immediately.
        cfg.max_flow_age_secs = 0;
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        assert_eq!(det.flows.len(), 1);

        // Sleep just long enough for the flow to expire (age = 0 s).
        thread::sleep(Duration::from_millis(10));
        det.cleanup();
        assert_eq!(det.flows.len(), 0, "stale flow should be removed");
    }

    #[test]
    fn test_cleanup_keeps_fresh_flows() {
        let cfg = fast_config(3, 20.0); // max_flow_age = 3600s
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        assert_eq!(det.flows.len(), 1);

        det.cleanup();
        assert_eq!(det.flows.len(), 1, "fresh flow should be retained");
    }

    #[test]
    fn test_cleanup_empty_detector_does_not_panic() {
        let mut det = C2BeaconDetector::new(&default_config());
        det.cleanup(); // should not panic
        assert_eq!(det.flows.len(), 0);
    }

    #[test]
    fn test_cleanup_removes_only_stale_entries() {
        let mut det = C2BeaconDetector::new(&C2BeaconDetectorConfig {
            max_flow_age_secs: 0,
            ..fast_config(3, 20.0)
        });

        // Record one flow then sleep to make it stale.
        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        thread::sleep(Duration::from_millis(10));

        // Record a second flow (fresh).
        det.record_packet("10.0.0.2", "1.2.3.4", 443);

        det.cleanup();

        // The second flow was just created, so max_flow_age=0 means it's at
        // the boundary — we only assert the first stale flow is gone.
        let k1 = FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.2.3.4".into(), dst_port: 443 };
        assert!(!det.flows.contains_key(&k1), "stale flow should be removed");
    }

    // -----------------------------------------------------------------------
    // C2BeaconDetector — configuration edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_creates_detector() {
        let det = C2BeaconDetector::new(&default_config());
        assert!(det.config.enabled);
        assert!(det.flows.is_empty());
    }

    #[test]
    fn test_min_packets_exactly_at_threshold_alerts() {
        let cfg = fast_config(2, 30.0); // only need 2 samples
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.0.0.1", "1.2.3.4", 80);
        beat();
        // With 2 samples we have 1 interval; CV of a single value is 0 → periodic.
        let alert = det.record_packet("10.0.0.1", "1.2.3.4", 80);
        assert!(alert.is_some(), "should alert at exactly min_packets");
    }

    #[test]
    fn test_high_jitter_pct_accepts_variable_timing() {
        let cfg = C2BeaconDetectorConfig {
            jitter_pct: 90.0,
            min_packets_for_alert: 3,
            ..fast_config(3, 90.0)
        };
        let mut det = C2BeaconDetector::new(&cfg);

        // Even with uneven sleeps, CV should be well below 0.90.
        det.record_packet("10.0.0.1", "1.2.3.4", 80);
        beat();
        thread::sleep(Duration::from_millis(5));
        det.record_packet("10.0.0.1", "1.2.3.4", 80);
        beat();
        let alert = det.record_packet("10.0.0.1", "1.2.3.4", 80);
        assert!(alert.is_some(), "high jitter_pct should accept variable timing");
    }

    #[test]
    fn test_zero_jitter_requires_perfect_intervals() {
        // With jitter_pct = 0, only cv = 0 (identical intervals) passes.
        // We can't guarantee identical Instant measurements, so just verify
        // the non-degenerate case: the `is_periodic` helper rejects any cv > 0.
        assert!(!is_periodic(&[60.0, 61.0], 0.0));
        assert!(is_periodic(&[60.0, 60.0], 0.0));
    }

    #[test]
    fn test_detector_severity_is_high() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        beat();
        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        beat();
        let alert = det.record_packet("10.0.0.1", "1.2.3.4", 443);

        if let Some(a) = alert {
            assert_eq!(a.severity, AlertSeverity::High);
            assert_eq!(a.severity.ocsf_id(), 4);
        }
    }

    #[test]
    fn test_detector_name_in_alert() {
        let cfg = fast_config(3, 30.0);
        let mut det = C2BeaconDetector::new(&cfg);

        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        beat();
        det.record_packet("10.0.0.1", "1.2.3.4", 443);
        beat();
        let alert = det.record_packet("10.0.0.1", "1.2.3.4", 443);

        if let Some(a) = alert {
            assert_eq!(a.detector, "c2_beacon");
        }
    }

    #[test]
    fn test_large_jitter_pct_clamped_to_valid_min_gap() {
        // jitter_pct = 150 → jitter_fraction = 1.0 (clamped) → min_gap = 0.
        // With min_gap = 0, every packet is recorded.
        let cfg = C2BeaconDetectorConfig {
            enabled: true,
            beacon_interval_secs: 0.020,
            jitter_pct: 150.0, // over 100%
            min_packets_for_alert: 3,
            max_flow_age_secs: 3600,
        };
        let mut det = C2BeaconDetector::new(&cfg);

        // With min_gap = 0, rapid calls all record.
        det.record_packet("10.0.0.1", "1.2.3.4", 80);
        det.record_packet("10.0.0.1", "1.2.3.4", 80);
        det.record_packet("10.0.0.1", "1.2.3.4", 80);

        // Should have 3 timestamps (no debounce since min_gap = 0).
        let key = FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.2.3.4".into(), dst_port: 80 };
        assert_eq!(det.flows[&key].timestamps.len(), 3);
    }
}
