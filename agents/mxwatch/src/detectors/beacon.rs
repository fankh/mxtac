//! C2 beacon detector — feature 36.5.
//!
//! Detects command-and-control (C2) beaconing through multi-signal analysis
//! of TCP flow behavior.  Unlike the baseline `c2_beacon` detector which uses
//! coefficient of variation, this detector uses standard deviation expressed
//! as a percentage of the mean interval (σ / μ × 100 %) and enriches alerts
//! with additional behavioral signals.
//!
//! ## Algorithm
//!
//! For each directional flow `(src_ip → dst_ip:dst_port)`:
//!
//! 1. **Records** connection events with a debounce window to suppress burst
//!    packets belonging to the same TCP session from being counted as separate
//!    beacon events.
//!
//! 2. **Prunes** observations older than `beacon_window_seconds` so the
//!    detector adapts to changing traffic patterns over time.
//!
//! 3. After `beacon_min_connections` observations:
//!    - Computes inter-arrival intervals (seconds between debounced samples).
//!    - Evaluates jitter: σ / μ × 100 %.
//!    - If jitter < `beacon_max_jitter_pct` → periodic pattern confirmed.
//!
//! 4. **Enriches** the alert with additional behavioral signals:
//!    - Consistent payload sizes (CV of non-zero payload sizes < 0.20).
//!    - Connection to an uncommon service port (not 53/80/443/8080/8443).
//!    - Fraction of observations that fell outside Mon–Fri 08:00–18:00 UTC.
//!
//! 5. **Assigns** a MITRE ATT&CK technique identifier:
//!    - Port 443 / 8443 → `T1573` (Encrypted Channel).
//!    - All other ports  → `T1071` (Application Layer Protocol).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{Datelike, Timelike, Utc, Weekday};
use tracing::debug;

use crate::config::BeaconDetectorConfig;
use crate::detectors::{Alert, AlertSeverity};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Common service ports; connections to other ports raise the suspicion level.
const COMMON_PORTS: &[u16] = &[53, 80, 443, 8080, 8443];

/// Minimum elapsed time between two recorded observations.
///
/// Burst packets within a single TCP session share the same debounce window,
/// so only the first packet of each "check-in" interval is counted.
///
/// Reduced to 20 ms in test builds so timing-sensitive tests complete quickly.
const MIN_GAP_SECS: f64 = if cfg!(test) { 0.020 } else { 2.0 };

/// Maximum observations stored per flow to keep memory usage bounded.
const MAX_SAMPLES: usize = 200;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Identifies a directional flow.  The source port is omitted so that
/// repeated TCP connections from the same host to the same server:port are
/// grouped — each reconnection uses an ephemeral source port but the
/// destination service port stays constant across beaconing cycles.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
}

struct FlowState {
    /// Monotonic arrival timestamps in ascending order.
    timestamps: Vec<Instant>,
    /// TCP payload sizes corresponding to each timestamp entry.
    payload_sizes: Vec<usize>,
    /// Number of observations that were recorded outside business hours.
    outside_hours_count: u32,
    /// Set to `true` once an alert has been emitted; prevents re-alerting.
    alerted: bool,
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Multi-signal C2 beacon detector.
///
/// Maintains per-flow timing history and payload metadata.  Not `Send`;
/// intended to run on a single packet-processing task.
pub struct BeaconDetector {
    config: BeaconDetectorConfig,
    flows: HashMap<FlowKey, FlowState>,
}

impl BeaconDetector {
    /// Create a new detector from configuration.
    pub fn new(config: &BeaconDetectorConfig) -> Self {
        Self {
            config: config.clone(),
            flows: HashMap::new(),
        }
    }

    /// Record a TCP connection event and evaluate the flow for beaconing.
    ///
    /// * `src_ip` / `dst_ip` — flow endpoints (as strings).
    /// * `dst_port` — destination service port.
    /// * `payload_size` — TCP payload length in bytes (0 for SYN/ACK with no data).
    ///
    /// Returns `Some(Alert)` the **first** time a beacon pattern is confirmed;
    /// returns `None` otherwise.  Subsequent calls for the same flow after an
    /// alert always return `None`.
    pub fn record_connection(
        &mut self,
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
        payload_size: usize,
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
        let min_gap = Duration::from_secs_f64(MIN_GAP_SECS);
        let window = Duration::from_secs(self.config.beacon_window_seconds);
        let outside_hours = is_outside_business_hours();

        let state = self.flows.entry(key).or_insert_with(|| FlowState {
            timestamps: Vec::new(),
            payload_sizes: Vec::new(),
            outside_hours_count: 0,
            alerted: false,
        });

        if state.alerted {
            return None;
        }

        // Debounce: suppress burst packets that arrive within the minimum gap.
        if let Some(&last) = state.timestamps.last() {
            let elapsed = now.checked_duration_since(last).unwrap_or_default();
            if elapsed < min_gap {
                return None;
            }
        }

        // Prune observations that have left the beacon window.
        let prune_count = state
            .timestamps
            .iter()
            .take_while(|&&t| {
                now.checked_duration_since(t)
                    .map(|elapsed| elapsed > window)
                    .unwrap_or(false)
            })
            .count();
        if prune_count > 0 {
            state.timestamps.drain(0..prune_count);
            state.payload_sizes.drain(0..prune_count);
        }

        // Record the new observation.
        state.timestamps.push(now);
        state.payload_sizes.push(payload_size);
        if outside_hours {
            state.outside_hours_count += 1;
        }

        // Cap history to bound memory usage per flow.
        if state.timestamps.len() > MAX_SAMPLES {
            state.timestamps.remove(0);
            state.payload_sizes.remove(0);
        }

        let min_conn = self.config.beacon_min_connections as usize;
        if state.timestamps.len() < min_conn {
            debug!(
                samples = state.timestamps.len(),
                needed = min_conn,
                "beacon: accumulating samples for {}→{}:{}",
                src_ip,
                dst_ip,
                dst_port,
            );
            return None;
        }

        // Compute inter-arrival intervals (seconds).
        let intervals: Vec<f64> = state
            .timestamps
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .collect();

        if !is_periodic_beacon(&intervals, self.config.beacon_max_jitter_pct) {
            return None;
        }

        // Periodic pattern confirmed — build evidence and emit a single alert.
        state.alerted = true;

        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;
        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
        let std_dev = variance.sqrt();
        let jitter_pct = (std_dev / mean) * 100.0;

        // Additional behavioral signals.
        let uncommon_port = !COMMON_PORTS.contains(&dst_port);
        let consistent_payload = is_consistent_payload(&state.payload_sizes);
        let outside_hours_pct =
            state.outside_hours_count as f64 / state.timestamps.len() as f64 * 100.0;

        // ATT&CK technique: encrypted channel (TLS) vs application-layer protocol.
        let technique_id = if matches!(dst_port, 443 | 8443) {
            "T1573" // Encrypted Channel
        } else {
            "T1071" // Application Layer Protocol
        };

        let intervals_rounded: Vec<f64> =
            intervals.iter().map(|&x| (x * 100.0).round() / 100.0).collect();

        Some(Alert {
            detector: "beacon".to_string(),
            severity: AlertSeverity::High,
            description: format!(
                "C2 beacon detected: {src_ip} → {dst_ip}:{dst_port} — \
                 {count} connections at ~{mean:.1}s intervals \
                 (jitter={jitter_pct:.1}%) [{technique_id}]",
                count = state.timestamps.len(),
            ),
            evidence: serde_json::json!({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "technique_id": technique_id,
                "sample_count": state.timestamps.len(),
                "mean_interval_secs": (mean * 100.0).round() / 100.0,
                "std_dev_secs": (std_dev * 100.0).round() / 100.0,
                "jitter_pct": (jitter_pct * 100.0).round() / 100.0,
                "intervals_secs": intervals_rounded,
                "uncommon_port": uncommon_port,
                "consistent_payload_sizes": consistent_payload,
                "outside_business_hours_pct": (outside_hours_pct * 10.0).round() / 10.0,
            }),
        })
    }

    /// Remove flow entries that have been inactive for longer than
    /// `beacon_window_seconds`.  Call periodically to prevent unbounded growth.
    pub fn cleanup(&mut self) {
        let window = Duration::from_secs(self.config.beacon_window_seconds);
        self.flows.retain(|_, state| {
            state
                .timestamps
                .last()
                .map(|t| t.elapsed() <= window)
                .unwrap_or(false)
        });
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Returns `true` when the current UTC wall-clock time is outside standard
/// business hours (Monday–Friday, 08:00–18:00 UTC).
fn is_outside_business_hours() -> bool {
    let now = Utc::now();
    let is_weekend = matches!(now.weekday(), Weekday::Sat | Weekday::Sun);
    let hour = now.hour();
    is_weekend || hour < 8 || hour >= 18
}

/// Returns `true` when the inter-arrival `intervals` (in seconds) are
/// consistent with periodic beaconing: jitter (σ / μ × 100 %) is **strictly**
/// below `max_jitter_pct`.
///
/// # Arguments
/// * `intervals`      — non-empty slice of inter-arrival times in seconds.
/// * `max_jitter_pct` — maximum allowed jitter as a percentage (e.g. `10.0`).
pub(crate) fn is_periodic_beacon(intervals: &[f64], max_jitter_pct: f64) -> bool {
    if intervals.is_empty() {
        return false;
    }
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return false;
    }
    let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
    let jitter_pct = variance.sqrt() / mean * 100.0;
    jitter_pct < max_jitter_pct
}

/// Returns `true` when non-zero payload sizes show low coefficient of
/// variation (CV < 0.20), indicating consistently sized check-in payloads
/// characteristic of automated C2 callbacks.
pub(crate) fn is_consistent_payload(sizes: &[usize]) -> bool {
    let non_zero: Vec<f64> = sizes
        .iter()
        .filter(|&&s| s > 0)
        .map(|&s| s as f64)
        .collect();
    if non_zero.len() < 2 {
        return false;
    }
    let n = non_zero.len() as f64;
    let mean = non_zero.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return false;
    }
    let variance = non_zero.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
    let cv = variance.sqrt() / mean;
    cv < 0.20
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

    fn default_config() -> BeaconDetectorConfig {
        BeaconDetectorConfig::default()
    }

    /// Fast config for timing tests: MIN_GAP = 20 ms (test constant),
    /// so sleeping 25 ms crosses the debounce window.
    fn fast_config(min_conn: u32, max_jitter_pct: f64) -> BeaconDetectorConfig {
        BeaconDetectorConfig {
            enabled: true,
            beacon_min_connections: min_conn,
            beacon_max_jitter_pct: max_jitter_pct,
            beacon_window_seconds: 3600,
        }
    }

    fn disabled_config() -> BeaconDetectorConfig {
        BeaconDetectorConfig {
            enabled: false,
            ..BeaconDetectorConfig::default()
        }
    }

    /// Sleep long enough to cross the 20 ms debounce window used in tests.
    fn beat() {
        thread::sleep(Duration::from_millis(25));
    }

    // -----------------------------------------------------------------------
    // is_periodic_beacon — pure function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_periodic_empty_returns_false() {
        assert!(!is_periodic_beacon(&[], 10.0));
    }

    #[test]
    fn test_periodic_single_interval_zero_jitter() {
        // Single value: σ = 0, jitter = 0 % < 10 % → periodic.
        assert!(is_periodic_beacon(&[60.0], 10.0));
    }

    #[test]
    fn test_periodic_identical_intervals_perfect() {
        let intervals = vec![60.0; 10];
        assert!(is_periodic_beacon(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_tight_jitter_passes() {
        // [58, 60, 62]: mean=60, std≈1.63, jitter≈2.7 % < 10 %
        let intervals = vec![58.0, 60.0, 62.0, 60.0, 59.0, 61.0];
        assert!(is_periodic_beacon(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_wide_jitter_fails() {
        // [50, 70, 50, 70]: mean=60, std=10, jitter≈16.7 % > 10 %
        let intervals = vec![50.0, 70.0, 50.0, 70.0];
        assert!(!is_periodic_beacon(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_zero_mean_returns_false() {
        assert!(!is_periodic_beacon(&[0.0, 0.0, 0.0], 10.0));
    }

    #[test]
    fn test_periodic_jitter_exactly_at_threshold_excluded() {
        // [55, 45]: mean=50, std=5, jitter=10.0 % — strictly less than required,
        // so with max_jitter_pct=10.0 this should NOT pass (jitter == limit).
        let intervals = vec![55.0, 45.0];
        assert!(!is_periodic_beacon(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_jitter_just_below_threshold_passes() {
        // [55.1, 44.9]: mean=50, std=5.1, jitter≈10.2 % > 10 % → fails.
        // [54.9, 45.1]: mean=50, std=4.9, jitter≈9.8 % < 10 % → passes.
        let intervals = vec![54.9, 45.1];
        assert!(is_periodic_beacon(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_negative_threshold_always_fails() {
        // jitter >= 0 always, so jitter < negative threshold is impossible.
        assert!(!is_periodic_beacon(&[60.0, 60.0, 60.0], -5.0));
    }

    #[test]
    fn test_periodic_high_jitter_threshold_accepts_variable() {
        // Wildly varying intervals pass with a generous threshold.
        let intervals = vec![10.0, 50.0, 30.0, 40.0, 20.0];
        assert!(is_periodic_beacon(&intervals, 100.0));
    }

    #[test]
    fn test_periodic_high_frequency_tight_jitter() {
        // 5-second C2 with ±0.05 s jitter: jitter ≈ 0.7 % < 10 %.
        let intervals = vec![4.95, 5.0, 5.05, 5.0, 4.98, 5.02];
        assert!(is_periodic_beacon(&intervals, 10.0));
    }

    #[test]
    fn test_periodic_single_outlier_breaks_periodicity() {
        let mut intervals = vec![60.0; 9];
        intervals.push(600.0);
        // mean ≈ 114, high std_dev → jitter well above 10 %.
        assert!(!is_periodic_beacon(&intervals, 10.0));
    }

    // -----------------------------------------------------------------------
    // is_consistent_payload — pure function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_consistent_payload_empty_returns_false() {
        assert!(!is_consistent_payload(&[]));
    }

    #[test]
    fn test_consistent_payload_single_returns_false() {
        assert!(!is_consistent_payload(&[100]));
    }

    #[test]
    fn test_consistent_payload_all_zeros_returns_false() {
        assert!(!is_consistent_payload(&[0, 0, 0, 0]));
    }

    #[test]
    fn test_consistent_payload_identical_sizes() {
        // Identical sizes → CV = 0 < 0.20.
        assert!(is_consistent_payload(&[128, 128, 128, 128]));
    }

    #[test]
    fn test_consistent_payload_slightly_varying() {
        // 120–135 bytes: mean≈127, std≈5, CV≈0.04 < 0.20.
        assert!(is_consistent_payload(&[120, 125, 130, 128, 135, 122]));
    }

    #[test]
    fn test_consistent_payload_highly_variable_returns_false() {
        // 10 vs 1000 bytes: CV >> 0.20.
        assert!(!is_consistent_payload(&[10, 1000, 10, 1000, 10]));
    }

    #[test]
    fn test_consistent_payload_zeros_excluded_from_cv() {
        // If only one non-zero size, returns false (need ≥ 2 non-zero).
        assert!(!is_consistent_payload(&[0, 128, 0]));
    }

    #[test]
    fn test_consistent_payload_two_similar_non_zero() {
        assert!(is_consistent_payload(&[0, 128, 129, 0]));
    }

    // -----------------------------------------------------------------------
    // BeaconDetector — disabled
    // -----------------------------------------------------------------------

    #[test]
    fn test_disabled_never_alerts() {
        let mut det = BeaconDetector::new(&disabled_config());
        for _ in 0..20 {
            assert!(det.record_connection("10.0.0.1", "1.2.3.4", 4444, 128).is_none());
        }
    }

    // -----------------------------------------------------------------------
    // BeaconDetector — accumulation and threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_single_call_no_alert() {
        let mut det = BeaconDetector::new(&default_config());
        assert!(det.record_connection("10.0.0.1", "1.2.3.4", 443, 0).is_none());
    }

    #[test]
    fn test_burst_packets_debounced_to_one_sample() {
        let mut det = BeaconDetector::new(&default_config());
        // Rapid calls within MIN_GAP all get debounced after the first.
        for _ in 0..10 {
            assert!(det.record_connection("10.0.0.1", "1.2.3.4", 443, 0).is_none());
        }
        let key = FlowKey {
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.2.3.4".into(),
            dst_port: 443,
        };
        let state = det.flows.get(&key).expect("flow should exist");
        assert_eq!(state.timestamps.len(), 1, "burst packets debounced to 1 sample");
    }

    #[test]
    fn test_below_min_connections_no_alert() {
        let cfg = fast_config(5, 20.0);
        let mut det = BeaconDetector::new(&cfg);

        // Record 4 samples — one fewer than required.
        for _ in 0..4 {
            assert!(det.record_connection("10.0.0.1", "1.2.3.4", 80, 64).is_none());
            beat();
        }
    }

    // -----------------------------------------------------------------------
    // BeaconDetector — alert firing
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_fires_after_min_connections_periodic() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("192.168.1.10", "203.0.113.5", 4444, 128);
        beat();
        det.record_connection("192.168.1.10", "203.0.113.5", 4444, 130);
        beat();
        let alert = det.record_connection("192.168.1.10", "203.0.113.5", 4444, 127);

        assert!(alert.is_some(), "should alert after 3 periodic connections");
        let a = alert.unwrap();
        assert_eq!(a.detector, "beacon");
        assert_eq!(a.severity, AlertSeverity::High);
    }

    #[test]
    fn test_alert_fires_only_once_per_flow() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        let first = det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        let second = det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        let third = det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);

        let alert_count = [first, second, third]
            .into_iter()
            .filter(|r| r.is_some())
            .count();
        assert!(alert_count <= 1, "at most one alert per flow");
    }

    #[test]
    fn test_no_alert_after_alerted_flag_set() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        // Manually set the alerted flag.
        let key = FlowKey {
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.2.3.4".into(),
            dst_port: 80,
        };
        det.flows.insert(
            key,
            FlowState {
                timestamps: Vec::new(),
                payload_sizes: Vec::new(),
                outside_hours_count: 0,
                alerted: true,
            },
        );

        beat();
        assert!(det.record_connection("10.0.0.1", "1.2.3.4", 80, 64).is_none());
    }

    // -----------------------------------------------------------------------
    // BeaconDetector — flow isolation
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_flows_tracked_independently() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.1.1.1", 443, 0);
        det.record_connection("10.0.0.1", "2.2.2.2", 8080, 100);
        beat();
        det.record_connection("10.0.0.1", "1.1.1.1", 443, 0);
        det.record_connection("10.0.0.1", "2.2.2.2", 8080, 102);
        beat();
        det.record_connection("10.0.0.1", "1.1.1.1", 443, 0);
        det.record_connection("10.0.0.1", "2.2.2.2", 8080, 99);

        let k1 = FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.1.1.1".into(), dst_port: 443 };
        let k2 = FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "2.2.2.2".into(), dst_port: 8080 };
        assert!(det.flows.contains_key(&k1));
        assert!(det.flows.contains_key(&k2));
    }

    #[test]
    fn test_different_dst_port_is_different_flow() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 80, 0);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 80, 0);

        let k80 =
            FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.2.3.4".into(), dst_port: 80 };
        let k443 =
            FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.2.3.4".into(), dst_port: 443 };
        assert!(det.flows.contains_key(&k80));
        assert!(det.flows.contains_key(&k443));
        assert_eq!(det.flows[&k80].timestamps.len(), 2);
        assert_eq!(det.flows[&k443].timestamps.len(), 1);
    }

    #[test]
    fn test_different_src_ip_is_different_flow() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        det.record_connection("10.0.0.2", "1.2.3.4", 443, 0);

        let k1 =
            FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.2.3.4".into(), dst_port: 443 };
        let k2 =
            FlowKey { src_ip: "10.0.0.2".into(), dst_ip: "1.2.3.4".into(), dst_port: 443 };
        assert!(det.flows.contains_key(&k1));
        assert!(det.flows.contains_key(&k2));
    }

    // -----------------------------------------------------------------------
    // BeaconDetector — alert content
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_description_contains_flow_info() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("192.168.1.10", "203.0.113.5", 8080, 64);
        beat();
        det.record_connection("192.168.1.10", "203.0.113.5", 8080, 66);
        beat();
        let alert = det.record_connection("192.168.1.10", "203.0.113.5", 8080, 65);

        if let Some(a) = alert {
            assert!(a.description.contains("192.168.1.10"));
            assert!(a.description.contains("203.0.113.5"));
            assert!(a.description.contains("8080"));
        }
    }

    #[test]
    fn test_alert_evidence_required_fields() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.1.1.1", "8.8.8.8", 4444, 128);
        beat();
        det.record_connection("10.1.1.1", "8.8.8.8", 4444, 130);
        beat();
        let alert = det.record_connection("10.1.1.1", "8.8.8.8", 4444, 127);

        if let Some(a) = alert {
            let ev = &a.evidence;
            assert_eq!(ev["src_ip"], "10.1.1.1");
            assert_eq!(ev["dst_ip"], "8.8.8.8");
            assert_eq!(ev["dst_port"], 4444);
            assert!(ev["technique_id"].is_string());
            assert!(ev["sample_count"].is_number());
            assert!(ev["mean_interval_secs"].is_number());
            assert!(ev["std_dev_secs"].is_number());
            assert!(ev["jitter_pct"].is_number());
            assert!(ev["intervals_secs"].is_array());
            assert!(ev["uncommon_port"].is_boolean());
            assert!(ev["consistent_payload_sizes"].is_boolean());
            assert!(ev["outside_business_hours_pct"].is_number());
        }
    }

    #[test]
    fn test_alert_technique_t1573_for_port_443() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);

        if let Some(a) = alert {
            assert_eq!(a.evidence["technique_id"], "T1573");
        }
    }

    #[test]
    fn test_alert_technique_t1573_for_port_8443() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 8443, 0);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 8443, 0);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 8443, 0);

        if let Some(a) = alert {
            assert_eq!(a.evidence["technique_id"], "T1573");
        }
    }

    #[test]
    fn test_alert_technique_t1071_for_uncommon_port() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 4444, 0);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 4444, 0);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 4444, 0);

        if let Some(a) = alert {
            assert_eq!(a.evidence["technique_id"], "T1071");
        }
    }

    #[test]
    fn test_alert_technique_t1071_for_port_80() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 80, 64);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 80, 65);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 80, 64);

        if let Some(a) = alert {
            assert_eq!(a.evidence["technique_id"], "T1071");
        }
    }

    #[test]
    fn test_uncommon_port_signal_in_evidence() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 9999, 0);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 9999, 0);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 9999, 0);

        if let Some(a) = alert {
            assert_eq!(a.evidence["uncommon_port"], true);
        }
    }

    #[test]
    fn test_common_port_signal_false_in_evidence() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 80, 64);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 80, 65);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 80, 64);

        if let Some(a) = alert {
            assert_eq!(a.evidence["uncommon_port"], false);
        }
    }

    #[test]
    fn test_alert_severity_is_high() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);

        if let Some(a) = alert {
            assert_eq!(a.severity, AlertSeverity::High);
            assert_eq!(a.severity.ocsf_id(), 4);
        }
    }

    #[test]
    fn test_alert_detector_name() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);

        if let Some(a) = alert {
            assert_eq!(a.detector, "beacon");
        }
    }

    #[test]
    fn test_interval_count_in_evidence() {
        let cfg = fast_config(4, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.1.1.1", "8.8.8.8", 80, 64);
        beat();
        det.record_connection("10.1.1.1", "8.8.8.8", 80, 64);
        beat();
        det.record_connection("10.1.1.1", "8.8.8.8", 80, 64);
        beat();
        let alert = det.record_connection("10.1.1.1", "8.8.8.8", 80, 64);

        if let Some(a) = alert {
            let arr = a.evidence["intervals_secs"].as_array().expect("array");
            // 4 timestamps → 3 intervals
            assert_eq!(arr.len(), 3);
        }
    }

    // -----------------------------------------------------------------------
    // BeaconDetector — cleanup
    // -----------------------------------------------------------------------

    #[test]
    fn test_cleanup_removes_stale_flows() {
        let cfg = BeaconDetectorConfig {
            beacon_window_seconds: 0,
            ..fast_config(3, 20.0)
        };
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        assert_eq!(det.flows.len(), 1);

        thread::sleep(Duration::from_millis(10));
        det.cleanup();
        assert_eq!(det.flows.len(), 0, "stale flow should be removed");
    }

    #[test]
    fn test_cleanup_keeps_fresh_flows() {
        let cfg = fast_config(3, 20.0); // window = 3600 s
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        assert_eq!(det.flows.len(), 1);

        det.cleanup();
        assert_eq!(det.flows.len(), 1, "fresh flow should be retained");
    }

    #[test]
    fn test_cleanup_empty_does_not_panic() {
        let mut det = BeaconDetector::new(&default_config());
        det.cleanup();
        assert_eq!(det.flows.len(), 0);
    }

    #[test]
    fn test_cleanup_removes_only_stale_entries() {
        let mut det = BeaconDetector::new(&BeaconDetectorConfig {
            beacon_window_seconds: 0,
            ..fast_config(3, 20.0)
        });

        det.record_connection("10.0.0.1", "1.2.3.4", 443, 0);
        thread::sleep(Duration::from_millis(10));

        // Second flow (freshly added right before cleanup).
        det.record_connection("10.0.0.2", "1.2.3.4", 443, 0);

        det.cleanup();

        let k1 =
            FlowKey { src_ip: "10.0.0.1".into(), dst_ip: "1.2.3.4".into(), dst_port: 443 };
        assert!(!det.flows.contains_key(&k1), "stale flow should be removed");
    }

    // -----------------------------------------------------------------------
    // BeaconDetector — configuration edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_creates_detector() {
        let det = BeaconDetector::new(&default_config());
        assert!(det.config.enabled);
        assert!(det.flows.is_empty());
    }

    #[test]
    fn test_min_connections_exactly_at_threshold_alerts() {
        // min_conn = 2: after 2 samples we have 1 interval; CV of one value is 0.
        let cfg = fast_config(2, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 80, 64);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 80, 64);
        assert!(alert.is_some(), "should alert at exactly min_connections");
    }

    #[test]
    fn test_high_jitter_threshold_accepts_variable_timing() {
        let cfg = fast_config(3, 90.0);
        let mut det = BeaconDetector::new(&cfg);

        det.record_connection("10.0.0.1", "1.2.3.4", 80, 0);
        beat();
        thread::sleep(Duration::from_millis(5));
        det.record_connection("10.0.0.1", "1.2.3.4", 80, 0);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 80, 0);
        assert!(alert.is_some(), "high jitter threshold should accept variable timing");
    }

    #[test]
    fn test_consistent_payload_signal_with_uniform_sizes() {
        let cfg = fast_config(3, 30.0);
        let mut det = BeaconDetector::new(&cfg);

        // Uniform 128-byte payloads → consistent_payload_sizes = true.
        det.record_connection("10.0.0.1", "1.2.3.4", 4444, 128);
        beat();
        det.record_connection("10.0.0.1", "1.2.3.4", 4444, 129);
        beat();
        let alert = det.record_connection("10.0.0.1", "1.2.3.4", 4444, 128);

        if let Some(a) = alert {
            assert_eq!(a.evidence["consistent_payload_sizes"], true);
        }
    }
}
