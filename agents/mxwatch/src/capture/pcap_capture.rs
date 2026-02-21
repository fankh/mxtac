//! libpcap-based packet capture.
//!
//! Provides two capture modes:
//!
//! * **Live** — captures from a named network interface with an optional BPF
//!   filter.  If the named interface is not found in the OS device list, the
//!   backend falls back to `pcap::Device::lookup()`, which returns the
//!   OS-preferred interface.  This makes the backend portable across Linux,
//!   macOS, and Windows without requiring platform-specific configuration.
//!
//! * **Offline** — replays packets from a `.pcap` file for testing, forensic
//!   analysis, or CI pipelines.  Original capture timestamps are preserved.
//!   Enable by setting `[capture.pcap] read_file = "/path/to/file.pcap"`.
//!
//! # When is this backend used?
//!
//! * Always on non-Linux platforms (macOS, Windows).
//! * On Linux when `[capture] use_afpacket = false` (the default).
//!
//! # Performance
//!
//! Delivers approximately 100 000 packets per second — sufficient for most
//! enterprise deployments.  For higher throughput on Linux, enable the
//! AF_PACKET + MMAP backend (`use_afpacket = true`).
//!
//! # Privileges
//!
//! Live capture requires `CAP_NET_RAW` (Linux) or administrator rights
//! (Windows/macOS).  Offline replay has no privilege requirements.

use chrono::{DateTime, Utc};
use pcap::{Capture, Device, Packet, PacketHeader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::capture::RawPacket;
use crate::config::CaptureConfig;

// ── Timestamp conversion ──────────────────────────────────────────────────────

/// Convert a POSIX `timeval` (seconds + microseconds) to [`DateTime<Utc>`].
///
/// libpcap records timestamps as `struct timeval` (`tv_sec` + `tv_usec`).
/// We convert microseconds to nanoseconds for consistency with the AF_PACKET
/// backend, which records timestamps at nanosecond precision.
///
/// `tv_usec` is clamped to `[0, 999_999]` before conversion to guard against
/// malformed pcap files.  Returns `Utc::now()` on arithmetic overflow, which
/// should never occur with well-formed pcap data.
fn ts_to_datetime(tv_sec: i64, tv_usec: i64) -> DateTime<Utc> {
    let usec_clamped = tv_usec.clamp(0, 999_999) as u32;
    let nsecs = usec_clamped.saturating_mul(1_000);
    DateTime::from_timestamp(tv_sec, nsecs).unwrap_or_else(Utc::now)
}

/// Extract a [`DateTime<Utc>`] from a pcap [`PacketHeader`].
///
/// Uses the timestamp recorded by the kernel (or stored in the offline file),
/// not the wall-clock time at the moment of processing.
fn extract_timestamp(header: &PacketHeader) -> DateTime<Utc> {
    ts_to_datetime(header.ts.tv_sec as i64, header.ts.tv_usec as i64)
}

// ── Device discovery ──────────────────────────────────────────────────────────

/// Resolve the configured interface name to a pcap [`Device`].
///
/// Performs an exact name match against `pcap::Device::list()`.  If no match
/// is found, emits a warning and falls back to `pcap::Device::lookup()`, which
/// returns the OS-preferred capture interface.
///
/// Fallback rationale: interface naming conventions differ across platforms
/// (`eth0` on Linux, `en0` on macOS, `\Device\NPF_{...}` on Windows).
/// Auto-discovery allows a single config file to work without modification
/// when the agent is promoted from one OS to another.
fn find_device(interface: &str) -> anyhow::Result<Device> {
    let devices = Device::list().map_err(|e| {
        anyhow::anyhow!(
            "Failed to enumerate pcap devices (is libpcap installed?): {e}"
        )
    })?;

    // Prefer the exact name the operator configured.
    if let Some(dev) = devices.into_iter().find(|d| d.name == interface) {
        debug!(interface = %interface, "Resolved interface to pcap device");
        return Ok(dev);
    }

    // Interface not found — try the OS default instead.
    warn!(
        configured = %interface,
        "Configured interface not found; falling back to OS-default capture device"
    );

    Device::lookup()
        .map_err(|e| anyhow::anyhow!("Failed to look up default pcap device: {e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No suitable network interface found. \
                 Verify that libpcap is installed and the agent has \
                 CAP_NET_RAW privileges (Linux) or is run as Administrator \
                 (Windows/macOS)."
            )
        })
}

// ── RawPacket construction ────────────────────────────────────────────────────

/// Build a [`RawPacket`] from a libpcap [`Packet`].
///
/// Copies the captured bytes into an owned `Vec<u8>` and attaches the
/// timestamp from the pcap packet header (not `Utc::now()`).
fn build_raw_packet(packet: &Packet<'_>) -> RawPacket {
    RawPacket {
        timestamp: extract_timestamp(packet.header),
        data: packet.data.to_vec(),
        length: packet.header.len as usize,
        caplen: packet.header.caplen as usize,
    }
}

// ── Capture backend ───────────────────────────────────────────────────────────

/// libpcap packet capture backend.
///
/// Supports both **live** (network interface) and **offline** (`.pcap` file)
/// capture modes.  The mode is selected by `config.pcap.read_file`:
///
/// * `None` or empty string → live capture on the configured interface.
/// * Non-empty path → offline replay from the named file.
pub struct PcapCapture {
    config: CaptureConfig,
}

impl PcapCapture {
    /// Create a new [`PcapCapture`] from the provided configuration.
    pub fn new(config: &CaptureConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Start capturing packets.
    ///
    /// Dispatches to live or offline capture based on `config.pcap.read_file`.
    ///
    /// **Blocking**: does not return until the capture source is exhausted
    /// (offline) or an error / shutdown signal is received (live).  Callers
    /// must run this method via `tokio::task::spawn_blocking`.
    pub fn run_blocking(&self, tx: mpsc::Sender<RawPacket>) -> anyhow::Result<()> {
        if let Some(ref path) = self.config.pcap.read_file {
            if !path.is_empty() {
                return self.run_offline(path, tx);
            }
        }
        self.run_live(tx)
    }

    // ── Live capture ──────────────────────────────────────────────────────────

    /// Open a live capture on the configured network interface.
    ///
    /// Steps:
    /// 1. Resolve the interface name, with auto-discovery fallback.
    /// 2. Open the pcap handle (snaplen, promisc, timeout, kernel buffer).
    /// 3. Apply the BPF filter if configured.
    /// 4. Enter the capture loop.
    fn run_live(&self, tx: mpsc::Sender<RawPacket>) -> anyhow::Result<()> {
        let device = find_device(&self.config.interface)?;

        info!(
            interface  = %device.name,
            snaplen    = self.config.snaplen,
            promisc    = self.config.promiscuous,
            timeout_ms = self.config.pcap.timeout_ms,
            "Opening live pcap capture"
        );

        let mut cap = Capture::from_device(device)?
            .promisc(self.config.promiscuous)
            .snaplen(self.config.snaplen)
            .buffer_size(self.config.buffer_size)
            .timeout(self.config.pcap.timeout_ms)
            .open()?;

        if !self.config.bpf_filter.is_empty() {
            cap.filter(&self.config.bpf_filter, true)?;
            debug!(filter = %self.config.bpf_filter, "BPF filter applied");
        }

        info!(interface = %self.config.interface, "Live pcap capture started");
        self.live_capture_loop(cap, tx)
    }

    /// Inner receive loop for live captures.
    ///
    /// Runs until the packet channel closes or a non-recoverable error occurs.
    /// On `TimeoutExpired`, checks whether the channel is still alive before
    /// looping, allowing graceful shutdown without waiting for the next packet.
    /// Emits periodic kernel capture statistics when `stats_interval > 0`.
    fn live_capture_loop(
        &self,
        mut cap: Capture<pcap::Active>,
        tx: mpsc::Sender<RawPacket>,
    ) -> anyhow::Result<()> {
        let stats_interval = self.config.pcap.stats_interval;
        let mut count: u64 = 0;

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    count += 1;
                    let raw = build_raw_packet(&packet);

                    if tx.blocking_send(raw).is_err() {
                        info!(
                            packets = count,
                            "Packet channel closed — stopping live capture"
                        );
                        break;
                    }

                    // Emit periodic kernel capture statistics.
                    if stats_interval > 0 && count % stats_interval == 0 {
                        match cap.stats() {
                            Ok(s) => info!(
                                received   = s.received,
                                dropped    = s.dropped,
                                if_dropped = s.if_dropped,
                                "pcap capture statistics"
                            ),
                            Err(e) => debug!("Failed to read pcap stats: {e}"),
                        }
                    }
                }

                // Read timeout expired — check channel liveness and retry.
                // This allows the loop to detect a closed channel promptly
                // without waiting for the next packet to arrive.
                Err(pcap::Error::TimeoutExpired) => {
                    if tx.is_closed() {
                        info!(
                            packets = count,
                            "Packet channel closed — stopping live capture"
                        );
                        break;
                    }
                    // Channel still open; keep capturing.
                }

                Err(e) => {
                    error!("Live capture error: {e}");
                    return Err(e.into());
                }
            }
        }

        Ok(())
    }

    // ── Offline replay ────────────────────────────────────────────────────────

    /// Replay packets from an offline `.pcap` file.
    ///
    /// Reads packets sequentially until EOF (`NoMorePackets`) or the downstream
    /// channel closes.  An optional BPF filter can be applied to skip
    /// irrelevant packets.  Original capture timestamps are preserved.
    ///
    /// This mode is useful for:
    /// * Unit and integration testing without a live network interface.
    /// * Forensic re-analysis of previously captured traffic.
    /// * CI/CD pipelines where capturing live traffic is impractical.
    fn run_offline(&self, path: &str, tx: mpsc::Sender<RawPacket>) -> anyhow::Result<()> {
        info!(file = %path, "Opening offline pcap file for replay");

        let mut cap = Capture::from_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to open pcap file '{}': {e}", path))?;

        if !self.config.bpf_filter.is_empty() {
            cap.filter(&self.config.bpf_filter, true)?;
            debug!(filter = %self.config.bpf_filter, "BPF filter applied to pcap file");
        }

        let mut count: u64 = 0;

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    count += 1;
                    let raw = build_raw_packet(&packet);

                    if tx.blocking_send(raw).is_err() {
                        info!(
                            packets = count,
                            "Packet channel closed — stopping offline replay"
                        );
                        break;
                    }
                }

                // End of file — normal termination for offline replay.
                Err(pcap::Error::NoMorePackets) => {
                    info!(packets = count, file = %path, "Offline pcap replay complete");
                    break;
                }

                Err(e) => {
                    error!(file = %path, "Offline pcap read error: {e}");
                    return Err(anyhow::anyhow!("pcap read error in '{}': {e}", path));
                }
            }
        }

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CaptureConfig;

    // ── Timestamp conversion ──────────────────────────────────────────────────

    #[test]
    fn test_ts_epoch_zero() {
        let dt = ts_to_datetime(0, 0);
        assert_eq!(dt.timestamp(), 0);
        assert_eq!(dt.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn test_ts_one_second() {
        let dt = ts_to_datetime(1, 0);
        assert_eq!(dt.timestamp(), 1);
        assert_eq!(dt.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn test_ts_half_second() {
        // 500 000 µs → 500 000 000 ns (0.5 s)
        let dt = ts_to_datetime(1_000_000, 500_000);
        assert_eq!(dt.timestamp(), 1_000_000);
        assert_eq!(dt.timestamp_subsec_nanos(), 500_000_000);
    }

    #[test]
    fn test_ts_microsecond_precision() {
        // 123 456 µs → 123 456 000 ns
        let dt = ts_to_datetime(1_000_000, 123_456);
        assert_eq!(dt.timestamp(), 1_000_000);
        assert_eq!(dt.timestamp_subsec_nanos(), 123_456_000);
    }

    #[test]
    fn test_ts_max_microseconds() {
        // 999 999 µs (one below the cap) — should not be clamped.
        let dt = ts_to_datetime(0, 999_999);
        assert_eq!(dt.timestamp_subsec_nanos(), 999_999_000);
    }

    #[test]
    fn test_ts_overflow_microseconds_clamped() {
        // tv_usec = 1 000 000 is out of range; must be clamped to 999 999.
        // The call must not panic and must return a valid DateTime.
        let dt = ts_to_datetime(1, 1_000_000);
        let _ = dt.timestamp(); // just assert no panic
    }

    #[test]
    fn test_ts_negative_usec_clamped_to_zero() {
        // Malformed pcap may have negative tv_usec; clamp to 0.
        let dt = ts_to_datetime(1, -1);
        assert_eq!(dt.timestamp_subsec_nanos(), 0);
    }

    #[test]
    fn test_ts_large_positive_seconds() {
        // Unix timestamp well into the 21st century.
        let dt = ts_to_datetime(2_000_000_000, 0);
        assert_eq!(dt.timestamp(), 2_000_000_000);
    }

    // ── PcapCapture constructor ───────────────────────────────────────────────

    #[test]
    fn test_pcap_capture_new_does_not_panic() {
        let cfg = CaptureConfig::default();
        let _cap = PcapCapture::new(&cfg);
    }

    #[test]
    fn test_pcap_capture_stores_config() {
        let mut cfg = CaptureConfig::default();
        cfg.pcap.timeout_ms = 2_000;
        cfg.pcap.stats_interval = 5_000;
        let cap = PcapCapture::new(&cfg);
        assert_eq!(cap.config.pcap.timeout_ms, 2_000);
        assert_eq!(cap.config.pcap.stats_interval, 5_000);
    }

    // ── Mode dispatch (offline vs live) ──────────────────────────────────────

    #[test]
    fn test_run_blocking_offline_nonexistent_file() {
        // An offline path that does not exist must produce an error mentioning
        // the filename — not silently fall through to live capture.
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut cfg = CaptureConfig::default();
        cfg.pcap.read_file = Some("/nonexistent/capture_xyz_test.pcap".to_string());
        let cap = PcapCapture::new(&cfg);
        let result = cap.run_blocking(tx);
        assert!(result.is_err(), "Expected error for missing pcap file");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("capture_xyz_test.pcap") || msg.contains("nonexistent"),
            "Error message should reference the configured file path: {msg}"
        );
    }

    #[test]
    fn test_run_blocking_empty_read_file_routes_to_live() {
        // An empty `read_file` string must not attempt to open a pcap file.
        // The live path will fail at device enumeration or opening — but the
        // error must not mention a .pcap file path.
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut cfg = CaptureConfig::default();
        cfg.pcap.read_file = Some(String::new());
        let cap = PcapCapture::new(&cfg);
        let result = cap.run_blocking(tx);
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains(".pcap"),
                "Empty read_file must not trigger offline mode: {msg}"
            );
        }
    }

    #[test]
    fn test_run_blocking_none_read_file_routes_to_live() {
        // `None` read_file must not attempt to open a pcap file.
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut cfg = CaptureConfig::default();
        cfg.pcap.read_file = None;
        let cap = PcapCapture::new(&cfg);
        let result = cap.run_blocking(tx);
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains(".pcap"),
                "None read_file must not trigger offline mode: {msg}"
            );
        }
    }
}
