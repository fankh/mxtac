//! Configuration module for MxWatch NDR agent.

use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub parsers: ParsersConfig,
    #[serde(default)]
    pub detectors: DetectorsConfig,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub resources: ResourceLimitsConfig,
    #[serde(default)]
    pub health: HealthConfig,
}

// ---------------------------------------------------------------------------
// Sub-sections
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_agent_name")]
    pub name: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_agent_name() -> String {
    "mxwatch".into()
}
fn default_log_level() -> String {
    "info".into()
}

// -- Capture -----------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureConfig {
    #[serde(default = "default_interface")]
    pub interface: String,
    #[serde(default = "default_snaplen")]
    pub snaplen: i32,
    #[serde(default = "default_true")]
    pub promiscuous: bool,
    #[serde(default = "default_bpf_filter")]
    pub bpf_filter: String,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: i32,
    /// Use AF_PACKET + MMAP zero-copy capture instead of libpcap (Linux only).
    #[serde(default)]
    pub use_afpacket: bool,
    /// AF_PACKET ring-buffer tuning (only used when `use_afpacket = true`).
    #[serde(default)]
    pub afpacket: AfPacketConfig,
    /// libpcap-specific tuning (only used when `use_afpacket = false`).
    #[serde(default)]
    pub pcap: PcapConfig,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: default_interface(),
            snaplen: default_snaplen(),
            promiscuous: true,
            bpf_filter: default_bpf_filter(),
            buffer_size: default_buffer_size(),
            use_afpacket: false,
            afpacket: AfPacketConfig::default(),
            pcap: PcapConfig::default(),
        }
    }
}

fn default_interface() -> String {
    "eth0".into()
}
fn default_snaplen() -> i32 {
    65535
}
fn default_bpf_filter() -> String {
    "tcp or udp".into()
}
fn default_buffer_size() -> i32 {
    10_000
}

// -- AF_PACKET ring-buffer config --------------------------------------------

/// Tuning parameters for the `TPACKET_V3` MMAP ring buffer.
///
/// Sensible defaults work for most deployments; adjust only when profiling
/// shows packet loss at the capture layer.
#[derive(Debug, Clone, Deserialize)]
pub struct AfPacketConfig {
    /// Size of each ring-buffer block in bytes.
    ///
    /// Must be a power of two and at least one system page size (4 096 bytes).
    /// Larger blocks reduce the number of kernel hand-offs per second.
    #[serde(default = "default_afpacket_block_size")]
    pub block_size: usize,

    /// Number of blocks in the ring buffer.
    ///
    /// Total ring memory = `block_size × block_count`.  More blocks provide a
    /// larger burst buffer at the cost of higher memory usage.
    #[serde(default = "default_afpacket_block_count")]
    pub block_count: usize,

    /// Maximum expected frame size in bytes (used to compute `tp_frame_nr`).
    ///
    /// Set to at least `TPACKET_ALIGN(sizeof(tpacket3_hdr)) + snaplen`
    /// (≈ 48 + your MTU).  The default of 2 048 bytes handles standard
    /// Ethernet frames.
    #[serde(default = "default_afpacket_frame_size")]
    pub frame_size: usize,

    /// Block retire timeout in milliseconds (`tp_retire_blk_tov`).
    ///
    /// When non-zero, the kernel flushes a partially filled block after this
    /// many milliseconds, bounding capture latency at low packet rates.
    #[serde(default = "default_afpacket_retire_tov")]
    pub block_retire_tov_ms: u32,
}

impl Default for AfPacketConfig {
    fn default() -> Self {
        Self {
            block_size: default_afpacket_block_size(),
            block_count: default_afpacket_block_count(),
            frame_size: default_afpacket_frame_size(),
            block_retire_tov_ms: default_afpacket_retire_tov(),
        }
    }
}

fn default_afpacket_block_size() -> usize {
    1 << 20 // 1 MiB — power-of-two, fits 512 standard Ethernet frames
}
fn default_afpacket_block_count() -> usize {
    64 // 64 MiB total ring buffer
}
fn default_afpacket_frame_size() -> usize {
    2048 // covers standard MTU (1500) + tpacket3_hdr (48) + headroom
}
fn default_afpacket_retire_tov() -> u32 {
    60 // retire partial blocks after 60 ms
}

// -- libpcap tuning ----------------------------------------------------------

/// Tuning parameters for the libpcap capture backend.
///
/// Applied when `use_afpacket = false` (the default) or on non-Linux platforms.
#[derive(Debug, Clone, Deserialize)]
pub struct PcapConfig {
    /// Read timeout in milliseconds.
    ///
    /// `0` blocks indefinitely until a packet arrives (libpcap default).
    /// A non-zero value (e.g. `1000`) enables periodic wakeups so the agent
    /// can detect when the downstream processing pipeline has shut down and
    /// exit gracefully without waiting for the next packet.
    #[serde(default = "default_pcap_timeout_ms")]
    pub timeout_ms: i32,

    /// Path to an offline `.pcap` file for replay.
    ///
    /// When set to a non-empty path, MxWatch replays packets from the file
    /// instead of opening a live interface.  Useful for testing, forensic
    /// analysis, and CI pipelines.  When `None` or empty, live capture is used.
    #[serde(default)]
    pub read_file: Option<String>,

    /// Log capture statistics every N packets (`0` = disabled).
    ///
    /// Requests kernel-level receive and drop counts from libpcap and emits
    /// them at `info` level.  Helps detect packet loss due to ring-buffer
    /// overflow.
    #[serde(default = "default_pcap_stats_interval")]
    pub stats_interval: u64,
}

impl Default for PcapConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_pcap_timeout_ms(),
            read_file: None,
            stats_interval: default_pcap_stats_interval(),
        }
    }
}

fn default_pcap_timeout_ms() -> i32 {
    1_000 // 1-second read timeout for graceful shutdown handling
}
fn default_pcap_stats_interval() -> u64 {
    10_000 // log stats every 10 000 packets
}

// -- Parsers -----------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ParsersConfig {
    #[serde(default)]
    pub tcp: TcpParserConfig,
    #[serde(default)]
    pub udp: UdpParserConfig,
    #[serde(default)]
    pub dns: DnsParserConfig,
    #[serde(default)]
    pub http: HttpParserConfig,
    #[serde(default)]
    pub tls: TlsParserConfig,
    #[serde(default)]
    pub smb: SmbParserConfig,
    #[serde(default)]
    pub ssh: SshParserConfig,
    #[serde(default)]
    pub rdp: RdpParserConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpParserConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}
impl Default for TcpParserConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UdpParserConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}
impl Default for UdpParserConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsParserConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
}
impl Default for DnsParserConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy_threshold: 4.5,
        }
    }
}

fn default_entropy_threshold() -> f64 {
    4.5
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpParserConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub suspicious_patterns: Vec<String>,
}
impl Default for HttpParserConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suspicious_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsParserConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}
impl Default for TlsParserConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmbParserConfig {
    /// Enable or disable SMB2/CIFS parsing on port 445.
    #[serde(default = "default_true")]
    pub enabled: bool,
}
impl Default for SmbParserConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshParserConfig {
    /// Enable or disable SSH banner and binary-packet parsing on port 22.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Software version substrings that trigger a suspicion alert
    /// (case-insensitive substring match, e.g., `"paramiko"`, `"libssh"`).
    #[serde(default)]
    pub software_blocklist: Vec<String>,
}
impl Default for SshParserConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            software_blocklist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RdpParserConfig {
    /// Enable or disable RDP connection-request parsing on port 3389.
    #[serde(default = "default_true")]
    pub enabled: bool,
}
impl Default for RdpParserConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// -- Detectors ---------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DetectorsConfig {
    #[serde(default)]
    pub dns_tunnel: DnsTunnelDetectorConfig,
    #[serde(default)]
    pub port_scan: PortScanDetectorConfig,
    #[serde(default)]
    pub proto_anomaly: ProtoAnomalyDetectorConfig,
    #[serde(default)]
    pub c2_beacon: C2BeaconDetectorConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsTunnelDetectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default = "default_max_label_len")]
    pub max_label_length: usize,
}
impl Default for DnsTunnelDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy_threshold: 4.5,
            max_label_length: 100,
        }
    }
}

fn default_max_label_len() -> usize {
    100
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortScanDetectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_scan_threshold")]
    pub threshold_ports: usize,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}
impl Default for PortScanDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_ports: 20,
            window_secs: 60,
        }
    }
}

fn default_scan_threshold() -> usize {
    20
}
fn default_window_secs() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtoAnomalyDetectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}
impl Default for ProtoAnomalyDetectorConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct C2BeaconDetectorConfig {
    /// Enable or disable the detector.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Expected interval between beacon callbacks, in seconds.
    ///
    /// Used to set the debounce window that suppresses burst packets within a
    /// single connection from being counted as separate beacon events.
    #[serde(default = "default_beacon_interval_secs")]
    pub beacon_interval_secs: f64,
    /// Allowed timing jitter as a percentage of the beacon interval.
    ///
    /// This value is used both as the debounce threshold
    /// (`min_gap = interval × (1 − jitter/100)`) and as the coefficient-of-
    /// variation limit for the periodicity check.  A value of `20.0` means
    /// ±20 % jitter is tolerated.
    #[serde(default = "default_beacon_jitter_pct")]
    pub jitter_pct: f64,
    /// Minimum number of debounced samples before an alert is considered.
    #[serde(default = "default_beacon_min_packets")]
    pub min_packets_for_alert: u32,
    /// Remove flow state after this many seconds of inactivity.
    #[serde(default = "default_beacon_max_flow_age")]
    pub max_flow_age_secs: u64,
}

impl Default for C2BeaconDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            beacon_interval_secs: 60.0,
            jitter_pct: 20.0,
            min_packets_for_alert: 5,
            max_flow_age_secs: 3600,
        }
    }
}

fn default_beacon_interval_secs() -> f64 {
    60.0
}
fn default_beacon_jitter_pct() -> f64 {
    20.0
}
fn default_beacon_min_packets() -> u32 {
    5
}
fn default_beacon_max_flow_age() -> u64 {
    3600
}

// -- Transport ---------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct TransportConfig {
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_ms: u64,
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            endpoint: default_endpoint(),
            api_key: String::new(),
            batch_size: 100,
            flush_interval_ms: 5000,
            retry_attempts: 3,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_endpoint() -> String {
    "http://127.0.0.1:8080/api/v1/ingest/ocsf".into()
}
fn default_batch_size() -> usize {
    100
}
fn default_flush_interval() -> u64 {
    5000
}
fn default_retry_attempts() -> u32 {
    3
}

// -- Health ------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct HealthConfig {
    #[serde(default = "default_health_addr")]
    pub listen_addr: String,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_health_addr(),
        }
    }
}

fn default_health_addr() -> String {
    "0.0.0.0:9002".into()
}

// -- Resource limits ---------------------------------------------------------

/// Resource consumption limits for the MxWatch process.
///
/// When `enabled` is true, a background task samples CPU usage and RSS every
/// `check_interval_ms` milliseconds and emits warnings when either limit is
/// exceeded.  The packet-processing loop also reads the latest snapshot and
/// applies backpressure (brief sleep) to stay within the thresholds.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceLimitsConfig {
    /// Enable resource monitoring and enforcement.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum CPU usage as a percentage of one logical core (e.g. `5.0` = 5 %).
    ///
    /// When the measured CPU% exceeds this value the packet-processing loop
    /// inserts a short adaptive sleep to reduce throughput.
    #[serde(default = "default_max_cpu_pct")]
    pub max_cpu_pct: f64,

    /// Maximum Resident Set Size in mebibytes (e.g. `120` = 120 MiB).
    ///
    /// When RSS exceeds this value the monitor emits a warning and the
    /// packet-processing loop skips processing cycles to allow memory pressure
    /// to subside.
    #[serde(default = "default_max_ram_mb")]
    pub max_ram_mb: u64,

    /// Sampling interval in milliseconds.
    ///
    /// Lower values give more responsive throttling at the cost of slightly
    /// more overhead from `/proc` reads.
    #[serde(default = "default_check_interval_ms")]
    pub check_interval_ms: u64,
}

impl Default for ResourceLimitsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_cpu_pct: default_max_cpu_pct(),
            max_ram_mb: default_max_ram_mb(),
            check_interval_ms: default_check_interval_ms(),
        }
    }
}

fn default_max_cpu_pct() -> f64 {
    5.0
}
fn default_max_ram_mb() -> u64 {
    120
}
fn default_check_interval_ms() -> u64 {
    1_000
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn default_config() -> Self {
        Self {
            agent: AgentConfig {
                name: "mxwatch".into(),
                log_level: "info".into(),
            },
            capture: CaptureConfig::default(),
            parsers: ParsersConfig::default(),
            detectors: DetectorsConfig::default(),
            transport: TransportConfig::default(),
            resources: ResourceLimitsConfig::default(),
            health: HealthConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const MINIMAL_TOML: &str = r#"
[agent]
name = "test-watch"
log_level = "debug"
"#;

    fn write_temp_toml(content: &str) -> (tempfile::NamedTempFile, String) {
        let mut f = tempfile::NamedTempFile::new().expect("tmp file");
        f.write_all(content.as_bytes()).expect("write");
        let path = f.path().to_str().unwrap().to_owned();
        (f, path)
    }

    // -----------------------------------------------------------------------
    // Default values
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_agent() {
        let cfg = Config::default_config();
        assert_eq!(cfg.agent.log_level, "info");
        assert_eq!(cfg.agent.name, "mxwatch");
    }

    #[test]
    fn test_default_capture_values() {
        let cap = CaptureConfig::default();
        assert_eq!(cap.interface, "eth0");
        assert_eq!(cap.snaplen, 65535);
        assert!(cap.promiscuous);
        assert_eq!(cap.bpf_filter, "tcp or udp");
        assert_eq!(cap.buffer_size, 10_000);
        assert!(!cap.use_afpacket);
    }

    #[test]
    fn test_default_afpacket_config() {
        let af = AfPacketConfig::default();
        assert_eq!(af.block_size, 1 << 20);
        assert_eq!(af.block_count, 64);
        assert_eq!(af.frame_size, 2048);
        assert_eq!(af.block_retire_tov_ms, 60);
        // block_size must be a power of two
        assert!(af.block_size.is_power_of_two());
    }

    #[test]
    fn test_default_transport_values() {
        let t = TransportConfig::default();
        assert_eq!(t.endpoint, "http://127.0.0.1:8080/api/v1/ingest/ocsf");
        assert_eq!(t.batch_size, 100);
        assert_eq!(t.flush_interval_ms, 5000);
        assert_eq!(t.retry_attempts, 3);
        assert!(t.api_key.is_empty());
    }

    #[test]
    fn test_default_dns_tunnel_detector() {
        let d = DnsTunnelDetectorConfig::default();
        assert!(d.enabled);
        assert!((d.entropy_threshold - 4.5).abs() < f64::EPSILON);
        assert_eq!(d.max_label_length, 100);
    }

    #[test]
    fn test_default_port_scan_detector() {
        let d = PortScanDetectorConfig::default();
        assert!(d.enabled);
        assert_eq!(d.threshold_ports, 20);
        assert_eq!(d.window_secs, 60);
    }

    // -----------------------------------------------------------------------
    // TOML parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_minimal_toml() {
        let cfg: Config = toml::from_str(MINIMAL_TOML).expect("parse");
        assert_eq!(cfg.agent.name, "test-watch");
        assert_eq!(cfg.agent.log_level, "debug");
        // Unspecified sections use defaults.
        assert_eq!(cfg.capture.interface, "eth0");
        assert_eq!(cfg.transport.batch_size, 100);
    }

    #[test]
    fn test_parse_transport_section() {
        let toml = r#"
[agent]
name = "prod-watch"

[transport]
endpoint          = "https://mxtac.example.com/api/v1/ingest/ocsf"
api_key           = "tok-secret"
batch_size        = 250
flush_interval_ms = 2000
retry_attempts    = 5
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.transport.endpoint, "https://mxtac.example.com/api/v1/ingest/ocsf");
        assert_eq!(cfg.transport.api_key, "tok-secret");
        assert_eq!(cfg.transport.batch_size, 250);
        assert_eq!(cfg.transport.flush_interval_ms, 2000);
        assert_eq!(cfg.transport.retry_attempts, 5);
    }

    #[test]
    fn test_parse_capture_section() {
        let toml = r#"
[agent]
name = "w"

[capture]
interface   = "ens3"
snaplen     = 1514
promiscuous = false
bpf_filter  = "tcp port 443"
buffer_size = 5000
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.capture.interface, "ens3");
        assert_eq!(cfg.capture.snaplen, 1514);
        assert!(!cfg.capture.promiscuous);
        assert_eq!(cfg.capture.bpf_filter, "tcp port 443");
        assert_eq!(cfg.capture.buffer_size, 5000);
        // use_afpacket defaults to false when not specified
        assert!(!cfg.capture.use_afpacket);
    }

    #[test]
    fn test_parse_afpacket_section() {
        let toml = r#"
[agent]
name = "w"

[capture]
use_afpacket = true

[capture.afpacket]
block_size           = 2097152
block_count          = 32
frame_size           = 4096
block_retire_tov_ms  = 100
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(cfg.capture.use_afpacket);
        assert_eq!(cfg.capture.afpacket.block_size, 2097152);
        assert_eq!(cfg.capture.afpacket.block_count, 32);
        assert_eq!(cfg.capture.afpacket.frame_size, 4096);
        assert_eq!(cfg.capture.afpacket.block_retire_tov_ms, 100);
    }

    #[test]
    fn test_afpacket_defaults_when_section_omitted() {
        let toml = r#"
[agent]
name = "w"

[capture]
use_afpacket = true
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(cfg.capture.use_afpacket);
        // afpacket sub-section should fall back to defaults
        assert_eq!(cfg.capture.afpacket.block_size, 1 << 20);
        assert_eq!(cfg.capture.afpacket.block_count, 64);
        assert_eq!(cfg.capture.afpacket.frame_size, 2048);
        assert_eq!(cfg.capture.afpacket.block_retire_tov_ms, 60);
    }

    #[test]
    fn test_parse_detectors_section() {
        let toml = r#"
[agent]
name = "w"

[detectors.dns_tunnel]
enabled           = true
entropy_threshold = 3.8
max_label_length  = 80

[detectors.port_scan]
enabled         = false
threshold_ports = 10
window_secs     = 30
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(cfg.detectors.dns_tunnel.enabled);
        assert!((cfg.detectors.dns_tunnel.entropy_threshold - 3.8).abs() < f64::EPSILON);
        assert_eq!(cfg.detectors.dns_tunnel.max_label_length, 80);
        assert!(!cfg.detectors.port_scan.enabled);
        assert_eq!(cfg.detectors.port_scan.threshold_ports, 10);
        assert_eq!(cfg.detectors.port_scan.window_secs, 30);
    }

    // -----------------------------------------------------------------------
    // PcapConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_pcap_config() {
        let cfg = CaptureConfig::default();
        assert_eq!(cfg.pcap.timeout_ms, 1_000);
        assert!(cfg.pcap.read_file.is_none());
        assert_eq!(cfg.pcap.stats_interval, 10_000);
    }

    #[test]
    fn test_parse_pcap_section() {
        let toml = r#"
[agent]
name = "w"

[capture.pcap]
timeout_ms     = 500
read_file      = "/tmp/capture.pcap"
stats_interval = 5000
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.capture.pcap.timeout_ms, 500);
        assert_eq!(
            cfg.capture.pcap.read_file.as_deref(),
            Some("/tmp/capture.pcap")
        );
        assert_eq!(cfg.capture.pcap.stats_interval, 5000);
    }

    #[test]
    fn test_pcap_defaults_when_section_omitted() {
        let toml = r#"
[agent]
name = "w"
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.capture.pcap.timeout_ms, 1_000);
        assert!(cfg.capture.pcap.read_file.is_none());
        assert_eq!(cfg.capture.pcap.stats_interval, 10_000);
    }

    #[test]
    fn test_pcap_read_file_absent_is_none() {
        let toml = r#"
[agent]
name = "w"

[capture.pcap]
timeout_ms = 2000
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(cfg.capture.pcap.read_file.is_none());
    }

    #[test]
    fn test_default_c2_beacon_detector() {
        let d = C2BeaconDetectorConfig::default();
        assert!(d.enabled);
        assert!((d.beacon_interval_secs - 60.0).abs() < f64::EPSILON);
        assert!((d.jitter_pct - 20.0).abs() < f64::EPSILON);
        assert_eq!(d.min_packets_for_alert, 5);
        assert_eq!(d.max_flow_age_secs, 3600);
    }

    #[test]
    fn test_parse_c2_beacon_section() {
        let toml = r#"
[agent]
name = "w"

[detectors.c2_beacon]
enabled               = true
beacon_interval_secs  = 30.0
jitter_pct            = 15.0
min_packets_for_alert = 8
max_flow_age_secs     = 7200
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        let d = &cfg.detectors.c2_beacon;
        assert!(d.enabled);
        assert!((d.beacon_interval_secs - 30.0).abs() < f64::EPSILON);
        assert!((d.jitter_pct - 15.0).abs() < f64::EPSILON);
        assert_eq!(d.min_packets_for_alert, 8);
        assert_eq!(d.max_flow_age_secs, 7200);
    }

    #[test]
    fn test_c2_beacon_defaults_when_section_omitted() {
        let toml = r#"
[agent]
name = "w"
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        let d = &cfg.detectors.c2_beacon;
        assert!(d.enabled);
        assert!((d.beacon_interval_secs - 60.0).abs() < f64::EPSILON);
        assert!((d.jitter_pct - 20.0).abs() < f64::EPSILON);
        assert_eq!(d.min_packets_for_alert, 5);
        assert_eq!(d.max_flow_age_secs, 3600);
    }

    #[test]
    fn test_c2_beacon_disabled_via_toml() {
        let toml = r#"
[agent]
name = "w"

[detectors.c2_beacon]
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(!cfg.detectors.c2_beacon.enabled);
    }

    #[test]
    fn test_parse_invalid_toml_returns_error() {
        let result: Result<Config, toml::de::Error> = toml::from_str("not valid toml ][");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // from_file
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_file_reads_agent_section() {
        let (_f, path) = write_temp_toml(MINIMAL_TOML);
        let cfg = Config::from_file(&path).expect("from_file");
        assert_eq!(cfg.agent.name, "test-watch");
        assert_eq!(cfg.agent.log_level, "debug");
    }

    #[test]
    fn test_from_file_nonexistent_returns_io_error() {
        let result = Config::from_file("/nonexistent/path/mxwatch.toml");
        assert!(matches!(result, Err(ConfigError::Io(_))));
    }

    // -----------------------------------------------------------------------
    // ResourceLimitsConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_resource_limits() {
        let r = ResourceLimitsConfig::default();
        assert!(r.enabled);
        assert!((r.max_cpu_pct - 5.0).abs() < f64::EPSILON);
        assert_eq!(r.max_ram_mb, 120);
        assert_eq!(r.check_interval_ms, 1_000);
    }

    #[test]
    fn test_resource_limits_section_omitted_uses_defaults() {
        let toml = r#"
[agent]
name = "w"
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(cfg.resources.enabled);
        assert!((cfg.resources.max_cpu_pct - 5.0).abs() < f64::EPSILON);
        assert_eq!(cfg.resources.max_ram_mb, 120);
        assert_eq!(cfg.resources.check_interval_ms, 1_000);
    }

    #[test]
    fn test_parse_resource_limits_section() {
        let toml = r#"
[agent]
name = "w"

[resources]
enabled           = true
max_cpu_pct       = 3.0
max_ram_mb        = 80
check_interval_ms = 500
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(cfg.resources.enabled);
        assert!((cfg.resources.max_cpu_pct - 3.0).abs() < f64::EPSILON);
        assert_eq!(cfg.resources.max_ram_mb, 80);
        assert_eq!(cfg.resources.check_interval_ms, 500);
    }

    #[test]
    fn test_resource_limits_disabled_via_toml() {
        let toml = r#"
[agent]
name = "w"

[resources]
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!(!cfg.resources.enabled);
        // Other fields fall back to defaults.
        assert!((cfg.resources.max_cpu_pct - 5.0).abs() < f64::EPSILON);
        assert_eq!(cfg.resources.max_ram_mb, 120);
    }

    #[test]
    fn test_resource_limits_custom_cpu_only() {
        let toml = r#"
[agent]
name = "w"

[resources]
max_cpu_pct = 2.5
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert!((cfg.resources.max_cpu_pct - 2.5).abs() < f64::EPSILON);
        // Other fields fall back to defaults.
        assert_eq!(cfg.resources.max_ram_mb, 120);
        assert!(cfg.resources.enabled);
    }

    #[test]
    fn test_default_config_includes_resource_limits() {
        let cfg = Config::default_config();
        assert!(cfg.resources.enabled);
        assert!((cfg.resources.max_cpu_pct - 5.0).abs() < f64::EPSILON);
        assert_eq!(cfg.resources.max_ram_mb, 120);
    }

    // -----------------------------------------------------------------------
    // HealthConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_health_listen_addr_uses_port_9002() {
        let h = HealthConfig::default();
        assert!(
            h.listen_addr.ends_with(":9002"),
            "default listen_addr should end with :9002, got: {}",
            h.listen_addr
        );
    }

    #[test]
    fn test_default_health_listen_addr_binds_all_interfaces() {
        let h = HealthConfig::default();
        assert!(
            h.listen_addr.starts_with("0.0.0.0:"),
            "default listen_addr should bind all interfaces (0.0.0.0), got: {}",
            h.listen_addr
        );
    }

    #[test]
    fn test_default_config_includes_health() {
        let cfg = Config::default_config();
        assert_eq!(cfg.health.listen_addr, "0.0.0.0:9002");
    }

    #[test]
    fn test_parse_health_section() {
        let toml = r#"
[agent]
name = "w"

[health]
listen_addr = "127.0.0.1:9099"
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.health.listen_addr, "127.0.0.1:9099");
    }

    #[test]
    fn test_health_defaults_when_section_omitted() {
        let toml = r#"
[agent]
name = "w"
"#;
        let cfg: Config = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.health.listen_addr, "0.0.0.0:9002");
    }
}
