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
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: default_interface(),
            snaplen: default_snaplen(),
            promiscuous: true,
            bpf_filter: default_bpf_filter(),
            buffer_size: default_buffer_size(),
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

// -- Detectors ---------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DetectorsConfig {
    #[serde(default)]
    pub dns_tunnel: DnsTunnelDetectorConfig,
    #[serde(default)]
    pub port_scan: PortScanDetectorConfig,
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
}
