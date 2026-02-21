//! Configuration module for MxGuard EDR agent.
//!
//! Loads and validates TOML-based configuration from disk.

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
    pub collectors: CollectorsConfig,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub health: HealthConfig,
}

// ---------------------------------------------------------------------------
// Sub-sections
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
    #[serde(default = "default_agent_name")]
    pub name: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_agent_id() -> String {
    String::new()
}
fn default_agent_name() -> String {
    "mxguard".into()
}
fn default_log_level() -> String {
    "info".into()
}

// -- Collectors --------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CollectorsConfig {
    #[serde(default)]
    pub process: ProcessCollectorConfig,
    #[serde(default)]
    pub file: FileCollectorConfig,
    #[serde(default)]
    pub network: NetworkCollectorConfig,
    #[serde(default)]
    pub auth: AuthCollectorConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProcessCollectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_process_interval")]
    pub scan_interval_ms: u64,
}

impl Default for ProcessCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_ms: 2000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileCollectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_watch_paths")]
    pub watch_paths: Vec<String>,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

impl Default for FileCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_paths: default_watch_paths(),
            exclude_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkCollectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_network_interval")]
    pub scan_interval_ms: u64,
}

impl Default for NetworkCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_ms: 5000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthCollectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Log files to tail. Defaults to Debian/Ubuntu and RHEL/CentOS paths.
    #[serde(default = "default_auth_log_paths")]
    pub log_paths: Vec<String>,
    /// How often to poll log files for new lines (milliseconds).
    #[serde(default = "default_auth_poll_interval")]
    pub poll_interval_ms: u64,
}

impl Default for AuthCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_paths: default_auth_log_paths(),
            poll_interval_ms: default_auth_poll_interval(),
        }
    }
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

// ---------------------------------------------------------------------------
// Default helpers
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}
fn default_process_interval() -> u64 {
    2000
}
fn default_network_interval() -> u64 {
    5000
}
fn default_watch_paths() -> Vec<String> {
    vec!["/etc".into(), "/usr/bin".into(), "/tmp".into()]
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
fn default_health_addr() -> String {
    "0.0.0.0:9001".into()
}
fn default_auth_log_paths() -> Vec<String> {
    // Debian/Ubuntu: /var/log/auth.log
    // RHEL/CentOS/Fedora: /var/log/secure
    vec!["/var/log/auth.log".into(), "/var/log/secure".into()]
}
fn default_auth_poll_interval() -> u64 {
    2000
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl Config {
    /// Load configuration from a TOML file on disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Return a sensible default configuration (useful when no file is given).
    pub fn default_config() -> Self {
        Self {
            agent: AgentConfig {
                agent_id: String::new(),
                name: "mxguard".into(),
                log_level: "info".into(),
            },
            collectors: CollectorsConfig::default(),
            transport: TransportConfig::default(),
            health: HealthConfig::default(),
        }
    }
}
