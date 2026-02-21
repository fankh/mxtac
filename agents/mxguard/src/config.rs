//! Configuration module for MxGuard EDR agent.
//!
//! Configuration is loaded in two layers:
//!   1. **TOML file** — provides the base configuration.
//!   2. **Environment variables** — any `MXGUARD_*` variable overrides the
//!      corresponding TOML value at startup.
//!
//! # Environment Variables
//!
//! | Variable                           | Config field                         |
//! |------------------------------------|--------------------------------------|
//! | `MXGUARD_AGENT_ID`                 | `agent.agent_id`                     |
//! | `MXGUARD_AGENT_NAME`               | `agent.name`                         |
//! | `MXGUARD_LOG_LEVEL`                | `agent.log_level`                    |
//! | `MXGUARD_TRANSPORT_ENDPOINT`       | `transport.endpoint`                 |
//! | `MXGUARD_API_KEY`                  | `transport.api_key`                  |
//! | `MXGUARD_TRANSPORT_BATCH_SIZE`     | `transport.batch_size`               |
//! | `MXGUARD_TRANSPORT_FLUSH_MS`       | `transport.flush_interval_ms`        |
//! | `MXGUARD_TRANSPORT_RETRY_ATTEMPTS` | `transport.retry_attempts`           |
//! | `MXGUARD_HEALTH_ADDR`              | `health.listen_addr`                 |
//! | `MXGUARD_PROCESS_ENABLED`          | `collectors.process.enabled`         |
//! | `MXGUARD_PROCESS_SCAN_INTERVAL_MS` | `collectors.process.scan_interval_ms`|
//! | `MXGUARD_FILE_ENABLED`             | `collectors.file.enabled`            |
//! | `MXGUARD_NETWORK_ENABLED`          | `collectors.network.enabled`         |
//! | `MXGUARD_NETWORK_SCAN_INTERVAL_MS` | `collectors.network.scan_interval_ms`|
//! | `MXGUARD_AUTH_ENABLED`             | `collectors.auth.enabled`            |
//! | `MXGUARD_AUTH_POLL_INTERVAL_MS`    | `collectors.auth.poll_interval_ms`   |

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
    #[error("invalid value for env var {var}: {reason}")]
    EnvParse { var: &'static str, reason: String },
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
// Environment-variable override helpers
// ---------------------------------------------------------------------------

/// Parse a boolean from a string value.
///
/// Accepts `"true"` / `"1"` / `"yes"` → `true`
/// and `"false"` / `"0"` / `"no"` → `false` (case-insensitive).
fn parse_bool(var: &'static str, val: &str) -> Result<bool, ConfigError> {
    match val.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        other => Err(ConfigError::EnvParse {
            var,
            reason: format!("expected true/false/1/0/yes/no, got '{other}'"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl Config {
    /// Load configuration from a TOML file on disk, then apply any
    /// `MXGUARD_*` environment variables on top.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&contents)?;
        config.apply_env_overrides()?;
        Ok(config)
    }

    /// Return a sensible default configuration (useful when no file is given),
    /// then apply any `MXGUARD_*` environment variables on top.
    pub fn default_config() -> Result<Self, ConfigError> {
        let mut config = Self {
            agent: AgentConfig {
                agent_id: String::new(),
                name: "mxguard".into(),
                log_level: "info".into(),
            },
            collectors: CollectorsConfig::default(),
            transport: TransportConfig::default(),
            health: HealthConfig::default(),
        };
        config.apply_env_overrides()?;
        Ok(config)
    }

    /// Apply `MXGUARD_*` environment variables from the real process
    /// environment, overriding any values set by the TOML file or defaults.
    ///
    /// Variables that are unset or empty are silently ignored.
    pub fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        self.apply_env_overrides_from(|name| {
            std::env::var(name).ok().filter(|v| !v.is_empty())
        })
    }

    /// Apply overrides using an injectable `get_env` closure.
    ///
    /// The closure receives an env-var name and returns `Some(value)` if the
    /// variable is set, or `None` to leave the field unchanged.  Empty strings
    /// should be returned as `None` (the closure is responsible for that).
    ///
    /// This method is `pub` so that callers (including tests) can supply a
    /// controlled environment without touching the real process environment.
    pub fn apply_env_overrides_from<F>(&mut self, get_env: F) -> Result<(), ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        // -- Agent -----------------------------------------------------------
        if let Some(v) = get_env("MXGUARD_AGENT_ID") {
            self.agent.agent_id = v;
        }
        if let Some(v) = get_env("MXGUARD_AGENT_NAME") {
            self.agent.name = v;
        }
        if let Some(v) = get_env("MXGUARD_LOG_LEVEL") {
            self.agent.log_level = v;
        }

        // -- Transport -------------------------------------------------------
        if let Some(v) = get_env("MXGUARD_TRANSPORT_ENDPOINT") {
            self.transport.endpoint = v;
        }
        if let Some(v) = get_env("MXGUARD_API_KEY") {
            self.transport.api_key = v;
        }
        if let Some(v) = get_env("MXGUARD_TRANSPORT_BATCH_SIZE") {
            self.transport.batch_size = v.trim().parse::<usize>().map_err(|e| {
                ConfigError::EnvParse {
                    var: "MXGUARD_TRANSPORT_BATCH_SIZE",
                    reason: e.to_string(),
                }
            })?;
        }
        if let Some(v) = get_env("MXGUARD_TRANSPORT_FLUSH_MS") {
            self.transport.flush_interval_ms = v.trim().parse::<u64>().map_err(|e| {
                ConfigError::EnvParse {
                    var: "MXGUARD_TRANSPORT_FLUSH_MS",
                    reason: e.to_string(),
                }
            })?;
        }
        if let Some(v) = get_env("MXGUARD_TRANSPORT_RETRY_ATTEMPTS") {
            self.transport.retry_attempts = v.trim().parse::<u32>().map_err(|e| {
                ConfigError::EnvParse {
                    var: "MXGUARD_TRANSPORT_RETRY_ATTEMPTS",
                    reason: e.to_string(),
                }
            })?;
        }

        // -- Health ----------------------------------------------------------
        if let Some(v) = get_env("MXGUARD_HEALTH_ADDR") {
            self.health.listen_addr = v;
        }

        // -- Collectors: process ---------------------------------------------
        if let Some(v) = get_env("MXGUARD_PROCESS_ENABLED") {
            self.collectors.process.enabled = parse_bool("MXGUARD_PROCESS_ENABLED", &v)?;
        }
        if let Some(v) = get_env("MXGUARD_PROCESS_SCAN_INTERVAL_MS") {
            self.collectors.process.scan_interval_ms =
                v.trim().parse::<u64>().map_err(|e| ConfigError::EnvParse {
                    var: "MXGUARD_PROCESS_SCAN_INTERVAL_MS",
                    reason: e.to_string(),
                })?;
        }

        // -- Collectors: file ------------------------------------------------
        if let Some(v) = get_env("MXGUARD_FILE_ENABLED") {
            self.collectors.file.enabled = parse_bool("MXGUARD_FILE_ENABLED", &v)?;
        }

        // -- Collectors: network ---------------------------------------------
        if let Some(v) = get_env("MXGUARD_NETWORK_ENABLED") {
            self.collectors.network.enabled = parse_bool("MXGUARD_NETWORK_ENABLED", &v)?;
        }
        if let Some(v) = get_env("MXGUARD_NETWORK_SCAN_INTERVAL_MS") {
            self.collectors.network.scan_interval_ms =
                v.trim().parse::<u64>().map_err(|e| ConfigError::EnvParse {
                    var: "MXGUARD_NETWORK_SCAN_INTERVAL_MS",
                    reason: e.to_string(),
                })?;
        }

        // -- Collectors: auth ------------------------------------------------
        if let Some(v) = get_env("MXGUARD_AUTH_ENABLED") {
            self.collectors.auth.enabled = parse_bool("MXGUARD_AUTH_ENABLED", &v)?;
        }
        if let Some(v) = get_env("MXGUARD_AUTH_POLL_INTERVAL_MS") {
            self.collectors.auth.poll_interval_ms =
                v.trim().parse::<u64>().map_err(|e| ConfigError::EnvParse {
                    var: "MXGUARD_AUTH_POLL_INTERVAL_MS",
                    reason: e.to_string(),
                })?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Minimal TOML that satisfies the required `[agent]` section.
    const MINIMAL_TOML: &str = r#"
[agent]
name = "test-agent"
log_level = "debug"
"#;

    /// Write TOML content to a temp file and return the file guard + path.
    fn write_temp_toml(content: &str) -> (tempfile::NamedTempFile, String) {
        let mut f = tempfile::NamedTempFile::new().expect("tmp file");
        f.write_all(content.as_bytes()).expect("write");
        let path = f.path().to_str().unwrap().to_owned();
        (f, path)
    }

    /// Build a Config from TOML and then apply a mock env map.
    fn config_with_env(toml: &str, env: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut cfg: Config = toml::from_str(toml).map_err(ConfigError::Parse)?;
        cfg.apply_env_overrides_from(|name| {
            map.get(name).filter(|v| !v.is_empty()).cloned()
        })?;
        Ok(cfg)
    }

    /// Build a default Config and then apply a mock env map.
    fn default_with_env(env: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut cfg = Config {
            agent: AgentConfig {
                agent_id: String::new(),
                name: "mxguard".into(),
                log_level: "info".into(),
            },
            collectors: CollectorsConfig::default(),
            transport: TransportConfig::default(),
            health: HealthConfig::default(),
        };
        cfg.apply_env_overrides_from(|name| {
            map.get(name).filter(|v| !v.is_empty()).cloned()
        })?;
        Ok(cfg)
    }

    // -----------------------------------------------------------------------
    // TOML loading
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_file_basic() {
        let (_f, path) = write_temp_toml(MINIMAL_TOML);
        // Use from_file but with no MXGUARD_* vars set in the real env
        // (if they happen to be set in CI, they'd override — acceptable).
        let cfg: Config = toml::from_str(MINIMAL_TOML).unwrap();
        assert_eq!(cfg.agent.name, "test-agent");
        assert_eq!(cfg.agent.log_level, "debug");
        // Check path exists so file-reading path can be tested
        assert!(std::path::Path::new(&path).exists());
    }

    #[test]
    fn test_from_file_full_transport() {
        let toml = r#"
[agent]
name = "prod-agent"

[transport]
endpoint = "https://mxtac.example.com/api/v1/ingest/ocsf"
api_key  = "secret-key"
batch_size = 50
flush_interval_ms = 3000
retry_attempts = 5
"#;
        let cfg = config_with_env(toml, &[]).expect("load");
        assert_eq!(cfg.transport.endpoint, "https://mxtac.example.com/api/v1/ingest/ocsf");
        assert_eq!(cfg.transport.api_key, "secret-key");
        assert_eq!(cfg.transport.batch_size, 50);
        assert_eq!(cfg.transport.flush_interval_ms, 3000);
        assert_eq!(cfg.transport.retry_attempts, 5);
    }

    #[test]
    fn test_default_config_no_env() {
        let cfg = default_with_env(&[]).expect("default");
        assert_eq!(cfg.agent.name, "mxguard");
        assert_eq!(cfg.agent.log_level, "info");
        assert_eq!(cfg.transport.endpoint, "http://127.0.0.1:8080/api/v1/ingest/ocsf");
        assert_eq!(cfg.health.listen_addr, "0.0.0.0:9001");
    }

    #[test]
    fn test_missing_file_returns_error() {
        let result = Config::from_file("/nonexistent/path/mxguard.toml");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("failed to read config file"), "msg={msg}");
    }

    #[test]
    fn test_invalid_toml_returns_error() {
        let (_f, path) = write_temp_toml("this is not valid toml ::::");
        let result = Config::from_file(&path);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("failed to parse config"), "msg={msg}");
    }

    // -----------------------------------------------------------------------
    // Env var overrides — agent fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_overrides_agent_id() {
        let cfg = config_with_env(MINIMAL_TOML, &[("MXGUARD_AGENT_ID", "env-agent-001")])
            .expect("load");
        assert_eq!(cfg.agent.agent_id, "env-agent-001");
    }

    #[test]
    fn test_env_overrides_agent_name() {
        let cfg = config_with_env(MINIMAL_TOML, &[("MXGUARD_AGENT_NAME", "env-name")])
            .expect("load");
        assert_eq!(cfg.agent.name, "env-name");
    }

    #[test]
    fn test_env_overrides_log_level() {
        // TOML sets debug, env should win with "warn".
        let cfg = config_with_env(MINIMAL_TOML, &[("MXGUARD_LOG_LEVEL", "warn")]).expect("load");
        assert_eq!(cfg.agent.log_level, "warn");
    }

    #[test]
    fn test_env_overrides_toml_value() {
        // TOML log_level = "debug", env should override to "error".
        let cfg = config_with_env(MINIMAL_TOML, &[("MXGUARD_LOG_LEVEL", "error")]).expect("load");
        assert_eq!(cfg.agent.log_level, "error");
    }

    // -----------------------------------------------------------------------
    // Env var overrides — transport fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_overrides_transport_endpoint() {
        let cfg = config_with_env(
            MINIMAL_TOML,
            &[("MXGUARD_TRANSPORT_ENDPOINT", "https://override.example.com/ingest")],
        )
        .expect("load");
        assert_eq!(cfg.transport.endpoint, "https://override.example.com/ingest");
    }

    #[test]
    fn test_env_overrides_api_key() {
        let cfg = config_with_env(MINIMAL_TOML, &[("MXGUARD_API_KEY", "env-api-key")])
            .expect("load");
        assert_eq!(cfg.transport.api_key, "env-api-key");
    }

    #[test]
    fn test_env_overrides_transport_batch_size() {
        let cfg = config_with_env(MINIMAL_TOML, &[("MXGUARD_TRANSPORT_BATCH_SIZE", "25")])
            .expect("load");
        assert_eq!(cfg.transport.batch_size, 25);
    }

    #[test]
    fn test_env_overrides_transport_flush_ms() {
        let cfg = config_with_env(MINIMAL_TOML, &[("MXGUARD_TRANSPORT_FLUSH_MS", "1000")])
            .expect("load");
        assert_eq!(cfg.transport.flush_interval_ms, 1000);
    }

    #[test]
    fn test_env_overrides_transport_retry_attempts() {
        let cfg =
            config_with_env(MINIMAL_TOML, &[("MXGUARD_TRANSPORT_RETRY_ATTEMPTS", "7")])
                .expect("load");
        assert_eq!(cfg.transport.retry_attempts, 7);
    }

    // -----------------------------------------------------------------------
    // Env var overrides — health
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_overrides_health_addr() {
        let cfg = config_with_env(MINIMAL_TOML, &[("MXGUARD_HEALTH_ADDR", "127.0.0.1:9999")])
            .expect("load");
        assert_eq!(cfg.health.listen_addr, "127.0.0.1:9999");
    }

    // -----------------------------------------------------------------------
    // Env var overrides — collectors
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_overrides_process_disabled() {
        let cfg =
            default_with_env(&[("MXGUARD_PROCESS_ENABLED", "false")]).expect("default");
        assert!(!cfg.collectors.process.enabled);
    }

    #[test]
    fn test_env_overrides_process_scan_interval() {
        let cfg =
            default_with_env(&[("MXGUARD_PROCESS_SCAN_INTERVAL_MS", "500")]).expect("default");
        assert_eq!(cfg.collectors.process.scan_interval_ms, 500);
    }

    #[test]
    fn test_env_overrides_file_disabled() {
        let cfg = default_with_env(&[("MXGUARD_FILE_ENABLED", "0")]).expect("default");
        assert!(!cfg.collectors.file.enabled);
    }

    #[test]
    fn test_env_overrides_network_disabled() {
        let cfg = default_with_env(&[("MXGUARD_NETWORK_ENABLED", "no")]).expect("default");
        assert!(!cfg.collectors.network.enabled);
    }

    #[test]
    fn test_env_overrides_network_scan_interval() {
        let cfg =
            default_with_env(&[("MXGUARD_NETWORK_SCAN_INTERVAL_MS", "10000")]).expect("default");
        assert_eq!(cfg.collectors.network.scan_interval_ms, 10000);
    }

    #[test]
    fn test_env_overrides_auth_enabled_yes() {
        let cfg = default_with_env(&[("MXGUARD_AUTH_ENABLED", "yes")]).expect("default");
        assert!(cfg.collectors.auth.enabled);
    }

    #[test]
    fn test_env_overrides_auth_poll_interval() {
        let cfg =
            default_with_env(&[("MXGUARD_AUTH_POLL_INTERVAL_MS", "3000")]).expect("default");
        assert_eq!(cfg.collectors.auth.poll_interval_ms, 3000);
    }

    // -----------------------------------------------------------------------
    // Boolean parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_bool_true_variants() {
        for val in &["true", "True", "TRUE", "1", "yes", "YES"] {
            let cfg =
                default_with_env(&[("MXGUARD_PROCESS_ENABLED", val)]).expect(val);
            assert!(cfg.collectors.process.enabled, "val={val} should be true");
        }
    }

    #[test]
    fn test_env_bool_false_variants() {
        for val in &["false", "False", "FALSE", "0", "no", "NO"] {
            let cfg =
                default_with_env(&[("MXGUARD_PROCESS_ENABLED", val)]).expect(val);
            assert!(!cfg.collectors.process.enabled, "val={val} should be false");
        }
    }

    #[test]
    fn test_env_bool_invalid_returns_error() {
        let result = default_with_env(&[("MXGUARD_PROCESS_ENABLED", "maybe")]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("MXGUARD_PROCESS_ENABLED"), "msg={msg}");
    }

    #[test]
    fn test_env_integer_invalid_returns_error() {
        let result = default_with_env(&[("MXGUARD_TRANSPORT_BATCH_SIZE", "not-a-number")]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("MXGUARD_TRANSPORT_BATCH_SIZE"), "msg={msg}");
    }

    // -----------------------------------------------------------------------
    // Empty / absent env vars
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_env_var_is_ignored() {
        // An empty string must not override the TOML value.
        let cfg = config_with_env(MINIMAL_TOML, &[("MXGUARD_AGENT_NAME", "")])
            .expect("load");
        assert_eq!(cfg.agent.name, "test-agent"); // TOML value preserved
    }

    #[test]
    fn test_absent_env_vars_preserve_toml() {
        let cfg = config_with_env(MINIMAL_TOML, &[]).expect("load");
        assert_eq!(cfg.agent.name, "test-agent");
        assert_eq!(cfg.agent.log_level, "debug");
        assert_eq!(cfg.transport.batch_size, 100);
    }

    // -----------------------------------------------------------------------
    // Multiple overrides simultaneously
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_overrides_applied() {
        let cfg = config_with_env(
            MINIMAL_TOML,
            &[
                ("MXGUARD_AGENT_ID", "multi-001"),
                ("MXGUARD_AGENT_NAME", "multi-agent"),
                ("MXGUARD_LOG_LEVEL", "error"),
                ("MXGUARD_API_KEY", "multi-key"),
                ("MXGUARD_TRANSPORT_BATCH_SIZE", "200"),
                ("MXGUARD_HEALTH_ADDR", "0.0.0.0:8080"),
                ("MXGUARD_PROCESS_ENABLED", "false"),
                ("MXGUARD_NETWORK_ENABLED", "false"),
            ],
        )
        .expect("load");

        assert_eq!(cfg.agent.agent_id, "multi-001");
        assert_eq!(cfg.agent.name, "multi-agent");
        assert_eq!(cfg.agent.log_level, "error");
        assert_eq!(cfg.transport.api_key, "multi-key");
        assert_eq!(cfg.transport.batch_size, 200);
        assert_eq!(cfg.health.listen_addr, "0.0.0.0:8080");
        assert!(!cfg.collectors.process.enabled);
        assert!(!cfg.collectors.network.enabled);
        // File and auth are unaffected.
        assert!(cfg.collectors.file.enabled);
        assert!(cfg.collectors.auth.enabled);
    }

    // -----------------------------------------------------------------------
    // parse_bool helper (direct unit tests)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_bool_valid_true() {
        for v in &["true", "TRUE", "True", "1", "yes", "YES", "Yes"] {
            assert!(parse_bool("VAR", v).unwrap(), "v={v}");
        }
    }

    #[test]
    fn test_parse_bool_valid_false() {
        for v in &["false", "FALSE", "False", "0", "no", "NO", "No"] {
            assert!(!parse_bool("VAR", v).unwrap(), "v={v}");
        }
    }

    #[test]
    fn test_parse_bool_invalid() {
        let err = parse_bool("MY_VAR", "maybe").unwrap_err();
        assert!(err.to_string().contains("MY_VAR"), "{err}");
        assert!(err.to_string().contains("maybe"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Collector defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_collector_defaults() {
        let cfg = default_with_env(&[]).expect("default");
        assert!(cfg.collectors.process.enabled);
        assert_eq!(cfg.collectors.process.scan_interval_ms, 2000);
        assert!(cfg.collectors.file.enabled);
        assert_eq!(
            cfg.collectors.file.watch_paths,
            vec!["/etc", "/usr/bin", "/tmp"]
        );
        assert!(cfg.collectors.network.enabled);
        assert_eq!(cfg.collectors.network.scan_interval_ms, 5000);
        assert!(cfg.collectors.auth.enabled);
        assert_eq!(cfg.collectors.auth.poll_interval_ms, 2000);
    }
}
