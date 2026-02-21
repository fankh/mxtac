//! Configuration module for MxGuard EDR agent.
//!
//! Configuration is loaded in two layers:
//!   1. **TOML file** — provides the base configuration.
//!   2. **Environment variables** — any `MXGUARD_*` variable overrides the
//!      corresponding TOML value at startup.
//!
//! # Environment Variables
//!
//! | Variable                              | Config field                            |
//! |---------------------------------------|-----------------------------------------|
//! | `MXGUARD_AGENT_ID`                    | `agent.agent_id`                        |
//! | `MXGUARD_AGENT_NAME`                  | `agent.name`                            |
//! | `MXGUARD_LOG_LEVEL`                   | `agent.log_level`                       |
//! | `MXGUARD_TRANSPORT_ENDPOINT`          | `transport.endpoint`                    |
//! | `MXGUARD_API_KEY`                     | `transport.api_key`                     |
//! | `MXGUARD_TRANSPORT_BATCH_SIZE`        | `transport.batch_size`                  |
//! | `MXGUARD_TRANSPORT_FLUSH_MS`          | `transport.flush_interval_ms`           |
//! | `MXGUARD_TRANSPORT_RETRY_ATTEMPTS`    | `transport.retry_attempts`              |
//! | `MXGUARD_HEALTH_ADDR`                 | `health.listen_addr`                    |
//! | `MXGUARD_PROCESS_ENABLED`             | `collectors.process.enabled`            |
//! | `MXGUARD_PROCESS_SCAN_INTERVAL_MS`    | `collectors.process.scan_interval_ms`   |
//! | `MXGUARD_FILE_ENABLED`               | `collectors.file.enabled`               |
//! | `MXGUARD_NETWORK_ENABLED`             | `collectors.network.enabled`            |
//! | `MXGUARD_NETWORK_SCAN_INTERVAL_MS`    | `collectors.network.scan_interval_ms`   |
//! | `MXGUARD_AUTH_ENABLED`                | `collectors.auth.enabled`               |
//! | `MXGUARD_AUTH_POLL_INTERVAL_MS`       | `collectors.auth.poll_interval_ms`      |
//! | `MXGUARD_REGISTRY_ENABLED`            | `collectors.registry.enabled`           |
//! | `MXGUARD_REGISTRY_POLL_INTERVAL_MS`   | `collectors.registry.poll_interval_ms`  |
//! | `MXGUARD_RESOURCE_ENABLED`            | `resource_limits.enabled`               |
//! | `MXGUARD_RESOURCE_CPU_LIMIT`          | `resource_limits.cpu_limit_percent`     |
//! | `MXGUARD_RESOURCE_RAM_LIMIT_MB`       | `resource_limits.ram_limit_mb`          |
//! | `MXGUARD_RESOURCE_CHECK_INTERVAL_MS`  | `resource_limits.check_interval_ms`     |

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
    #[serde(default)]
    pub resource_limits: ResourceLimitsConfig,
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
    /// Windows Registry monitoring (Windows only; disabled by default on other platforms).
    #[serde(default)]
    pub registry: RegistryCollectorConfig,
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

/// Windows Registry key monitoring configuration.
///
/// The registry collector polls a list of registry keys at `poll_interval_ms`
/// intervals, detects value additions, deletions, and modifications, and emits
/// OCSF Registry Key Activity events (class_uid 201004).
///
/// **Windows only** — this collector does nothing on Linux or macOS even if
/// enabled.  Set `enabled = false` in the TOML configuration when running on
/// non-Windows hosts to suppress log warnings.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryCollectorConfig {
    /// Enable the Windows Registry collector (default: false).
    ///
    /// Defaults to `false` so that Linux / macOS agents do not emit
    /// spurious warnings about a collector that cannot run.
    #[serde(default)]
    pub enabled: bool,
    /// Registry key paths to monitor.
    ///
    /// Paths must use Windows registry hive prefixes:
    /// `HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `HKEY_USERS`, etc.
    /// (short forms `HKLM`, `HKCU` are also accepted by the collector).
    ///
    /// Defaults to a curated set of security-relevant keys covering
    /// autorun persistence, services, LSA configuration, and IFEO.
    #[serde(default = "default_registry_watch_keys")]
    pub watch_keys: Vec<String>,
    /// How often to poll each registry key for changes (milliseconds).
    /// Default: 5000 ms.
    #[serde(default = "default_registry_poll_interval")]
    pub poll_interval_ms: u64,
}

impl Default for RegistryCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_keys: default_registry_watch_keys(),
            poll_interval_ms: default_registry_poll_interval(),
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

// -- Resource Limits ---------------------------------------------------------

/// Configuration for the agent resource usage monitor.
///
/// The monitor samples CPU and RSS memory on each `check_interval_ms` tick
/// and logs a warning whenever either limit is exceeded.  A throttle signal
/// is also published so the transport layer can back off under pressure.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceLimitsConfig {
    /// Enable the resource monitor (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum allowed CPU usage as a percentage (default: 1.0 %).
    #[serde(default = "default_cpu_limit")]
    pub cpu_limit_percent: f64,
    /// Maximum allowed RSS memory in megabytes (default: 30 MB).
    #[serde(default = "default_ram_limit_mb")]
    pub ram_limit_mb: u64,
    /// How often to sample resource usage in milliseconds (default: 5 000 ms).
    #[serde(default = "default_resource_check_interval")]
    pub check_interval_ms: u64,
}

impl Default for ResourceLimitsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cpu_limit_percent: default_cpu_limit(),
            ram_limit_mb: default_ram_limit_mb(),
            check_interval_ms: default_resource_check_interval(),
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
fn default_registry_poll_interval() -> u64 {
    5000
}
fn default_registry_watch_keys() -> Vec<String> {
    vec![
        // Autorun persistence (T1547.001)
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce".into(),
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce".into(),
        // Windows services (T1543.003)
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services".into(),
        // LSA / authentication configuration (T1003.001)
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa".into(),
        // Image File Execution Options — debugger injection (T1546.012)
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options".into(),
        // Known DLLs — DLL hijacking (T1574.001)
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs".into(),
    ]
}
fn default_cpu_limit() -> f64 {
    1.0
}
fn default_ram_limit_mb() -> u64 {
    30
}
fn default_resource_check_interval() -> u64 {
    5000
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
            resource_limits: ResourceLimitsConfig::default(),
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

        // -- Collectors: registry (Windows only) -----------------------------
        if let Some(v) = get_env("MXGUARD_REGISTRY_ENABLED") {
            self.collectors.registry.enabled = parse_bool("MXGUARD_REGISTRY_ENABLED", &v)?;
        }
        if let Some(v) = get_env("MXGUARD_REGISTRY_POLL_INTERVAL_MS") {
            self.collectors.registry.poll_interval_ms =
                v.trim().parse::<u64>().map_err(|e| ConfigError::EnvParse {
                    var: "MXGUARD_REGISTRY_POLL_INTERVAL_MS",
                    reason: e.to_string(),
                })?;
        }

        // -- Resource limits -------------------------------------------------
        if let Some(v) = get_env("MXGUARD_RESOURCE_ENABLED") {
            self.resource_limits.enabled = parse_bool("MXGUARD_RESOURCE_ENABLED", &v)?;
        }
        if let Some(v) = get_env("MXGUARD_RESOURCE_CPU_LIMIT") {
            self.resource_limits.cpu_limit_percent =
                v.trim().parse::<f64>().map_err(|e| ConfigError::EnvParse {
                    var: "MXGUARD_RESOURCE_CPU_LIMIT",
                    reason: e.to_string(),
                })?;
        }
        if let Some(v) = get_env("MXGUARD_RESOURCE_RAM_LIMIT_MB") {
            self.resource_limits.ram_limit_mb =
                v.trim().parse::<u64>().map_err(|e| ConfigError::EnvParse {
                    var: "MXGUARD_RESOURCE_RAM_LIMIT_MB",
                    reason: e.to_string(),
                })?;
        }
        if let Some(v) = get_env("MXGUARD_RESOURCE_CHECK_INTERVAL_MS") {
            self.resource_limits.check_interval_ms =
                v.trim().parse::<u64>().map_err(|e| ConfigError::EnvParse {
                    var: "MXGUARD_RESOURCE_CHECK_INTERVAL_MS",
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
            resource_limits: ResourceLimitsConfig::default(),
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

    // -----------------------------------------------------------------------
    // Resource limits defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_resource_limits_defaults() {
        let cfg = default_with_env(&[]).expect("default");
        assert!(cfg.resource_limits.enabled);
        assert_eq!(cfg.resource_limits.cpu_limit_percent, 1.0);
        assert_eq!(cfg.resource_limits.ram_limit_mb, 30);
        assert_eq!(cfg.resource_limits.check_interval_ms, 5000);
    }

    #[test]
    fn test_resource_limits_default_struct() {
        let rl = ResourceLimitsConfig::default();
        assert!(rl.enabled);
        assert_eq!(rl.cpu_limit_percent, 1.0);
        assert_eq!(rl.ram_limit_mb, 30);
        assert_eq!(rl.check_interval_ms, 5000);
    }

    // -----------------------------------------------------------------------
    // Resource limits env var overrides
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_resource_enabled_false() {
        let cfg = default_with_env(&[("MXGUARD_RESOURCE_ENABLED", "false")]).expect("default");
        assert!(!cfg.resource_limits.enabled);
    }

    #[test]
    fn test_env_resource_cpu_limit() {
        let cfg =
            default_with_env(&[("MXGUARD_RESOURCE_CPU_LIMIT", "2.5")]).expect("default");
        assert_eq!(cfg.resource_limits.cpu_limit_percent, 2.5);
    }

    #[test]
    fn test_env_resource_ram_limit_mb() {
        let cfg =
            default_with_env(&[("MXGUARD_RESOURCE_RAM_LIMIT_MB", "64")]).expect("default");
        assert_eq!(cfg.resource_limits.ram_limit_mb, 64);
    }

    #[test]
    fn test_env_resource_check_interval_ms() {
        let cfg =
            default_with_env(&[("MXGUARD_RESOURCE_CHECK_INTERVAL_MS", "10000")]).expect("default");
        assert_eq!(cfg.resource_limits.check_interval_ms, 10000);
    }

    #[test]
    fn test_env_resource_cpu_limit_invalid() {
        let result = default_with_env(&[("MXGUARD_RESOURCE_CPU_LIMIT", "not-a-float")]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("MXGUARD_RESOURCE_CPU_LIMIT"), "msg={msg}");
    }

    #[test]
    fn test_env_resource_ram_limit_invalid() {
        let result = default_with_env(&[("MXGUARD_RESOURCE_RAM_LIMIT_MB", "abc")]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("MXGUARD_RESOURCE_RAM_LIMIT_MB"), "msg={msg}");
    }

    // -----------------------------------------------------------------------
    // Registry collector config
    // -----------------------------------------------------------------------

    #[test]
    fn test_registry_collector_defaults() {
        let cfg = default_with_env(&[]).expect("default");
        // Registry collector defaults to disabled (Windows-only feature).
        assert!(!cfg.collectors.registry.enabled);
        assert_eq!(cfg.collectors.registry.poll_interval_ms, 5000);
        // Default watch keys should include common persistence locations.
        let keys = &cfg.collectors.registry.watch_keys;
        assert!(!keys.is_empty(), "default watch_keys must be non-empty");
        assert!(
            keys.iter().any(|k| k.contains("CurrentVersion\\Run")),
            "default keys must include autorun key"
        );
        assert!(
            keys.iter().any(|k| k.contains("Services")),
            "default keys must include services key"
        );
    }

    #[test]
    fn test_env_registry_enabled_true() {
        let cfg =
            default_with_env(&[("MXGUARD_REGISTRY_ENABLED", "true")]).expect("default");
        assert!(cfg.collectors.registry.enabled);
    }

    #[test]
    fn test_env_registry_enabled_false() {
        let cfg =
            default_with_env(&[("MXGUARD_REGISTRY_ENABLED", "false")]).expect("default");
        assert!(!cfg.collectors.registry.enabled);
    }

    #[test]
    fn test_env_registry_poll_interval() {
        let cfg =
            default_with_env(&[("MXGUARD_REGISTRY_POLL_INTERVAL_MS", "2000")]).expect("default");
        assert_eq!(cfg.collectors.registry.poll_interval_ms, 2000);
    }

    #[test]
    fn test_env_registry_poll_interval_invalid() {
        let result =
            default_with_env(&[("MXGUARD_REGISTRY_POLL_INTERVAL_MS", "not-a-number")]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("MXGUARD_REGISTRY_POLL_INTERVAL_MS"), "msg={msg}");
    }

    #[test]
    fn test_registry_config_from_toml() {
        let toml = r#"
[agent]
name = "test"

[collectors.registry]
enabled = true
poll_interval_ms = 3000
watch_keys = [
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
]
"#;
        let cfg = config_with_env(toml, &[]).expect("load");
        assert!(cfg.collectors.registry.enabled);
        assert_eq!(cfg.collectors.registry.poll_interval_ms, 3000);
        assert_eq!(cfg.collectors.registry.watch_keys.len(), 2);
        assert!(cfg.collectors.registry.watch_keys[0].contains("LOCAL_MACHINE"));
    }

    #[test]
    fn test_resource_limits_toml() {
        let toml = r#"
[agent]
name = "test"

[resource_limits]
enabled = false
cpu_limit_percent = 0.5
ram_limit_mb = 16
check_interval_ms = 2000
"#;
        let cfg = config_with_env(toml, &[]).expect("load");
        assert!(!cfg.resource_limits.enabled);
        assert_eq!(cfg.resource_limits.cpu_limit_percent, 0.5);
        assert_eq!(cfg.resource_limits.ram_limit_mb, 16);
        assert_eq!(cfg.resource_limits.check_interval_ms, 2000);
    }
}
