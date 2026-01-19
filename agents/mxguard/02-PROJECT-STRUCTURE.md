# MxGuard - Project Structure

> **Version**: 1.0
> **Date**: 2026-01-19
> **Language**: Rust 1.75+

---

## Repository Structure

```
mxguard/
├── src/
│   ├── main.rs                        # Entry point
│   ├── lib.rs                         # Library root
│   │
│   ├── agent/
│   │   ├── mod.rs                     # Agent orchestrator
│   │   ├── config.rs                  # Configuration loader
│   │   └── lifecycle.rs               # Startup/shutdown
│   │
│   ├── collectors/
│   │   ├── mod.rs                     # Collector trait
│   │   ├── file/
│   │   │   ├── mod.rs                 # File monitoring
│   │   │   ├── monitor_linux.rs       # Linux (inotify)
│   │   │   ├── monitor_windows.rs     # Windows (ReadDirectoryChangesW)
│   │   │   ├── monitor_macos.rs       # macOS (FSEvents)
│   │   │   └── hash.rs                # File hashing
│   │   │
│   │   ├── process/
│   │   │   ├── mod.rs                 # Process monitoring
│   │   │   ├── monitor_linux.rs       # /proc parsing
│   │   │   ├── monitor_windows.rs     # WMI integration
│   │   │   ├── monitor_macos.rs       # kqueue/sysctl
│   │   │   └── tree.rs                # Process tree tracking
│   │   │
│   │   ├── network/
│   │   │   ├── mod.rs                 # Network monitoring
│   │   │   ├── monitor_linux.rs       # /proc/net/tcp
│   │   │   ├── monitor_windows.rs     # GetExtendedTcpTable
│   │   │   ├── monitor_macos.rs       # lsof wrapper
│   │   │   └── connection.rs          # Connection tracking
│   │   │
│   │   └── logs/
│   │       ├── mod.rs                 # Log monitoring
│   │       ├── tailer.rs              # Log file tailer
│   │       ├── journald.rs            # Systemd journal (Linux)
│   │       ├── eventlog.rs            # Windows Event Log
│   │       └── oslog.rs               # macOS Unified Logging
│   │
│   ├── ocsf/
│   │   ├── mod.rs                     # OCSF module root
│   │   ├── builder.rs                 # Event builder
│   │   ├── models.rs                  # Data structures
│   │   ├── file_activity.rs           # File Activity (1001)
│   │   ├── process_activity.rs        # Process Activity (1007)
│   │   ├── network_activity.rs        # Network Activity (4001)
│   │   ├── auth_activity.rs           # Authentication (3002)
│   │   ├── enrichment.rs              # Event enrichment
│   │   └── severity.rs                # Severity calculation
│   │
│   ├── buffer/
│   │   ├── mod.rs                     # Event buffer
│   │   ├── queue.rs                   # Ring buffer
│   │   ├── batcher.rs                 # Batch processor
│   │   └── priority.rs                # Priority queue
│   │
│   ├── output/
│   │   ├── mod.rs                     # Output trait
│   │   ├── http.rs                    # HTTP/HTTPS output
│   │   ├── file.rs                    # File output
│   │   ├── syslog.rs                  # Syslog output
│   │   └── retry.rs                   # Retry logic
│   │
│   ├── filter/
│   │   ├── mod.rs                     # Event filtering
│   │   ├── rules.rs                   # Filter rules
│   │   └── patterns.rs                # Pattern matching
│   │
│   └── utils/
│       ├── mod.rs                     # Utilities module
│       ├── system.rs                  # System information
│       ├── crypto.rs                  # Hashing
│       └── error.rs                   # Error types
│
├── configs/
│   ├── config.toml                    # Default configuration
│   ├── config.linux.toml              # Linux-specific
│   ├── config.windows.toml            # Windows-specific
│   └── config.macos.toml              # macOS-specific
│
├── scripts/
│   ├── build.sh                       # Build script
│   ├── install.sh                     # Installation
│   └── test.sh                        # Test runner
│
├── deployments/
│   ├── systemd/
│   │   └── mxguard.service            # Systemd unit
│   ├── launchd/
│   │   └── com.mxtac.mxguard.plist    # macOS launchd
│   └── windows/
│       └── install-service.ps1        # Windows service
│
├── tests/
│   ├── integration/
│   │   ├── file_tests.rs
│   │   ├── process_tests.rs
│   │   └── network_tests.rs
│   └── common/
│       └── mod.rs                     # Test utilities
│
├── benches/
│   ├── ocsf_builder.rs                # OCSF benchmarks
│   └── buffer.rs                      # Buffer benchmarks
│
├── Cargo.toml                         # Rust dependencies
├── Cargo.lock                         # Dependency lock
├── build.rs                           # Build script
├── .cargo/
│   └── config.toml                    # Cargo config
├── LICENSE
└── README.md
```

---

## Core Modules

### 1. Agent Orchestrator (`src/agent/mod.rs`)

```rust
// src/agent/mod.rs
use tokio::sync::mpsc;
use crate::collectors::Collector;
use crate::buffer::EventBuffer;
use crate::output::OutputHandler;

pub struct Agent {
    config: Config,
    collectors: Vec<Box<dyn Collector>>,
    buffer: EventBuffer,
    output: Box<dyn OutputHandler>,
}

impl Agent {
    pub fn new(config_path: &str) -> Result<Self, Error> {
        let config = Config::from_file(config_path)?;

        Ok(Self {
            config,
            collectors: Vec::new(),
            buffer: EventBuffer::new(10000),
            output: Box::new(HttpOutput::new(&config.output)),
        })
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        // Initialize collectors
        self.init_collectors()?;

        // Create event channel
        let (tx, mut rx) = mpsc::channel(10000);

        // Start collectors
        for collector in &mut self.collectors {
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                collector.start(tx_clone).await
            });
        }

        // Start event processing
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                self.buffer.add(event).await;
            }
        });

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await?;
        self.stop().await
    }

    async fn stop(&mut self) -> Result<(), Error> {
        // Stop collectors
        for collector in &mut self.collectors {
            collector.stop().await?;
        }

        // Flush buffer
        self.buffer.flush().await?;

        Ok(())
    }

    fn init_collectors(&mut self) -> Result<(), Error> {
        if self.config.collectors.file.enabled {
            self.collectors.push(Box::new(FileCollector::new(&self.config.collectors.file)?));
        }

        if self.config.collectors.process.enabled {
            self.collectors.push(Box::new(ProcessCollector::new(&self.config.collectors.process)?));
        }

        if self.config.collectors.network.enabled {
            self.collectors.push(Box::new(NetworkCollector::new(&self.config.collectors.network)?));
        }

        Ok(())
    }
}
```

### 2. Collector Trait (`src/collectors/mod.rs`)

```rust
// src/collectors/mod.rs
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

#[async_trait]
pub trait Collector: Send + Sync {
    /// Start collecting events
    async fn start(&mut self, tx: Sender<Event>) -> Result<(), Error>;

    /// Stop the collector
    async fn stop(&mut self) -> Result<(), Error>;

    /// Get collector name
    fn name(&self) -> &str;

    /// Get collector status
    fn status(&self) -> CollectorStatus;
}

#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: EventType,
    pub timestamp: i64,
    pub data: EventData,
    pub severity: u8,
}

#[derive(Debug, Clone)]
pub enum EventType {
    File,
    Process,
    Network,
    Auth,
}

#[derive(Debug, Clone)]
pub enum EventData {
    File(FileEvent),
    Process(ProcessEvent),
    Network(NetworkEvent),
    Auth(AuthEvent),
}

#[derive(Debug)]
pub struct CollectorStatus {
    pub running: bool,
    pub event_count: u64,
    pub error_count: u64,
}
```

### 3. File Collector (`src/collectors/file/mod.rs`)

```rust
// src/collectors/file/mod.rs
use notify::{Watcher, RecursiveMode, watcher, DebouncedEvent};
use std::sync::mpsc::channel;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

pub struct FileCollector {
    paths: Vec<String>,
    exclude: Vec<String>,
    hash_files: bool,
    watcher: Option<notify::RecommendedWatcher>,
    event_count: u64,
}

impl FileCollector {
    pub fn new(config: &FileConfig) -> Result<Self, Error> {
        Ok(Self {
            paths: config.paths.clone(),
            exclude: config.exclude.clone(),
            hash_files: config.hash_files,
            watcher: None,
            event_count: 0,
        })
    }

    fn should_monitor(&self, path: &str) -> bool {
        // Check if path matches exclude patterns
        for pattern in &self.exclude {
            if glob::Pattern::new(pattern)
                .unwrap()
                .matches(path) {
                return false;
            }
        }
        true
    }

    fn hash_file(&self, path: &str) -> Result<String, Error> {
        use sha2::{Sha256, Digest};
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 4096];

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 { break; }
            hasher.update(&buffer[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    fn is_suspicious(&self, path: &str) -> bool {
        let suspicious_patterns = vec![
            "mimikatz", "nc", "ncat", ".exe", ".ps1", ".bat", ".vbs"
        ];

        let path_lower = path.to_lowercase();
        suspicious_patterns.iter().any(|p| path_lower.contains(p))
    }
}

#[async_trait]
impl Collector for FileCollector {
    async fn start(&mut self, tx: Sender<Event>) -> Result<(), Error> {
        let (notify_tx, notify_rx) = channel();

        let mut watcher = watcher(notify_tx, Duration::from_secs(1))?;

        // Watch all configured paths
        for path in &self.paths {
            watcher.watch(path, RecursiveMode::Recursive)?;
        }

        self.watcher = Some(watcher);

        // Process events
        loop {
            match notify_rx.recv() {
                Ok(event) => {
                    match event {
                        DebouncedEvent::Create(path) |
                        DebouncedEvent::Write(path) |
                        DebouncedEvent::Remove(path) => {
                            let path_str = path.to_str().unwrap();

                            if !self.should_monitor(path_str) {
                                continue;
                            }

                            // Calculate hash if configured
                            let hash = if self.hash_files && path.exists() {
                                self.hash_file(path_str).ok()
                            } else {
                                None
                            };

                            // Determine severity
                            let severity = if self.is_suspicious(path_str) {
                                4 // High
                            } else {
                                2 // Low
                            };

                            let file_event = FileEvent {
                                path: path_str.to_string(),
                                action: self.event_to_action(&event),
                                hash,
                                size: path.metadata().ok().map(|m| m.len()),
                            };

                            let event = Event {
                                event_type: EventType::File,
                                timestamp: chrono::Utc::now().timestamp(),
                                data: EventData::File(file_event),
                                severity,
                            };

                            tx.send(event).await?;
                            self.event_count += 1;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    log::error!("File watcher error: {}", e);
                }
            }
        }
    }

    async fn stop(&mut self) -> Result<(), Error> {
        self.watcher = None;
        Ok(())
    }

    fn name(&self) -> &str {
        "file-collector"
    }

    fn status(&self) -> CollectorStatus {
        CollectorStatus {
            running: self.watcher.is_some(),
            event_count: self.event_count,
            error_count: 0,
        }
    }
}
```

### 4. OCSF Builder (`src/ocsf/builder.rs`)

```rust
// src/ocsf/builder.rs
use serde::{Serialize, Deserialize};
use chrono::Utc;

pub struct OCSFBuilder {
    product: Product,
    device: Device,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Product {
    pub name: String,
    pub vendor: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Device {
    pub hostname: String,
    pub ip: String,
    pub os: OSInfo,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OSInfo {
    pub name: String,
    pub version: String,
}

impl OCSFBuilder {
    pub fn new(product: Product, device: Device) -> Self {
        Self { product, device }
    }

    pub fn build_file_activity(
        &self,
        activity: &str,
        activity_id: u32,
        file: FileInfo,
        actor: ActorInfo,
        severity: u8,
    ) -> FileSystemActivity {
        FileSystemActivity {
            metadata: Metadata {
                version: "1.1.0".to_string(),
                product: self.product.clone(),
            },
            time: Utc::now().timestamp(),
            class_uid: 1001,
            category_uid: 1,
            activity: activity.to_string(),
            activity_id,
            severity_id: severity,
            severity: self.severity_to_string(severity),
            file,
            actor,
            device: self.device.clone(),
        }
    }

    pub fn build_process_activity(
        &self,
        activity: &str,
        activity_id: u32,
        process: ProcessInfo,
        severity: u8,
    ) -> ProcessActivity {
        ProcessActivity {
            metadata: Metadata {
                version: "1.1.0".to_string(),
                product: self.product.clone(),
            },
            time: Utc::now().timestamp(),
            class_uid: 1007,
            category_uid: 1,
            activity: activity.to_string(),
            activity_id,
            severity_id: severity,
            severity: self.severity_to_string(severity),
            process,
            device: self.device.clone(),
        }
    }

    fn severity_to_string(&self, severity: u8) -> String {
        match severity {
            1 => "Informational".to_string(),
            2 => "Low".to_string(),
            3 => "Medium".to_string(),
            4 => "High".to_string(),
            5 => "Critical".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FileSystemActivity {
    pub metadata: Metadata,
    pub time: i64,
    pub class_uid: u32,
    pub category_uid: u32,
    pub activity: String,
    pub activity_id: u32,
    pub severity_id: u8,
    pub severity: String,
    pub file: FileInfo,
    pub actor: ActorInfo,
    pub device: Device,
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub version: String,
    pub product: Product,
}
```

### 5. HTTP Output (`src/output/http.rs`)

```rust
// src/output/http.rs
use reqwest::{Client, header};
use serde::Serialize;
use async_trait::async_trait;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

pub struct HttpOutput {
    client: Client,
    url: String,
    api_key: String,
    retries: u32,
}

impl HttpOutput {
    pub fn new(config: &HttpConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();

        Self {
            client,
            url: config.url.clone(),
            api_key: config.api_key.clone(),
            retries: config.retry_attempts,
        }
    }

    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    async fn send_with_retry(&self, payload: Vec<u8>) -> Result<(), Error> {
        let mut attempt = 0;

        loop {
            attempt += 1;

            match self.send_request(&payload).await {
                Ok(_) => return Ok(()),
                Err(e) if attempt >= self.retries => return Err(e),
                Err(e) => {
                    log::warn!("Request failed (attempt {}): {}", attempt, e);
                    tokio::time::sleep(std::time::Duration::from_secs(
                        2u64.pow(attempt - 1) // Exponential backoff
                    )).await;
                }
            }
        }
    }

    async fn send_request(&self, payload: &[u8]) -> Result<(), Error> {
        let response = self.client
            .post(&self.url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::AUTHORIZATION, format!("Bearer {}", self.api_key))
            .body(payload.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::HttpError(response.status().as_u16()));
        }

        Ok(())
    }
}

#[async_trait]
impl OutputHandler for HttpOutput {
    async fn send(&self, events: Vec<Event>) -> Result<(), Error> {
        // Serialize events to JSON
        let json = serde_json::to_vec(&events)?;

        // Compress
        let compressed = self.compress(&json)?;

        // Send with retry
        self.send_with_retry(compressed).await
    }

    fn name(&self) -> &str {
        "http-output"
    }
}
```

---

## Configuration Structure

```toml
# config.toml
[agent]
name = "mxguard-agent"
version = "1.0.0"
log_level = "info"
log_file = "/var/log/mxguard/agent.log"

[collectors.file]
enabled = true
paths = ["/etc", "/usr/bin", "/tmp"]
exclude = ["*.log", "*.tmp"]
hash_files = true
hash_threshold = 10485760  # 10 MB

[collectors.process]
enabled = true
scan_interval = "2s"
track_children = true

[collectors.network]
enabled = true
scan_interval = "5s"
track_established = true

[buffer]
size = 10000
batch_size = 100
batch_timeout = "5s"

[output.http]
enabled = true
url = "https://mxtac.example.com/api/v1/ingest/ocsf"
api_key = "${MXGUARD_API_KEY}"
retry_attempts = 3
retry_backoff = "1s"
```

---

## Dependencies (Cargo.toml)

```toml
[package]
name = "mxguard"
version = "1.0.0"
edition = "2021"
rust-version = "1.75"

[dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }
async-trait = "0.1"

# File monitoring
notify = "6.1"

# Process monitoring
sysinfo = "0.30"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# HTTP client
reqwest = { version = "0.11", features = ["json", "gzip"] }

# Hashing
sha2 = "0.10"

# Compression
flate2 = "1.0"

# Logging
log = "0.4"
env_logger = "0.11"

# Time
chrono = { version = "0.4", features = ["serde"] }

# Pattern matching
glob = "0.3"

# Error handling
thiserror = "1.0"
anyhow = "1.0"

# Platform-specific (conditional compilation)
[target.'cfg(target_os = "linux")'.dependencies]
libc = "0.2"

[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.52", features = [
    "Win32_System_Registry",
    "Win32_System_EventLog",
    "Win32_Foundation",
] }

[target.'cfg(target_os = "macos")'.dependencies]
core-foundation = "0.9"

[dev-dependencies]
tokio-test = "0.4"
criterion = "0.5"

[[bench]]
name = "ocsf_builder"
harness = false

[[bench]]
name = "buffer"
harness = false
```

---

## Build System

### Makefile

```makefile
.PHONY: build test clean install

VERSION := $(shell git describe --tags --always --dirty)

build:
\tcargo build --release

build-linux:
\tcargo build --release --target x86_64-unknown-linux-gnu
\tcargo build --release --target aarch64-unknown-linux-gnu

build-windows:
\tcargo build --release --target x86_64-pc-windows-gnu

build-darwin:
\tcargo build --release --target x86_64-apple-darwin
\tcargo build --release --target aarch64-apple-darwin

build-all: build-linux build-windows build-darwin

test:
\tcargo test --all-features

test-integration:
\tcargo test --test '*' -- --ignored

bench:
\tcargo bench

clean:
\tcargo clean

install:
\tcp target/release/mxguard /usr/local/bin/
\tmkdir -p /etc/mxguard
\tcp configs/config.toml /etc/mxguard/

# Cross-compilation setup
setup-cross:
\tcargo install cross

# Build with cross for all targets
cross-build:
\tcross build --release --target x86_64-unknown-linux-gnu
\tcross build --release --target x86_64-pc-windows-gnu
\tcross build --release --target x86_64-apple-darwin
```

---

*Project structure designed for Rust implementation*
*Next: See 03-CONFIGURATION.md for configuration details*
