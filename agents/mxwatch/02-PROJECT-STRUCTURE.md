# MxWatch - Project Structure

> **Version**: 1.0
> **Date**: 2026-01-19
> **Language**: Rust 1.75+

---

## Repository Structure

```
mxwatch/
├── src/
│   ├── main.rs                        # Entry point
│   ├── lib.rs                         # Library root
│   │
│   ├── agent/
│   │   ├── mod.rs                     # Agent orchestrator
│   │   ├── config.rs                  # Configuration
│   │   └── lifecycle.rs               # Lifecycle management
│   │
│   ├── capture/
│   │   ├── mod.rs                     # Packet capture trait
│   │   ├── pcap.rs                    # libpcap wrapper
│   │   ├── capture_linux.rs           # Linux optimizations
│   │   ├── capture_windows.rs         # Windows (Npcap)
│   │   ├── capture_macos.rs           # macOS optimizations
│   │   └── bpf_filter.rs              # BPF filter builder
│   │
│   ├── parsers/
│   │   ├── mod.rs                     # Parser trait
│   │   ├── http/
│   │   │   ├── mod.rs                 # HTTP parser
│   │   │   ├── request.rs             # Request parsing
│   │   │   ├── response.rs            # Response parsing
│   │   │   └── patterns.rs            # Suspicious patterns
│   │   │
│   │   ├── dns/
│   │   │   ├── mod.rs                 # DNS parser
│   │   │   ├── query.rs               # Query parsing
│   │   │   ├── response.rs            # Response parsing
│   │   │   ├── tunneling.rs           # Tunneling detection
│   │   │   └── dga.rs                 # DGA detection
│   │   │
│   │   ├── tls/
│   │   │   ├── mod.rs                 # TLS parser
│   │   │   ├── handshake.rs           # Handshake parsing
│   │   │   ├── certificate.rs         # Certificate parsing
│   │   │   └── sni.rs                 # SNI extraction
│   │   │
│   │   └── tcp/
│   │       ├── mod.rs                 # TCP analyzer
│   │       ├── flags.rs               # Flag analysis
│   │       └── reassembly.rs          # Stream reassembly
│   │
│   ├── detectors/
│   │   ├── mod.rs                     # Detector trait
│   │   ├── c2beacon/
│   │   │   ├── mod.rs                 # C2 beacon detector
│   │   │   ├── interval.rs            # Interval analysis
│   │   │   └── signatures.rs          # Known signatures
│   │   │
│   │   ├── portscan/
│   │   │   ├── mod.rs                 # Port scan detector
│   │   │   ├── vertical.rs            # Vertical scan
│   │   │   └── horizontal.rs          # Horizontal scan
│   │   │
│   │   ├── exfiltration/
│   │   │   ├── mod.rs                 # Exfiltration detector
│   │   │   ├── volume.rs              # Volume-based
│   │   │   └── protocol.rs            # Protocol-based
│   │   │
│   │   └── lateral/
│   │       ├── mod.rs                 # Lateral movement
│   │       └── patterns.rs            # Movement patterns
│   │
│   ├── ocsf/
│   │   ├── mod.rs                     # OCSF module
│   │   ├── builder.rs                 # Event builder
│   │   ├── models.rs                  # Data structures
│   │   ├── network_activity.rs        # Network Activity (4001)
│   │   ├── enrichment.rs              # Enrichment
│   │   └── severity.rs                # Severity calc
│   │
│   ├── buffer/
│   │   ├── mod.rs                     # Event buffer
│   │   ├── queue.rs                   # Ring buffer
│   │   └── batcher.rs                 # Batch processor
│   │
│   ├── output/
│   │   ├── mod.rs                     # Output trait
│   │   ├── http.rs                    # HTTP output
│   │   ├── file.rs                    # File output
│   │   └── retry.rs                   # Retry logic
│   │
│   └── utils/
│       ├── mod.rs                     # Utilities
│       ├── network.rs                 # Network utils
│       ├── stats.rs                   # Statistics
│       └── error.rs                   # Error types
│
├── configs/
│   ├── config.toml                    # Default config
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
│   │   └── mxwatch.service            # Systemd unit
│   ├── launchd/
│   │   └── com.mxtac.mxwatch.plist    # macOS launchd
│   └── windows/
│       └── install-service.ps1        # Windows service
│
├── tests/
│   ├── integration/
│   │   ├── http_tests.rs
│   │   ├── dns_tests.rs
│   │   └── c2beacon_tests.rs
│   ├── common/
│   │   └── mod.rs                     # Test utilities
│   └── fixtures/
│       └── pcaps/                     # Sample PCAPs
│
├── benches/
│   ├── packet_parsing.rs              # Parser benchmarks
│   └── detection.rs                   # Detector benchmarks
│
├── Cargo.toml                         # Dependencies
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
use crate::capture::PacketCapture;
use crate::parsers::Parser;
use crate::detectors::Detector;

pub struct Agent {
    config: Config,
    capture: Box<dyn PacketCapture>,
    parsers: Vec<Box<dyn Parser>>,
    detectors: Vec<Box<dyn Detector>>,
    buffer: EventBuffer,
    output: Box<dyn OutputHandler>,
}

impl Agent {
    pub fn new(config_path: &str) -> Result<Self, Error> {
        let config = Config::from_file(config_path)?;

        Ok(Self {
            config: config.clone(),
            capture: Box::new(PcapCapture::new(&config.capture)?),
            parsers: Vec::new(),
            detectors: Vec::new(),
            buffer: EventBuffer::new(10000),
            output: Box::new(HttpOutput::new(&config.output)?),
        })
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        // Initialize parsers and detectors
        self.init_parsers()?;
        self.init_detectors()?;

        // Create packet channel
        let (pkt_tx, mut pkt_rx) = mpsc::channel(10000);

        // Start packet capture
        let mut capture = self.capture.clone();
        tokio::spawn(async move {
            capture.start(pkt_tx).await
        });

        // Create event channel
        let (evt_tx, mut evt_rx) = mpsc::channel(10000);

        // Start parsers
        for parser in &mut self.parsers {
            let pkt_rx_clone = pkt_rx.clone();
            let evt_tx_clone = evt_tx.clone();
            tokio::spawn(async move {
                parser.parse(pkt_rx_clone, evt_tx_clone).await
            });
        }

        // Start detectors
        for detector in &mut self.detectors {
            let evt_rx_clone = evt_rx.clone();
            tokio::spawn(async move {
                detector.detect(evt_rx_clone).await
            });
        }

        // Process events
        tokio::spawn(async move {
            while let Some(event) = evt_rx.recv().await {
                self.buffer.add(event).await;
            }
        });

        // Wait for shutdown
        tokio::signal::ctrl_c().await?;
        self.stop().await
    }

    async fn stop(&mut self) -> Result<(), Error> {
        self.capture.stop().await?;
        self.buffer.flush().await?;
        Ok(())
    }
}
```

### 2. Packet Capture (`src/capture/pcap.rs`)

```rust
// src/capture/pcap.rs
use pcap::{Device, Capture, Active};
use tokio::sync::mpsc::Sender;
use pnet::packet::Packet;

pub struct PcapCapture {
    interface: String,
    snaplen: i32,
    promiscuous: bool,
    filter: String,
    handle: Option<Capture<Active>>,
}

impl PcapCapture {
    pub fn new(config: &CaptureConfig) -> Result<Self, Error> {
        Ok(Self {
            interface: config.interface.clone(),
            snaplen: config.snaplen,
            promiscuous: config.promiscuous,
            filter: config.bpf_filter.clone(),
            handle: None,
        })
    }

    pub async fn start(&mut self, tx: Sender<RawPacket>) -> Result<(), Error> {
        // Open capture device
        let mut cap = Capture::from_device(self.interface.as_str())?
            .promisc(self.promiscuous)
            .snaplen(self.snaplen)
            .open()?;

        // Set BPF filter
        cap.filter(&self.filter, true)?;

        self.handle = Some(cap);

        // Capture packets
        loop {
            match self.handle.as_mut().unwrap().next_packet() {
                Ok(packet) => {
                    let raw_packet = RawPacket {
                        timestamp: packet.header.ts.tv_sec as i64,
                        data: packet.data.to_vec(),
                        length: packet.header.len as usize,
                    };

                    if tx.send(raw_packet).await.is_err() {
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    log::error!("Packet capture error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), Error> {
        self.handle = None;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RawPacket {
    pub timestamp: i64,
    pub data: Vec<u8>,
    pub length: usize,
}
```

### 3. HTTP Parser (`src/parsers/http/mod.rs`)

```rust
// src/parsers/http/mod.rs
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use httparse::{Request, Response};

pub struct HttpParser {
    suspicious_patterns: Vec<String>,
}

impl HttpParser {
    pub fn new(config: &HttpParserConfig) -> Self {
        Self {
            suspicious_patterns: config.suspicious_patterns.clone(),
        }
    }

    pub fn parse_request(&self, data: &[u8]) -> Option<HttpRequest> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);

        match req.parse(data) {
            Ok(httparse::Status::Complete(_)) => {
                Some(HttpRequest {
                    method: req.method?.to_string(),
                    path: req.path?.to_string(),
                    version: req.version?,
                    headers: req.headers.iter()
                        .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).to_string()))
                        .collect(),
                })
            }
            _ => None,
        }
    }

    pub fn is_suspicious(&self, req: &HttpRequest) -> bool {
        // Command injection
        if req.path.contains(';') || req.path.contains('|') {
            return true;
        }

        // SQL injection
        if req.path.to_uppercase().contains(" OR 1=1") {
            return true;
        }

        // Directory traversal
        if req.path.contains("../") {
            return true;
        }

        // Check configured patterns
        for pattern in &self.suspicious_patterns {
            if req.path.contains(pattern) {
                return true;
            }
        }

        false
    }
}

#[async_trait]
impl Parser for HttpParser {
    async fn parse(
        &mut self,
        mut pkt_rx: Receiver<RawPacket>,
        evt_tx: Sender<NetworkEvent>,
    ) -> Result<(), Error> {
        while let Some(packet) = pkt_rx.recv().await {
            // Parse Ethernet -> IP -> TCP
            if let Some(ethernet) = EthernetPacket::new(&packet.data) {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                        let payload = tcp.payload();

                        // Try to parse HTTP
                        if let Some(request) = self.parse_request(payload) {
                            if self.is_suspicious(&request) {
                                let event = NetworkEvent {
                                    timestamp: packet.timestamp,
                                    event_type: NetworkEventType::Http,
                                    severity: 4, // High
                                    data: EventData::Http(request),
                                };

                                evt_tx.send(event).await?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: u8,
    pub headers: Vec<(String, String)>,
}
```

### 4. DNS Parser (`src/parsers/dns/mod.rs`)

```rust
// src/parsers/dns/mod.rs
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::RecordType;

pub struct DnsParser {
    entropy_threshold: f64,
}

impl DnsParser {
    pub fn new(config: &DnsParserConfig) -> Self {
        Self {
            entropy_threshold: config.entropy_threshold,
        }
    }

    pub fn parse_query(&self, data: &[u8]) -> Option<Message> {
        Message::from_vec(data).ok()
    }

    pub fn is_tunneling(&self, query: &str) -> bool {
        // Check length
        if query.len() > 100 {
            return true;
        }

        // Check entropy
        let entropy = self.calculate_entropy(query);
        if entropy > self.entropy_threshold {
            return true;
        }

        // Check label count
        let labels = query.matches('.').count();
        if labels > 10 {
            return true;
        }

        false
    }

    pub fn is_dga(&self, domain: &str) -> bool {
        // High entropy check
        let entropy = self.calculate_entropy(domain);
        if entropy > 4.0 {
            return true;
        }

        // Suspicious TLDs
        let suspicious_tlds = vec![".tk", ".ml", ".ga", ".cf", ".gq"];
        for tld in suspicious_tlds {
            if domain.ends_with(tld) {
                return true;
            }
        }

        false
    }

    fn calculate_entropy(&self, s: &str) -> f64 {
        use std::collections::HashMap;

        let mut freq = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for count in freq.values() {
            let p = *count as f64 / len;
            entropy -= p * p.log2();
        }

        entropy
    }
}

#[async_trait]
impl Parser for DnsParser {
    async fn parse(
        &mut self,
        mut pkt_rx: Receiver<RawPacket>,
        evt_tx: Sender<NetworkEvent>,
    ) -> Result<(), Error> {
        while let Some(packet) = pkt_rx.recv().await {
            if let Some(ethernet) = EthernetPacket::new(&packet.data) {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                        // DNS typically on port 53
                        if udp.get_destination() == 53 || udp.get_source() == 53 {
                            if let Some(msg) = self.parse_query(udp.payload()) {
                                for query in msg.queries() {
                                    let domain = query.name().to_string();

                                    if self.is_tunneling(&domain) || self.is_dga(&domain) {
                                        let event = NetworkEvent {
                                            timestamp: packet.timestamp,
                                            event_type: NetworkEventType::Dns,
                                            severity: 4,
                                            data: EventData::Dns(DnsQuery {
                                                domain,
                                                query_type: query.query_type().to_string(),
                                            }),
                                        };

                                        evt_tx.send(event).await?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
```

### 5. C2 Beacon Detector (`src/detectors/c2beacon/mod.rs`)

```rust
// src/detectors/c2beacon/mod.rs
use std::collections::HashMap;
use std::time::Duration;

pub struct C2BeaconDetector {
    connections: HashMap<String, ConnectionTracker>,
    min_connections: usize,
    cv_threshold: f64,
}

struct ConnectionTracker {
    dst_ip: String,
    dst_port: u16,
    timestamps: Vec<i64>,
    bytes_sent: Vec<u64>,
}

impl C2BeaconDetector {
    pub fn new(config: &C2Config) -> Self {
        Self {
            connections: HashMap::new(),
            min_connections: config.min_connections,
            cv_threshold: config.interval_threshold,
        }
    }

    pub fn track_connection(&mut self, conn: &Connection) -> Option<Alert> {
        let key = format!("{}:{}", conn.dst_ip, conn.dst_port);

        let tracker = self.connections
            .entry(key.clone())
            .or_insert_with(|| ConnectionTracker {
                dst_ip: conn.dst_ip.clone(),
                dst_port: conn.dst_port,
                timestamps: Vec::new(),
                bytes_sent: Vec::new(),
            });

        tracker.timestamps.push(conn.timestamp);
        tracker.bytes_sent.push(conn.bytes_sent);

        // Analyze after sufficient data
        if tracker.timestamps.len() >= self.min_connections {
            if self.is_beaconing(tracker) {
                return Some(Alert {
                    alert_type: AlertType::C2Beacon,
                    severity: 5, // Critical
                    description: format!("C2 beacon detected to {}:{}", tracker.dst_ip, tracker.dst_port),
                    evidence: self.build_evidence(tracker),
                });
            }
        }

        None
    }

    fn is_beaconing(&self, tracker: &ConnectionTracker) -> bool {
        // Calculate intervals
        let mut intervals = Vec::new();
        for i in 1..tracker.timestamps.len() {
            let interval = (tracker.timestamps[i] - tracker.timestamps[i-1]) as f64;
            intervals.push(interval);
        }

        // Calculate statistics
        let mean = self.mean(&intervals);
        let stddev = self.stddev(&intervals, mean);

        // Coefficient of variation
        let cv = stddev / mean;

        // Low CV indicates regular beaconing
        cv < self.cv_threshold && mean > 5.0 && mean < 3600.0
    }

    fn mean(&self, values: &[f64]) -> f64 {
        values.iter().sum::<f64>() / values.len() as f64
    }

    fn stddev(&self, values: &[f64], mean: f64) -> f64 {
        let variance: f64 = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        variance.sqrt()
    }
}
```

---

## Configuration

```toml
# config.toml
[agent]
name = "mxwatch-agent"
version = "1.0.0"
log_level = "info"

[capture]
interface = "eth0"
snaplen = 65535
promiscuous = true
bpf_filter = "tcp or udp"
buffer_size = 10000

[parsers.http]
enabled = true
suspicious_patterns = ["'; DROP TABLE", "../", "; ls"]

[parsers.dns]
enabled = true
detect_tunneling = true
detect_dga = true
entropy_threshold = 4.5

[detectors.c2beacon]
enabled = true
min_connections = 10
interval_threshold = 0.2

[buffer]
size = 10000
batch_size = 100
batch_timeout = "5s"

[output.http]
enabled = true
url = "https://mxtac.example.com/api/v1/ingest/ocsf"
api_key = "${MXWATCH_API_KEY}"
retry_attempts = 3
```

---

## Dependencies (Cargo.toml)

```toml
[package]
name = "mxwatch"
version = "1.0.0"
edition = "2021"
rust-version = "1.75"

[dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }
async-trait = "0.1"

# Packet capture
pcap = "1.1"
pnet = "0.34"

# DNS parsing
trust-dns-proto = "0.23"

# HTTP parsing
httparse = "1.8"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# HTTP client
reqwest = { version = "0.11", features = ["json", "gzip"] }

# Compression
flate2 = "1.0"

# Logging
log = "0.4"
env_logger = "0.11"

# Time
chrono = { version = "0.4", features = ["serde"] }

# Statistics
statistical = "1.0"

# Error handling
thiserror = "1.0"
anyhow = "1.0"

[dev-dependencies]
tokio-test = "0.4"
criterion = "0.5"

[[bench]]
name = "packet_parsing"
harness = false
```

---

## Build System

```makefile
.PHONY: build test clean install

build:
\tcargo build --release

build-linux:
\tcargo build --release --target x86_64-unknown-linux-gnu

build-windows:
\tcargo build --release --target x86_64-pc-windows-gnu

build-darwin:
\tcargo build --release --target x86_64-apple-darwin

build-all: build-linux build-windows build-darwin

test:
\tcargo test --all-features

bench:
\tcargo bench

clean:
\tcargo clean

install:
\tcp target/release/mxwatch /usr/local/bin/
\tmkdir -p /etc/mxwatch
\tcp configs/config.toml /etc/mxwatch/

# Requires libpcap-dev
setup-deps:
\tsudo apt-get install libpcap-dev  # Debian/Ubuntu
```

---

*Project structure designed for Rust implementation*
*Next: See 03-CONFIGURATION.md for configuration details*
