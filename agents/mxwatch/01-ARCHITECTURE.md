# MxWatch - Architecture Overview

> **Version**: 1.0
> **Date**: 2026-01-19
> **Status**: Design Phase

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Component Design](#2-component-design)
3. [Data Flow](#3-data-flow)
4. [OCSF Event Generation](#4-ocsf-event-generation)
5. [Performance Considerations](#5-performance-considerations)
6. [Security Design](#6-security-design)

---

## 1. System Architecture

### 1.1 High-Level Architecture

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Network["Network Traffic"]
        style Network fill:#e3f2fd,stroke:#1565c0
        NIC[Network Interface Card]
        PACKETS[1-5M pps]
    end

    subgraph Agent["MxWatch Agent"]
        style Agent fill:#e8f5e9,stroke:#2e7d32

        subgraph Capture["Packet Capture"]
            style Capture fill:#fff3e0,stroke:#ef6c00
            AFPACKET[AF_PACKET + MMAP]
            BPF[BPF Filter]
            FANOUT[PACKET_FANOUT]
        end

        subgraph Parsers["Protocol Parsers"]
            style Parsers fill:#f3e5f5,stroke:#7b1fa2
            HTTP[HTTP/HTTPS Parser]
            DNS[DNS Parser]
            TLS[TLS Parser]
        end

        subgraph Detection["Detection Engine"]
            style Detection fill:#e0f2f1,stroke:#00695c
            C2[C2 Beacon Detector]
            SCAN[Port Scan Detector]
            EXFIL[Exfiltration Detector]
        end

        subgraph Core["Core Engine"]
            style Core fill:#fce4ec,stroke:#ad1457
            BUILDER[OCSF Event Builder]
            ENRICH[Enrichment]
            BUFFER[Event Buffer]
        end

        subgraph Output["Output"]
            style Output fill:#fff9c4,stroke:#f57f17
            HTTP_OUT[HTTP Sender]
        end
    end

    subgraph Platform["MxTac Platform"]
        style Platform fill:#fff3e0,stroke:#ef6c00
        API[Ingestion API]
    end

    NIC --> BPF
    BPF --> AFPACKET
    AFPACKET --> FANOUT
    FANOUT --> Parsers
    Parsers --> Detection
    Detection --> Core
    Core --> Output
    Output --> API
```

### 1.2 Component Layers

| Layer | Components | Responsibility |
|-------|------------|----------------|
| **Capture** | AF_PACKET + MMAP, BPF Filter, PACKET_FANOUT | Zero-copy packet capture at 1-5M pps |
| **Parsing** | HTTP, DNS, TLS Parsers | Extract protocol data |
| **Detection** | C2, Port Scan, Exfiltration Detectors | Identify threats |
| **Processing** | OCSF Builder, Enrichment | Transform to OCSF |
| **Buffering** | Event Buffer | Optimize output |
| **Output** | HTTP Sender | Deliver to MxTac |

### 1.3 Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| **Throughput** | 1-5M pps | With AF_PACKET on 4-8 core system |
| **Network Speed** | Up to 10 Gbps | Kernel-dependent |
| **Packet Loss** | 1-5% | Under normal conditions @ 10 Gbps |
| **Latency** | < 10 μs | Per-packet processing |
| **CPU Usage** | 5-15% | 4-8 cores @ 1-10 Gbps |
| **Memory** | 40-120 MB | Scales with cores and buffer size |

---

## 2. Component Design

### 2.1 Packet Capture (AF_PACKET + MMAP)

**Technology**: AF_PACKET + MMAP (Linux), libpcap (Windows/macOS)

**Capture Architecture**:
- **Primary**: AF_PACKET with PACKET_MMAP (Linux kernel built-in)
- **Fallback**: libpcap for Windows/macOS
- **Performance**: 1-5M packets/second (10x better than libpcap)

**Key Features**:
- Zero-copy packet delivery via memory-mapped ring buffer
- Built into Linux kernel (no modules to install)
- Multi-core load balancing with PACKET_FANOUT
- BPF filtering at kernel level
- High-resolution timestamps
- Pure Rust implementation (no FFI)

**Architecture**:

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph NIC["Network Interface Card"]
        style NIC fill:#e3f2fd,stroke:#1565c0
        PACKETS[Network Packets<br/>1-5M pps]
    end

    subgraph Kernel["Linux Kernel - AF_PACKET"]
        style Kernel fill:#e8f5e9,stroke:#2e7d32

        subgraph Ring["PACKET_MMAP Ring Buffer"]
            style Ring fill:#f3e5f5,stroke:#7b1fa2
            RINGBUF[Circular Buffer<br/>Zero-Copy]
            BPF[BPF Filter]
            FANOUT[PACKET_FANOUT<br/>Load Balancing]
        end
    end

    subgraph Agent["MxWatch Agent - Rust"]
        style Agent fill:#fff9c4,stroke:#f57f17

        subgraph Workers["Multi-Core Workers"]
            style Workers fill:#fce4ec,stroke:#ad1457
            CORE0[Core 0]
            CORE1[Core 1]
            CORE2[Core 2]
            CORE3[Core 3]
        end
    end

    PACKETS --> Ring
    Ring -->|mmap<br/>Zero-Copy| Workers
```

**Implementation**:

```rust
use nix::sys::socket::*;
use nix::libc::{self, ETH_P_ALL};
use std::os::unix::io::RawFd;
use tokio::sync::mpsc;

pub struct PacketCapture {
    workers: Vec<AfPacketWorker>,
    config: CaptureConfig,
    packet_tx: mpsc::Sender<RawPacket>,
}

pub struct AfPacketWorker {
    socket_fd: RawFd,
    ring_buffer: *mut u8,
    ring_size: usize,
    core_id: usize,
    interface: String,
}

pub struct CaptureConfig {
    pub interface: String,
    pub workers: usize,           // Number of CPU cores
    pub block_size: u32,          // MMAP block size (4096)
    pub frame_size: u32,          // Frame size (2048)
    pub block_count: u32,         // Number of blocks (256)
    pub fanout_group: u16,        // PACKET_FANOUT group ID
}

impl PacketCapture {
    pub fn new(config: CaptureConfig) -> Result<Self, Error> {
        let (packet_tx, _) = mpsc::channel(100000);
        let mut workers = Vec::new();

        // Create one AF_PACKET socket per CPU core
        for core_id in 0..config.workers {
            let worker = AfPacketWorker::new(
                &config.interface,
                core_id,
                &config,
            )?;
            workers.push(worker);
        }

        Ok(Self {
            workers,
            config,
            packet_tx,
        })
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        let mut handles = Vec::new();

        // Spawn one tokio task per core
        for mut worker in self.workers.drain(..) {
            let tx = self.packet_tx.clone();

            let handle = tokio::spawn(async move {
                worker.run(tx).await
            });

            handles.push(handle);
        }

        // Wait for all workers
        for handle in handles {
            handle.await.unwrap();
        }

        Ok(())
    }
}

impl AfPacketWorker {
    pub fn new(
        interface: &str,
        core_id: usize,
        config: &CaptureConfig,
    ) -> Result<Self, Error> {
        unsafe {
            // Create raw AF_PACKET socket
            let socket_fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (ETH_P_ALL as u16).to_be() as i32
            );

            if socket_fd < 0 {
                return Err(Error::SocketError("Failed to create AF_PACKET socket"));
            }

            // Get interface index
            let if_index = Self::get_interface_index(interface)?;

            // Setup PACKET_MMAP ring buffer
            let req = libc::tpacket_req {
                tp_block_size: config.block_size,
                tp_frame_size: config.frame_size,
                tp_block_nr: config.block_count,
                tp_frame_nr: (config.block_count * config.block_size) / config.frame_size,
            };

            // Set socket options for PACKET_MMAP (version 2)
            let version = libc::TPACKET_V2;
            libc::setsockopt(
                socket_fd,
                libc::SOL_PACKET,
                libc::PACKET_VERSION,
                &version as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            );

            // Configure ring buffer
            libc::setsockopt(
                socket_fd,
                libc::SOL_PACKET,
                libc::PACKET_RX_RING,
                &req as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::tpacket_req>() as u32,
            );

            // Setup PACKET_FANOUT for load balancing across cores
            let fanout_arg = (config.fanout_group as u32) |
                            (libc::PACKET_FANOUT_HASH << 16);
            libc::setsockopt(
                socket_fd,
                libc::SOL_PACKET,
                libc::PACKET_FANOUT,
                &fanout_arg as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as u32,
            );

            // Memory-map the ring buffer (zero-copy)
            let ring_size = (req.tp_block_size * req.tp_block_nr) as usize;
            let ring_buffer = libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                socket_fd,
                0,
            ) as *mut u8;

            if ring_buffer == libc::MAP_FAILED as *mut u8 {
                libc::close(socket_fd);
                return Err(Error::MmapError("Failed to mmap ring buffer"));
            }

            // Bind socket to interface
            let sll = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: (ETH_P_ALL as u16).to_be(),
                sll_ifindex: if_index,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };

            libc::bind(
                socket_fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            );

            Ok(Self {
                socket_fd,
                ring_buffer,
                ring_size,
                core_id,
                interface: interface.to_string(),
            })
        }
    }

    fn get_interface_index(interface: &str) -> Result<i32, Error> {
        use std::ffi::CString;
        unsafe {
            let iface = CString::new(interface)?;
            let mut ifr: libc::ifreq = std::mem::zeroed();
            libc::strcpy(ifr.ifr_name.as_mut_ptr(), iface.as_ptr());

            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            libc::ioctl(sock, libc::SIOCGIFINDEX, &mut ifr);
            libc::close(sock);

            Ok(ifr.ifr_ifru.ifru_ivalue)
        }
    }

    pub async fn run(&mut self, tx: mpsc::Sender<RawPacket>) {
        let mut frame_offset = 0;
        let frame_size = 2048; // tp_frame_size

        loop {
            unsafe {
                let frame_ptr = self.ring_buffer.add(frame_offset);
                let hdr = frame_ptr as *mut libc::tpacket2_hdr;

                // Check if frame is ready (TP_STATUS_USER bit set)
                while (*hdr).tp_status & libc::TP_STATUS_USER == 0 {
                    tokio::task::yield_now().await;
                }

                // Extract packet data
                let packet_data = frame_ptr.add((*hdr).tp_mac as usize);
                let packet_len = (*hdr).tp_snaplen as usize;

                let packet = RawPacket {
                    data: std::slice::from_raw_parts(packet_data, packet_len).to_vec(),
                    timestamp: (*hdr).tp_sec as i64,
                    timestamp_ns: (*hdr).tp_nsec as i64,
                    length: (*hdr).tp_len as usize,
                    core_id: self.core_id,
                };

                if tx.send(packet).await.is_err() {
                    break; // Channel closed
                }

                // Mark frame as kernel-owned (release for reuse)
                (*hdr).tp_status = libc::TP_STATUS_KERNEL;

                // Move to next frame
                frame_offset = (frame_offset + frame_size) % self.ring_size;
            }
        }
    }

    pub fn set_bpf_filter(&self, filter: &str) -> Result<(), Error> {
        // Compile and attach BPF filter
        // (Implementation uses libpcap for BPF compilation, then attaches to socket)
        Ok(())
    }
}

impl Drop for AfPacketWorker {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ring_buffer as *mut libc::c_void, self.ring_size);
            libc::close(self.socket_fd);
        }
    }
}

pub struct RawPacket {
    pub data: Vec<u8>,
    pub timestamp: i64,      // Unix timestamp (seconds)
    pub timestamp_ns: i64,   // Nanosecond precision
    pub length: usize,
    pub core_id: usize,      // Which core received this
}
```

**BPF Filter Configuration**:

```rust
impl PacketCapture {
    pub fn configure_bpf_filters(&mut self) -> Result<(), Error> {
        // BPF filter for HTTP/HTTPS/DNS traffic only
        let filter = "tcp port 80 or tcp port 443 or udp port 53";

        for worker in &mut self.workers {
            worker.set_bpf_filter(filter)?;
        }

        Ok(())
    }
}
```

**Configuration** (`/etc/mxwatch/config.yaml`):

```yaml
capture:
  interface: eth0
  engine: afpacket        # AF_PACKET + MMAP (Linux)

  afpacket:
    workers: 8            # CPU cores to use
    block_size: 4096      # MMAP block size
    frame_size: 2048      # Frame size
    block_count: 256      # Number of blocks
    fanout_group: 1       # PACKET_FANOUT group ID

    # BPF filter (kernel-level filtering)
    bpf_filter: "tcp port 80 or tcp port 443 or udp port 53"

output:
  http:
    url: https://mxtac.example.com/api/v1/events
    batch_size: 1000
```

**Dependencies** (`Cargo.toml`):

```toml
[dependencies]
nix = "0.27"            # POSIX APIs (socket, mmap, ioctl)
libc = "0.2"            # Linux syscalls
tokio = { version = "1.35", features = ["full"] }
serde = "1.0"           # Serialization
serde_yaml = "0.9"      # YAML config parsing
```

### 2.2 HTTP/HTTPS Parser

**Monitored Fields**:
- Request method, URI, headers
- Response status code, headers
- User-Agent, Referer
- Content-Type, Content-Length
- Cookies, authentication headers

**Key Features**:
- HTTP/1.1 and HTTP/2 support
- Request/response correlation
- Header parsing
- Suspicious pattern detection (command injection, SQL injection)

**Implementation**:
```go
type HTTPParser struct {
    requests  map[string]*HTTPRequest
    events    chan ocsf.NetworkActivity
}

type HTTPRequest struct {
    Method      string
    URI         string
    Host        string
    UserAgent   string
    Headers     map[string]string
    Timestamp   time.Time
}

type HTTPResponse struct {
    StatusCode  int
    Headers     map[string]string
    Timestamp   time.Time
}

func (hp *HTTPParser) ParsePacket(packet gopacket.Packet) {
    if httpLayer := packet.Layer(layers.LayerTypeHTTP); httpLayer != nil {
        http := httpLayer.(*layers.HTTP)

        if len(http.Method) > 0 {
            // HTTP Request
            req := &HTTPRequest{
                Method:    string(http.Method),
                URI:       string(http.RequestURI),
                Host:      string(http.Host),
                UserAgent: hp.extractUserAgent(http.Headers),
                Timestamp: packet.Metadata().Timestamp,
            }

            // Check for suspicious patterns
            if hp.isSuspicious(req) {
                event := hp.buildOCSFEvent(req)
                hp.events <- event
            }
        } else if http.StatusCode > 0 {
            // HTTP Response
            resp := &HTTPResponse{
                StatusCode: int(http.StatusCode),
                Timestamp:  packet.Metadata().Timestamp,
            }

            // Check for errors or suspicious responses
            if resp.StatusCode >= 400 || hp.isSuspiciousResponse(resp) {
                event := hp.buildOCSFEvent(resp)
                hp.events <- event
            }
        }
    }
}

func (hp *HTTPParser) isSuspicious(req *HTTPRequest) bool {
    // Check for command injection
    if strings.Contains(req.URI, ";") || strings.Contains(req.URI, "|") {
        return true
    }

    // Check for SQL injection
    if strings.Contains(req.URI, "'") || strings.Contains(req.URI, "OR 1=1") {
        return true
    }

    // Check for directory traversal
    if strings.Contains(req.URI, "../") {
        return true
    }

    return false
}
```

### 2.3 DNS Parser

**Monitored Fields**:
- Query name, type, class
- Response records (A, AAAA, CNAME, MX, TXT)
- Query/response timestamps
- DNS server IP

**Key Features**:
- DNS tunneling detection
- DGA domain detection
- Suspicious TLD detection
- Fast-flux detection

**Implementation**:
```go
type DNSParser struct {
    queries   map[uint16]*DNSQuery
    events    chan ocsf.NetworkActivity
}

type DNSQuery struct {
    Name      string
    Type      string
    Class     string
    Timestamp time.Time
    SrcIP     string
}

type DNSResponse struct {
    Name      string
    Answers   []DNSAnswer
    Timestamp time.Time
}

type DNSAnswer struct {
    Name  string
    Type  string
    Data  string
    TTL   uint32
}

func (dp *DNSParser) ParsePacket(packet gopacket.Packet) {
    if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
        dns := dnsLayer.(*layers.DNS)

        if dns.QR {
            // DNS Response
            for _, answer := range dns.Answers {
                if dp.isSuspiciousDomain(string(answer.Name)) {
                    event := dp.buildOCSFEvent(answer)
                    dp.events <- event
                }
            }
        } else {
            // DNS Query
            for _, question := range dns.Questions {
                query := &DNSQuery{
                    Name:      string(question.Name),
                    Type:      question.Type.String(),
                    Timestamp: packet.Metadata().Timestamp,
                }

                // Check for DNS tunneling
                if dp.isDNSTunneling(query) {
                    event := dp.buildOCSFEvent(query)
                    dp.events <- event
                }

                // Check for DGA domain
                if dp.isDGA(query.Name) {
                    event := dp.buildOCSFEvent(query)
                    dp.events <- event
                }
            }
        }
    }
}

func (dp *DNSParser) isDNSTunneling(query *DNSQuery) bool {
    // Check for unusually long subdomain
    if len(query.Name) > 100 {
        return true
    }

    // Check for high entropy (random-looking)
    entropy := dp.calculateEntropy(query.Name)
    if entropy > 4.5 {
        return true
    }

    // Check for excessive labels
    labels := strings.Count(query.Name, ".")
    if labels > 10 {
        return true
    }

    return false
}

func (dp *DNSParser) isDGA(domain string) bool {
    // Check for random-looking domain
    entropy := dp.calculateEntropy(domain)
    if entropy > 4.0 {
        return true
    }

    // Check for suspicious TLDs
    suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".gq"}
    for _, tld := range suspiciousTLDs {
        if strings.HasSuffix(domain, tld) {
            return true
        }
    }

    return false
}

func (dp *DNSParser) calculateEntropy(s string) float64 {
    freq := make(map[rune]int)
    for _, c := range s {
        freq[c]++
    }

    var entropy float64
    for _, count := range freq {
        p := float64(count) / float64(len(s))
        entropy -= p * math.Log2(p)
    }

    return entropy
}
```

### 2.4 TLS/SSL Parser

**Monitored Fields**:
- TLS version
- Cipher suites
- Server certificate (CN, issuer, validity)
- SNI (Server Name Indication)
- Certificate chain

**Key Features**:
- Self-signed certificate detection
- Expired certificate detection
- Weak cipher detection
- SNI extraction

**Implementation**:
```go
type TLSParser struct {
    events chan ocsf.NetworkActivity
}

func (tp *TLSParser) ParsePacket(packet gopacket.Packet) {
    if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
        tls := tlsLayer.(*layers.TLS)

        for _, record := range tls.Contents {
            // Server Hello
            if record.ContentType == layers.TLSContentTypeHandshake {
                if tp.isWeakCipher(record.CipherSuite) {
                    event := tp.buildOCSFEvent(record)
                    tp.events <- event
                }
            }

            // Certificate
            if record.ContentType == layers.TLSContentTypeCertificate {
                cert := tp.parseCertificate(record)

                if tp.isSelfSigned(cert) || tp.isExpired(cert) {
                    event := tp.buildOCSFEvent(cert)
                    tp.events <- event
                }
            }
        }
    }
}

func (tp *TLSParser) isWeakCipher(cipher uint16) bool {
    weakCiphers := []uint16{
        0x0004, // TLS_RSA_WITH_RC4_128_MD5
        0x0005, // TLS_RSA_WITH_RC4_128_SHA
        // ... more weak ciphers
    }

    for _, weak := range weakCiphers {
        if cipher == weak {
            return true
        }
    }

    return false
}
```

### 2.5 C2 Beacon Detector

**Detection Methods**:
- Fixed interval beaconing
- Jitter-based beaconing
- Statistical analysis of connection patterns
- Known C2 signatures

**Key Features**:
- Time-series analysis
- Frequency analysis
- Anomaly detection

**Implementation**:
```go
type C2BeaconDetector struct {
    connections map[string]*ConnectionTracker
    events      chan ocsf.NetworkActivity
}

type ConnectionTracker struct {
    DstIP       string
    DstPort     int
    Timestamps  []time.Time
    BytesSent   []int64
    BytesRecv   []int64
}

func (cbd *C2BeaconDetector) TrackConnection(conn Connection) {
    key := fmt.Sprintf("%s:%d", conn.DstIP, conn.DstPort)

    tracker, exists := cbd.connections[key]
    if !exists {
        tracker = &ConnectionTracker{
            DstIP:      conn.DstIP,
            DstPort:    conn.DstPort,
            Timestamps: make([]time.Time, 0),
        }
        cbd.connections[key] = tracker
    }

    tracker.Timestamps = append(tracker.Timestamps, conn.Timestamp)
    tracker.BytesSent = append(tracker.BytesSent, conn.BytesSent)
    tracker.BytesRecv = append(tracker.BytesRecv, conn.BytesRecv)

    // Analyze after 10 connections
    if len(tracker.Timestamps) >= 10 {
        if cbd.isBeaconing(tracker) {
            event := cbd.buildOCSFEvent(tracker)
            cbd.events <- event
        }
    }
}

func (cbd *C2BeaconDetector) isBeaconing(tracker *ConnectionTracker) bool {
    // Calculate intervals between connections
    intervals := make([]float64, 0)
    for i := 1; i < len(tracker.Timestamps); i++ {
        interval := tracker.Timestamps[i].Sub(tracker.Timestamps[i-1]).Seconds()
        intervals = append(intervals, interval)
    }

    // Calculate mean and standard deviation
    mean := cbd.mean(intervals)
    stddev := cbd.stddev(intervals, mean)

    // Check for regular interval (low std dev)
    // Coefficient of Variation < 0.2 indicates beaconing
    cv := stddev / mean
    if cv < 0.2 && mean > 5 && mean < 3600 {
        return true
    }

    // Check for consistent payload size
    if cbd.isConsistentPayload(tracker.BytesSent) {
        return true
    }

    return false
}

func (cbd *C2BeaconDetector) mean(values []float64) float64 {
    sum := 0.0
    for _, v := range values {
        sum += v
    }
    return sum / float64(len(values))
}

func (cbd *C2BeaconDetector) stddev(values []float64, mean float64) float64 {
    variance := 0.0
    for _, v := range values {
        variance += math.Pow(v-mean, 2)
    }
    return math.Sqrt(variance / float64(len(values)))
}

func (cbd *C2BeaconDetector) isConsistentPayload(sizes []int64) bool {
    if len(sizes) < 5 {
        return false
    }

    // Convert to float64 for stats
    floatSizes := make([]float64, len(sizes))
    for i, s := range sizes {
        floatSizes[i] = float64(s)
    }

    mean := cbd.mean(floatSizes)
    stddev := cbd.stddev(floatSizes, mean)

    // CV < 0.1 indicates very consistent payload
    cv := stddev / mean
    return cv < 0.1
}
```

### 2.6 Port Scan Detector

**Detection Methods**:
- Vertical scan (many ports, one host)
- Horizontal scan (one port, many hosts)
- SYN scan, FIN scan, Xmas scan

**Implementation**:
```go
type PortScanDetector struct {
    scanners map[string]*ScanTracker
    events   chan ocsf.NetworkActivity
}

type ScanTracker struct {
    SrcIP       string
    DstPorts    map[int]bool
    DstHosts    map[string]bool
    Timestamps  []time.Time
}

func (psd *PortScanDetector) TrackConnection(conn Connection) {
    tracker, exists := psd.scanners[conn.SrcIP]
    if !exists {
        tracker = &ScanTracker{
            SrcIP:    conn.SrcIP,
            DstPorts: make(map[int]bool),
            DstHosts: make(map[string]bool),
        }
        psd.scanners[conn.SrcIP] = tracker
    }

    tracker.DstPorts[conn.DstPort] = true
    tracker.DstHosts[conn.DstIP] = true
    tracker.Timestamps = append(tracker.Timestamps, conn.Timestamp)

    // Vertical scan: >10 ports on same host in <60 sec
    if len(tracker.DstPorts) > 10 && len(tracker.DstHosts) == 1 {
        duration := tracker.Timestamps[len(tracker.Timestamps)-1].Sub(tracker.Timestamps[0])
        if duration < 60*time.Second {
            event := psd.buildOCSFEvent(tracker, "Vertical Port Scan")
            psd.events <- event
        }
    }

    // Horizontal scan: same port on >10 hosts in <60 sec
    if len(tracker.DstHosts) > 10 && len(tracker.DstPorts) == 1 {
        duration := tracker.Timestamps[len(tracker.Timestamps)-1].Sub(tracker.Timestamps[0])
        if duration < 60*time.Second {
            event := psd.buildOCSFEvent(tracker, "Horizontal Port Scan")
            psd.events <- event
        }
    }
}
```

---

## 3. Data Flow

### 3.1 Packet Processing Pipeline

```
┌──────────────┐
│ Network      │
│ Interface    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ libpcap      │
│ (BPF Filter) │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Packet       │
│ Decoder      │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Protocol     │
│ Parser       │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Detection    │
│ Engine       │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ OCSF Builder │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Event Buffer │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ HTTP Output  │
└──────────────┘
```

---

## 4. OCSF Event Generation

### 4.1 Network Activity Event (Class 4001)

```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {
      "name": "MxWatch",
      "vendor": "MxTac",
      "version": "1.0.0"
    }
  },
  "time": 1705660800,
  "class_uid": 4001,
  "category_uid": 4,
  "activity": "Traffic",
  "activity_id": 5,
  "severity_id": 4,
  "severity": "High",
  "message": "C2 beacon detected",
  "connection_info": {
    "direction": "Outbound",
    "protocol_name": "HTTPS",
    "protocol_num": 443
  },
  "src_endpoint": {
    "ip": "192.168.1.100",
    "port": 54321
  },
  "dst_endpoint": {
    "ip": "203.0.113.50",
    "port": 443
  },
  "http_request": {
    "method": "GET",
    "url": "/api/v1/checkin",
    "user_agent": "Mozilla/5.0"
  },
  "tls": {
    "version": "1.2",
    "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "sni": "malicious-c2.example.com"
  }
}
```

---

## 5. Performance Considerations

### 5.1 Packet Capture Optimization

**Primary: AF_PACKET + MMAP** (Linux):
- Zero-copy via memory-mapped ring buffer
- PACKET_FANOUT for multi-core load balancing
- BPF filters at kernel level (minimal overhead)
- No kernel modules required (built into Linux)
- Performance: ~1-5M packets/second

**Fallback: libpcap** (Windows/macOS):
- Standard packet capture
- BPF filters for basic filtering
- Cross-platform compatibility
- Performance: ~100K-500K packets/second

**Performance Comparison**:

| Engine | Throughput | CPU Usage | Packet Loss | Dependencies | Use Case |
|--------|------------|-----------|-------------|--------------|----------|
| **libpcap** | 100K pps | 80-100% | 10-30% | None | < 1 Gbps, Windows/macOS |
| **AF_PACKET + MMAP** | 1-5M pps | 10-30% | 1-5% | Linux kernel | 1-10 Gbps, Linux |

**Key Optimizations for AF_PACKET + MMAP**:

1. **PACKET_FANOUT** - Automatically distributes packets across CPU cores
2. **BPF Filtering** - Kernel-level filtering before copying to userspace
3. **Zero-Copy mmap()** - Direct access to kernel ring buffer
4. **Async I/O** - Non-blocking packet processing with tokio
5. **Batch Processing** - Process multiple packets per syscall

**Performance Targets**:

| Network Speed | Workers | Expected Throughput | CPU Usage | Memory |
|---------------|---------|---------------------|-----------|--------|
| **100 Mbps** | 2 | 10K pps | 5-10% | 40 MB |
| **1 Gbps** | 4 | 150K pps | 10-15% | 60 MB |
| **10 Gbps** | 8 | 1.5M pps | 20-30% | 120 MB |

**When to Use AF_PACKET + MMAP** (Linux):
- ✅ Network traffic 100 Mbps - 10 Gbps
- ✅ Linux servers (kernel 2.6.27+)
- ✅ No kernel module installation allowed
- ✅ Pure Rust implementation required
- ✅ Multi-core systems (4-8 cores)

**When to Use libpcap** (Cross-platform):
- ✅ Windows or macOS deployment
- ✅ Network traffic < 100 Mbps
- ✅ Simple deployment requirements
- ✅ Limited CPU resources (1-2 cores)

### 5.2 Memory Management

Already covered in section 2.1 implementation with `RawPacket` struct and drop trait.
use std::ffi::CString;

pub struct PFRingCapture {
    ring: *mut pfring,
    interface: String,
    cluster_id: u16,
}

impl PFRingCapture {
    pub fn new(interface: &str, cluster_id: u16) -> Result<Self, Error> {
        unsafe {
            let iface = CString::new(interface)?;

            // Open PF_RING with zero-copy and timestamping
            let ring = pfring_open(
                iface.as_ptr(),
                1536,           // snaplen (Ethernet MTU)
                PF_RING_PROMISC |
                PF_RING_TIMESTAMP |
                PF_RING_DNA |
                PF_RING_ZC
            );

            if ring.is_null() {
                return Err(Error::PFRingOpen("Failed to open PF_RING"));
            }

            // Enable ring
            pfring_enable_ring(ring);

            // Set application name (for monitoring)
            let app_name = CString::new("mxwatch")?;
            pfring_set_application_name(ring, app_name.as_ptr());

            Ok(Self {
                ring,
                interface: interface.to_string(),
                cluster_id
            })
        }
    }

    pub async fn recv_packet(&mut self) -> Result<Packet, Error> {
        unsafe {
            let mut hdr: pfring_pkthdr = std::mem::zeroed();
            let mut buffer = vec![0u8; 65535];

            loop {
                let rc = pfring_recv(
                    self.ring,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut hdr,
                    1  // wait_for_packet
                );

                match rc {
                    1 => {
                        return Ok(Packet {
                            data: buffer[..hdr.caplen as usize].to_vec(),
                            timestamp: hdr.ts.tv_sec as i64,
                            length: hdr.len as usize,
                            hash: hdr.extended_hdr.pkt_hash,
                        });
                    }
                    0 => tokio::task::yield_now().await,
                    _ => return Err(Error::RecvError("PF_RING recv error")),
                }
            }
        }
    }

    pub fn set_cluster(&mut self, cluster_type: pfring_cluster_type) -> Result<(), Error> {
        unsafe {
            let rc = pfring_set_cluster(
                self.ring,
                self.cluster_id,
                cluster_type
            );
            if rc < 0 {
                return Err(Error::ClusterError("Failed to set cluster"));
            }
            Ok(())
        }
    }

    pub fn add_bpf_filter(&mut self, filter: &str) -> Result<(), Error> {
        unsafe {
            let filter_str = CString::new(filter)?;
            let rc = pfring_set_bpf_filter(self.ring, filter_str.as_ptr());
            if rc < 0 {
                return Err(Error::FilterError("Failed to set BPF filter"));
            }
            Ok(())
        }
    }

    pub fn enable_hw_timestamp(&mut self) -> Result<(), Error> {
        unsafe {
            let rc = pfring_enable_hw_timestamp(
                self.ring,
                std::ptr::null_mut(),
                1  // enable
            );
            if rc < 0 {
                return Err(Error::TimestampError("Failed to enable HW timestamp"));
            }
            Ok(())
        }
    }
}

impl Drop for PFRingCapture {
    fn drop(&mut self) {
        unsafe {
            pfring_close(self.ring);
        }
    }
}
```

**Multi-Core Load Balancing**:

```rust
pub struct MultiCoreCapture {
    cores: usize,
    cluster_id: u16,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl MultiCoreCapture {
    pub fn new(interface: &str, cores: usize) -> Result<Self, Error> {
        let cluster_id = 1;
        let mut workers = Vec::new();

        for core_id in 0..cores {
            let iface = interface.to_string();

            let worker = tokio::spawn(async move {
                // Set CPU affinity
                set_cpu_affinity(core_id);

                // Open PF_RING on this core
                let mut capture = PFRingCapture::new(&iface, cluster_id).unwrap();

                // Configure per-flow load balancing
                capture.set_cluster(pfring_cluster_type::cluster_per_flow).unwrap();

                // Start packet processing
                loop {
                    if let Ok(packet) = capture.recv_packet().await {
                        process_packet_on_core(packet, core_id);
                    }
                }
            });

            workers.push(worker);
        }

        Ok(Self { cores, cluster_id, workers })
    }
}

fn set_cpu_affinity(core_id: usize) {
    use nix::sched::{sched_setaffinity, CpuSet};
    use nix::unistd::Pid;

    let mut cpu_set = CpuSet::new();
    cpu_set.set(core_id).unwrap();
    sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();
}
```

**Hardware Filtering** (offload to NIC):

```rust
impl PFRingCapture {
    pub fn add_hw_filter(&mut self, rule: &HardwareFilterRule) -> Result<(), Error> {
        unsafe {
            let mut hw_rule: hw_filtering_rule = std::mem::zeroed();

            // Configure rule
            hw_rule.rule_id = rule.id as u16;
            hw_rule.rule_action = hw_filter_rule_command::forward_packet_and_stop_rule_evaluation;

            // Match criteria
            hw_rule.core_fields.src_ip = rule.src_ip;
            hw_rule.core_fields.dst_ip = rule.dst_ip;
            hw_rule.core_fields.src_port = rule.src_port;
            hw_rule.core_fields.dst_port = rule.dst_port;
            hw_rule.core_fields.proto = rule.protocol as u8;

            // Add rule to NIC
            let rc = pfring_add_hw_rule(self.ring, &mut hw_rule);
            if rc < 0 {
                return Err(Error::HWFilterError("Failed to add hardware filter"));
            }

            Ok(())
        }
    }
}

pub struct HardwareFilterRule {
    pub id: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8, // TCP=6, UDP=17
}
```

**Configuration**:

```yaml
capture:
  engine: pfring  # Options: libpcap, afpacket, pfring

  # PF_RING specific settings
  pfring:
    cluster_id: 1
    cluster_type: per_flow  # Options: per_flow, round_robin, per_flow_5_tuple
    enable_hw_timestamp: true
    enable_zero_copy: true
    ring_slots: 32768

    # Multi-core configuration
    workers: 8  # Number of CPU cores to use
    cpu_affinity: true

    # Hardware filtering (offload to NIC)
    hw_filters:
      - id: 1
        src_port: 443
        protocol: tcp
        action: forward

      - id: 2
        dst_port: 53
        protocol: udp
        action: forward
```

**Installation**:

```bash
# Install PF_RING kernel module
git clone https://github.com/ntop/PF_RING.git
cd PF_RING/kernel
make && sudo make install
sudo modprobe pf_ring

# Install PF_RING userspace library
cd ../userland/lib
./configure && make && sudo make install

# Add Rust bindings to Cargo.toml
[dependencies]
pfring-sys = "0.1"  # FFI bindings to PF_RING C library
nix = "0.27"        # For CPU affinity
```

**Performance Targets**:

| Network Speed | Workers | Expected Throughput | CPU Usage | Memory |
|---------------|---------|---------------------|-----------|--------|
| **1 Gbps** | 2 | 150K pps | 5-10% | 40 MB |
| **10 Gbps** | 4 | 1.5M pps | 10-15% | 60 MB |
| **40 Gbps** | 8 | 6M pps | 20-30% | 120 MB |
| **100 Gbps** | 16 | 14.8M pps | 40-50% | 240 MB |

**When to Use PF_RING**:
- ✅ Network traffic > 1 Gbps
- ✅ Packet rate > 500K pps
- ✅ Multiple CPU cores available (4+)
- ✅ Linux servers with compatible NICs
- ✅ Zero packet loss requirement

**When to Use libpcap**:
- ✅ Network traffic < 1 Gbps
- ✅ Cross-platform deployment (Windows, macOS)
- ✅ Simple deployment requirements
- ✅ Limited CPU resources

### 5.2 Memory Management

```go
// Use object pools for packet processing
var packetPool = sync.Pool{
    New: func() interface{} {
        return &ProcessedPacket{}
    },
}
```

---

## 6. Security Design

### 6.1 Agent Security

- Requires elevated privileges (CAP_NET_RAW)
- Drop privileges after initialization
- Secure configuration storage
- TLS for all HTTP communication

---

*Architecture designed for production deployment*
*Next: See 02-PROJECT-STRUCTURE.md for code organization*
