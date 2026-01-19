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
    subgraph Network[\"Network Traffic\"]
        style Network fill:#e3f2fd,stroke:#1565c0
        PACKETS[Network Packets]
    end

    subgraph Agent[\"MxWatch Agent\"]
        style Agent fill:#e8f5e9,stroke:#2e7d32

        subgraph Capture[\"Packet Capture\"]
            style Capture fill:#fff3e0,stroke:#ef6c00
            PCAP[libpcap Interface]
            FILTER[BPF Filter]
        end

        subgraph Parsers[\"Protocol Parsers\"]
            style Parsers fill:#f3e5f5,stroke:#7b1fa2
            HTTP[HTTP/HTTPS Parser]
            DNS[DNS Parser]
            TLS[TLS Parser]
            TCP[TCP Analyzer]
        end

        subgraph Detection[\"Detection Engine\"]
            style Detection fill:#e0f2f1,stroke:#00695c
            C2[C2 Beacon Detector]
            SCAN[Port Scan Detector]
            EXFIL[Exfiltration Detector]
            LATERAL[Lateral Movement]
        end

        subgraph Core[\"Core Engine\"]
            style Core fill:#fce4ec,stroke:#ad1457
            BUILDER[OCSF Event Builder]
            ENRICH[Enrichment]
            BUFFER[Event Buffer]
        end

        subgraph Output[\"Output\"]
            style Output fill:#fff9c4,stroke:#f57f17
            HTTP_OUT[HTTP Sender]
        end
    end

    subgraph Platform[\"MxTac Platform\"]
        style Platform fill:#fff3e0,stroke:#ef6c00
        API[Ingestion API]
    end

    PACKETS --> Capture
    Capture --> Parsers
    Parsers --> Detection
    Detection --> Core
    Core --> Output
    Output --> Platform
```

### 1.2 Component Layers

| Layer | Components | Responsibility |
|-------|------------|----------------|
| **Capture** | libpcap, BPF Filter | Capture network packets |
| **Parsing** | HTTP, DNS, TLS Parsers | Extract protocol data |
| **Detection** | C2, Port Scan, Exfiltration Detectors | Identify threats |
| **Processing** | OCSF Builder, Enrichment | Transform to OCSF |
| **Buffering** | Event Buffer | Optimize output |
| **Output** | HTTP Sender | Deliver to MxTac |

---

## 2. Component Design

### 2.1 Packet Capture

**Technology**: libpcap (all platforms)

**Capture Methods**:
- **Linux**: AF_PACKET sockets, libpcap
- **Windows**: WinPcap/Npcap, libpcap
- **macOS**: BPF, libpcap

**Key Features**:
- Berkeley Packet Filter (BPF) for efficient filtering
- Zero-copy capture (where supported)
- Packet buffering
- Promiscuous mode support

**Implementation**:
```go
type PacketCapture struct {
    handle      *pcap.Handle
    interface   string
    snaplen     int32
    promiscuous bool
    filter      string
    packets     chan gopacket.Packet
}

func NewPacketCapture(iface string) (*PacketCapture, error) {
    handle, err := pcap.OpenLive(
        iface,
        65535,  // snaplen
        true,   // promiscuous
        pcap.BlockForever,
    )
    if err != nil {
        return nil, err
    }

    // Set BPF filter (exclude SSH, internal traffic)
    if err := handle.SetBPFFilter("tcp or udp"); err != nil {
        return nil, err
    }

    return &PacketCapture{
        handle:    handle,
        interface: iface,
        packets:   make(chan gopacket.Packet, 1000),
    }, nil
}

func (pc *PacketCapture) Start() {
    packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())

    for packet := range packetSource.Packets() {
        pc.packets <- packet
    }
}
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

- Use BPF filters to reduce packet processing
- Zero-copy capture where supported
- Packet buffers to handle bursts
- Drop packets under extreme load (rather than crash)

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
