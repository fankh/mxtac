# MxWatch - Project Structure

> **Version**: 1.0
> **Date**: 2026-01-19
> **Language**: Go 1.21+

---

## Repository Structure

```
mxwatch/
├── cmd/
│   └── mxwatch/
│       └── main.go                    # Entry point
│
├── internal/
│   ├── agent/
│   │   ├── agent.go                   # Main agent orchestrator
│   │   ├── config.go                  # Configuration loader
│   │   └── lifecycle.go               # Startup/shutdown
│   │
│   ├── capture/
│   │   ├── capture.go                 # Packet capture interface
│   │   ├── capture_linux.go           # Linux-specific (AF_PACKET)
│   │   ├── capture_windows.go         # Windows-specific (Npcap)
│   │   ├── capture_darwin.go          # macOS-specific (BPF)
│   │   └── bpf_filter.go              # BPF filter management
│   │
│   ├── parsers/
│   │   ├── parser.go                  # Base parser interface
│   │   ├── http/
│   │   │   ├── parser.go              # HTTP/HTTPS parser
│   │   │   ├── request.go             # HTTP request parsing
│   │   │   ├── response.go            # HTTP response parsing
│   │   │   └── patterns.go            # Suspicious pattern matching
│   │   │
│   │   ├── dns/
│   │   │   ├── parser.go              # DNS parser
│   │   │   ├── query.go               # DNS query parsing
│   │   │   ├── response.go            # DNS response parsing
│   │   │   ├── tunneling.go           # DNS tunneling detection
│   │   │   └── dga.go                 # DGA detection
│   │   │
│   │   ├── tls/
│   │   │   ├── parser.go              # TLS/SSL parser
│   │   │   ├── handshake.go           # TLS handshake parsing
│   │   │   ├── certificate.go         # Certificate parsing
│   │   │   └── sni.go                 # SNI extraction
│   │   │
│   │   └── tcp/
│   │       ├── analyzer.go            # TCP stream analysis
│   │       ├── flags.go               # TCP flag analysis
│   │       └── reassembly.go          # TCP stream reassembly
│   │
│   ├── detectors/
│   │   ├── detector.go                # Base detector interface
│   │   ├── c2beacon/
│   │   │   ├── detector.go            # C2 beacon detector
│   │   │   ├── interval.go            # Interval analysis
│   │   │   └── signatures.go          # Known C2 signatures
│   │   │
│   │   ├── portscan/
│   │   │   ├── detector.go            # Port scan detector
│   │   │   ├── vertical.go            # Vertical scan detection
│   │   │   └── horizontal.go          # Horizontal scan detection
│   │   │
│   │   ├── exfiltration/
│   │   │   ├── detector.go            # Data exfiltration detector
│   │   │   ├── volume.go              # Volume-based detection
│   │   │   └── protocol.go            # Protocol-based detection
│   │   │
│   │   └── lateral/
│   │       ├── detector.go            # Lateral movement detector
│   │       └── patterns.go            # Known lateral movement patterns
│   │
│   ├── ocsf/
│   │   ├── builder.go                 # OCSF event builder
│   │   ├── models.go                  # OCSF data structures
│   │   ├── network_activity.go        # Network Activity (4001)
│   │   ├── enrichment.go              # Event enrichment
│   │   └── severity.go                # Severity calculation
│   │
│   ├── buffer/
│   │   ├── buffer.go                  # Event buffer
│   │   ├── queue.go                   # Ring buffer implementation
│   │   └── batcher.go                 # Batch processor
│   │
│   ├── output/
│   │   ├── output.go                  # Output handler interface
│   │   ├── http.go                    # HTTP/HTTPS output
│   │   ├── file.go                    # File output
│   │   └── retry.go                   # Retry logic with backoff
│   │
│   └── utils/
│       ├── network.go                 # Network utilities
│       ├── crypto.go                  # Hashing utilities
│       ├── stats.go                   # Statistical functions
│       └── errors.go                  # Error handling
│
├── pkg/
│   └── api/
│       └── types.go                   # Public API types
│
├── configs/
│   ├── config.yaml                    # Default configuration
│   ├── config.linux.yaml              # Linux-specific config
│   ├── config.windows.yaml            # Windows-specific config
│   └── config.darwin.yaml             # macOS-specific config
│
├── scripts/
│   ├── build.sh                       # Build script
│   ├── install.sh                     # Installation script
│   ├── package.sh                     # Package creation
│   └── test.sh                        # Test runner
│
├── deployments/
│   ├── systemd/
│   │   └── mxwatch.service            # Systemd unit file
│   ├── launchd/
│   │   └── com.mxtac.mxwatch.plist    # macOS launchd plist
│   ├── windows/
│   │   └── install-service.ps1        # Windows service installer
│   └── docker/
│       └── Dockerfile                  # Docker image
│
├── docs/
│   ├── README.md
│   ├── ARCHITECTURE.md
│   ├── CONFIGURATION.md
│   ├── DEPLOYMENT.md
│   └── API.md
│
├── tests/
│   ├── integration/
│   │   ├── http_test.go
│   │   ├── dns_test.go
│   │   └── c2beacon_test.go
│   ├── unit/
│   │   ├── parsers_test.go
│   │   ├── detectors_test.go
│   │   └── ocsf_test.go
│   └── fixtures/
│       ├── pcaps/                     # Sample PCAP files
│       └── events.json
│
├── .github/
│   └── workflows/
│       ├── build.yml                  # Build workflow
│       ├── test.yml                   # Test workflow
│       └── release.yml                # Release workflow
│
├── go.mod                             # Go modules
├── go.sum                             # Dependency checksums
├── Makefile                           # Build automation
├── LICENSE                            # Apache 2.0
└── README.md                          # Project README
```

---

## Core Modules

### 1. Agent Orchestrator (`internal/agent/`)

```go
// agent.go
package agent

type Agent struct {
    config      *Config
    capture     capture.PacketCapture
    parsers     []parser.Parser
    detectors   []detector.Detector
    buffer      *buffer.EventBuffer
    output      output.Handler
    shutdown    chan struct{}
}

func New(configPath string) (*Agent, error) {
    config, err := LoadConfig(configPath)
    if err != nil {
        return nil, err
    }

    return &Agent{
        config:   config,
        shutdown: make(chan struct{}),
    }, nil
}

func (a *Agent) Start() error {
    // Initialize packet capture
    a.capture = capture.New(a.config.Capture.Interface)

    // Start packet capture
    go a.capture.Start()

    // Start parsers
    for _, p := range a.parsers {
        go p.Start(a.capture.Packets())
    }

    // Start detectors
    for _, d := range a.detectors {
        go d.Start()
    }

    // Start buffer
    go a.buffer.Start()

    // Wait for shutdown signal
    <-a.shutdown
    return a.Stop()
}

func (a *Agent) Stop() error {
    // Stop capture
    a.capture.Stop()

    // Stop parsers
    for _, p := range a.parsers {
        p.Stop()
    }

    // Flush buffer
    a.buffer.Flush()

    return nil
}
```

### 2. Packet Capture (`internal/capture/capture.go`)

```go
package capture

type PacketCapture interface {
    Start() error
    Stop() error
    Packets() <-chan gopacket.Packet
    Stats() CaptureStats
}

type Capture struct {
    handle      *pcap.Handle
    interface   string
    snaplen     int32
    promiscuous bool
    filter      string
    packets     chan gopacket.Packet
}

type CaptureStats struct {
    PacketsReceived uint64
    PacketsDropped  uint64
    PacketsIfDropped uint64
}

func New(iface string) *Capture {
    return &Capture{
        interface:   iface,
        snaplen:     65535,
        promiscuous: true,
        packets:     make(chan gopacket.Packet, 10000),
    }
}

func (c *Capture) Start() error {
    handle, err := pcap.OpenLive(
        c.interface,
        c.snaplen,
        c.promiscuous,
        pcap.BlockForever,
    )
    if err != nil {
        return err
    }

    // Set BPF filter
    if err := handle.SetBPFFilter(c.filter); err != nil {
        return err
    }

    c.handle = handle

    // Start packet processing
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for packet := range packetSource.Packets() {
        c.packets <- packet
    }

    return nil
}
```

### 3. HTTP Parser (`internal/parsers/http/parser.go`)

```go
package http

type HTTPParser struct {
    packets   <-chan gopacket.Packet
    events    chan ocsf.NetworkActivity
    requests  map[string]*HTTPRequest
}

func (hp *HTTPParser) Start(packets <-chan gopacket.Packet) {
    hp.packets = packets

    for packet := range packets {
        hp.parsePacket(packet)
    }
}

func (hp *HTTPParser) parsePacket(packet gopacket.Packet) {
    if httpLayer := packet.Layer(layers.LayerTypeHTTP); httpLayer != nil {
        http := httpLayer.(*layers.HTTP)

        if len(http.Method) > 0 {
            // Parse HTTP request
            req := &HTTPRequest{
                Method:    string(http.Method),
                URI:       string(http.RequestURI),
                Host:      string(http.Host),
                UserAgent: hp.extractUserAgent(http.Headers),
                Headers:   hp.parseHeaders(http.Headers),
                Timestamp: packet.Metadata().Timestamp,
            }

            // Check for suspicious patterns
            if hp.isSuspicious(req) {
                event := hp.buildOCSFEvent(req)
                hp.events <- event
            }
        }
    }
}

func (hp *HTTPParser) isSuspicious(req *HTTPRequest) bool {
    // Command injection
    if strings.ContainsAny(req.URI, ";|&") {
        return true
    }

    // SQL injection
    if strings.Contains(strings.ToUpper(req.URI), " OR 1=1") {
        return true
    }

    // Directory traversal
    if strings.Contains(req.URI, "../") {
        return true
    }

    return false
}
```

### 4. C2 Beacon Detector (`internal/detectors/c2beacon/detector.go`)

```go
package c2beacon

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

    // Analyze after sufficient data
    if len(tracker.Timestamps) >= 10 {
        if cbd.isBeaconing(tracker) {
            event := cbd.buildOCSFEvent(tracker)
            cbd.events <- event
        }
    }
}

func (cbd *C2BeaconDetector) isBeaconing(tracker *ConnectionTracker) bool {
    // Calculate intervals
    intervals := make([]float64, 0)
    for i := 1; i < len(tracker.Timestamps); i++ {
        interval := tracker.Timestamps[i].Sub(tracker.Timestamps[i-1]).Seconds()
        intervals = append(intervals, interval)
    }

    // Calculate statistics
    mean := cbd.mean(intervals)
    stddev := cbd.stddev(intervals, mean)

    // Check for regular interval (low coefficient of variation)
    cv := stddev / mean
    if cv < 0.2 && mean > 5 && mean < 3600 {
        return true
    }

    return false
}
```

### 5. OCSF Builder (`internal/ocsf/builder.go`)

```go
package ocsf

type Builder struct {
    product Product
    device  Device
}

type Product struct {
    Name    string
    Vendor  string
    Version string
}

type Device struct {
    Hostname string
    IP       string
}

func (b *Builder) BuildNetworkActivity(
    activity string,
    activityID int,
    conn ConnectionInfo,
    http *HTTPInfo,
    tls *TLSInfo,
) *NetworkActivity {
    return &NetworkActivity{
        Metadata: Metadata{
            Version: "1.1.0",
            Product: b.product,
        },
        Time:        time.Now().Unix(),
        ClassUID:    4001,
        CategoryUID: 4,
        Activity:    activity,
        ActivityID:  activityID,
        SeverityID:  calculateSeverity(conn, http),
        ConnectionInfo: conn,
        HTTPRequest:    http,
        TLS:            tls,
        Device:         b.device,
    }
}
```

---

## Configuration Structure

```yaml
# config.yaml
agent:
  name: "mxwatch-agent"
  version: "1.0.0"
  log_level: "info"
  log_file: "/var/log/mxwatch/agent.log"

capture:
  interface: "eth0"
  snaplen: 65535
  promiscuous: true
  bpf_filter: "tcp or udp"
  buffer_size: 10000

parsers:
  http:
    enabled: true
    track_responses: true
    suspicious_patterns:
      - "'; DROP TABLE"
      - "../"
      - "; ls"

  dns:
    enabled: true
    detect_tunneling: true
    detect_dga: true
    entropy_threshold: 4.5

  tls:
    enabled: true
    extract_sni: true
    detect_weak_ciphers: true

detectors:
  c2beacon:
    enabled: true
    min_connections: 10
    interval_threshold: 0.2  # CV threshold

  portscan:
    enabled: true
    port_threshold: 10
    time_window: 60s

  exfiltration:
    enabled: true
    volume_threshold: 100MB
    time_window: 300s

buffer:
  size: 10000
  batch_size: 100
  batch_timeout: 5s

output:
  http:
    enabled: true
    url: "https://mxtac.example.com/api/v1/ingest/ocsf"
    api_key: "${MXWATCH_API_KEY}"
    retry_attempts: 3
    retry_backoff: 1s

  file:
    enabled: false
    path: "/var/log/mxwatch/events.json"
```

---

## Build System

### Makefile

```makefile
.PHONY: build test clean install

VERSION := $(shell git describe --tags --always --dirty)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

build:
\tgo build -ldflags="$(LDFLAGS)" -o bin/mxwatch cmd/mxwatch/main.go

build-linux:
\tGOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/mxwatch-linux-amd64 cmd/mxwatch/main.go

build-windows:
\tGOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/mxwatch-windows-amd64.exe cmd/mxwatch/main.go

build-darwin:
\tGOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/mxwatch-darwin-amd64 cmd/mxwatch/main.go
\tGOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/mxwatch-darwin-arm64 cmd/mxwatch/main.go

build-all: build-linux build-windows build-darwin

test:
\tgo test -v -race -coverprofile=coverage.out ./...

test-integration:
\tgo test -v -tags=integration ./tests/integration/...

clean:
\trm -rf bin/
\trm -f coverage.out

install:
\tcp bin/mxwatch /usr/local/bin/
\tmkdir -p /etc/mxwatch
\tcp configs/config.yaml /etc/mxwatch/
```

---

## Dependencies (go.mod)

```go
module github.com/mxtac/mxwatch

go 1.21

require (
    github.com/google/gopacket v1.1.19
    gopkg.in/yaml.v3 v3.0.1
)

require (
    golang.org/x/net v0.20.0
    golang.org/x/sys v0.16.0
)
```

**Key Dependencies**:
- **gopacket**: Packet decoding and protocol parsing
- **libpcap**: Packet capture (system dependency)

---

*Project structure designed for maintainability and scalability*
*Next: See 03-CONFIGURATION.md for configuration details*
