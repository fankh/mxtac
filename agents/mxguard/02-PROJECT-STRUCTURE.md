# MxGuard - Project Structure

> **Version**: 1.0
> **Date**: 2026-01-19
> **Language**: Go 1.21+

---

## Repository Structure

```
mxguard/
├── cmd/
│   └── mxguard/
│       └── main.go                    # Entry point
│
├── internal/
│   ├── agent/
│   │   ├── agent.go                   # Main agent orchestrator
│   │   ├── config.go                  # Configuration loader
│   │   └── lifecycle.go               # Startup/shutdown
│   │
│   ├── collectors/
│   │   ├── collector.go               # Base collector interface
│   │   ├── file/
│   │   │   ├── monitor.go            # File monitoring implementation
│   │   │   ├── monitor_linux.go      # Linux-specific (inotify)
│   │   │   ├── monitor_windows.go    # Windows-specific (ReadDirectoryChangesW)
│   │   │   ├── monitor_darwin.go     # macOS-specific (FSEvents)
│   │   │   └── hash.go               # File hashing utilities
│   │   │
│   │   ├── process/
│   │   │   ├── monitor.go            # Process monitoring implementation
│   │   │   ├── monitor_linux.go      # /proc filesystem parsing
│   │   │   ├── monitor_windows.go    # WMI integration
│   │   │   ├── monitor_darwin.go     # kqueue integration
│   │   │   └── tree.go               # Process tree tracking
│   │   │
│   │   ├── network/
│   │   │   ├── monitor.go            # Network monitoring implementation
│   │   │   ├── monitor_linux.go      # /proc/net/tcp parsing
│   │   │   ├── monitor_windows.go    # GetExtendedTcpTable API
│   │   │   ├── monitor_darwin.go     # lsof wrapper
│   │   │   └── connection.go         # Connection tracking
│   │   │
│   │   └── logs/
│   │       ├── monitor.go            # Log monitoring implementation
│   │       ├── tailer.go             # Log file tailer
│   │       ├── journald.go           # Systemd journal reader (Linux)
│   │       ├── eventlog.go           # Windows Event Log reader
│   │       └── oslog.go              # macOS Unified Logging
│   │
│   ├── ocsf/
│   │   ├── builder.go                 # OCSF event builder
│   │   ├── models.go                  # OCSF data structures
│   │   ├── file_activity.go           # File System Activity (1001)
│   │   ├── process_activity.go        # Process Activity (1007)
│   │   ├── network_activity.go        # Network Activity (4001)
│   │   ├── auth_activity.go           # Authentication (3002)
│   │   ├── enrichment.go              # Event enrichment
│   │   └── severity.go                # Severity calculation
│   │
│   ├── buffer/
│   │   ├── buffer.go                  # Event buffer
│   │   ├── queue.go                   # Ring buffer implementation
│   │   ├── batcher.go                 # Batch processor
│   │   └── priority.go                # Event prioritization
│   │
│   ├── output/
│   │   ├── output.go                  # Output handler interface
│   │   ├── http.go                    # HTTP/HTTPS output
│   │   ├── file.go                    # File output
│   │   ├── syslog.go                  # Syslog output
│   │   └── retry.go                   # Retry logic with backoff
│   │
│   ├── filter/
│   │   ├── filter.go                  # Event filtering
│   │   ├── rules.go                   # Filter rules
│   │   └── patterns.go                # Pattern matching
│   │
│   └── utils/
│       ├── system.go                  # System information
│       ├── crypto.go                  # Hashing, encryption
│       ├── network.go                 # Network utilities
│       └── errors.go                  # Error handling
│
├── pkg/
│   └── api/
│       └── types.go                   # Public API types
│
├── configs/
│   ├── config.yaml                    # Default configuration
│   ├── config.linux.yaml             # Linux-specific config
│   ├── config.windows.yaml           # Windows-specific config
│   └── config.darwin.yaml            # macOS-specific config
│
├── scripts/
│   ├── build.sh                       # Build script
│   ├── install.sh                     # Installation script
│   ├── package.sh                     # Package creation
│   └── test.sh                        # Test runner
│
├── deployments/
│   ├── systemd/
│   │   └── mxguard.service           # Systemd unit file
│   ├── launchd/
│   │   └── com.mxtac.mxguard.plist   # macOS launchd plist
│   ├── windows/
│   │   └── install-service.ps1       # Windows service installer
│   └── docker/
│       └── Dockerfile                 # Docker image
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
│   │   ├── file_test.go
│   │   ├── process_test.go
│   │   └── network_test.go
│   ├── unit/
│   │   ├── ocsf_test.go
│   │   ├── buffer_test.go
│   │   └── output_test.go
│   └── fixtures/
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
    collectors  []collector.Collector
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
    // Initialize collectors
    a.initCollectors()

    // Start collectors
    for _, c := range a.collectors {
        go c.Start()
    }

    // Start buffer
    go a.buffer.Start()

    // Wait for shutdown signal
    <-a.shutdown
    return a.Stop()
}

func (a *Agent) Stop() error {
    // Stop collectors
    for _, c := range a.collectors {
        c.Stop()
    }

    // Flush buffer
    a.buffer.Flush()

    return nil
}
```

### 2. Collector Interface (`internal/collectors/collector.go`)

```go
package collector

type Collector interface {
    Start() error
    Stop() error
    Events() <-chan Event
}

type Event struct {
    Type      EventType
    Timestamp time.Time
    Data      interface{}
    Severity  int
}

type EventType int

const (
    EventTypeFile EventType = iota
    EventTypeProcess
    EventTypeNetwork
    EventTypeAuth
)
```

### 3. OCSF Builder (`internal/ocsf/builder.go`)

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
    OS       OSInfo
}

func (b *Builder) BuildFileActivity(
    activity string,
    activityID int,
    file FileInfo,
    actor ActorInfo,
) *FileSystemActivity {
    return &FileSystemActivity{
        Metadata: Metadata{
            Version: "1.1.0",
            Product: b.product,
        },
        Time:        time.Now().Unix(),
        ClassUID:    1001,
        CategoryUID: 1,
        Activity:    activity,
        ActivityID:  activityID,
        SeverityID:  calculateSeverity(file),
        File:        file,
        Actor:       actor,
        Device:      b.device,
    }
}
```

### 4. Event Buffer (`internal/buffer/buffer.go`)

```go
package buffer

type EventBuffer struct {
    queue     chan Event
    batchSize int
    timeout   time.Duration
    output    output.Handler
    shutdown  chan struct{}
}

func New(batchSize int, timeout time.Duration, out output.Handler) *EventBuffer {
    return &EventBuffer{
        queue:     make(chan Event, 10000),
        batchSize: batchSize,
        timeout:   timeout,
        output:    out,
        shutdown:  make(chan struct{}),
    }
}

func (eb *EventBuffer) Add(event Event) {
    eb.queue <- event
}

func (eb *EventBuffer) Start() {
    batch := make([]Event, 0, eb.batchSize)
    ticker := time.NewTicker(eb.timeout)

    for {
        select {
        case event := <-eb.queue:
            batch = append(batch, event)

            // Send immediately if critical or batch full
            if event.SeverityID >= 5 || len(batch) >= eb.batchSize {
                eb.flush(batch)
                batch = batch[:0]
            }

        case <-ticker.C:
            if len(batch) > 0 {
                eb.flush(batch)
                batch = batch[:0]
            }

        case <-eb.shutdown:
            eb.flush(batch)
            return
        }
    }
}
```

### 5. HTTP Output (`internal/output/http.go`)

```go
package output

type HTTPOutput struct {
    client  *http.Client
    url     string
    apiKey  string
    retries int
}

func NewHTTPOutput(url, apiKey string) *HTTPOutput {
    return &HTTPOutput{
        client: &http.Client{
            Timeout: 30 * time.Second,
            Transport: &http.Transport{
                MaxIdleConns:        10,
                IdleConnTimeout:     90 * time.Second,
                TLSHandshakeTimeout: 10 * time.Second,
            },
        },
        url:     url,
        apiKey:  apiKey,
        retries: 3,
    }
}

func (h *HTTPOutput) Send(events []Event) error {
    payload, err := json.Marshal(events)
    if err != nil {
        return err
    }

    // Compress
    var buf bytes.Buffer
    gz := gzip.NewWriter(&buf)
    gz.Write(payload)
    gz.Close()

    // Build request
    req, _ := http.NewRequest("POST", h.url, &buf)
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Content-Encoding", "gzip")
    req.Header.Set("Authorization", "Bearer "+h.apiKey)

    // Send with retry
    return h.sendWithRetry(req)
}
```

---

## Configuration Structure

```yaml
# config.yaml
agent:
  name: "mxguard-agent"
  version: "1.0.0"
  log_level: "info"
  log_file: "/var/log/mxguard/agent.log"

collectors:
  file:
    enabled: true
    paths:
      - /etc/
      - /usr/bin/
      - /tmp/
    exclude:
      - "*.log"
      - "*.tmp"
    hash_files: true
    hash_threshold: 10485760  # 10MB

  process:
    enabled: true
    scan_interval: 2s
    track_children: true

  network:
    enabled: true
    scan_interval: 5s
    track_established: true

  logs:
    enabled: true
    sources:
      - /var/log/auth.log
      - /var/log/syslog

buffer:
  size: 10000
  batch_size: 100
  batch_timeout: 5s

output:
  http:
    enabled: true
    url: "https://mxtac.example.com/api/v1/ingest/ocsf"
    api_key: "${MXGUARD_API_KEY}"
    retry_attempts: 3
    retry_backoff: 1s

  file:
    enabled: false
    path: "/var/log/mxguard/events.json"

  syslog:
    enabled: false
    host: "localhost"
    port: 514
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
	go build -ldflags="$(LDFLAGS)" -o bin/mxguard cmd/mxguard/main.go

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/mxguard-linux-amd64 cmd/mxguard/main.go

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/mxguard-windows-amd64.exe cmd/mxguard/main.go

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/mxguard-darwin-amd64 cmd/mxguard/main.go
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/mxguard-darwin-arm64 cmd/mxguard/main.go

build-all: build-linux build-windows build-darwin

test:
	go test -v -race -coverprofile=coverage.out ./...

test-integration:
	go test -v -tags=integration ./tests/integration/...

clean:
	rm -rf bin/
	rm -f coverage.out

install:
	cp bin/mxguard /usr/local/bin/
	mkdir -p /etc/mxguard
	cp configs/config.yaml /etc/mxguard/
```

---

## Dependencies (go.mod)

```go
module github.com/mxtac/mxguard

go 1.21

require (
    github.com/fsnotify/fsnotify v1.7.0
    github.com/hpcloud/tail v1.0.0
    github.com/shirou/gopsutil/v3 v3.23.12
    gopkg.in/yaml.v3 v3.0.1
)

require (
    golang.org/x/sys v0.16.0
    golang.org/x/net v0.20.0
)
```

---

*Project structure designed for maintainability and scalability*
*Next: See 03-CONFIGURATION.md for configuration details*
