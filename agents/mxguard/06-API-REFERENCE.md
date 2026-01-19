# MxGuard - API Reference

> **Version**: 1.0
> **Date**: 2026-01-19
> **Target**: Developers, Integration Engineers

---

## Table of Contents

1. [OCSF Event Schemas](#1-ocsf-event-schemas)
2. [Internal API](#2-internal-api)
3. [Configuration API](#3-configuration-api)
4. [Command-Line Interface](#4-command-line-interface)

---

## 1. OCSF Event Schemas

### 1.1 File System Activity (Class 1001)

**Activity IDs**:
| ID | Activity | Description |
|----|----------|-------------|
| 1 | Create | File created |
| 2 | Delete | File deleted |
| 3 | Read | File read |
| 4 | Write | File modified |
| 5 | Rename | File renamed/moved |
| 6 | Set Attributes | File attributes changed |

**Event Schema**:
```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {
      "name": "MxGuard",
      "vendor": "MxTac",
      "version": "1.0.0"
    }
  },
  "time": 1705660800,
  "class_uid": 1001,
  "category_uid": 1,
  "activity": "Create",
  "activity_id": 1,
  "severity_id": 3,
  "severity": "Medium",
  "message": "File created: /tmp/malware.sh",
  "file": {
    "path": "/tmp/malware.sh",
    "name": "malware.sh",
    "type": "Regular File",
    "type_id": 1,
    "size": 4096,
    "modified_time": 1705660800,
    "accessed_time": 1705660800,
    "created_time": 1705660800,
    "hashes": [
      {
        "algorithm": "SHA-256",
        "algorithm_id": 3,
        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    ],
    "attributes": 33188,
    "uid": "1000",
    "gid": "1000"
  },
  "actor": {
    "process": {
      "pid": 1234,
      "name": "bash",
      "file": {
        "path": "/bin/bash"
      },
      "cmdline": "/bin/bash -c 'touch /tmp/malware.sh'",
      "uid": "1000",
      "gid": "1000",
      "user": {
        "name": "ubuntu",
        "uid": "1000"
      },
      "parent_process": {
        "pid": 1000,
        "name": "sshd"
      }
    }
  },
  "device": {
    "hostname": "web-server-01",
    "os": {
      "name": "Linux",
      "version": "5.15.0-89-generic",
      "type": "Linux",
      "type_id": 100
    },
    "ip": "192.168.1.100",
    "mac": "00:0c:29:12:34:56",
    "type": "Server",
    "type_id": 1
  }
}
```

### 1.2 Process Activity (Class 1007)

**Activity IDs**:
| ID | Activity | Description |
|----|----------|-------------|
| 1 | Launch | Process started |
| 2 | Terminate | Process terminated |
| 3 | Open | Process opened |

**Event Schema**:
```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {
      "name": "MxGuard",
      "vendor": "MxTac",
      "version": "1.0.0"
    }
  },
  "time": 1705660800,
  "class_uid": 1007,
  "category_uid": 1,
  "activity": "Launch",
  "activity_id": 1,
  "severity_id": 4,
  "severity": "High",
  "message": "Suspicious process started: /tmp/mimikatz",
  "process": {
    "pid": 5678,
    "name": "mimikatz",
    "file": {
      "path": "/tmp/mimikatz",
      "name": "mimikatz",
      "hashes": [
        {
          "algorithm": "SHA-256",
          "algorithm_id": 3,
          "value": "abc123..."
        }
      ]
    },
    "cmdline": "/tmp/mimikatz sekurlsa::logonpasswords",
    "uid": "1000",
    "gid": "1000",
    "user": {
      "name": "ubuntu",
      "uid": "1000"
    },
    "parent_process": {
      "pid": 1234,
      "name": "bash",
      "cmdline": "/bin/bash"
    }
  },
  "device": {
    "hostname": "web-server-01",
    "os": {
      "name": "Linux",
      "version": "5.15.0-89-generic"
    },
    "ip": "192.168.1.100"
  }
}
```

### 1.3 Network Activity (Class 4001)

**Activity IDs**:
| ID | Activity | Description |
|----|----------|-------------|
| 1 | Open | Connection opened |
| 2 | Close | Connection closed |
| 5 | Traffic | Network traffic |

**Event Schema**:
```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {
      "name": "MxGuard",
      "vendor": "MxTac",
      "version": "1.0.0"
    }
  },
  "time": 1705660800,
  "class_uid": 4001,
  "category_uid": 4,
  "activity": "Open",
  "activity_id": 1,
  "severity_id": 3,
  "severity": "Medium",
  "message": "Outbound connection to suspicious port",
  "connection_info": {
    "direction": "Outbound",
    "direction_id": 2,
    "protocol_name": "TCP",
    "protocol_num": 6
  },
  "src_endpoint": {
    "ip": "192.168.1.100",
    "port": 54321,
    "hostname": "web-server-01"
  },
  "dst_endpoint": {
    "ip": "10.0.0.50",
    "port": 4444,
    "hostname": "unknown"
  },
  "process": {
    "pid": 1234,
    "name": "nc",
    "cmdline": "nc 10.0.0.50 4444"
  },
  "device": {
    "hostname": "web-server-01",
    "os": {
      "name": "Linux",
      "version": "5.15.0-89-generic"
    },
    "ip": "192.168.1.100"
  }
}
```

### 1.4 Authentication (Class 3002)

**Activity IDs**:
| ID | Activity | Description |
|----|----------|-------------|
| 1 | Logon | Successful logon |
| 2 | Logoff | Logoff |
| 3 | Authentication Failure | Failed authentication |

**Event Schema**:
```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {
      "name": "MxGuard",
      "vendor": "MxTac",
      "version": "1.0.0"
    }
  },
  "time": 1705660800,
  "class_uid": 3002,
  "category_uid": 3,
  "activity": "Logon",
  "activity_id": 1,
  "severity_id": 2,
  "severity": "Low",
  "message": "SSH login successful",
  "auth_protocol": "SSH",
  "auth_protocol_id": 23,
  "logon_type": "Network",
  "logon_type_id": 3,
  "user": {
    "name": "admin",
    "uid": "1000",
    "type": "User",
    "type_id": 1
  },
  "session": {
    "uid": "123456",
    "created_time": 1705660800
  },
  "src_endpoint": {
    "ip": "203.0.113.10",
    "port": 45678,
    "hostname": "attacker.example.com"
  },
  "device": {
    "hostname": "web-server-01",
    "os": {
      "name": "Linux",
      "version": "5.15.0-89-generic"
    },
    "ip": "192.168.1.100"
  }
}
```

### 1.5 Severity Mapping

| Severity ID | Severity | Description | Use Cases |
|-------------|----------|-------------|-----------|
| 1 | Informational | Normal activity | File read, process list |
| 2 | Low | Interesting but benign | Successful login |
| 3 | Medium | Suspicious activity | New network connection |
| 4 | High | Likely malicious | Mimikatz execution |
| 5 | Critical | Confirmed attack | Rootkit detection |

---

## 2. Internal API

### 2.1 Collector Interface

```go
package collector

// Collector interface for all data collectors
type Collector interface {
    // Start begins collecting events
    Start() error

    // Stop gracefully stops the collector
    Stop() error

    // Events returns a channel of collected events
    Events() <-chan Event

    // Name returns the collector name
    Name() string

    // Status returns the collector status
    Status() Status
}

// Event represents a raw event from a collector
type Event struct {
    Type      EventType
    Timestamp time.Time
    Data      interface{}
    Metadata  map[string]interface{}
}

// EventType defines the type of event
type EventType int

const (
    EventTypeFile EventType = iota
    EventTypeProcess
    EventTypeNetwork
    EventTypeAuth
    EventTypeRegistry  // Windows only
)

// Status represents collector status
type Status struct {
    Running    bool
    EventCount uint64
    ErrorCount uint64
    LastError  error
}
```

### 2.2 OCSF Builder Interface

```go
package ocsf

// Builder builds OCSF events from raw data
type Builder interface {
    // BuildFileActivity creates a File System Activity event (1001)
    BuildFileActivity(
        activity string,
        activityID int,
        file FileInfo,
        actor ActorInfo,
    ) (*FileSystemActivity, error)

    // BuildProcessActivity creates a Process Activity event (1007)
    BuildProcessActivity(
        activity string,
        activityID int,
        process ProcessInfo,
    ) (*ProcessActivity, error)

    // BuildNetworkActivity creates a Network Activity event (4001)
    BuildNetworkActivity(
        activity string,
        activityID int,
        connection ConnectionInfo,
        process ProcessInfo,
    ) (*NetworkActivity, error)

    // BuildAuthActivity creates an Authentication event (3002)
    BuildAuthActivity(
        activity string,
        activityID int,
        user UserInfo,
        session SessionInfo,
    ) (*AuthActivity, error)
}

// FileInfo contains file metadata
type FileInfo struct {
    Path         string
    Name         string
    Type         string
    Size         int64
    ModifiedTime int64
    Hash         string
    HashAlgorithm string
}

// ActorInfo contains actor (process) information
type ActorInfo struct {
    PID          int
    Name         string
    CommandLine  string
    UID          string
    User         string
    ParentPID    int
    ParentName   string
}

// ProcessInfo contains process information
type ProcessInfo struct {
    PID         int
    Name        string
    Path        string
    CommandLine string
    UID         string
    GID         string
    User        string
    ParentPID   int
}

// ConnectionInfo contains network connection information
type ConnectionInfo struct {
    Protocol     string
    SrcIP        string
    SrcPort      int
    DstIP        string
    DstPort      int
    Direction    string
    State        string
}
```

### 2.3 Output Handler Interface

```go
package output

// Handler sends events to output destinations
type Handler interface {
    // Send sends a batch of events
    Send(events []Event) error

    // Name returns the handler name
    Name() string

    // Close closes the handler
    Close() error
}

// Event represents an OCSF event ready for output
type Event struct {
    ClassUID    int
    CategoryUID int
    Time        int64
    Data        map[string]interface{}
}

// HTTPHandler sends events via HTTP
type HTTPHandler struct {
    URL     string
    APIKey  string
    Client  *http.Client
    Retries int
}

func NewHTTPHandler(url, apiKey string) *HTTPHandler {
    return &HTTPHandler{
        URL:     url,
        APIKey:  apiKey,
        Client:  &http.Client{Timeout: 30 * time.Second},
        Retries: 3,
    }
}

func (h *HTTPHandler) Send(events []Event) error {
    // Implementation
}
```

### 2.4 Event Buffer Interface

```go
package buffer

// EventBuffer buffers events for batch processing
type EventBuffer interface {
    // Add adds an event to the buffer
    Add(event Event)

    // Start begins processing events
    Start()

    // Stop stops processing and flushes remaining events
    Stop()

    // Flush immediately sends all buffered events
    Flush()

    // Stats returns buffer statistics
    Stats() BufferStats
}

// BufferStats contains buffer statistics
type BufferStats struct {
    Size         int
    Utilization  float64
    EventsIn     uint64
    EventsOut    uint64
    EventsDropped uint64
}
```

---

## 3. Configuration API

### 3.1 Configuration Structure

```go
package config

// Config represents the agent configuration
type Config struct {
    Agent      AgentConfig      `yaml:"agent"`
    Collectors CollectorsConfig `yaml:"collectors"`
    Buffer     BufferConfig     `yaml:"buffer"`
    Output     OutputConfig     `yaml:"output"`
    Security   SecurityConfig   `yaml:"security"`
}

type AgentConfig struct {
    Name      string            `yaml:"name"`
    Version   string            `yaml:"version"`
    LogLevel  string            `yaml:"log_level"`
    LogFile   string            `yaml:"log_file"`
    Tags      []string          `yaml:"tags"`
    Metadata  map[string]string `yaml:"metadata"`
}

type CollectorsConfig struct {
    File    FileCollectorConfig    `yaml:"file"`
    Process ProcessCollectorConfig `yaml:"process"`
    Network NetworkCollectorConfig `yaml:"network"`
    Logs    LogsCollectorConfig    `yaml:"logs"`
}

type FileCollectorConfig struct {
    Enabled            bool     `yaml:"enabled"`
    Paths              []string `yaml:"paths"`
    Exclude            []string `yaml:"exclude"`
    HashFiles          bool     `yaml:"hash_files"`
    SuspiciousPatterns []string `yaml:"suspicious_patterns"`
}

type BufferConfig struct {
    Size         int           `yaml:"size"`
    BatchSize    int           `yaml:"batch_size"`
    BatchTimeout time.Duration `yaml:"batch_timeout"`
}

type OutputConfig struct {
    HTTP   HTTPOutputConfig   `yaml:"http"`
    File   FileOutputConfig   `yaml:"file"`
    Syslog SyslogOutputConfig `yaml:"syslog"`
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    // Substitute environment variables
    data = []byte(os.ExpandEnv(string(data)))

    var config Config
    if err := yaml.Unmarshal(data, &config); err != nil {
        return nil, err
    }

    return &config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
    if c.Agent.Name == "" {
        return errors.New("agent.name is required")
    }

    if c.Output.HTTP.Enabled && c.Output.HTTP.URL == "" {
        return errors.New("output.http.url is required when HTTP output is enabled")
    }

    return nil
}
```

---

## 4. Command-Line Interface

### 4.1 CLI Commands

```bash
mxguard [command] [flags]
```

**Commands**:
| Command | Description |
|---------|-------------|
| `run` | Run the agent (default) |
| `version` | Show version information |
| `config` | Configuration commands |
| `service` | Service management (install/uninstall) |

### 4.2 Global Flags

```bash
--config string       Configuration file path (default "/etc/mxguard/config.yaml")
--log-level string    Log level: debug, info, warn, error (default "info")
--log-file string     Log file path (default "/var/log/mxguard/agent.log")
--help                Show help
--version             Show version
```

### 4.3 Run Command

```bash
mxguard run [flags]

Flags:
  --config string       Configuration file path
  --daemon              Run as daemon
  --pid-file string     PID file path
  --dry-run             Validate configuration and exit
  --test-connection     Test connection to MxTac and exit
```

**Examples**:
```bash
# Run with default config
mxguard run

# Run with custom config
mxguard run --config /etc/mxguard/custom.yaml

# Run as daemon
mxguard run --daemon --pid-file /var/run/mxguard.pid

# Test configuration
mxguard run --dry-run

# Test connection
mxguard run --test-connection
```

### 4.4 Config Command

```bash
mxguard config [subcommand]

Subcommands:
  validate              Validate configuration file
  show                  Show resolved configuration
  generate              Generate default configuration
```

**Examples**:
```bash
# Validate config
mxguard config validate --config /etc/mxguard/config.yaml

# Show config (with env vars substituted)
mxguard config show --config /etc/mxguard/config.yaml

# Generate default config
mxguard config generate > /etc/mxguard/config.yaml
```

### 4.5 Service Command (Windows)

```bash
mxguard service [subcommand]

Subcommands:
  install               Install Windows service
  uninstall             Uninstall Windows service
  start                 Start service
  stop                  Stop service
  restart               Restart service
```

**Examples**:
```bash
# Install service
mxguard service install --config C:\ProgramData\MxGuard\config.yaml

# Start service
mxguard service start

# Uninstall service
mxguard service uninstall
```

### 4.6 Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Connection error |
| 4 | Permission denied |
| 130 | Interrupted (Ctrl+C) |

---

*API reference for developers and integrators*
*Next: See 07-BENCHMARKS.md for performance metrics*
