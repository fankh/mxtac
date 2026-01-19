# MxGuard - Configuration Guide

> **Version**: 1.0
> **Date**: 2026-01-19
> **Target**: System Administrators, DevOps Engineers

---

## Table of Contents

1. [Configuration File Format](#1-configuration-file-format)
2. [Agent Settings](#2-agent-settings)
3. [Collector Configuration](#3-collector-configuration)
4. [Buffer and Performance](#4-buffer-and-performance)
5. [Output Configuration](#5-output-configuration)
6. [Security Settings](#6-security-settings)
7. [Platform-Specific Configuration](#7-platform-specific-configuration)
8. [Environment Variables](#8-environment-variables)
9. [Configuration Validation](#9-configuration-validation)

---

## 1. Configuration File Format

### 1.1 File Location

**Linux**:
- `/etc/mxguard/config.yaml` (default)
- `/etc/mxguard/config.d/*.yaml` (drop-in configs)

**Windows**:
- `C:\Program Files\MxGuard\config.yaml`

**macOS**:
- `/usr/local/etc/mxguard/config.yaml`

### 1.2 File Format

Configuration uses **YAML** format with support for:
- Environment variable substitution: `${VAR_NAME}`
- Includes: `!include other-config.yaml`
- Comments: `# This is a comment`

---

## 2. Agent Settings

### 2.1 Basic Agent Configuration

```yaml
agent:
  # Agent name (defaults to hostname)
  name: "mxguard-agent"

  # Agent version (auto-populated at build time)
  version: "1.0.0"

  # Log level: debug, info, warn, error
  log_level: "info"

  # Log output
  log_file: "/var/log/mxguard/agent.log"

  # Log rotation
  log_max_size: 100      # MB
  log_max_backups: 5
  log_max_age: 30        # days
  log_compress: true

  # PID file location
  pid_file: "/var/run/mxguard.pid"

  # Data directory for temporary files
  data_dir: "/var/lib/mxguard"
```

### 2.2 Agent Identity

```yaml
agent:
  # Unique agent ID (auto-generated on first run)
  id: "agent-${HOSTNAME}-${UUID}"

  # Agent tags for filtering/grouping
  tags:
    - "production"
    - "web-server"
    - "us-east-1"

  # Custom metadata
  metadata:
    environment: "production"
    datacenter: "aws-us-east-1"
    team: "platform"
```

---

## 3. Collector Configuration

### 3.1 File Integrity Monitoring

```yaml
collectors:
  file:
    # Enable/disable file monitoring
    enabled: true

    # Paths to monitor
    paths:
      - /etc/
      - /usr/bin/
      - /usr/sbin/
      - /tmp/
      - /var/www/

    # Exclusion patterns (glob format)
    exclude:
      - "*.log"
      - "*.tmp"
      - "/tmp/*.cache"
      - "/var/log/**"

    # File hashing settings
    hash_files: true
    hash_algorithm: "sha256"      # sha1, sha256, md5
    hash_threshold: 10485760      # 10 MB (don't hash files larger than this)

    # Suspicious file patterns
    suspicious_patterns:
      - "*.exe"        # Executables in unexpected locations
      - "mimikatz*"    # Known malware names
      - "*.ps1"        # PowerShell scripts
      - "nc"           # Netcat
      - "ncat"

    # Suspicious paths
    suspicious_paths:
      - "/tmp/"
      - "/dev/shm/"
      - "/var/tmp/"

    # Event rate limiting (events per second)
    rate_limit: 1000

    # Watch options
    recursive: true
    follow_symlinks: false
```

**Platform-Specific File Monitoring**:

**Linux**:
```yaml
collectors:
  file:
    linux:
      # inotify options
      max_watches: 8192
      buffer_size: 16384
```

**Windows**:
```yaml
collectors:
  file:
    windows:
      # ReadDirectoryChangesW options
      buffer_size: 65536
      watch_subtree: true
```

**macOS**:
```yaml
collectors:
  file:
    darwin:
      # FSEvents options
      latency: 1.0    # seconds
```

### 3.2 Process Monitoring

```yaml
collectors:
  process:
    # Enable/disable process monitoring
    enabled: true

    # Scan interval
    scan_interval: 2s

    # Track child processes
    track_children: true

    # Track process tree depth
    max_tree_depth: 5

    # Suspicious process names
    suspicious_names:
      - "mimikatz"
      - "procdump"
      - "nc"
      - "ncat"
      - "socat"
      - "psexec"

    # Suspicious command line patterns
    suspicious_cmdline:
      - ".*powershell.*-enc.*"           # Encoded PowerShell
      - ".*powershell.*-e .*"
      - ".*bash.*-c.*curl.*\\|.*sh.*"    # Download and execute
      - ".*wget.*\\|.*sh.*"

    # Monitor specific users
    monitor_users:
      - "root"
      - "admin"
      - "www-data"

    # Exclude processes
    exclude_names:
      - "kworker*"     # Kernel workers
      - "migration/*"

    # Event rate limiting
    rate_limit: 500
```

### 3.3 Network Monitoring

```yaml
collectors:
  network:
    # Enable/disable network monitoring
    enabled: true

    # Scan interval
    scan_interval: 5s

    # Track connection states
    track_established: true
    track_listening: true
    track_time_wait: false

    # Suspicious ports
    suspicious_ports:
      remote:
        - 4444        # Metasploit
        - 5555        # Android Debug Bridge
        - 6666        # IRC
        - 1337        # Common backdoor
      local:
        - 22          # SSH (if not expected)
        - 3389        # RDP

    # Suspicious IPs (CIDR notation)
    suspicious_ips:
      - "10.0.0.0/8"         # If not internal
      - "192.168.0.0/16"     # If not internal

    # Whitelist IPs (don't alert on these)
    whitelist_ips:
      - "10.0.0.0/8"         # Internal network
      - "192.168.1.0/24"     # Office network

    # Monitor specific processes
    monitor_processes:
      - "ssh"
      - "sshd"
      - "nginx"
      - "apache2"

    # Event rate limiting
    rate_limit: 1000
```

### 3.4 Log File Monitoring

```yaml
collectors:
  logs:
    # Enable/disable log monitoring
    enabled: true

    # Log sources
    sources:
      - path: "/var/log/auth.log"
        patterns:
          - "Failed password"
          - "authentication failure"
          - "sudo: .*COMMAND"

      - path: "/var/log/syslog"
        patterns:
          - ".*error.*"
          - ".*critical.*"

      - path: "/var/log/nginx/access.log"
        patterns:
          - ".* 40[0-9] .*"    # 4xx errors
          - ".* 50[0-9] .*"    # 5xx errors

    # Journald integration (Linux)
    journald:
      enabled: true
      filters:
        - "_SYSTEMD_UNIT=ssh.service"
        - "_SYSTEMD_UNIT=nginx.service"

    # Windows Event Log (Windows)
    eventlog:
      enabled: true
      sources:
        - name: "Security"
          event_ids:
            - 4624    # Successful logon
            - 4625    # Failed logon
            - 4672    # Special privileges assigned

        - name: "System"
          event_ids:
            - 7045    # Service installed

    # Multi-line log support
    multiline:
      pattern: "^\\d{4}-\\d{2}-\\d{2}"    # Timestamp pattern
      negate: true
      match: "after"

    # Event rate limiting
    rate_limit: 2000
```

### 3.5 Windows Registry Monitoring (Windows Only)

```yaml
collectors:
  registry:
    enabled: true

    # Registry keys to monitor
    keys:
      - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
      - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
      - "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
      - "HKLM\\SYSTEM\\CurrentControlSet\\Services"

    # Event types to monitor
    monitor:
      - "create"
      - "modify"
      - "delete"

    # Event rate limiting
    rate_limit: 500
```

---

## 4. Buffer and Performance

### 4.1 Event Buffer

```yaml
buffer:
  # Queue size (number of events)
  size: 10000

  # Batch size (events per batch)
  batch_size: 100

  # Batch timeout (flush even if batch not full)
  batch_timeout: 5s

  # Priority queue for critical events
  priority:
    enabled: true
    # Critical events (severity >= 5) sent immediately
    critical_threshold: 5

  # Backpressure handling
  backpressure:
    # Drop oldest events when buffer full
    drop_policy: "drop_oldest"    # drop_oldest, drop_newest, block
    # Alert when buffer utilization exceeds threshold
    alert_threshold: 0.8          # 80%
```

### 4.2 Performance Tuning

```yaml
performance:
  # Worker pool size
  workers:
    collectors: 4       # Collector workers
    processors: 4       # Event processing workers
    outputs: 2          # Output workers

  # CPU limiting
  cpu:
    max_percent: 10     # Max CPU usage (%)

  # Memory limiting
  memory:
    max_mb: 100         # Max memory usage (MB)
    gc_percent: 50      # GOGC setting

  # Object pooling
  object_pools:
    enabled: true
    event_pool_size: 1000
```

---

## 5. Output Configuration

### 5.1 HTTP Output

```yaml
output:
  http:
    # Enable/disable HTTP output
    enabled: true

    # MxTac ingestion endpoint
    url: "https://mxtac.example.com/api/v1/ingest/ocsf"

    # Authentication
    api_key: "${MXGUARD_API_KEY}"

    # TLS settings
    tls:
      enabled: true
      verify: true
      ca_cert: "/etc/mxguard/ca.pem"
      client_cert: "/etc/mxguard/client.pem"
      client_key: "/etc/mxguard/client.key"
      min_version: "1.2"    # TLS 1.2 minimum

    # HTTP client settings
    timeout: 30s
    idle_conn_timeout: 90s
    max_idle_conns: 10

    # Compression
    compression: "gzip"     # gzip, none

    # Retry settings
    retry:
      enabled: true
      attempts: 3
      backoff: "exponential"    # exponential, linear, constant
      initial_delay: 1s
      max_delay: 30s

    # Rate limiting
    rate_limit:
      enabled: true
      requests_per_second: 10
      burst: 20
```

### 5.2 File Output

```yaml
output:
  file:
    # Enable/disable file output
    enabled: false

    # Output file path
    path: "/var/log/mxguard/events.json"

    # File rotation
    rotate:
      enabled: true
      max_size: 100       # MB
      max_backups: 10
      max_age: 30         # days
      compress: true

    # Format
    format: "json"        # json, ndjson
    pretty: false
```

### 5.3 Syslog Output

```yaml
output:
  syslog:
    # Enable/disable syslog output
    enabled: false

    # Syslog server
    host: "localhost"
    port: 514
    protocol: "udp"       # udp, tcp, tcp+tls

    # Syslog format
    format: "rfc5424"     # rfc3164, rfc5424

    # Facility and severity
    facility: "local0"
    severity: "info"

    # TLS (if protocol is tcp+tls)
    tls:
      verify: true
      ca_cert: "/etc/mxguard/ca.pem"
```

---

## 6. Security Settings

### 6.1 Agent Security

```yaml
security:
  # API key encryption
  encryption:
    enabled: true
    method: "aes-256-gcm"
    # Key derivation from master password
    kdf: "pbkdf2"
    iterations: 100000

  # Self-integrity check
  integrity:
    enabled: true
    # Binary hash (set at build time)
    binary_hash: "${BINARY_SHA256}"
    check_interval: 1h

  # Tamper protection
  tamper_protection:
    enabled: true
    # Monitor agent files for modification
    monitor_files:
      - "/usr/local/bin/mxguard"
      - "/etc/mxguard/config.yaml"
```

### 6.2 Communication Security

```yaml
security:
  communication:
    # TLS settings
    tls:
      min_version: "1.2"
      cipher_suites:
        - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
      prefer_server_cipher_suites: true

    # Certificate pinning
    cert_pinning:
      enabled: true
      pins:
        - "sha256//XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```

---

## 7. Platform-Specific Configuration

### 7.1 Linux Configuration

```yaml
platform:
  linux:
    # Systemd integration
    systemd:
      enabled: true
      notify: true
      watchdog: 30s

    # Resource limits
    limits:
      nofile: 8192
      nproc: 2048

    # SELinux/AppArmor
    mandatory_access_control:
      enabled: true
      policy: "enforcing"
```

### 7.2 Windows Configuration

```yaml
platform:
  windows:
    # Windows service settings
    service:
      name: "MxGuard"
      display_name: "MxGuard EDR Agent"
      description: "Endpoint detection and response agent"
      start_type: "automatic"

    # Event Log integration
    eventlog:
      enabled: true
      source: "MxGuard"
```

### 7.3 macOS Configuration

```yaml
platform:
  darwin:
    # launchd integration
    launchd:
      enabled: true
      label: "com.mxtac.mxguard"
      run_at_load: true
      keep_alive: true
```

---

## 8. Environment Variables

MxGuard supports environment variable substitution in configuration files:

| Variable | Description | Example |
|----------|-------------|---------|
| `MXGUARD_API_KEY` | MxTac API key | `export MXGUARD_API_KEY=xxx` |
| `MXGUARD_URL` | MxTac ingestion URL | `https://mxtac.example.com/...` |
| `MXGUARD_LOG_LEVEL` | Override log level | `debug`, `info`, `warn`, `error` |
| `MXGUARD_DATA_DIR` | Data directory | `/var/lib/mxguard` |
| `HOSTNAME` | System hostname | `web-server-01` |

**Usage in config.yaml**:
```yaml
output:
  http:
    url: "${MXGUARD_URL}"
    api_key: "${MXGUARD_API_KEY}"

agent:
  name: "mxguard-${HOSTNAME}"
  log_level: "${MXGUARD_LOG_LEVEL:-info}"    # Default to "info"
```

---

## 9. Configuration Validation

### 9.1 Validate Configuration

```bash
# Validate config file
mxguard --config /etc/mxguard/config.yaml --validate

# Output:
# ✓ Configuration is valid
# ✓ All paths exist
# ✓ Permissions are correct
# ✓ API endpoint is reachable
```

### 9.2 Test Configuration

```bash
# Test configuration with dry-run
mxguard --config /etc/mxguard/config.yaml --dry-run

# Output:
# ✓ File monitor: 5 paths configured
# ✓ Process monitor: enabled (2s interval)
# ✓ Network monitor: enabled (5s interval)
# ✓ HTTP output: https://mxtac.example.com/api/v1/ingest/ocsf
# ✓ Connection test: SUCCESS
```

### 9.3 Show Active Configuration

```bash
# Show resolved configuration (with env vars substituted)
mxguard --config /etc/mxguard/config.yaml --show-config
```

---

## Example Configurations

### Example 1: Minimal Configuration

```yaml
agent:
  log_level: "info"

collectors:
  file:
    enabled: true
    paths:
      - /etc/
  process:
    enabled: true
  network:
    enabled: false
  logs:
    enabled: false

output:
  http:
    enabled: true
    url: "${MXGUARD_URL}"
    api_key: "${MXGUARD_API_KEY}"
```

### Example 2: High-Security Configuration

```yaml
agent:
  log_level: "info"
  log_file: "/var/log/mxguard/agent.log"

collectors:
  file:
    enabled: true
    paths:
      - /etc/
      - /usr/bin/
      - /usr/sbin/
      - /var/www/
    hash_files: true
    suspicious_patterns:
      - "*.exe"
      - "mimikatz*"

  process:
    enabled: true
    scan_interval: 1s
    track_children: true

  network:
    enabled: true
    scan_interval: 2s
    track_established: true

  logs:
    enabled: true
    sources:
      - path: "/var/log/auth.log"
        patterns:
          - "Failed password"

buffer:
  size: 20000
  batch_size: 50
  batch_timeout: 3s

output:
  http:
    enabled: true
    url: "${MXGUARD_URL}"
    api_key: "${MXGUARD_API_KEY}"
    tls:
      enabled: true
      verify: true
      min_version: "1.3"
    retry:
      enabled: true
      attempts: 5

security:
  integrity:
    enabled: true
  tamper_protection:
    enabled: true
```

### Example 3: Development Configuration

```yaml
agent:
  log_level: "debug"
  log_file: "stdout"

collectors:
  file:
    enabled: true
    paths:
      - /tmp/test/
  process:
    enabled: true
    scan_interval: 5s

buffer:
  size: 1000
  batch_size: 10
  batch_timeout: 1s

output:
  file:
    enabled: true
    path: "./events.json"
    format: "json"
    pretty: true

  http:
    enabled: false
```

---

*Configuration guide for production deployment*
*Next: See 04-DEPLOYMENT.md for installation and deployment*
