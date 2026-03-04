# MxGuard Installation Guide

MxGuard is a cross-platform Endpoint Detection & Response (EDR) agent that monitors file integrity, processes, network connections, and authentication events. It reports OCSF-formatted telemetry to the MxTac platform.

## Prerequisites

### Hardware

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 core | 2 cores |
| Memory | 50 MB | 100 MB |
| Disk | 100 MB | 500 MB (with logs) |

### Software

| Component | Version | Notes |
|-----------|---------|-------|
| Rust | 1.75+ | Build only |
| OS | Linux (kernel 3.10+), Windows 10+, macOS 10.15+ | See platform details below |

### Platform Support

| Platform | Collectors | Notes |
|----------|-----------|-------|
| Linux (RHEL 7+, Ubuntu 18.04+) | File, process, network, auth | Primary platform; inotify for file monitoring |
| Windows (10, Server 2016+) | File, process, network, registry, scheduled tasks | Registry + scheduled task collectors |
| macOS (10.15+) | File, process, network, auth | FSEvents for file monitoring |

---

## Quick Start (Development)

```bash
git clone https://github.com/fankh/mxguard.git
cd mxguard

# Build
cargo build --release

# Configure
cp config/mxguard.toml.example config/mxguard.toml
# Edit config/mxguard.toml:
#   - Set [transport] endpoint to your MxTac API URL
#   - Set [transport] api_key to your MxTac API key
#   - Adjust [collectors.*] for your environment

# Run (requires elevated privileges for system monitoring)
# Linux / macOS
sudo ./target/release/mxguard --config config/mxguard.toml

# Windows (run as Administrator)
.\target\release\mxguard.exe --config config\mxguard.toml
```

### Verify It Works

```bash
# Debug mode to see events being collected
sudo ./target/release/mxguard --config config/mxguard.toml --log-level debug

# Health endpoint
curl http://localhost:9001/health

# Trigger a test event (e.g., create a file in a monitored path)
touch /tmp/test-mxguard
```

---

## Production Deployment

See [04-DEPLOYMENT.md](04-DEPLOYMENT.md) for full platform-specific procedures.

### Docker

```bash
# Build
docker build -t mxguard:latest .

# Run — requires privileged access for system monitoring
docker run -d \
  --name mxguard \
  --pid=host \
  --network=host \
  -v /etc/mxguard/mxguard.toml:/etc/mxguard/mxguard.toml:ro \
  -v /var/log:/var/log:ro \
  -v /proc:/host/proc:ro \
  mxguard:latest \
  --config /etc/mxguard/mxguard.toml
```

The Dockerfile uses a multi-stage build (Rust 1.75 builder → Debian bookworm-slim runtime) and runs as a non-root user (`mxguard`, UID 10001).

### Linux — Systemd

Create `/etc/systemd/system/mxguard.service`:

```ini
[Unit]
Description=MxGuard EDR Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mxguard --config /etc/mxguard/mxguard.toml
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/log/mxguard /var/lib/mxguard

[Install]
WantedBy=multi-user.target
```

```bash
# Install
sudo cp target/release/mxguard /usr/local/bin/
sudo mkdir -p /etc/mxguard /var/log/mxguard /var/lib/mxguard
sudo cp config/mxguard.toml.example /etc/mxguard/mxguard.toml
# Edit /etc/mxguard/mxguard.toml

sudo systemctl daemon-reload
sudo systemctl enable --now mxguard
```

### Windows — Windows Service

```powershell
# Copy binary
Copy-Item target\release\mxguard.exe "C:\Program Files\MxGuard\"

# Create config directory
New-Item -ItemType Directory -Path "C:\Program Files\MxGuard\config" -Force
Copy-Item config\mxguard.toml.example "C:\Program Files\MxGuard\config\mxguard.toml"
# Edit C:\Program Files\MxGuard\config\mxguard.toml

# Register as a Windows Service
sc.exe create MxGuard binPath= "\"C:\Program Files\MxGuard\mxguard.exe\" --config \"C:\Program Files\MxGuard\config\mxguard.toml\"" start= auto
sc.exe description MxGuard "MxGuard EDR Agent for MxTac"
sc.exe start MxGuard
```

### macOS — launchd

Create `/Library/LaunchDaemons/com.mxtac.mxguard.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mxtac.mxguard</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/mxguard</string>
        <string>--config</string>
        <string>/usr/local/etc/mxguard/mxguard.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/mxguard/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/mxguard/stderr.log</string>
    <key>WorkingDirectory</key>
    <string>/usr/local/var/lib/mxguard</string>
</dict>
</plist>
```

```bash
sudo cp target/release/mxguard /usr/local/bin/
sudo mkdir -p /usr/local/etc/mxguard /usr/local/var/log/mxguard /usr/local/var/lib/mxguard
sudo cp config/mxguard.toml.example /usr/local/etc/mxguard/mxguard.toml
# Edit /usr/local/etc/mxguard/mxguard.toml

sudo launchctl load /Library/LaunchDaemons/com.mxtac.mxguard.plist
```

---

## Configuration Reference

Config file: TOML format.

| Platform | Default Path |
|----------|-------------|
| Linux | `/etc/mxguard/mxguard.toml` |
| Windows | `C:\Program Files\MxGuard\config\mxguard.toml` |
| macOS | `/usr/local/etc/mxguard/mxguard.toml` |

See [config/mxguard.toml.example](config/mxguard.toml.example) for a fully commented template, and [03-CONFIGURATION.md](03-CONFIGURATION.md) for the complete configuration reference.

### Key Sections

```toml
[agent]
agent_id = ""                    # Auto-generated on first run if empty
name = "mxguard-node-01"        # Instance identifier
log_level = "info"               # trace | debug | info | warn | error

[collectors.process]
enabled = true
scan_interval_ms = 2000          # Process scan frequency

[collectors.file]
enabled = true
watch_paths = ["/etc", "/usr/bin", "/usr/sbin", "/tmp"]
exclude_patterns = ["*.log", "*.tmp", "*.swp"]

[collectors.network]
enabled = true
scan_interval_ms = 5000          # Connection scan frequency

[collectors.auth]
enabled = true
log_paths = ["/var/log/auth.log", "/var/log/secure"]
poll_interval_ms = 2000

[transport]
endpoint = "http://mxtac:8080/api/v1/ingest/ocsf"
api_key = ""                     # MxTac API key (Bearer token)
batch_size = 100                 # Events per batch
flush_interval_ms = 5000         # Flush interval
retry_attempts = 3               # Retries on transport failure

[health]
listen_addr = "0.0.0.0:9001"    # Health check endpoint
```

### Environment Variable Overrides

| Variable | Description |
|----------|-------------|
| `MXGUARD_API_KEY` | MxTac API key |
| `MXGUARD_URL` | MxTac endpoint URL |
| `MXGUARD_LOG_LEVEL` | Override log level |
| `MXGUARD_DATA_DIR` | Data directory path |

### CLI Arguments

```
mxguard [OPTIONS]

Options:
  -c, --config <PATH>      Config file path [default: /etc/mxguard/mxguard.toml]
  -l, --log-level <LEVEL>  Override log level (trace, debug, info, warn, error)
  -h, --help               Print help
  -V, --version            Print version
```

---

## Health Checks & Verification

```bash
# Health endpoint
curl http://localhost:9001/health

# Check service status
sudo systemctl status mxguard           # Linux
sc.exe query MxGuard                     # Windows
sudo launchctl list com.mxtac.mxguard    # macOS

# Validate configuration
mxguard --config /etc/mxguard/mxguard.toml --validate

# Test connection to MxTac
mxguard --config /etc/mxguard/mxguard.toml --test-connection
```

---

## Upgrading

### Linux

```bash
# Build new version
git pull
cargo build --release

# Replace binary and restart
sudo systemctl stop mxguard
sudo cp target/release/mxguard /usr/local/bin/
sudo systemctl start mxguard
```

### Windows

```powershell
sc.exe stop MxGuard
Copy-Item target\release\mxguard.exe "C:\Program Files\MxGuard\" -Force
sc.exe start MxGuard
```

### macOS

```bash
sudo launchctl unload /Library/LaunchDaemons/com.mxtac.mxguard.plist
sudo cp target/release/mxguard /usr/local/bin/
sudo launchctl load /Library/LaunchDaemons/com.mxtac.mxguard.plist
```

### Docker

```bash
docker build -t mxguard:latest .
docker stop mxguard && docker rm mxguard
# Re-run docker run command
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Agent won't start | Check config syntax: `mxguard --config path --validate`. Check logs for details. |
| No events reaching MxTac | Verify `[transport] endpoint` and `api_key`. Test: `curl http://mxtac:8080/health` |
| File events missing | Ensure paths in `[collectors.file] watch_paths` exist and are readable. Check `exclude_patterns`. |
| High CPU usage | Increase `scan_interval_ms` for process/network collectors. Reduce watched paths. |
| Permission denied | Linux: run as root or with appropriate capabilities. Windows: run as Administrator. |
| inotify watch limit | Increase limit: `echo 65536 \| sudo tee /proc/sys/fs/inotify/max_user_watches` |
| Windows registry events missing | Ensure the registry collector is enabled (Windows only) |
| Health endpoint unreachable | Check `[health] listen_addr` and firewall rules |

### Logs

```bash
# Systemd (Linux)
journalctl -u mxguard -f --no-pager

# Windows
Get-EventLog -LogName Application -Source MxGuard -Newest 50

# macOS
tail -f /usr/local/var/log/mxguard/stdout.log

# Docker
docker logs -f mxguard

# Direct (foreground)
sudo ./target/release/mxguard --config config/mxguard.toml --log-level debug
```

---

## Further Reading

- [04-DEPLOYMENT.md](04-DEPLOYMENT.md) — Full deployment procedures for all platforms
- [03-CONFIGURATION.md](03-CONFIGURATION.md) — Complete configuration reference
- [00-README.md](00-README.md) — Project overview
- [01-ARCHITECTURE.md](01-ARCHITECTURE.md) — System architecture and collector design
- [config/mxguard.toml.example](config/mxguard.toml.example) — Fully commented configuration template
