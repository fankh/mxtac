# MxWatch Installation Guide

MxWatch is a lightweight Network Detection & Response (NDR) agent that captures network traffic, parses protocols, and detects threats using behavioral analysis. It reports OCSF-formatted events to the MxTac platform.

## Prerequisites

### Hardware

| Resource | Minimum | Recommended | High-Performance |
|----------|---------|-------------|------------------|
| CPU | 2 cores | 4 cores | 8 cores |
| Memory | 40 MB | 60 MB | 120 MB |
| Disk | 50 MB (binary) | 1 GB (with logs) | 10 GB (with logs) |
| Network | 100 Mbps | 1 Gbps | 10 Gbps |
| Packet Rate | 10K pps | 150K pps | 1.5M pps |

### Software

| Component | Version | Notes |
|-----------|---------|-------|
| Rust | 1.75+ | Build only |
| libpcap-dev | any | Build dependency (Linux) |
| libpcap0.8 | any | Runtime dependency (Linux) |
| pkg-config | any | Build dependency |
| OS | Linux (primary), Windows, macOS | Linux required for AF_PACKET |

> **Important:** MxWatch requires `CAP_NET_RAW` capability for packet capture. Run with `sudo` or grant the capability explicitly.

### Platform Support

| Platform | Capture Engine | Max Throughput |
|----------|----------------|----------------|
| Linux (amd64, arm64) | AF_PACKET + MMAP | 1–5M pps |
| Windows (amd64) | libpcap / Npcap | ~100K pps |
| macOS (amd64, arm64) | libpcap / BPF | ~100K pps |

---

## Quick Start (Development)

```bash
git clone https://github.com/fankh/mxwatch.git
cd mxwatch

# Install build dependencies (Debian/Ubuntu)
sudo apt install -y libpcap-dev pkg-config

# Build
cargo build --release

# Configure
cp config/mxwatch.toml.example config/mxwatch.toml
# Edit config/mxwatch.toml:
#   - Set [capture] interface to your network interface (e.g., eth0)
#   - Set [transport] endpoint to your MxTac API URL
#   - Set [transport] api_key to your MxTac API key

# Run (requires root for packet capture)
sudo ./target/release/mxwatch --config config/mxwatch.toml
```

### Verify It Works

```bash
# Check the agent started and is capturing
sudo ./target/release/mxwatch --config config/mxwatch.toml --log-level debug

# Health endpoint (if configured)
curl http://localhost:9000/health

# Generate some test traffic and watch events flow
curl http://example.com
```

### Offline PCAP Replay

For development without live traffic, set `read_file` in the config:

```toml
[capture.pcap]
read_file = "/path/to/capture.pcap"
```

---

## Production Deployment

### Docker

```bash
# Build
docker build -t mxwatch:latest .

# Run — CAP_NET_RAW is required, host network for interface access
docker run -d \
  --name mxwatch \
  --cap-add=NET_RAW \
  --network host \
  -v /path/to/mxwatch.toml:/etc/mxwatch/mxwatch.toml:ro \
  mxwatch:latest \
  --config /etc/mxwatch/mxwatch.toml
```

The Dockerfile uses a multi-stage build (Rust 1.75 builder → Debian bookworm-slim runtime) and runs as a non-root user (`mxwatch`, UID 10001). The runtime image includes only `ca-certificates`, `libssl3`, and `libpcap0.8`.

### Systemd (Linux)

Create `/etc/systemd/system/mxwatch.service`:

```ini
[Unit]
Description=MxWatch NDR Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mxwatch --config /etc/mxwatch/mxwatch.toml
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/mxwatch
User=mxwatch
Group=mxwatch

[Install]
WantedBy=multi-user.target
```

```bash
# Install
sudo cp target/release/mxwatch /usr/local/bin/
sudo mkdir -p /etc/mxwatch /var/log/mxwatch
sudo cp config/mxwatch.toml.example /etc/mxwatch/mxwatch.toml
# Edit /etc/mxwatch/mxwatch.toml

sudo useradd -r -s /usr/sbin/nologin mxwatch
sudo chown mxwatch:mxwatch /var/log/mxwatch

sudo systemctl daemon-reload
sudo systemctl enable --now mxwatch
```

### High-Performance Mode (AF_PACKET + MMAP)

For Linux deployments handling >100K pps, enable AF_PACKET in the config:

```toml
[capture]
use_afpacket = true

[capture.afpacket]
block_size = 1048576    # 1 MiB per block
block_count = 64        # 64 MiB ring buffer total
frame_size = 2048       # MTU + headers
block_retire_tov_ms = 60
```

This bypasses libpcap and uses the kernel's zero-copy ring buffer for 1–5M pps throughput.

---

## Configuration Reference

Config file: TOML format. Default path: `/etc/mxwatch/mxwatch.toml`

See [config/mxwatch.toml.example](config/mxwatch.toml.example) for a fully commented template.

### Key Sections

```toml
[agent]
name = "mxwatch-node-01"       # Instance identifier
log_level = "info"              # trace | debug | info | warn | error

[capture]
interface = "eth0"              # Network interface to monitor
snaplen = 65535                 # Capture full packets
promiscuous = true              # See all traffic on the segment
bpf_filter = "tcp or udp"      # Kernel-level packet filter
buffer_size = 2097152           # 2 MiB kernel ring buffer
use_afpacket = false            # Set true for high-performance Linux capture

[parsers.http]
enabled = true
suspicious_patterns = ["../", "' OR ", "UNION SELECT", "DROP TABLE", "/etc/passwd"]

[parsers.dns]
enabled = true
entropy_threshold = 4.5         # Flag high-entropy subdomains

[parsers.tls]
enabled = true

[parsers.tcp]
enabled = true

[parsers.udp]
enabled = true

[detectors.dns_tunnel]
enabled = true
entropy_threshold = 4.5
max_label_length = 100

[detectors.port_scan]
enabled = true
threshold_ports = 20            # Ports scanned before alert
window_secs = 60                # Detection window

[transport]
endpoint = "http://mxtac:8080/api/v1/ingest/ocsf"
api_key = ""                    # MxTac API key (Bearer token)
batch_size = 100                # Events per batch
flush_interval_ms = 5000        # Flush interval
retry_attempts = 3              # Retries on transport failure
```

### CLI Arguments

```
mxwatch [OPTIONS]

Options:
  -c, --config <PATH>      Config file path [default: /etc/mxwatch/mxwatch.toml]
  -l, --log-level <LEVEL>  Override log level (trace, debug, info, warn, error)
  -h, --help               Print help
  -V, --version            Print version
```

---

## Health Checks & Verification

```bash
# Health endpoint (if health server is configured)
curl http://localhost:9000/health
# Returns: capture_running, transport_connected, last_event_sent_secs

# Systemd status
sudo systemctl status mxwatch

# Check logs
journalctl -u mxwatch -f

# Docker logs
docker logs -f mxwatch

# Verify packets are being captured (look for parser/detector log lines)
sudo ./target/release/mxwatch --config config/mxwatch.toml --log-level debug 2>&1 | head -50
```

---

## Upgrading

```bash
# Pull latest source
git pull

# Rebuild
cargo build --release

# Replace binary and restart
sudo systemctl stop mxwatch
sudo cp target/release/mxwatch /usr/local/bin/
sudo systemctl start mxwatch

# Docker
docker build -t mxwatch:latest .
docker stop mxwatch && docker rm mxwatch
# Re-run docker run command from above
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Permission denied` on capture | Run with `sudo` or grant `CAP_NET_RAW`: `sudo setcap cap_net_raw+ep /usr/local/bin/mxwatch` |
| `No such device` for interface | Check interface name: `ip link show`. Use the correct name (e.g., `ens33` not `eth0`). |
| No events reaching MxTac | Verify `[transport] endpoint` and `api_key`. Check MxTac is running: `curl http://mxtac:8080/health` |
| High CPU usage | Tighten the BPF filter to reduce captured traffic. Enable AF_PACKET for zero-copy capture. |
| `libpcap not found` build error | Install: `sudo apt install libpcap-dev pkg-config` |
| AF_PACKET not working | Only available on Linux. Ensure `use_afpacket = true` in config. Requires `CAP_NET_RAW`. |
| Events batching too slowly | Reduce `flush_interval_ms` or `batch_size` in `[transport]` |

### Logs

```bash
# Systemd
journalctl -u mxwatch -f --no-pager

# Docker
docker logs -f mxwatch

# Direct (foreground)
sudo ./target/release/mxwatch --config config/mxwatch.toml --log-level debug
```

---

## Further Reading

- [00-README.md](00-README.md) — Project overview, features, and roadmap
- [01-ARCHITECTURE.md](01-ARCHITECTURE.md) — System architecture, data flow, and detector design
- [02-PROJECT-STRUCTURE.md](02-PROJECT-STRUCTURE.md) — Source code organization
- [config/mxwatch.toml.example](config/mxwatch.toml.example) — Fully commented configuration template
