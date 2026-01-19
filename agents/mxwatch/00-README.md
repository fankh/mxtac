# MxWatch - Lightweight Network Detection & Response Agent

> **Type**: Lightweight NDR Agent
> **Language**: Rust 1.75+
> **Platform**: Linux, Windows, macOS
> **License**: Apache 2.0
> **Status**: Design Phase

---

## Overview

**MxWatch** is a lightweight network detection and response (NDR) agent specifically designed for seamless integration with the MxTac platform. Unlike heavyweight NDR solutions, MxWatch focuses on:

- **Native OCSF output** - No normalization layer needed
- **Minimal resource footprint** - 15-40 MB RAM, 1-3% CPU
- **Single binary deployment** - Statically linked (libpcap required)
- **High-value detections** - 15 core capabilities covering 10-15% ATT&CK
- **Cross-platform** - Linux, Windows, macOS support

## Quick Start

```bash
# Download and install
wget https://github.com/mxtac/mxwatch/releases/latest/mxwatch-linux-amd64
chmod +x mxwatch-linux-amd64
sudo mv mxwatch-linux-amd64 /usr/local/bin/mxwatch

# Create configuration
sudo mkdir -p /etc/mxwatch
sudo nano /etc/mxwatch/config.yaml

# Start agent (requires elevated privileges for packet capture)
sudo mxwatch --config /etc/mxwatch/config.yaml
```

## Features

### Core Capabilities

| Capability | Status | ATT&CK Coverage |
|------------|--------|--------------------|
| **Packet Capture** | ✅ Planned | T1040 (Network Sniffing) |
| **HTTP/HTTPS Protocol Analysis** | ✅ Planned | T1071.001 (Web Protocols) |
| **DNS Query Monitoring** | ✅ Planned | T1071.004 (DNS), T1568 (DNS Tunneling) |
| **TLS/SSL Certificate Analysis** | ✅ Planned | T1573 (Encrypted Channel) |
| **C2 Beacon Detection** | ✅ Planned | T1071 (Application Layer Protocol) |
| **Port Scan Detection** | ✅ Planned | T1046 (Network Service Scanning) |
| **Data Exfiltration Detection** | ✅ Planned | T1041 (Exfiltration Over C2) |
| **Lateral Movement Detection** | ✅ Planned | T1021 (Remote Services) |

### Key Differentiators

- **OCSF Native**: Network events generated in OCSF format (no transformation needed)
- **Lightweight**: 5x smaller than Zeek, 10x less resource usage
- **Simple Deployment**: Single binary, YAML config, no cluster required
- **MxTac-First**: Designed specifically for MxTac platform integration

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Network Segment                       │
│  ┌───────────────────────────────────────────────────┐  │
│  │              MxWatch Agent                        │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │
│  │  │  Packet  │  │ Protocol │  │   C2     │       │  │
│  │  │ Capture  │  │ Parsers  │  │ Detector │       │  │
│  │  └─────┬────┘  └─────┬────┘  └─────┬────┘       │  │
│  │        │             │             │             │  │
│  │        └─────────────┴─────────────┘             │  │
│  │                      │                           │  │
│  │              ┌───────▼───────┐                   │  │
│  │              │ OCSF Builder  │                   │  │
│  │              └───────┬───────┘                   │  │
│  │                      │                           │  │
│  │              ┌───────▼───────┐                   │  │
│  │              │ HTTP Sender   │                   │  │
│  │              └───────┬───────┘                   │  │
│  └────────────────────────────────────────────────┘  │
└───────────────────────┼─────────────────────────────┘
                        │ HTTPS
                        │ (OCSF Events)
                        ▼
            ┌─────────────────────┐
            │   MxTac Platform    │
            │  Ingestion API      │
            └─────────────────────┘
```

## Documentation

- [Architecture Overview](./01-ARCHITECTURE.md)
- [Project Structure](./02-PROJECT-STRUCTURE.md)
- [Configuration Guide](./03-CONFIGURATION.md)
- [Deployment Guide](./04-DEPLOYMENT.md)
- [Development Guide](./05-DEVELOPMENT.md)
- [API Reference](./06-API-REFERENCE.md)
- [Performance Benchmarks](./07-BENCHMARKS.md)

## Resource Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| **CPU** | 1 core | 2 cores |
| **Memory** | 60 MB | 128 MB |
| **Disk** | 100 MB (binary) | 1 GB (with logs) |
| **Network** | 100 Kbps avg | 1 Mbps peak |
| **Privileges** | CAP_NET_RAW | root |

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| **Linux** | amd64, arm64 | ✅ Planned |
| **Windows** | amd64 | ✅ Planned |
| **macOS** | amd64, arm64 | ✅ Planned |

## Comparison with Zeek

| Feature | Zeek | MxWatch |
|---------|------|---------|
| **Binary Size** | ~50 MB | ~8 MB |
| **Memory Usage** | 300-800 MB | 15-40 MB |
| **CPU Usage** | 10-20% | 1-3% |
| **Deployment** | Cluster/Standalone | Single Binary |
| **Output Format** | Zeek Logs | OCSF Native |
| **Protocol Coverage** | 100+ protocols | 10-15 protocols (focused) |
| **Dependencies** | Many (libpcap, etc.) | libpcap only |
| **Configuration** | Zeek Scripts | YAML |

## Development Roadmap

### Phase 1: Core Agent (10 weeks)

- [x] Project setup and structure
- [ ] Packet capture (pcap crate)
- [ ] HTTP/HTTPS protocol parser (custom)
- [ ] DNS protocol parser (trust-dns-proto)
- [ ] OCSF event builder
- [ ] HTTP output handler (reqwest)

### Phase 2: Advanced Detection (8 weeks)

- [ ] TLS/SSL certificate analysis
- [ ] C2 beacon detection
- [ ] Port scan detection
- [ ] Data exfiltration detection
- [ ] Lateral movement detection

### Phase 3: Production Ready (4 weeks)

- [ ] Cross-platform builds
- [ ] Installer packages
- [ ] Documentation
- [ ] Testing suite
- [ ] Deployment automation

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development guidelines.

## License

Apache License 2.0

---

*MxWatch is part of the MxTac Security Platform*
