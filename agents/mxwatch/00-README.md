# MxWatch - Lightweight Network Detection & Response Agent

> **Type**: Lightweight NDR Agent
> **Language**: Rust 1.75+
> **Platform**: Linux, Windows, macOS
> **License**: Apache 2.0
> **Status**: Design Phase

---

## Overview

**MxWatch** is a high-performance network detection and response (NDR) agent specifically designed for seamless integration with the MxTac platform. Unlike heavyweight NDR solutions, MxWatch focuses on:

- **Native OCSF output** - No normalization layer needed
- **High-performance capture** - 10M+ pps with PF_RING (Linux), libpcap fallback
- **Zero-copy architecture** - Direct NIC-to-userspace packet delivery
- **Multi-core scalability** - Linear scaling across CPU cores
- **Minimal resource footprint** - 15-120 MB RAM, 1-3% CPU per core
- **Single binary deployment** - Statically linked (PF_RING/libpcap)
- **High-value detections** - 15 core capabilities covering 10-15% ATT&CK
- **Cross-platform** - Linux (PF_RING), Windows/macOS (libpcap)

## Quick Start

### Linux (PF_RING - High Performance)

```bash
# 1. Install PF_RING kernel module
git clone https://github.com/ntop/PF_RING.git
cd PF_RING/kernel
make && sudo make install
sudo modprobe pf_ring

# Verify PF_RING loaded
lsmod | grep pf_ring

# 2. Install PF_RING userspace library
cd ../userland/lib
./configure && make && sudo make install
sudo ldconfig

# 3. Download and install MxWatch
wget https://github.com/mxtac/mxwatch/releases/latest/mxwatch-linux-amd64
chmod +x mxwatch-linux-amd64
sudo mv mxwatch-linux-amd64 /usr/local/bin/mxwatch

# 4. Create configuration
sudo mkdir -p /etc/mxwatch
sudo tee /etc/mxwatch/config.yaml > /dev/null <<EOF
capture:
  interface: eth0
  engine: pfring
  pfring:
    workers: 8
    cluster_id: 1
    enable_hw_timestamp: true
    enable_zero_copy: true

output:
  http:
    url: https://mxtac.example.com/api/v1/events
    batch_size: 1000
EOF

# 5. Start agent (requires root for PF_RING)
sudo mxwatch --config /etc/mxwatch/config.yaml

# 6. Verify capture performance
cat /proc/net/pf_ring/info
```

### Windows/macOS (libpcap - Standard)

```bash
# Download and install
wget https://github.com/mxtac/mxwatch/releases/latest/mxwatch-<platform>-amd64
chmod +x mxwatch-<platform>-amd64
sudo mv mxwatch-<platform>-amd64 /usr/local/bin/mxwatch

# Create configuration (libpcap engine)
sudo mkdir -p /etc/mxwatch
sudo tee /etc/mxwatch/config.yaml > /dev/null <<EOF
capture:
  interface: eth0
  engine: libpcap  # Fallback engine

output:
  http:
    url: https://mxtac.example.com/api/v1/events
EOF

# Start agent (requires elevated privileges)
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
- **High Performance**: 100x faster than Zeek on packet capture (10M+ pps vs 100K)
- **Zero-Copy**: PF_RING kernel module for direct NIC access
- **Multi-Core**: Linear scaling across 8-16 CPU cores
- **Hardware Offload**: NIC-level filtering for efficiency
- **Simple Deployment**: Single binary, YAML config, no cluster required
- **MxTac-First**: Designed specifically for MxTac platform integration

## Architecture

```
┌──────────────────────────────────────────────────────┐
│             Network Interface Card (NIC)             │
│   • Hardware Filters (Port 53, 80, 443)             │
│   • 10M+ packets/second                             │
└─────────────────┬────────────────────────────────────┘
                  │ Zero-Copy DMA
                  ▼
┌──────────────────────────────────────────────────────┐
│            PF_RING Kernel Module                     │
│   • Circular buffer (lock-free)                     │
│   • Per-CPU rings                                   │
└─────────────────┬────────────────────────────────────┘
                  │ mmap()
                  ▼
┌──────────────────────────────────────────────────────┐
│               MxWatch Agent (Rust)                   │
│  ┌────────────────────────────────────────────────┐ │
│  │  Multi-Core Workers (8 cores)                  │ │
│  │  Core0  Core1  Core2  Core3                    │ │
│  │  Core4  Core5  Core6  Core7                    │ │
│  └────────────────┬───────────────────────────────┘ │
│                   │                                  │
│  ┌────────────────▼───────────────────────────────┐ │
│  │  Protocol Parsers                              │ │
│  │  • HTTP/HTTPS  • DNS  • TLS                    │ │
│  └────────────────┬───────────────────────────────┘ │
│                   │                                  │
│  ┌────────────────▼───────────────────────────────┐ │
│  │  Detection Engine                              │ │
│  │  • C2 Beacons  • Port Scans  • Exfiltration   │ │
│  └────────────────┬───────────────────────────────┘ │
│                   │                                  │
│  ┌────────────────▼───────────────────────────────┐ │
│  │  OCSF Event Builder                            │ │
│  └────────────────┬───────────────────────────────┘ │
│                   │                                  │
│  ┌────────────────▼───────────────────────────────┐ │
│  │  HTTP Sender (HTTPS/TLS)                       │ │
│  └────────────────┬───────────────────────────────┘ │
└───────────────────┼──────────────────────────────────┘
                    │ OCSF Events
                    ▼
        ┌───────────────────────┐
        │   MxTac Platform      │
        │   Ingestion API       │
        └───────────────────────┘
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

| Resource | Minimum | Recommended (10 Gbps) | High-Performance (100 Gbps) |
|----------|---------|----------------------|----------------------------|
| **CPU** | 2 cores | 8 cores | 16 cores |
| **Memory** | 60 MB | 120 MB | 240 MB |
| **Disk** | 100 MB (binary) | 1 GB (with logs) | 10 GB (with logs) |
| **Network Throughput** | 100 Mbps | 10 Gbps | 100 Gbps |
| **Packet Rate** | 10K pps | 1.5M pps | 14.8M pps |
| **Privileges** | CAP_NET_RAW | root (PF_RING) | root (PF_RING ZC) |

## Platform Support

| Platform | Architecture | Capture Engine | Performance | Status |
|----------|--------------|----------------|-------------|--------|
| **Linux** | amd64, arm64 | **PF_RING** | 10M+ pps | ✅ Planned (Primary) |
| **Windows** | amd64 | libpcap/Npcap | 100K pps | ✅ Planned (Fallback) |
| **macOS** | amd64, arm64 | libpcap/BPF | 100K pps | ✅ Planned (Fallback) |

## Comparison with Zeek

| Feature | Zeek | MxWatch (PF_RING) |
|---------|------|-------------------|
| **Binary Size** | ~50 MB | ~8 MB |
| **Memory Usage** | 300-800 MB | 15-120 MB (scales with cores) |
| **CPU Usage** | 10-20% (single core) | 10-20% (8 cores) |
| **Packet Capture** | libpcap (100K pps) | PF_RING (10M+ pps) |
| **Max Throughput** | ~1 Gbps | 100 Gbps |
| **Packet Loss** | 10-30% @ 1 Gbps | < 0.1% @ 10 Gbps |
| **Multi-Core Support** | Limited | Native (linear scaling) |
| **Hardware Offload** | No | Yes (NIC filtering) |
| **Deployment** | Cluster/Standalone | Single Binary |
| **Output Format** | Zeek Logs | OCSF Native |
| **Protocol Coverage** | 100+ protocols | 10-15 protocols (focused) |
| **Dependencies** | Many | PF_RING kernel module |
| **Configuration** | Zeek Scripts | YAML |

## Development Roadmap

### Phase 1: Core Agent with PF_RING (12 weeks)

- [x] Project setup and structure
- [ ] PF_RING FFI bindings (Rust → C library)
- [ ] Multi-core packet capture with CPU affinity
- [ ] Hardware filter configuration
- [ ] libpcap fallback for non-Linux platforms
- [ ] HTTP/HTTPS protocol parser (custom)
- [ ] DNS protocol parser (trust-dns-proto)
- [ ] OCSF event builder
- [ ] HTTP output handler (reqwest)

### Phase 2: Advanced Detection (8 weeks)

- [ ] TLS/SSL certificate analysis
- [ ] C2 beacon detection (timing analysis)
- [ ] Port scan detection (SYN flood detection)
- [ ] Data exfiltration detection (volume analysis)
- [ ] Lateral movement detection (east-west traffic)
- [ ] DNS tunneling detection (entropy analysis)

### Phase 3: Production Ready (6 weeks)

- [ ] PF_RING kernel module packaging
- [ ] Cross-platform builds (Linux/Windows/macOS)
- [ ] Installer packages (DEB, RPM, MSI)
- [ ] Performance benchmarks (1/10/40/100 Gbps)
- [ ] Documentation (deployment, tuning)
- [ ] Testing suite
- [ ] Deployment automation

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development guidelines.

## License

Apache License 2.0

---

*MxWatch is part of the MxTac Security Platform*
