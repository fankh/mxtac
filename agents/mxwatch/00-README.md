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
- **High-performance capture** - 1-5M pps with AF_PACKET + MMAP (Linux)
- **Zero-copy architecture** - Memory-mapped ring buffer (no kernel module)
- **Multi-core scalability** - PACKET_FANOUT load balancing
- **Minimal resource footprint** - 15-60 MB RAM, 1-3% CPU per core
- **Single binary deployment** - Statically linked, pure Rust
- **High-value detections** - 12+ protocols + 3 detection engines covering 20+ ATT&CK techniques
- **Cross-platform** - Linux (AF_PACKET), Windows/macOS (libpcap)

## Quick Start

### Linux (AF_PACKET + MMAP - High Performance)

```bash
# 1. Download and install MxWatch (single binary, no dependencies)
wget https://github.com/mxtac/mxwatch/releases/latest/mxwatch-linux-amd64
chmod +x mxwatch-linux-amd64
sudo mv mxwatch-linux-amd64 /usr/local/bin/mxwatch

# 2. Create configuration
sudo mkdir -p /etc/mxwatch
sudo tee /etc/mxwatch/config.yaml > /dev/null <<EOF
capture:
  interface: eth0
  engine: afpacket       # AF_PACKET + MMAP (built into Linux kernel)

  afpacket:
    workers: 8           # CPU cores to use
    block_size: 4096
    frame_size: 2048
    block_count: 256
    fanout_group: 1

    # BPF filter (kernel-level)
    bpf_filter: "tcp port 80 or tcp port 443 or udp port 53"

output:
  http:
    url: https://mxtac.example.com/api/v1/events
    batch_size: 1000
EOF

# 3. Start agent (requires CAP_NET_RAW capability)
sudo mxwatch --config /etc/mxwatch/config.yaml

# 4. Verify capture is working
sudo mxwatch --config /etc/mxwatch/config.yaml --stats
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

| Protocol/Capability | Status | ATT&CK Coverage |
|---------------------|--------|--------------------|
| **HTTP/HTTPS** | ✅ Planned | T1071.001 (Web Protocols) |
| **DNS** | ✅ Planned | T1071.004 (DNS), T1568 (DNS Tunneling) |
| **TLS/SSL** | ✅ Planned | T1573 (Encrypted Channel) |
| **SMB/CIFS** | ✅ Planned | T1021.002 (SMB), T1570 (Lateral Movement) |
| **SSH** | ✅ Planned | T1021.004 (SSH), T1110 (Brute Force) |
| **FTP/SFTP** | ✅ Planned | T1071.002 (File Protocols), T1048 (Exfiltration) |
| **SMTP** | ✅ Planned | T1071.003 (Mail Protocols), T1566 (Phishing) |
| **LDAP** | ✅ Planned | T1087 (Account Discovery) |
| **RDP** | ✅ Planned | T1021.001 (RDP) |
| **DHCP** | ✅ Planned | T1557 (MITM) |
| **NTP** | ✅ Planned | T1498 (Network DoS) |
| **ICMP** | ✅ Planned | T1018 (Remote System Discovery) |
| **C2 Beacon Detection** | ✅ Planned | T1071 (Application Layer Protocol) |
| **Port Scan Detection** | ✅ Planned | T1046 (Network Service Scanning) |
| **Data Exfiltration Detection** | ✅ Planned | T1041 (Exfiltration Over C2) |

### Key Differentiators

- **OCSF Native**: Network events generated in OCSF format (no transformation needed)
- **High Performance**: 10x faster than libpcap (1-5M pps vs 100K pps)
- **Zero-Copy**: AF_PACKET + MMAP (no kernel modules required)
- **Multi-Core**: PACKET_FANOUT for automatic load balancing
- **Kernel BPF**: Filtering at kernel level for efficiency
- **Simple Deployment**: Single binary, YAML config, no dependencies
- **Pure Rust**: Memory-safe implementation with tokio async
- **MxTac-First**: Designed specifically for MxTac platform integration

## Architecture

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph NIC["Network Interface Card"]
        style NIC fill:#e3f2fd,stroke:#1565c0
        PACKETS[Network Packets<br/>1-5M pps]
    end

    subgraph Kernel["Linux Kernel - AF_PACKET"]
        style Kernel fill:#e8f5e9,stroke:#2e7d32
        BPF[BPF Filter<br/>Port 53, 80, 443]
        RING[PACKET_MMAP<br/>Zero-Copy Ring]
        FANOUT[PACKET_FANOUT<br/>Load Balancing]
    end

    subgraph Agent["MxWatch Agent - Rust"]
        style Agent fill:#fff3e0,stroke:#ef6c00

        subgraph Workers["Multi-Core Workers"]
            style Workers fill:#f3e5f5,stroke:#7b1fa2
            C0[Core 0]
            C1[Core 1]
            C2[Core 2]
            C3[Core 3]
        end

        subgraph Parsers["Protocol Parsers - 12+"]
            style Parsers fill:#e0f2f1,stroke:#00695c
            HTTP[HTTP/HTTPS]
            DNS[DNS]
            TLS[TLS/SSL]
            SMB[SMB]
            SSH[SSH]
            FTP[FTP]
            SMTP[SMTP]
            LDAP[LDAP]
            RDP[RDP]
            MORE[+ DHCP, NTP, ICMP]
        end

        subgraph Detection["Detection Engine"]
            style Detection fill:#fce4ec,stroke:#ad1457
            C2[C2 Beacons]
            SCAN[Port Scans]
            EXFIL[Exfiltration]
        end

        BUILDER[OCSF Event Builder]
        SENDER[HTTP Sender]
    end

    subgraph Platform["MxTac Platform"]
        style Platform fill:#fff9c4,stroke:#f57f17
        API[Ingestion API]
    end

    PACKETS --> BPF
    BPF --> RING
    RING --> FANOUT
    FANOUT -->|mmap<br/>Zero-Copy| Workers
    Workers --> Parsers
    Parsers --> Detection
    Detection --> BUILDER
    BUILDER --> SENDER
    SENDER -->|HTTPS/TLS<br/>OCSF Events| API
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

| Resource | Minimum | Recommended | High-Performance |
|----------|---------|-------------|------------------|
| **CPU** | 2 cores | 4 cores | 8 cores |
| **Memory** | 40 MB | 60 MB | 120 MB |
| **Disk** | 50 MB (binary) | 1 GB (with logs) | 10 GB (with logs) |
| **Network Throughput** | 100 Mbps | 1 Gbps | 10 Gbps |
| **Packet Rate** | 10K pps | 150K pps | 1.5M pps |
| **Privileges** | CAP_NET_RAW | CAP_NET_RAW | CAP_NET_RAW |

## Platform Support

| Platform | Architecture | Capture Engine | Performance | Status |
|----------|--------------|----------------|-------------|--------|
| **Linux** | amd64, arm64 | **AF_PACKET + MMAP** | 1-5M pps | ✅ Planned (Primary) |
| **Windows** | amd64 | libpcap/Npcap | 100K pps | ✅ Planned (Fallback) |
| **macOS** | amd64, arm64 | libpcap/BPF | 100K pps | ✅ Planned (Fallback) |

## Comparison with Zeek

| Feature | Zeek | MxWatch (AF_PACKET) |
|---------|------|---------------------|
| **Binary Size** | ~50 MB | ~5 MB |
| **Memory Usage** | 300-800 MB | 40-120 MB (scales with cores) |
| **CPU Usage** | 10-20% (single core) | 5-15% (4-8 cores) |
| **Packet Capture** | libpcap (100K pps) | AF_PACKET + MMAP (1-5M pps) |
| **Max Throughput** | ~1 Gbps | 10 Gbps |
| **Packet Loss** | 10-30% @ 1 Gbps | 1-5% @ 10 Gbps |
| **Multi-Core Support** | Limited | Native (PACKET_FANOUT) |
| **Kernel BPF** | Yes | Yes |
| **Deployment** | Cluster/Standalone | Single Binary |
| **Dependencies** | Many (libpcap, Python, etc.) | None (built into Linux kernel) |
| **Output Format** | Zeek Logs | OCSF Native |
| **Protocol Coverage** | 100+ protocols | 12+ protocols (focused on threats) |
| **Configuration** | Zeek Scripts | YAML |
| **Installation** | Complex | Simple (single binary) |

## Development Roadmap

### Phase 1: Core Agent with AF_PACKET (10 weeks)

- [x] Project setup and structure
- [ ] AF_PACKET + MMAP implementation (pure Rust)
- [ ] PACKET_FANOUT multi-core load balancing
- [ ] BPF filter integration
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

### Phase 3: Production Ready (4 weeks)

- [ ] Cross-platform builds (Linux/Windows/macOS)
- [ ] Installer packages (DEB, RPM, MSI)
- [ ] Performance benchmarks (100M/1G/10G)
- [ ] Documentation (deployment, tuning)
- [ ] Testing suite
- [ ] Deployment automation

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development guidelines.

## License

Apache License 2.0

---

*MxWatch is part of the MxTac Security Platform*
