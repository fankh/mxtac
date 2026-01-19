# MxGuard - Lightweight Endpoint Detection & Response Agent

> **Type**: Lightweight EDR Agent
> **Language**: Go 1.21+
> **Platform**: Linux, Windows, macOS
> **License**: Apache 2.0
> **Status**: Design Phase

---

## Overview

**MxGuard** is a lightweight endpoint detection and response (EDR) agent specifically designed for seamless integration with the MxTac platform. Unlike heavyweight EDR solutions, MxGuard focuses on:

- **Native OCSF output** - No normalization layer needed
- **Minimal resource footprint** - 20-50 MB RAM, 1-2% CPU
- **Single binary deployment** - No external dependencies
- **High-value detections** - 20 core capabilities covering 30-40% ATT&CK
- **Cross-platform** - Linux, Windows, macOS support

## Quick Start

```bash
# Download and install
wget https://github.com/mxtac/mxguard/releases/latest/mxguard-linux-amd64
chmod +x mxguard-linux-amd64
sudo mv mxguard-linux-amd64 /usr/local/bin/mxguard

# Create configuration
sudo mkdir -p /etc/mxguard
sudo nano /etc/mxguard/config.yaml

# Start agent
sudo mxguard --config /etc/mxguard/config.yaml
```

## Features

### Core Capabilities

| Capability | Status | ATT&CK Coverage |
|------------|--------|-----------------|
| **File Integrity Monitoring** | ✅ Planned | T1105, T1547, T1574, T1036 |
| **Process Monitoring** | ✅ Planned | T1059, T1106, T1055, T1003 |
| **Network Connection Tracking** | ✅ Planned | T1071, T1095, T1021 |
| **Authentication Monitoring** | ✅ Planned | T1078, T1110, T1136 |
| **Registry Monitoring (Windows)** | ✅ Planned | T1547, T1112, T1574 |
| **Scheduled Task Monitoring** | ✅ Planned | T1053 |

### Key Differentiators

- **OCSF Native**: Events are generated in OCSF format (no transformation needed)
- **Lightweight**: 10x smaller than Wazuh, 10x less resource usage
- **Simple Deployment**: Single binary, YAML config, no manager required
- **MxTac-First**: Designed specifically for MxTac platform integration

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Endpoint Host                        │
│  ┌───────────────────────────────────────────────────┐  │
│  │              MxGuard Agent                        │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │
│  │  │   File   │  │ Process  │  │ Network  │       │  │
│  │  │ Monitor  │  │ Monitor  │  │ Monitor  │       │  │
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
| **Memory** | 50 MB | 100 MB |
| **Disk** | 100 MB (binary) | 1 GB (with logs) |
| **Network** | 10 Kbps avg | 100 Kbps peak |

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| **Linux** | amd64, arm64 | ✅ Planned |
| **Windows** | amd64 | ✅ Planned |
| **macOS** | amd64, arm64 | ✅ Planned |

## Comparison with Wazuh

| Feature | Wazuh Agent | MxGuard |
|---------|-------------|---------|
| **Binary Size** | ~100 MB | ~10 MB |
| **Memory Usage** | 200-500 MB | 20-50 MB |
| **CPU Usage** | 5-10% | 1-2% |
| **Deployment** | Manager + Agent | Single Binary |
| **Output Format** | Wazuh JSON | OCSF Native |
| **ATT&CK Coverage** | 60-70% | 30-40% |
| **Dependencies** | Many | None |

## Development Roadmap

### Phase 1: Core Agent (8 weeks)

- [x] Project setup and structure
- [ ] File monitoring (inotify/fsnotify)
- [ ] Process monitoring
- [ ] OCSF event builder
- [ ] HTTP output handler
- [ ] Basic configuration

### Phase 2: Enhanced Monitoring (6 weeks)

- [ ] Network connection tracking
- [ ] Log file monitoring
- [ ] Windows registry monitoring
- [ ] Authentication event tracking
- [ ] Performance optimization

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

*MxGuard is part of the MxTac Security Platform*
