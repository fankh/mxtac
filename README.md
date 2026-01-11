# MxTac

> **Matrix + Tactic = MxTac**  
> An open-source, ATT&CK-native security platform that integrates best-of-breed OSS tools to provide unified threat detection and response capabilities.

## Project Documents

| Document | Description |
|----------|-------------|
| [PRODUCT-SPECIFICATION.md](./PRODUCT-SPECIFICATION.md) | Complete product specification with features and requirements |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Technical architecture and component design |
| [INTEGRATION-GUIDE.md](./INTEGRATION-GUIDE.md) | Guide for integrating OSS security tools |
| [ROADMAP.md](./ROADMAP.md) | Development phases and milestones |

## Quick Overview

### What is MxTac?

**MxTac** (Matrix + Tactic) is an **integration platform** that unifies existing open-source security tools under a single ATT&CK-native interface, providing:

- **Unified ATT&CK Coverage Dashboard** - See your detection coverage across all 14 tactics
- **Native Sigma Rule Engine** - Run Sigma rules without conversion
- **OCSF Data Normalization** - Consistent schema across all data sources
- **Cross-Tool Correlation** - Detect attack chains spanning multiple tools
- **Integrated Response** - Orchestrated playbooks across tools

### Why "MxTac"?

```
Mx   = Matrix (ATT&CK Matrix)
Tac  = Tactic (14 ATT&CK Tactics)
─────────────────────────────────
MxTac = Full ATT&CK Coverage
```

### Why Not Just Use Existing Tools?

```
Current State (Fragmented):
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│  Wazuh  │ │  Zeek   │ │Suricata │ │ Prowler │
│  (EDR)  │ │  (NDR)  │ │  (IDS)  │ │ (Cloud) │
└────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
     │           │           │           │
     ▼           ▼           ▼           ▼
  Separate   Separate    Separate    Separate
  Dashboard  Dashboard   Dashboard   Dashboard
  
  ❌ No unified ATT&CK view
  ❌ No cross-tool correlation
  ❌ Different data formats
  ❌ Manual rule conversion

Future State (Unified with MxTac):
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│  Wazuh  │ │  Zeek   │ │Suricata │ │ Prowler │
└────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
     │           │           │           │
     └───────────┴─────┬─────┴───────────┘
                       │
              ┌────────▼────────┐
              │      MxTac      │
              │   Matrix+Tactic │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │ Unified ATT&CK  │
              │   Dashboard     │
              └─────────────────┘
              
  ✅ Single ATT&CK coverage view
  ✅ Cross-tool attack chain detection
  ✅ OCSF normalized data
  ✅ Native Sigma execution
```

### Core Principles

1. **Don't Reinvent** - Integrate existing mature OSS tools, don't rebuild them
2. **ATT&CK-Native** - Every feature maps to ATT&CK framework
3. **Open Standards** - Sigma for detection, OCSF for data, STIX for intel
4. **Community-Driven** - Open governance, community contributions
5. **Production-Ready** - Enterprise-grade reliability and scalability

## Integrated Components

| Category | Primary Tool | Backup Option | Coverage |
|----------|-------------|---------------|----------|
| **EDR/HIDS** | Wazuh | osquery + Velociraptor | Endpoint visibility |
| **NDR** | Zeek | Arkime | Network metadata |
| **IDS/IPS** | Suricata | Snort | Network signatures |
| **Cloud Security** | Prowler | ScoutSuite | AWS/Azure/GCP |
| **Threat Intel** | OpenCTI | MISP | IOC management |
| **SOAR** | Shuffle | n8n | Response automation |
| **Forensics** | Velociraptor | GRR | Deep investigation |

## Expected ATT&CK Coverage

| Integration Level | Coverage | Components |
|------------------|----------|------------|
| Phase 1 (MVP) | 50-60% | Wazuh + Zeek + Suricata |
| Phase 2 | 65-75% | + Prowler + OpenCTI |
| Phase 3 | 70-80% | + Correlation + Response |
| Full Platform | 75-85% | All integrations + tuning |

## Getting Started

*Coming Soon* - Platform is currently in specification phase.

### Planned Installation

```bash
# Clone repository
git clone https://github.com/mxtac/mxtac.git

# Run installer
cd mxtac
./install.sh

# Access dashboard
open https://localhost:8443
```

### CLI Preview

```bash
# Hunt for specific technique
$ mxtac hunt --technique T1059

# Check ATT&CK coverage
$ mxtac coverage --report

# Scan with Sigma rules
$ mxtac scan --sigma-rules ./rules

# Analyze attack chain
$ mxtac analyze --chain

# Real-time detection
$ mxtac detect --live
```

## Project Status

| Phase | Status | Timeline |
|-------|--------|----------|
| Specification | **In Progress** | Q1 2026 |
| Architecture Design | Planned | Q1 2026 |
| MVP Development | Planned | Q2-Q3 2026 |
| Beta Release | Planned | Q4 2026 |
| GA Release | Planned | Q1 2027 |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### Areas Needing Help

- Integration connectors for OSS tools
- Sigma rule development
- OCSF schema mapping
- Dashboard UI/UX
- Documentation

## License

Apache 2.0 (Planned)

---

*This is a conceptual project specification. Development has not yet begun.*
