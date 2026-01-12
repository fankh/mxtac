# MxTac - Open Source Alternatives Guide

> **Document Type**: Component Selection Guide  
> **Version**: 1.0  
> **Date**: January 2026  
> **Project**: MxTac (Matrix + Tactic)

---

## Overview

This guide provides alternative open-source solutions for each MxTac component, enabling flexible deployment based on organizational requirements, existing infrastructure, and team expertise.

### Selection Criteria

| Criteria | Weight | Description |
|----------|--------|-------------|
| **ATT&CK Compatibility** | High | Native or easy mapping to MITRE ATT&CK |
| **Community Activity** | High | GitHub stars, contributors, release frequency |
| **Enterprise Readiness** | Medium | Scalability, HA support, documentation |
| **Integration Ease** | Medium | API quality, plugin ecosystem |
| **Resource Requirements** | Medium | CPU, memory, storage footprint |

---

## Component Categories

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      MxTac Component Stack                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │     EDR     │ │     NDR     │ │    Cloud    │ │     TIP     │       │
│  │  Endpoint   │ │   Network   │ │  Security   │ │   Threat    │       │
│  │  Detection  │ │  Detection  │ │   Posture   │ │   Intel     │       │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘       │
│                                                                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │    SIEM     │ │    SOAR     │ │  Log Mgmt   │ │  Identity   │       │
│  │   Search    │ │  Response   │ │  Pipeline   │ │  Security   │       │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘       │
│                                                                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │   Message   │ │    Cache    │ │  Database   │ │   Object    │       │
│  │    Queue    │ │             │ │  (Metadata) │ │   Storage   │       │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. EDR (Endpoint Detection & Response)

### Primary: Wazuh

| Attribute | Details |
|-----------|---------|
| **Website** | https://wazuh.com |
| **GitHub** | https://github.com/wazuh/wazuh |
| **License** | GPLv2 |
| **Stars** | 10,000+ |

**Strengths:**
- Complete XDR platform (agent + manager + indexer)
- Native ATT&CK mapping in alerts
- File Integrity Monitoring (FIM)
- Vulnerability detection
- Active response capabilities
- Large rule set (3,000+ rules)

**ATT&CK Coverage:**
- Execution (T1059): Process monitoring
- Persistence (T1547): Registry/startup monitoring
- Defense Evasion (T1562): Agent tampering detection
- Credential Access (T1003): LSASS access monitoring

### Alternative 1: Velociraptor

| Attribute | Details |
|-----------|---------|
| **Website** | https://docs.velociraptor.app |
| **GitHub** | https://github.com/Velocidex/velociraptor |
| **License** | AGPL-3.0 |
| **Stars** | 3,000+ |

**Strengths:**
- VQL (Velociraptor Query Language) for flexible hunting
- Artifact-based collection
- Lightweight agent footprint
- Real-time streaming
- Excellent for forensics and IR

**Best For:** Threat hunting, incident response, forensic collection

**ATT&CK Coverage:**
- Superior for hunting across all tactics
- Artifact library maps to techniques
- Real-time process/file/registry monitoring

### Alternative 2: osquery + Fleet

| Attribute | Details |
|-----------|---------|
| **Website** | https://osquery.io / https://fleetdm.com |
| **GitHub** | https://github.com/osquery/osquery |
| **License** | Apache 2.0 / MIT |
| **Stars** | 21,000+ (osquery) |

**Strengths:**
- SQL-based endpoint queries
- Cross-platform (Windows, macOS, Linux)
- Low resource consumption
- Fleet provides management UI
- Scheduled and live queries

**Best For:** Compliance, asset inventory, lightweight monitoring

**ATT&CK Coverage:**
- Good visibility but requires custom queries
- Community packs available for ATT&CK techniques

### Alternative 3: OSSEC

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.ossec.net |
| **GitHub** | https://github.com/ossec/ossec-hids |
| **License** | GPLv2 |
| **Stars** | 4,000+ |

**Strengths:**
- Mature, battle-tested (since 2004)
- Log analysis and FIM
- Rootkit detection
- Active response

**Best For:** Legacy systems, simple deployments

### EDR Comparison Matrix

| Feature | Wazuh | Velociraptor | osquery+Fleet | OSSEC |
|---------|-------|--------------|---------------|-------|
| Agent Weight | Medium | Light | Very Light | Light |
| Real-time Detection | Yes | Yes | Limited | Yes |
| Threat Hunting | Good | Excellent | Good | Limited |
| Active Response | Yes | Yes | No | Yes |
| ATT&CK Mapping | Native | Via Artifacts | Manual | Limited |
| Management UI | Yes | Yes | Fleet | Limited |
| Scalability | High | High | High | Medium |
| Learning Curve | Medium | High | Medium | Low |

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  EDR Selection Guide                                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Primary Detection + Response     →  Wazuh                              │
│  Advanced Threat Hunting          →  Velociraptor (complement Wazuh)    │
│  Lightweight Compliance           →  osquery + Fleet                    │
│  Legacy/Simple Requirements       →  OSSEC                              │
│                                                                         │
│  Recommended Stack: Wazuh + Velociraptor                                │
│  - Wazuh: Continuous monitoring, alerts, compliance                     │
│  - Velociraptor: On-demand hunting, IR, forensics                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. NDR (Network Detection & Response)

### Primary: Zeek

| Attribute | Details |
|-----------|---------|
| **Website** | https://zeek.org |
| **GitHub** | https://github.com/zeek/zeek |
| **License** | BSD |
| **Stars** | 6,000+ |

**Strengths:**
- Deep protocol analysis (50+ protocols)
- Rich metadata extraction (not just alerts)
- Scriptable detection language
- Extensive logging (conn, dns, http, ssl, etc.)
- Community scripts and packages

**ATT&CK Coverage:**
- Command and Control (T1071): Protocol analysis
- Exfiltration (T1048): Data transfer detection
- Lateral Movement (T1021): Internal traffic analysis
- Discovery (T1046): Network scanning detection

### Alternative 1: Suricata

| Attribute | Details |
|-----------|---------|
| **Website** | https://suricata.io |
| **GitHub** | https://github.com/OISF/suricata |
| **License** | GPLv2 |
| **Stars** | 5,000+ |

**Strengths:**
- High-performance IDS/IPS
- Multi-threaded architecture
- Signature-based detection (Snort compatible)
- Protocol identification
- File extraction
- JA3/JA3S fingerprinting

**Best For:** Signature-based detection, IPS mode, compliance

**ATT&CK Coverage:**
- Excellent for known attack patterns
- ET Open rules map to techniques
- JA3 for C2 detection

### Alternative 2: Arkime (formerly Moloch)

| Attribute | Details |
|-----------|---------|
| **Website** | https://arkime.com |
| **GitHub** | https://github.com/arkime/arkime |
| **License** | Apache 2.0 |
| **Stars** | 6,000+ |

**Strengths:**
- Full packet capture and indexing
- Powerful search and analysis UI
- Session reconstruction
- PCAP export
- Integrates with Suricata/Zeek

**Best For:** Forensics, full packet analysis, regulatory compliance

### Alternative 3: ntopng

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.ntop.org/products/traffic-analysis/ntop/ |
| **GitHub** | https://github.com/ntop/ntopng |
| **License** | GPLv3 |
| **Stars** | 6,000+ |

**Strengths:**
- Real-time traffic analysis
- Flow-based monitoring (NetFlow/sFlow/IPFIX)
- Behavioral analysis
- Lightweight compared to full PCAP

**Best For:** Traffic monitoring, bandwidth analysis, flow analysis

### Alternative 4: Security Onion (Meta-Distribution)

| Attribute | Details |
|-----------|---------|
| **Website** | https://securityonionsolutions.com |
| **GitHub** | https://github.com/Security-Onion-Solutions/securityonion |
| **License** | GPLv2 |
| **Stars** | 3,000+ |

**Strengths:**
- Integrated platform (Zeek + Suricata + Wazuh + Elastic)
- Pre-configured and optimized
- SOC workflow tools included
- Active community

**Best For:** All-in-one deployment, smaller teams

### NDR Comparison Matrix

| Feature | Zeek | Suricata | Arkime | ntopng | Security Onion |
|---------|------|----------|--------|--------|----------------|
| Detection Type | Behavioral | Signature | Forensic | Flow | All |
| Protocol Depth | Deep | Medium | Deep | Basic | Deep |
| Performance | High | Very High | Medium | High | Medium |
| Storage Needs | Medium | Low | Very High | Low | High |
| Real-time Alerts | Via Scripts | Yes | No | Yes | Yes |
| Packet Capture | Metadata | Optional | Full | No | Full |
| Learning Curve | High | Medium | Medium | Low | Medium |

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  NDR Selection Guide                                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Behavioral Analysis + Metadata    →  Zeek                              │
│  Signature Detection + IPS         →  Suricata                          │
│  Full Packet Forensics             →  Arkime                            │
│  Flow Monitoring                   →  ntopng                            │
│  All-in-One Platform               →  Security Onion                    │
│                                                                         │
│  Recommended Stack: Zeek + Suricata                                     │
│  - Zeek: Rich metadata, behavioral detection, protocol analysis         │
│  - Suricata: Signature matching, known threats, IPS capability          │
│                                                                         │
│  Add Arkime if: Full packet capture required for forensics/compliance   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Event Store / SIEM Search

### Primary: OpenSearch

| Attribute | Details |
|-----------|---------|
| **Website** | https://opensearch.org |
| **GitHub** | https://github.com/opensearch-project/OpenSearch |
| **License** | Apache 2.0 |
| **Stars** | 9,000+ |

**Strengths:**
- Fork of Elasticsearch 7.10 (truly open source)
- Full-text search with analytics
- OpenSearch Dashboards (Kibana fork)
- Security plugin included (free)
- Alerting, anomaly detection built-in
- Active development by AWS + community

**ATT&CK Integration:**
- Store normalized events with technique tags
- Build ATT&CK Navigator dashboards
- Sigma rule backend support

### Alternative 1: Elasticsearch (Basic License)

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.elastic.co |
| **GitHub** | https://github.com/elastic/elasticsearch |
| **License** | Elastic License 2.0 / SSPL |
| **Stars** | 69,000+ |

**Strengths:**
- Mature, feature-rich
- Largest ecosystem
- Excellent documentation
- Kibana visualizations

**Considerations:**
- License restrictions (not OSI-approved open source)
- Security features require paid license
- Cloud service restrictions

**Best For:** Organizations comfortable with Elastic License

### Alternative 2: ClickHouse

| Attribute | Details |
|-----------|---------|
| **Website** | https://clickhouse.com |
| **GitHub** | https://github.com/ClickHouse/ClickHouse |
| **License** | Apache 2.0 |
| **Stars** | 37,000+ |

**Strengths:**
- Extremely fast for analytics
- Column-oriented storage
- Excellent compression
- SQL interface
- Low resource consumption for data volume

**Considerations:**
- Not a search engine (different paradigm)
- Less mature security tooling
- Requires custom UI

**Best For:** High-volume analytics, cost-sensitive deployments

### Alternative 3: Quickwit

| Attribute | Details |
|-----------|---------|
| **Website** | https://quickwit.io |
| **GitHub** | https://github.com/quickwit-oss/quickwit |
| **License** | AGPL-3.0 |
| **Stars** | 8,000+ |

**Strengths:**
- Cloud-native log search engine
- Sub-second search on cloud storage (S3)
- Elasticsearch-compatible API
- Very cost-effective for cold storage
- Built in Rust (performance)

**Best For:** Cloud deployments, cost optimization, archival search

### Alternative 4: Loki + Grafana

| Attribute | Details |
|-----------|---------|
| **Website** | https://grafana.com/oss/loki/ |
| **GitHub** | https://github.com/grafana/loki |
| **License** | AGPL-3.0 |
| **Stars** | 24,000+ |

**Strengths:**
- Prometheus-inspired log aggregation
- Label-based indexing (not full-text)
- Low storage overhead
- Native Grafana integration
- Simple to operate

**Considerations:**
- Not full-text search
- Different query paradigm (LogQL)
- Limited for complex analytics

**Best For:** Kubernetes environments, Prometheus users, simple log queries

### Event Store Comparison Matrix

| Feature | OpenSearch | Elasticsearch | ClickHouse | Quickwit | Loki |
|---------|------------|---------------|------------|----------|------|
| License | Apache 2.0 | Elastic/SSPL | Apache 2.0 | AGPL-3.0 | AGPL-3.0 |
| Search Type | Full-text | Full-text | Analytics | Full-text | Label |
| Query Language | DSL/SQL | DSL/SQL | SQL | DSL | LogQL |
| Performance | High | High | Very High | High | Medium |
| Storage Efficiency | Medium | Medium | High | Very High | High |
| Security Plugin | Free | Paid | Basic | Basic | Basic |
| Dashboard | Yes | Yes | No | No | Grafana |
| Sigma Backend | Yes | Yes | Community | Planned | No |

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Event Store Selection Guide                                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  General Purpose SIEM              →  OpenSearch (Primary Choice)       │
│  Elastic Ecosystem Required        →  Elasticsearch                     │
│  High-Volume Analytics             →  ClickHouse                        │
│  Cloud-Native / Cost Optimize      →  Quickwit                          │
│  Kubernetes / Simple Logs          →  Loki + Grafana                    │
│                                                                         │
│  MxTac Default: OpenSearch                                              │
│  - True open source (Apache 2.0)                                        │
│  - Security features included free                                      │
│  - Sigma backend support                                                │
│  - Active community development                                         │
│                                                                         │
│  Hybrid Option: OpenSearch + ClickHouse                                 │
│  - OpenSearch: Hot data, real-time search, alerts                       │
│  - ClickHouse: Cold data, long-term analytics, reporting                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Threat Intelligence Platform (TIP)

### Primary: OpenCTI

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.opencti.io |
| **GitHub** | https://github.com/OpenCTI-Platform/opencti |
| **License** | Apache 2.0 |
| **Stars** | 6,000+ |

**Strengths:**
- STIX 2.1 native
- Knowledge graph visualization
- Connectors for 100+ sources
- ATT&CK integration built-in
- Correlation and enrichment
- Modern React UI

**ATT&CK Integration:**
- Native ATT&CK framework import
- Technique-to-indicator mapping
- Campaign tracking with techniques
- Threat actor TTP profiles

### Alternative 1: MISP

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.misp-project.org |
| **GitHub** | https://github.com/MISP/MISP |
| **License** | AGPL-3.0 |
| **Stars** | 5,000+ |

**Strengths:**
- Mature platform (since 2011)
- Massive sharing community
- Flexible data model
- MISP Galaxies (including ATT&CK)
- PyMISP for automation
- Event-centric approach

**Best For:** Indicator sharing, community collaboration

### Alternative 2: YETI

| Attribute | Details |
|-----------|---------|
| **Website** | https://yeti-platform.io |
| **GitHub** | https://github.com/yeti-platform/yeti |
| **License** | Apache 2.0 |
| **Stars** | 2,000+ |

**Strengths:**
- Lightweight and fast
- Observable-centric
- Good for smaller teams
- Python-based, easy to extend

**Best For:** Smaller deployments, quick setup

### Alternative 3: TheHive (with Cortex)

| Attribute | Details |
|-----------|---------|
| **Website** | https://thehive-project.org |
| **GitHub** | https://github.com/TheHive-Project/TheHive |
| **License** | AGPL-3.0 |
| **Stars** | 3,000+ |

**Strengths:**
- Incident response platform
- Case management
- Cortex for automated analysis
- MISP integration

**Note:** More IR-focused than pure TIP, but excellent complement

### TIP Comparison Matrix

| Feature | OpenCTI | MISP | YETI | TheHive |
|---------|---------|------|------|---------|
| Primary Focus | Knowledge Graph | Indicator Sharing | Observables | Incident Response |
| Data Model | STIX 2.1 | MISP Format | Custom | Cases/Alerts |
| ATT&CK Native | Yes | Via Galaxy | Limited | Limited |
| Visualization | Excellent | Good | Basic | Case-focused |
| Sharing | TAXII | MISP Sync | API | API |
| Learning Curve | Medium | Medium | Low | Medium |
| Resource Needs | High | Medium | Low | Medium |

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  TIP Selection Guide                                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Enterprise Knowledge Management   →  OpenCTI                           │
│  Community Sharing Focus           →  MISP                              │
│  Lightweight Observable Store      →  YETI                              │
│  Incident Response Integration     →  TheHive + Cortex                  │
│                                                                         │
│  Recommended Stack: OpenCTI + MISP                                      │
│  - OpenCTI: Internal knowledge base, ATT&CK mapping                     │
│  - MISP: External sharing, community feeds                              │
│  - Sync: OpenCTI has native MISP connector                              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Cloud Security Posture Management (CSPM)

### Primary: Prowler

| Attribute | Details |
|-----------|---------|
| **Website** | https://prowler.pro |
| **GitHub** | https://github.com/prowler-cloud/prowler |
| **License** | Apache 2.0 |
| **Stars** | 10,000+ |

**Strengths:**
- Multi-cloud (AWS, Azure, GCP, K8s)
- 300+ security checks
- Compliance frameworks (CIS, PCI-DSS, HIPAA, etc.)
- ATT&CK mapping for findings
- CI/CD integration
- OCSF output format

**ATT&CK Coverage:**
- Initial Access: Exposed resources
- Persistence: IAM misconfigurations
- Privilege Escalation: Overpermissioned roles
- Defense Evasion: Logging disabled

### Alternative 1: ScoutSuite

| Attribute | Details |
|-----------|---------|
| **Website** | https://github.com/nccgroup/ScoutSuite |
| **GitHub** | https://github.com/nccgroup/ScoutSuite |
| **License** | GPLv2 |
| **Stars** | 6,000+ |

**Strengths:**
- Multi-cloud support
- HTML report generation
- Rule-based checks
- Easy to extend

**Best For:** Security assessments, audits

### Alternative 2: CloudSploit

| Attribute | Details |
|-----------|---------|
| **Website** | https://cloudsploit.com |
| **GitHub** | https://github.com/aquasecurity/cloudsploit |
| **License** | GPLv3 |
| **Stars** | 3,000+ |

**Strengths:**
- Real-time scanning
- Multi-cloud
- Compliance mapping
- Aqua Security backed

### Alternative 3: Steampipe

| Attribute | Details |
|-----------|---------|
| **Website** | https://steampipe.io |
| **GitHub** | https://github.com/turbot/steampipe |
| **License** | AGPL-3.0 |
| **Stars** | 7,000+ |

**Strengths:**
- SQL interface to cloud APIs
- 140+ plugins
- Compliance as code
- Dashboards included
- Very flexible

**Best For:** Custom queries, multi-source correlation

### Alternative 4: Trivy

| Attribute | Details |
|-----------|---------|
| **Website** | https://trivy.dev |
| **GitHub** | https://github.com/aquasecurity/trivy |
| **License** | Apache 2.0 |
| **Stars** | 24,000+ |

**Strengths:**
- Container/image vulnerability scanning
- IaC scanning (Terraform, CloudFormation)
- SBOM generation
- Fast and comprehensive
- CI/CD native

**Best For:** Container security, shift-left scanning

### CSPM Comparison Matrix

| Feature | Prowler | ScoutSuite | CloudSploit | Steampipe | Trivy |
|---------|---------|------------|-------------|-----------|-------|
| Multi-Cloud | Yes | Yes | Yes | Yes | Yes |
| Continuous Scan | Yes | No | Yes | Via Mods | Yes |
| Compliance Maps | Excellent | Good | Good | Excellent | Good |
| ATT&CK Mapping | Yes | Limited | Limited | Via Mods | Limited |
| Container Scan | Limited | No | No | Via Plugin | Excellent |
| IaC Scan | Limited | No | No | Via Plugin | Yes |
| Output Formats | Many | HTML | JSON | Many | Many |

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  CSPM Selection Guide                                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Cloud Security Posture           →  Prowler                            │
│  Security Assessments             →  ScoutSuite                         │
│  Custom Cloud Queries             →  Steampipe                          │
│  Container/Image Security         →  Trivy                              │
│  Real-time Cloud Monitoring       →  CloudSploit                        │
│                                                                         │
│  Recommended Stack: Prowler + Trivy                                     │
│  - Prowler: Cloud configuration, compliance, ATT&CK                     │
│  - Trivy: Container images, IaC, vulnerabilities                        │
│                                                                         │
│  Add Steampipe if: Complex multi-cloud queries needed                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. SOAR (Security Orchestration, Automation & Response)

### Primary: Shuffle

| Attribute | Details |
|-----------|---------|
| **Website** | https://shuffler.io |
| **GitHub** | https://github.com/Shuffle/Shuffle |
| **License** | AGPL-3.0 |
| **Stars** | 3,000+ |

**Strengths:**
- Visual workflow builder
- 1000+ app integrations
- OpenAPI app generator
- Webhook triggers
- Human-in-the-loop support
- Active development

**ATT&CK Use Cases:**
- Automated enrichment on technique detection
- Response playbooks per tactic
- Threat intel correlation workflows

### Alternative 1: n8n

| Attribute | Details |
|-----------|---------|
| **Website** | https://n8n.io |
| **GitHub** | https://github.com/n8n-io/n8n |
| **License** | Sustainable Use License |
| **Stars** | 50,000+ |

**Strengths:**
- Beautiful visual workflow editor
- 400+ integrations
- Self-hostable
- Active community
- Code nodes for custom logic

**Considerations:**
- Not security-specific
- License restrictions for some uses

**Best For:** General automation, non-security workflows too

### Alternative 2: StackStorm

| Attribute | Details |
|-----------|---------|
| **Website** | https://stackstorm.com |
| **GitHub** | https://github.com/StackStorm/st2 |
| **License** | Apache 2.0 |
| **Stars** | 6,000+ |

**Strengths:**
- Event-driven automation
- IFTTT for Ops
- Large pack ecosystem
- ChatOps integration
- Enterprise-grade

**Best For:** DevOps/SecOps automation, complex workflows

### Alternative 3: Tines (Community Edition)

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.tines.com |
| **License** | Proprietary (Community Free Tier) |

**Strengths:**
- Security-focused SOAR
- Story-based workflows
- No-code approach
- Community edition available

**Considerations:**
- Not fully open source
- Limited community edition

### Alternative 4: Apache Airflow

| Attribute | Details |
|-----------|---------|
| **Website** | https://airflow.apache.org |
| **GitHub** | https://github.com/apache/airflow |
| **License** | Apache 2.0 |
| **Stars** | 37,000+ |

**Strengths:**
- Mature workflow orchestration
- Python-based DAGs
- Extensive operator library
- Scheduling capabilities

**Best For:** Scheduled tasks, data pipelines, batch processing

### SOAR Comparison Matrix

| Feature | Shuffle | n8n | StackStorm | Tines CE | Airflow |
|---------|---------|-----|------------|----------|---------|
| Security Focus | High | Low | Medium | High | Low |
| Visual Builder | Yes | Excellent | Limited | Yes | No |
| Integrations | 1000+ | 400+ | 150+ | 100+ | Custom |
| Real-time Triggers | Yes | Yes | Yes | Yes | Limited |
| Learning Curve | Low | Low | High | Low | High |
| Self-Hosted | Yes | Yes | Yes | Limited | Yes |
| License | AGPL-3.0 | Custom | Apache 2.0 | Proprietary | Apache 2.0 |

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  SOAR Selection Guide                                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Security-Focused SOAR            →  Shuffle                            │
│  General Automation + Beautiful UI →  n8n                               │
│  Complex Event-Driven Workflows   →  StackStorm                         │
│  Scheduled Batch Processing       →  Apache Airflow                     │
│                                                                         │
│  MxTac Default: Shuffle                                                 │
│  - Security-focused design                                              │
│  - Visual playbook builder                                              │
│  - Native security tool integrations                                    │
│  - AGPL open source                                                     │
│                                                                         │
│  Alternative: n8n (if already using for other automation)               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Message Queue

### Primary: Apache Kafka

| Attribute | Details |
|-----------|---------|
| **Website** | https://kafka.apache.org |
| **GitHub** | https://github.com/apache/kafka |
| **License** | Apache 2.0 |
| **Stars** | 29,000+ |

**Strengths:**
- Industry standard for streaming
- High throughput (millions of events/sec)
- Durable, replicated
- Exactly-once semantics
- Kafka Connect ecosystem
- Kafka Streams processing

**MxTac Use:**
- Raw event ingestion from connectors
- Normalized event distribution
- Alert streaming

### Alternative 1: Apache Pulsar

| Attribute | Details |
|-----------|---------|
| **Website** | https://pulsar.apache.org |
| **GitHub** | https://github.com/apache/pulsar |
| **License** | Apache 2.0 |
| **Stars** | 14,000+ |

**Strengths:**
- Multi-tenancy native
- Geo-replication built-in
- Tiered storage
- Unified messaging (queue + stream)
- Better cloud-native fit

**Best For:** Multi-tenant deployments, geo-distributed

### Alternative 2: Redis Streams

| Attribute | Details |
|-----------|---------|
| **Website** | https://redis.io/docs/data-types/streams/ |
| **License** | BSD-3-Clause |

**Strengths:**
- Simple to operate
- Low latency
- Consumer groups
- Minimal footprint
- Already using Redis for cache

**Considerations:**
- Not as durable as Kafka
- Limited retention
- Single-node limitations

**Best For:** Small-medium deployments, simplicity priority

### Alternative 3: RabbitMQ

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.rabbitmq.com |
| **GitHub** | https://github.com/rabbitmq/rabbitmq-server |
| **License** | MPL 2.0 |
| **Stars** | 12,000+ |

**Strengths:**
- Mature, reliable
- Multiple protocols (AMQP, MQTT, STOMP)
- Flexible routing
- Easy to understand

**Considerations:**
- Lower throughput than Kafka
- Not designed for replay

**Best For:** Traditional messaging, lower throughput needs

### Alternative 4: NATS

| Attribute | Details |
|-----------|---------|
| **Website** | https://nats.io |
| **GitHub** | https://github.com/nats-io/nats-server |
| **License** | Apache 2.0 |
| **Stars** | 16,000+ |

**Strengths:**
- Ultra-low latency
- Simple, lightweight
- JetStream for persistence
- Edge-friendly

**Best For:** Low-latency requirements, edge deployments

### Message Queue Comparison Matrix

| Feature | Kafka | Pulsar | Redis Streams | RabbitMQ | NATS |
|---------|-------|--------|---------------|----------|------|
| Throughput | Very High | Very High | High | Medium | Very High |
| Durability | Excellent | Excellent | Good | Good | Good (JS) |
| Complexity | High | High | Low | Medium | Low |
| Replay | Yes | Yes | Limited | No | Yes (JS) |
| Latency | Medium | Low | Very Low | Low | Very Low |
| Ordering | Partition | Partition | Stream | Queue | Stream |

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Message Queue Selection Guide                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Large Scale (>10K EPS)           →  Kafka or Pulsar                    │
│  Medium Scale (<10K EPS)          →  Redis Streams                      │
│  Traditional Messaging            →  RabbitMQ                           │
│  Ultra-Low Latency               →  NATS                                │
│                                                                         │
│  MxTac Default: Kafka                                                   │
│  - Production: Kafka (durability, replay, scale)                        │
│  - Development: Redis Streams (simplicity)                              │
│                                                                         │
│  Decision Factor: Expected EPS                                          │
│  - < 5,000 EPS: Redis Streams sufficient                                │
│  - > 5,000 EPS: Kafka recommended                                       │
│  - > 50,000 EPS: Kafka required                                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Cache

### Primary: Redis

| Attribute | Details |
|-----------|---------|
| **Website** | https://redis.io |
| **GitHub** | https://github.com/redis/redis |
| **License** | BSD-3-Clause |
| **Stars** | 67,000+ |

**Strengths:**
- Industry standard
- Multiple data structures
- Pub/Sub support
- Lua scripting
- Cluster mode for HA
- Redis Streams for queuing

**MxTac Use:**
- Session cache
- Rate limiting
- Real-time correlation buffer
- Pub/Sub for alerts

### Alternative 1: Valkey

| Attribute | Details |
|-----------|---------|
| **Website** | https://valkey.io |
| **GitHub** | https://github.com/valkey-io/valkey |
| **License** | BSD-3-Clause |
| **Stars** | 17,000+ |

**Strengths:**
- Redis fork (after license change)
- Drop-in replacement
- Linux Foundation backed
- Community-driven development

**Best For:** Those concerned about Redis licensing direction

### Alternative 2: KeyDB

| Attribute | Details |
|-----------|---------|
| **Website** | https://keydb.dev |
| **GitHub** | https://github.com/Snapchat/KeyDB |
| **License** | BSD-3-Clause |
| **Stars** | 11,000+ |

**Strengths:**
- Multi-threaded (vs Redis single-threaded)
- Active replication
- Higher throughput
- Redis compatible

**Best For:** High-throughput requirements

### Alternative 3: Dragonfly

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.dragonflydb.io |
| **GitHub** | https://github.com/dragonflydb/dragonfly |
| **License** | BSL 1.1 |
| **Stars** | 26,000+ |

**Strengths:**
- 25x faster than Redis
- Multi-threaded
- Memory efficient
- Redis/Memcached compatible

**Considerations:**
- BSL license (converts to Apache after 4 years)

**Best For:** Performance-critical deployments

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Cache Selection Guide                                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  General Purpose                  →  Redis                              │
│  License Concerns                 →  Valkey (Redis fork)                │
│  High Throughput                  →  KeyDB or Dragonfly                 │
│                                                                         │
│  MxTac Default: Redis                                                   │
│  - Most mature, best documented                                         │
│  - Largest ecosystem                                                    │
│  - Valkey as drop-in if needed                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Metadata Database

### Primary: PostgreSQL

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.postgresql.org |
| **GitHub** | https://github.com/postgres/postgres |
| **License** | PostgreSQL License |
| **Stars** | 16,000+ |

**Strengths:**
- Most advanced open-source RDBMS
- JSONB for flexible schemas
- Excellent extensions (TimescaleDB, etc.)
- Strong consistency
- Battle-tested

**MxTac Use:**
- User/role management
- Rule definitions
- Connector configurations
- Audit logs
- Investigation metadata

### Alternative 1: MySQL / MariaDB

| Attribute | Details |
|-----------|---------|
| **Website** | https://mariadb.org |
| **GitHub** | https://github.com/MariaDB/server |
| **License** | GPLv2 |
| **Stars** | 6,000+ |

**Strengths:**
- Wide adoption
- Good performance
- Easy to operate
- MariaDB is MySQL-compatible fork

**Best For:** Teams with MySQL expertise

### Alternative 2: CockroachDB

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.cockroachlabs.com |
| **GitHub** | https://github.com/cockroachdb/cockroach |
| **License** | BSL 1.1 |
| **Stars** | 30,000+ |

**Strengths:**
- Distributed SQL
- Horizontal scaling
- Strong consistency
- Postgres-compatible
- Built-in HA

**Best For:** Large-scale, geo-distributed deployments

### Alternative 3: SQLite

| Attribute | Details |
|-----------|---------|
| **Website** | https://sqlite.org |
| **License** | Public Domain |

**Strengths:**
- Zero configuration
- Single file database
- Embedded
- Perfect for small deployments

**Best For:** Development, small single-node deployments

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Database Selection Guide                                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  General Production              →  PostgreSQL                          │
│  MySQL Ecosystem                 →  MariaDB                             │
│  Distributed/Multi-Region        →  CockroachDB                         │
│  Development/Small               →  SQLite                              │
│                                                                         │
│  MxTac Default: PostgreSQL                                              │
│  - Mature, feature-rich, widely supported                               │
│  - JSONB for semi-structured data                                       │
│  - Extensions ecosystem                                                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Object Storage

### Primary: MinIO

| Attribute | Details |
|-----------|---------|
| **Website** | https://min.io |
| **GitHub** | https://github.com/minio/minio |
| **License** | AGPL-3.0 |
| **Stars** | 49,000+ |

**Strengths:**
- S3-compatible API
- High performance
- Kubernetes native
- Erasure coding
- Encryption built-in

**MxTac Use:**
- PCAP storage
- Report exports
- Long-term archives
- Backup storage

### Alternative 1: SeaweedFS

| Attribute | Details |
|-----------|---------|
| **Website** | https://github.com/seaweedfs/seaweedfs |
| **License** | Apache 2.0 |
| **Stars** | 23,000+ |

**Strengths:**
- Simple, fast
- S3 compatible
- POSIX support
- Good for small files

### Alternative 2: Ceph (RADOS Gateway)

| Attribute | Details |
|-----------|---------|
| **Website** | https://ceph.io |
| **GitHub** | https://github.com/ceph/ceph |
| **License** | LGPL 2.1 |
| **Stars** | 14,000+ |

**Strengths:**
- Enterprise-grade
- Block + Object + File
- Self-healing
- Proven at scale

**Best For:** Large enterprise deployments

### Recommendation

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Object Storage Selection Guide                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  S3-Compatible, Simple           →  MinIO                               │
│  Small Files, High Volume        →  SeaweedFS                           │
│  Enterprise, Unified Storage     →  Ceph                                │
│                                                                         │
│  MxTac Default: MinIO                                                   │
│  - S3 API compatibility                                                 │
│  - Easy to deploy and operate                                           │
│  - Good performance                                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Identity & Access (Bonus)

### Primary: Keycloak

| Attribute | Details |
|-----------|---------|
| **Website** | https://www.keycloak.org |
| **GitHub** | https://github.com/keycloak/keycloak |
| **License** | Apache 2.0 |
| **Stars** | 24,000+ |

**Strengths:**
- Full IAM solution
- OIDC/SAML/OAuth2
- User federation (LDAP/AD)
- Fine-grained authorization
- Admin UI

### Alternative: Authentik

| Attribute | Details |
|-----------|---------|
| **Website** | https://goauthentik.io |
| **GitHub** | https://github.com/goauthentik/authentik |
| **License** | MIT |
| **Stars** | 14,000+ |

**Strengths:**
- Modern, lightweight
- Easy to deploy
- Beautiful UI
- Good for self-hosted

---

## Reference Architectures

### Small Deployment (<5K EPS)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Small Deployment Stack                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  EDR:           Wazuh (all-in-one)                                      │
│  NDR:           Suricata                                                │
│  Event Store:   OpenSearch (single node)                                │
│  TIP:           YETI                                                    │
│  CSPM:          Prowler                                                 │
│  SOAR:          Shuffle                                                 │
│  Queue:         Redis Streams                                           │
│  Cache:         Redis                                                   │
│  Database:      PostgreSQL                                              │
│  Storage:       Local filesystem                                        │
│                                                                         │
│  Resources: 8 vCPU, 32GB RAM, 1TB storage                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Medium Deployment (5K-50K EPS)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Medium Deployment Stack                                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  EDR:           Wazuh + Velociraptor                                    │
│  NDR:           Zeek + Suricata                                         │
│  Event Store:   OpenSearch (3-node cluster)                             │
│  TIP:           OpenCTI + MISP                                          │
│  CSPM:          Prowler + Trivy                                         │
│  SOAR:          Shuffle                                                 │
│  Queue:         Kafka (3 brokers)                                       │
│  Cache:         Redis (Sentinel)                                        │
│  Database:      PostgreSQL (Primary + Replica)                          │
│  Storage:       MinIO                                                   │
│                                                                         │
│  Resources: 32+ vCPU, 128GB+ RAM, 10TB+ storage                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Large Deployment (>50K EPS)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Large Deployment Stack                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  EDR:           Wazuh (clustered) + Velociraptor                        │
│  NDR:           Zeek + Suricata + Arkime                                │
│  Event Store:   OpenSearch (5+ nodes) + ClickHouse (analytics)          │
│  TIP:           OpenCTI + MISP                                          │
│  CSPM:          Prowler + Trivy + Steampipe                             │
│  SOAR:          Shuffle (HA) + StackStorm                               │
│  Queue:         Kafka (5+ brokers, multi-DC)                            │
│  Cache:         Redis Cluster                                           │
│  Database:      PostgreSQL (HA) or CockroachDB                          │
│  Storage:       MinIO (distributed) or Ceph                             │
│  Identity:      Keycloak                                                │
│                                                                         │
│  Resources: Kubernetes cluster, 100+ vCPU, 500GB+ RAM, 100TB+ storage   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference Card

| Category | Primary | Alternative 1 | Alternative 2 | Alternative 3 |
|----------|---------|---------------|---------------|---------------|
| **EDR** | Wazuh | Velociraptor | osquery+Fleet | OSSEC |
| **NDR** | Zeek | Suricata | Arkime | ntopng |
| **Event Store** | OpenSearch | ClickHouse | Quickwit | Loki |
| **TIP** | OpenCTI | MISP | YETI | TheHive |
| **CSPM** | Prowler | Trivy | ScoutSuite | Steampipe |
| **SOAR** | Shuffle | n8n | StackStorm | Airflow |
| **Queue** | Kafka | Redis Streams | Pulsar | NATS |
| **Cache** | Redis | Valkey | KeyDB | Dragonfly |
| **Database** | PostgreSQL | MariaDB | CockroachDB | SQLite |
| **Storage** | MinIO | SeaweedFS | Ceph | - |
| **Identity** | Keycloak | Authentik | - | - |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01 | Initial release |

---

*Document maintained by MxTac Project*
