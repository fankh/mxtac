# MxTac - Build vs Buy Decision Matrix

> **Document Type**: Architecture Decision
> **Version**: 1.0
> **Date**: 2026-01-19
> **Status**: Approved
> **Purpose**: Define which components to build in-house vs use existing OSS

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Decision Framework](#2-decision-framework)
3. [Components to Build (MxTac Core)](#3-components-to-build-mxtac-core)
4. [Components to Use (OSS Integration)](#4-components-to-use-oss-integration)
5. [Hybrid Components](#5-hybrid-components)
6. [Resource Requirements](#6-resource-requirements)
7. [Risk Assessment](#7-risk-assessment)
8. [Implementation Priority](#8-implementation-priority)

---

## 1. Executive Summary

### Strategic Direction

**MxTac follows an "Integration over Invention" philosophy**, building only components that:
1. Provide **unique value proposition** (ATT&CK-native integration)
2. Require **deep customization** (OCSF normalization)
3. Don't have **mature OSS alternatives** (coverage calculator)
4. Are **differentiators** in the market

### Build vs Buy Ratio

| Category | Build | Buy/Use OSS | Hybrid |
|----------|-------|-------------|--------|
| **Core Platform** | 8 components | 0 components | 1 component |
| **Data Layer** | 0 components | 4 components | 0 components |
| **Security Tools** | 2 components | 5 components | 0 components |
| **Infrastructure** | 0 components | 7 components | 0 components |
| **Total** | **10 (40%)** | **16 (65%)** | **1 (4%)** |

**Key Insight**: Build 40% (unique features), leverage 65% (infrastructure/tools)

---

## 2. Decision Framework

### Criteria for Building In-House

| Criterion | Weight | Description |
|-----------|--------|-------------|
| **Strategic Value** | 40% | Core to MxTac's value proposition |
| **Customization Need** | 25% | Requires deep customization |
| **OSS Maturity** | 20% | No mature alternatives available |
| **Integration Complexity** | 10% | Complex integration requirements |
| **Differentiation** | 5% | Market differentiator |

### Scoring Matrix

```
Score = (Strategic × 0.4) + (Customization × 0.25) + (OSS_Gap × 0.2) +
        (Integration × 0.1) + (Differentiation × 0.05)

Score ≥ 7.0 → BUILD
Score 4.0-6.9 → HYBRID (build wrapper, use OSS core)
Score < 4.0 → USE OSS
```

---

## 3. Components to Build (MxTac Core)

### 3.1 OCSF Normalization Engine ✅ BUILD

**Score**: 9.2/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 10/10 | Core differentiator - vendor-agnostic data model |
| Customization | 10/10 | Custom parsers for each data source |
| OSS Maturity | 5/10 | No comprehensive OCSF parser exists |
| Integration | 8/10 | Deep integration with connectors |
| Differentiation | 10/10 | Unique in OSS SIEM space |

**Decision**: ✅ **BUILD**

**Components**:
```python
backend/app/core/ocsf_normalizer/
├── __init__.py
├── base.py                    # Base normalizer class
├── parsers/
│   ├── wazuh_parser.py       # Wazuh JSON → OCSF
│   ├── zeek_parser.py        # Zeek logs → OCSF
│   ├── suricata_parser.py    # Suricata EVE → OCSF
│   ├── prowler_parser.py     # Prowler findings → OCSF
│   └── opencti_parser.py     # OpenCTI STIX → OCSF
├── schemas/
│   ├── ocsf_1_1_0.py         # OCSF 1.1.0 Pydantic models
│   └── validation.py         # Schema validation
├── enrichment/
│   ├── geoip.py              # IP geolocation
│   ├── asset.py              # Asset enrichment
│   └── threat_intel.py       # IOC enrichment
└── transformer.py            # Core transformation logic
```

**Effort**: 6-8 weeks
**Team**: 2 backend engineers

---

### 3.2 Sigma Detection Engine ✅ BUILD

**Score**: 9.5/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 10/10 | Core detection capability |
| Customization | 10/10 | Custom matching for OCSF events |
| OSS Maturity | 8/10 | pySigma exists but needs OCSF backend |
| Integration | 10/10 | Tight integration with pipeline |
| Differentiation | 9/10 | OCSF-native Sigma matching unique |

**Decision**: ✅ **BUILD** (using pySigma library)

**Components**:
```python
backend/app/core/sigma_engine/
├── __init__.py
├── engine.py                  # Main Sigma engine
├── loader.py                  # Rule loader (YAML → pySigma)
├── compiler.py                # Compile rules for OCSF
├── matcher.py                 # Event matching logic
├── indexer.py                 # Rule indexing by OCSF class
├── backends/
│   └── ocsf_backend.py       # Custom pySigma backend for OCSF
├── cache/
│   ├── rule_cache.py         # Redis rule cache
│   └── bloom_filter.py       # Bloom filter for quick pre-check
├── evaluator.py              # Parallel rule evaluation
└── attck_mapper.py           # Map rules to ATT&CK techniques
```

**Effort**: 8-10 weeks
**Team**: 2 backend engineers

**Key Library**: pySigma (for rule parsing, we build OCSF matching)

---

### 3.3 Correlation Engine ✅ BUILD

**Score**: 8.8/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 9/10 | Advanced multi-event detection |
| Customization | 10/10 | Complex custom logic needed |
| OSS Maturity | 3/10 | No mature correlation engines |
| Integration | 9/10 | Tight coupling with event pipeline |
| Differentiation | 9/10 | Attack chain detection unique |

**Decision**: ✅ **BUILD**

**Components**:
```python
backend/app/core/correlation_engine/
├── __init__.py
├── engine.py                  # Main correlation engine
├── rules/
│   ├── sequence.py           # Sequence detection (A→B→C)
│   ├── threshold.py          # Threshold detection (N events in M time)
│   ├── statistical.py        # Statistical anomalies
│   └── chain.py              # Attack chain detection
├── buffers/
│   ├── entity_buffer.py      # Buffer events by entity (IP/user/host)
│   ├── time_window.py        # Sliding time windows
│   └── redis_buffer.py       # Redis-backed buffer
├── state/
│   ├── state_machine.py      # State machine for sequences
│   └── context.py            # Correlation context
└── evaluator.py              # Correlation rule evaluation
```

**Effort**: 8-10 weeks
**Team**: 2 backend engineers

---

### 3.4 Alert Manager ✅ BUILD

**Score**: 8.5/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 9/10 | Alert lifecycle management critical |
| Customization | 9/10 | Custom enrichment & scoring |
| OSS Maturity | 4/10 | Generic alert managers don't fit |
| Integration | 8/10 | Deep integration with platform |
| Differentiation | 8/10 | ATT&CK-based risk scoring unique |

**Decision**: ✅ **BUILD**

**Components**:
```python
backend/app/core/alert_manager/
├── __init__.py
├── manager.py                 # Main alert manager
├── deduplication/
│   ├── hash_dedup.py         # Hash-based deduplication
│   ├── similarity.py         # Similarity-based grouping
│   └── time_window.py        # Time-window dedup
├── enrichment/
│   ├── threat_intel.py       # IOC matching from OpenCTI
│   ├── asset.py              # Asset context
│   ├── user.py               # User context
│   └── geoip.py              # Geographic enrichment
├── scoring/
│   ├── risk_scorer.py        # Risk score calculation
│   ├── attck_scorer.py       # ATT&CK-based scoring
│   └── ml_scorer.py          # ML-based scoring (future)
├── lifecycle/
│   ├── states.py             # Alert states (new, investigating, etc.)
│   ├── assignment.py         # Alert assignment
│   └── sla.py                # SLA tracking
└── notifications/
    ├── webhook.py            # Webhook notifications
    ├── email.py              # Email alerts
    └── slack.py              # Slack integration
```

**Effort**: 6-8 weeks
**Team**: 2 backend engineers

---

### 3.5 Integration Connectors ✅ BUILD

**Score**: 7.8/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 8/10 | Critical for data ingestion |
| Customization | 9/10 | Each source needs custom connector |
| OSS Maturity | 6/10 | Generic connectors exist but need adaptation |
| Integration | 8/10 | Tight coupling with normalizer |
| Differentiation | 5/10 | Connectors are commodity |

**Decision**: ✅ **BUILD** (lightweight glue code)

**Components**:
```python
backend/app/connectors/
├── __init__.py
├── base.py                    # Base connector interface
├── wazuh/
│   ├── connector.py          # Wazuh REST API connector
│   ├── api_client.py         # Wazuh API client
│   └── config.py             # Wazuh configuration
├── zeek/
│   ├── connector.py          # Zeek log file connector
│   ├── log_reader.py         # Zeek JSON log reader
│   └── config.py             # Zeek configuration
├── suricata/
│   ├── connector.py          # Suricata EVE connector
│   ├── eve_reader.py         # EVE JSON reader
│   └── config.py             # Suricata configuration
├── prowler/
│   ├── connector.py          # Prowler findings connector
│   ├── api_client.py         # Prowler API (if available)
│   └── config.py             # Prowler configuration
├── opencti/
│   ├── connector.py          # OpenCTI GraphQL connector
│   ├── graphql_client.py     # GraphQL client
│   └── config.py             # OpenCTI configuration
└── manager.py                # Connector manager
```

**Effort**: 3-4 weeks per connector (parallel development)
**Team**: 2-3 backend engineers

---

### 3.6 ATT&CK Coverage Calculator ✅ BUILD

**Score**: 9.0/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 10/10 | Unique value proposition |
| Customization | 9/10 | Custom ATT&CK mapping logic |
| OSS Maturity | 1/10 | Nothing like this exists |
| Integration | 9/10 | Deep integration with rules |
| Differentiation | 10/10 | Market differentiator |

**Decision**: ✅ **BUILD**

**Components**:
```python
backend/app/core/attck_coverage/
├── __init__.py
├── calculator.py              # Coverage calculation engine
├── mapper.py                  # Map rules to techniques
├── matrix.py                  # ATT&CK matrix representation
├── navigator.py               # Generate Navigator JSON
├── analytics/
│   ├── gap_analysis.py       # Identify coverage gaps
│   ├── quality.py            # Detection quality metrics
│   └── trends.py             # Coverage trends over time
├── data/
│   ├── attck_loader.py       # Load ATT&CK STIX data
│   ├── technique_db.py       # Technique database
│   └── update.py             # Update ATT&CK data
└── reports/
    ├── coverage_report.py    # Coverage reports
    └── export.py             # Export formats (JSON, CSV, PDF)
```

**Effort**: 4-6 weeks
**Team**: 1-2 backend engineers

---

### 3.7 MxTac Web UI ✅ BUILD

**Score**: 9.2/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 10/10 | User experience is critical |
| Customization | 10/10 | Custom workflow for security analysts |
| OSS Maturity | 5/10 | Generic dashboards don't fit |
| Integration | 9/10 | Tight integration with backend |
| Differentiation | 9/10 | ATT&CK-native UI unique |

**Decision**: ✅ **BUILD**

**Components**:
```typescript
frontend/src/
├── pages/
│   ├── Dashboard.tsx          // ATT&CK coverage dashboard
│   ├── Alerts.tsx             // Alert management
│   ├── Hunting.tsx            // Threat hunting interface
│   ├── Rules.tsx              // Sigma rule management
│   ├── Coverage.tsx           // ATT&CK coverage visualization
│   ├── Events.tsx             // Event search
│   ├── Response.tsx           // Response actions
│   └── Settings.tsx           // Configuration
├── components/
│   ├── attck/
│   │   ├── Navigator.tsx     // ATT&CK Navigator integration
│   │   ├── TechniqueCard.tsx // Technique details
│   │   └── Matrix.tsx        // ATT&CK matrix view
│   ├── alerts/
│   │   ├── AlertList.tsx     // Alert table
│   │   ├── AlertDetail.tsx   // Alert details
│   │   └── AlertTimeline.tsx // Alert timeline
│   ├── rules/
│   │   ├── RuleEditor.tsx    // Sigma rule editor
│   │   ├── RuleList.tsx      // Rule library
│   │   └── RuleTest.tsx      // Rule testing
│   └── hunting/
│       ├── QueryBuilder.tsx  // Query builder
│       └── ResultsView.tsx   // Search results
├── services/
│   ├── api.ts                // API client
│   ├── alertService.ts       // Alert API
│   ├── ruleService.ts        // Rule API
│   └── coverageService.ts    // Coverage API
└── stores/
    ├── authStore.ts          // Authentication state
    ├── alertStore.ts         // Alert state
    └── settingsStore.ts      // Settings state
```

**Effort**: 12-16 weeks
**Team**: 2-3 frontend engineers

---

### 3.8 API Gateway ✅ BUILD

**Score**: 8.0/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 8/10 | Critical for security & routing |
| Customization | 8/10 | Custom auth & RBAC logic |
| OSS Maturity | 7/10 | Kong/Tyk exist but need customization |
| Integration | 9/10 | Deep integration with backend |
| Differentiation | 5/10 | API gateways are commodity |

**Decision**: ✅ **BUILD** (using FastAPI middleware)

**Components**:
```python
backend/app/api/
├── __init__.py
├── gateway.py                 # Main API gateway
├── middleware/
│   ├── auth.py               # JWT authentication
│   ├── rbac.py               # Role-based access control
│   ├── rate_limit.py         # Rate limiting
│   ├── cors.py               # CORS handling
│   ├── logging.py            # Request logging
│   └── error.py              # Error handling
├── v1/
│   ├── alerts.py             # Alert endpoints
│   ├── events.py             # Event search endpoints
│   ├── rules.py              # Rule management
│   ├── coverage.py           # Coverage endpoints
│   ├── connectors.py         # Connector management
│   ├── response.py           # Response actions
│   ├── users.py              # User management
│   └── auth.py               # Authentication endpoints
├── deps.py                    # Dependency injection
└── router.py                  # Route registration
```

**Effort**: 4-6 weeks
**Team**: 1-2 backend engineers

---

### 3.9 MxGuard - Lightweight EDR ✅ BUILD

**Score**: 8.5/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 9/10 | Native OCSF output is valuable |
| Customization | 9/10 | Tailored for MxTac integration |
| OSS Maturity | 8/10 | Wazuh exists but heavyweight |
| Integration | 10/10 | Native OCSF, no normalization |
| Differentiation | 7/10 | Lightweight alternative |

**Decision**: ✅ **BUILD** (See 16-LIGHTWEIGHT-EDR-NDR-DESIGN.md)

**Components**:
```go
mxguard/
├── main.go
├── collectors/
│   ├── file_monitor.go       // File integrity monitoring
│   ├── process_monitor.go    // Process monitoring
│   ├── network_monitor.go    // Network connections
│   └── log_reader.go         // Log parsing
├── ocsf/
│   ├── builder.go            // OCSF event builder
│   ├── file_activity.go      // File events
│   ├── process_activity.go   // Process events
│   └── network_activity.go   // Network events
└── output/
    ├── http.go               // HTTP output to MxTac
    └── file.go               // File output
```

**Effort**: 8-10 weeks
**Team**: 1-2 backend engineers (Go)

---

### 3.10 MxWatch - Lightweight NDR ✅ BUILD

**Score**: 8.2/10

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 8/10 | Native OCSF network monitoring |
| Customization | 9/10 | Tailored for MxTac integration |
| OSS Maturity | 8/10 | Zeek/Suricata exist but heavyweight |
| Integration | 10/10 | Native OCSF, no normalization |
| Differentiation | 7/10 | Lightweight alternative |

**Decision**: ✅ **BUILD** (See 16-LIGHTWEIGHT-EDR-NDR-DESIGN.md)

**Components**:
```go
mxwatch/
├── main.go
├── capture/
│   ├── pcap.go               // Packet capture
│   └── reassembly.go         // TCP reassembly
├── parsers/
│   ├── http.go               // HTTP parser
│   ├── dns.go                // DNS parser
│   └── tls.go                // TLS inspector
├── detectors/
│   ├── c2_beacon.go          // C2 beacon detection
│   ├── port_scan.go          // Port scan detection
│   └── exfiltration.go       // Exfiltration detection
└── ocsf/
    ├── network_activity.go   // Network events
    └── http_activity.go      // HTTP events
```

**Effort**: 8-10 weeks
**Team**: 1-2 backend engineers (Go)

---

## 4. Components to Use (OSS Integration)

### 4.1 Event Store: OpenSearch ❌ USE OSS

**Score**: 2.5/10 (Use OSS)

| Metric | Score | Justification |
|--------|-------|---------------|
| Strategic Value | 2/10 | Commodity data store |
| Customization | 1/10 | Minimal customization needed |
| OSS Maturity | 10/10 | Production-grade, battle-tested |
| Integration | 3/10 | Standard Python client |
| Differentiation | 0/10 | Not a differentiator |

**Decision**: ❌ **USE OSS** - OpenSearch 2.x

**Why**:
- Production-grade search & analytics
- Horizontal scalability
- Time-series optimized
- Rich query DSL
- Active community

**Integration**:
```python
# Use official OpenSearch Python client
from opensearchpy import OpenSearch

client = OpenSearch([
    {'host': 'localhost', 'port': 9200}
])
```

**Effort**: 0 weeks (use as-is)

---

### 4.2 Metadata Database: PostgreSQL ❌ USE OSS

**Score**: 1.5/10 (Use OSS)

**Decision**: ❌ **USE OSS** - PostgreSQL 16

**Why**:
- Rock-solid reliability
- ACID compliance
- Rich feature set (JSONB, arrays, etc.)
- Excellent Python support (asyncpg)

**Integration**:
```python
# Use SQLAlchemy 2.0 with asyncpg
from sqlalchemy.ext.asyncio import create_async_engine

engine = create_async_engine(
    "postgresql+asyncpg://user:pass@localhost/mxtac"
)
```

**Effort**: 0 weeks (use as-is)

---

### 4.3 Cache & Pub/Sub: Redis ❌ USE OSS

**Score**: 1.8/10 (Use OSS)

**Decision**: ❌ **USE OSS** - Redis 7.x

**Why**:
- Fast in-memory operations
- Rich data structures
- Pub/sub support
- Excellent Python client (redis-py)

**Integration**:
```python
from redis.asyncio import Redis

redis = await Redis.from_url("redis://localhost")
```

**Effort**: 0 weeks (use as-is)

---

### 4.4 Message Queue: Kafka or Redis Streams ❌ USE OSS

**Score**: 2.2/10 (Use OSS)

**Decision**: ❌ **USE OSS**
- **MVP**: Redis Streams (simpler)
- **Production**: Apache Kafka 3.6+ (scale)

**Why**:
- Proven event streaming
- Durability & ordering guarantees
- Horizontal scalability

**Integration**:
```python
# Redis Streams (MVP)
from redis.asyncio import Redis
await redis.xadd("mxtac:raw", {"data": event})

# Kafka (Production)
from aiokafka import AIOKafkaProducer
await producer.send("mxtac.raw.wazuh", event)
```

**Effort**: 0 weeks (use as-is)

---

### 4.5 Full EDR: Wazuh ❌ USE OSS

**Score**: 3.0/10 (Use OSS)

**Decision**: ❌ **USE OSS** - Wazuh 4.7+ (alongside MxGuard)

**Why**:
- Comprehensive endpoint monitoring
- 60-70% ATT&CK coverage
- Active community
- Free & open source

**Use Case**: Deploy Wazuh for **comprehensive** coverage, MxGuard for **lightweight** deployments

**Integration**: Via connector (already in scope)

**Effort**: 0 weeks (integration already planned)

---

### 4.6 Network Detection: Zeek + Suricata ❌ USE OSS

**Score**: 2.8/10 (Use OSS)

**Decision**: ❌ **USE OSS**
- **Zeek 6.x**: Deep packet inspection
- **Suricata 7.x**: IDS/IPS with Sigma-like rules

**Why**:
- Battle-tested network security monitoring
- Rich protocol support
- Active communities

**Use Case**: Deploy Zeek/Suricata for **comprehensive** NDR, MxWatch for **lightweight** deployments

**Integration**: Via connectors (already in scope)

**Effort**: 0 weeks (integration already planned)

---

### 4.7 Threat Intelligence: OpenCTI ❌ USE OSS

**Score**: 2.5/10 (Use OSS)

**Decision**: ❌ **USE OSS** - OpenCTI 6.x

**Why**:
- Comprehensive CTI platform
- STIX/TAXII native
- GraphQL API
- MITRE ATT&CK integration

**Integration**:
```python
from pycti import OpenCTIApiClient

opencti = OpenCTIApiClient(
    url="https://opencti.example.com",
    token="..."
)
```

**Effort**: 0 weeks (use via connector)

---

### 4.8 Container Runtime: Docker ❌ USE OSS

**Score**: 1.0/10 (Use OSS)

**Decision**: ❌ **USE OSS**
- **Development**: Docker 24+
- **Production**: Kubernetes 1.29+

**Effort**: 0 weeks

---

### 4.9 Web Server: Nginx ❌ USE OSS

**Score**: 1.5/10 (Use OSS)

**Decision**: ❌ **USE OSS** - Nginx 1.25+

**Why**: Industry standard reverse proxy

**Effort**: 0 weeks

---

### 4.10 Monitoring: Prometheus + Grafana ❌ USE OSS

**Score**: 2.0/10 (Use OSS)

**Decision**: ❌ **USE OSS**
- **Prometheus 2.x**: Metrics
- **Grafana 10.x**: Visualization

**Effort**: 0 weeks

---

## 5. Hybrid Components

### 5.1 Sigma Rules: SigmaHQ + Custom ⚡ HYBRID

**Decision**: ⚡ **HYBRID**
- **Use**: SigmaHQ community rules (~3,000 rules)
- **Build**: Custom rules for specific environment

**Ratio**: 80% community, 20% custom

**Effort**:
- 0 weeks (community rules)
- Ongoing (custom rule development)

---

## 6. Resource Requirements

### 6.1 Development Team

| Component | Engineers | Duration | Total Person-Weeks |
|-----------|-----------|----------|-------------------|
| OCSF Normalizer | 2 | 8 weeks | 16 pw |
| Sigma Engine | 2 | 10 weeks | 20 pw |
| Correlation Engine | 2 | 10 weeks | 20 pw |
| Alert Manager | 2 | 8 weeks | 16 pw |
| Connectors (5x) | 3 | 4 weeks | 12 pw |
| Coverage Calculator | 2 | 6 weeks | 12 pw |
| Web UI | 3 | 16 weeks | 48 pw |
| API Gateway | 2 | 6 weeks | 12 pw |
| MxGuard EDR | 2 | 10 weeks | 20 pw |
| MxWatch NDR | 2 | 10 weeks | 20 pw |
| **Total** | **6-8 engineers** | **88 weeks** | **196 pw** |

**Parallel Development**: With 6 engineers, ~33 weeks (8 months)

### 6.2 Infrastructure Costs (Annual)

| Component | Type | Cost |
|-----------|------|------|
| OpenSearch cluster (3 nodes) | Self-hosted | $0 (OSS) |
| PostgreSQL (HA) | Self-hosted | $0 (OSS) |
| Redis cluster | Self-hosted | $0 (OSS) |
| Kafka cluster | Self-hosted | $0 (OSS) |
| Wazuh manager | Self-hosted | $0 (OSS) |
| Zeek/Suricata | Self-hosted | $0 (OSS) |
| OpenCTI | Self-hosted | $0 (OSS) |
| **Infrastructure (cloud)** | AWS/GCP | **$5K-15K/yr** |
| **Total OSS Tools** | - | **$0** |

---

## 7. Risk Assessment

### 7.1 Build Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **OCSF schema changes** | Medium | High | Version schema, automated tests |
| **pySigma compatibility** | Low | Medium | Pin versions, maintain fork |
| **Performance at scale** | Medium | High | Load testing, optimization |
| **Feature creep** | High | Medium | Strict scope, MVP focus |
| **Resource constraints** | Medium | High | Prioritization, phased approach |

### 7.2 OSS Dependency Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **OpenSearch licensing** | Low | High | Apache 2.0 stable |
| **Wazuh breaking changes** | Low | Medium | Pin versions, test updates |
| **Community abandonment** | Very Low | High | Choose mature projects only |
| **Security vulnerabilities** | Medium | High | Automated scanning, updates |

---

## 8. Implementation Priority

### Phase 1: MVP Foundation (Weeks 1-12)

| Priority | Component | Engineers | Duration |
|----------|-----------|-----------|----------|
| **P0** | OCSF Normalizer (Wazuh only) | 2 | 6 weeks |
| **P0** | Wazuh Connector | 1 | 3 weeks |
| **P0** | Sigma Engine (core) | 2 | 8 weeks |
| **P0** | Alert Manager (basic) | 2 | 6 weeks |
| **P0** | API Gateway | 2 | 4 weeks |
| **P0** | Web UI (dashboard, alerts) | 3 | 12 weeks |

**Deliverable**: Working prototype with Wazuh integration

### Phase 2: Enhanced Detection (Weeks 13-24)

| Priority | Component | Engineers | Duration |
|----------|-----------|-----------|----------|
| **P1** | Correlation Engine | 2 | 10 weeks |
| **P1** | Coverage Calculator | 2 | 6 weeks |
| **P1** | Additional Connectors (Zeek, Suricata) | 2 | 6 weeks |
| **P1** | Web UI (rules, coverage, hunting) | 2 | 12 weeks |

**Deliverable**: Full detection platform with multi-source integration

### Phase 3: Lightweight Agents (Weeks 25-36)

| Priority | Component | Engineers | Duration |
|----------|-----------|-----------|----------|
| **P2** | MxGuard EDR | 2 | 10 weeks |
| **P2** | MxWatch NDR | 2 | 10 weeks |
| **P2** | Agent Management UI | 1 | 4 weeks |

**Deliverable**: Complete platform with native agents

---

## Appendix: Decision Log

### A. Why Build OCSF Normalizer?

**Alternatives Considered**:
1. ❌ Use vendor-specific formats (Wazuh JSON, Zeek logs)
   - Rejected: Vendor lock-in, complex correlation
2. ❌ Use Elastic Common Schema (ECS)
   - Rejected: Not industry standard, Elastic-specific
3. ✅ Build OCSF normalizer
   - Selected: Vendor-agnostic, future-proof, industry standard

### B. Why Build Sigma Engine?

**Alternatives Considered**:
1. ❌ Use Elasticsearch queries
   - Rejected: OpenSearch-specific, no portability
2. ❌ Use custom query language
   - Rejected: Reinventing the wheel, no community
3. ✅ Build Sigma engine with pySigma
   - Selected: Industry standard, community rules, portable

### C. Why NOT Build Search Engine?

**Alternatives Considered**:
1. ❌ Build custom search engine
   - Rejected: Massive effort, reinventing wheel
2. ❌ Use commercial SIEM
   - Rejected: Expensive, vendor lock-in
3. ✅ Use OpenSearch
   - Selected: Production-grade, open source, scalable

---

*Document Status: Approved - Ready for Development*
*Decision Authority: Technical Architecture Board*
*Review Date: 2026-01-19*
