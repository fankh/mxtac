# MxTac - Technical Architecture

> **Document Type**: Technical Architecture  
> **Version**: 1.0  
> **Date**: January 2026  
> **Status**: Draft  
> **Project**: MxTac (Matrix + Tactic)

---

## Architecture Overview

### Design Principles

| Principle | Description |
|-----------|-------------|
| **Integration over Invention** | Leverage existing OSS tools, don't rebuild |
| **ATT&CK-Native** | Every component maps to ATT&CK |
| **Open Standards** | OCSF for data, Sigma for detection, STIX for intel |
| **Microservices** | Loosely coupled, independently deployable |
| **Scalability First** | Horizontal scaling from day one |
| **Security by Design** | Zero trust, encryption everywhere |

### System Context

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Users["Users"]
        ANALYST["SOC Analyst"]
        HUNTER["Threat Hunter"]
        ENGINEER["Detection Engineer"]
        ADMIN["Administrator"]
    end
    
    subgraph OAP["MxTac Platform"]
        UI["Web UI"]
        API["API Gateway"]
        CORE["Core Services"]
        DATA["Data Layer"]
    end
    
    subgraph Sources["Data Sources"]
        WAZUH["Wazuh"]
        ZEEK["Zeek"]
        SURI["Suricata"]
        PROW["Prowler"]
        OCTI["OpenCTI"]
    end
    
    subgraph Targets["Response Targets"]
        FW["Firewalls"]
        EDR_T["EDR Agents"]
        CLOUD_T["Cloud APIs"]
    end
    
    Users --> UI
    UI --> API
    API --> CORE
    CORE --> DATA
    Sources --> CORE
    CORE --> Targets
    
    style OAP fill:#e8f5e9,stroke:#2e7d32
    style Sources fill:#e3f2fd,stroke:#1565c0
    style Targets fill:#fff3e0,stroke:#ef6c00
```

---

## Component Architecture

### Layer 1: Presentation Layer

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Presentation["Presentation Layer"]
        style Presentation fill:#e3f2fd,stroke:#1565c0
        subgraph WebApp["Web Application - React"]
            style WebApp fill:#e8f5e9,stroke:#2e7d32
            DASH[Dashboard Module]
            ALERTS[Alerts Module]
            HUNT[Hunting Module]
            CONFIG[Config Module]
        end
        subgraph WebApp2["Web Application - React (cont.)"]
            style WebApp2 fill:#e8f5e9,stroke:#2e7d32
            ATTCK[ATT&CK Navigator]
            REPORTS[Reports Module]
            RESP[Response Module]
            ADMIN[Admin Module]
        end
    end
```

**Technology:** React 18+, TypeScript, TailwindCSS, Recharts  
**State Management:** Zustand or Redux Toolkit  
**API Client:** React Query + Axios

### Layer 2: API Gateway

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Gateway["API Gateway - Kong/Traefik"]
        style Gateway fill:#e8f5e9,stroke:#2e7d32
        AUTH[Auth & AuthZ<br/>JWT/OIDC]
        RATE[Rate Limiting]
        ROUTE[Request Routing]
    end
    
    subgraph Gateway2["API Gateway Features"]
        style Gateway2 fill:#e8f5e9,stroke:#2e7d32
        AUDIT[Audit Logging]
        CIRCUIT[Circuit Breaker]
        SSL[SSL Termination]
    end
```

**Endpoints:**
| Endpoint | Purpose |
|----------|---------|
| `/api/v1/alerts` | Alert management |
| `/api/v1/events` | Event search |
| `/api/v1/rules` | Sigma rule management |
| `/api/v1/coverage` | ATT&CK coverage |
| `/api/v1/connectors` | Integration management |
| `/api/v1/response` | Response actions |

### Layer 3: Core Services

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph CoreServices["Core Services"]
        style CoreServices fill:#fff3e0,stroke:#ef6c00
        subgraph Row1["Detection Services"]
            style Row1 fill:#e3f2fd,stroke:#1565c0
            SIGMA[Sigma Engine<br/>Parser, Matcher, Alert]
            CORR[Correlation Engine<br/>Buffer, Rules, Chain]
        end
        subgraph Row2["Management Services"]
            style Row2 fill:#e8f5e9,stroke:#2e7d32
            ALERT[Alert Manager<br/>Dedup, Enrich, Score]
            ATTCK[ATT&CK Mapper<br/>Map, Coverage, Gaps]
        end
    end
```

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph CoreServices2["Core Services (cont.)"]
        style CoreServices2 fill:#fff3e0,stroke:#ef6c00
        subgraph Row3["Query Services"]
            style Row3 fill:#f3e5f5,stroke:#7b1fa2
            SEARCH[Search Service<br/>Query, Aggregations]
            ENRICH[Enrichment Service<br/>TI, GeoIP, Asset]
        end
        subgraph Row4["Action Services"]
            style Row4 fill:#e0f2f1,stroke:#00796b
            RESP[Response Service<br/>Execute, Playbook, Audit]
            REPORT[Report Service<br/>Builder, Scheduler, Export]
        end
    end
```

**Technology:** Python 3.11+, FastAPI, asyncio  
**Communication:** gRPC (internal), REST (external)

### Layer 4: Data Processing

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph DataProcessing["Data Processing Layer"]
        style DataProcessing fill:#fff3e0,stroke:#ef6c00
        
        subgraph Normalization["OCSF Normalization Engine"]
            style Normalization fill:#e3f2fd,stroke:#1565c0
            
            subgraph Parsers["Input Parsers"]
                style Parsers fill:#e8f5e9,stroke:#2e7d32
                P1[Wazuh Parser]
                P2[Zeek Parser]
                P3[Suricata Parser]
            end
            
            subgraph Parsers2["Input Parsers (cont.)"]
                style Parsers2 fill:#e8f5e9,stroke:#2e7d32
                P4[Prowler Parser]
                P5[Generic Parser]
            end
            
            TRANS["OCSF Transformer<br/>Field Mapping | Type Coercion<br/>Validation | Enrichment"]
            OCSF["OCSF Events<br/>(Normalized)"]
        end
        
        subgraph MQ["Message Queue - Kafka"]
            style MQ fill:#f3e5f5,stroke:#7b1fa2
            T1["oap.raw.wazuh"]
            T2["oap.raw.zeek"]
            T3["oap.raw.suricata"]
            T4["oap.normalized"]
            T5["oap.alerts"]
            T6["oap.enriched"]
        end
    end
    
    P1 --> TRANS
    P2 --> TRANS
    P3 --> TRANS
    P4 --> TRANS
    P5 --> TRANS
    TRANS --> OCSF
```

**Technology:** Kafka (or Redis Streams for smaller deployments)

### Layer 5: Data Storage

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Storage["Data Storage Layer"]
        style Storage fill:#fff3e0,stroke:#ef6c00
        
        subgraph Row1["Primary Stores"]
            style Row1 fill:#e3f2fd,stroke:#1565c0
            
            subgraph OS["OpenSearch (Event Store)"]
                style OS fill:#e8f5e9,stroke:#2e7d32
                OS1["Indices:<br/>- oap-events-YYYY.MM.DD<br/>- oap-alerts-YYYY.MM.DD<br/>- oap-investigations"]
                OS2["Retention: Configurable<br/>(90 days events, 365 days alerts)"]
            end
            
            subgraph PG["PostgreSQL (Metadata DB)"]
                style PG fill:#f3e5f5,stroke:#7b1fa2
                PG1["Tables:<br/>- users, roles<br/>- rules, connectors<br/>- investigations"]
                PG2["Tables (cont.):<br/>- playbooks, settings<br/>- audit_logs"]
            end
        end
        
        subgraph Row2["Support Stores"]
            style Row2 fill:#e0f2f1,stroke:#00796b
            
            subgraph RD["Redis (Cache)"]
                style RD fill:#fce4ec,stroke:#c2185b
                RD1["Use Cases:<br/>- Session cache<br/>- Rate limiting<br/>- Real-time metrics<br/>- Pub/sub (alerts)"]
            end
            
            subgraph S3["Object Storage (MinIO/S3)"]
                style S3 fill:#fff8e1,stroke:#f57f17
                S31["Use Cases:<br/>- Report exports<br/>- PCAP storage<br/>- Long-term archives<br/>- Backup storage"]
            end
        end
    end
```

### Layer 6: Integration Connectors

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Connectors["Integration Connectors"]
        style Connectors fill:#fff3e0,stroke:#ef6c00
        
        subgraph Inbound1["Data Source Connectors (Inbound) - Row 1"]
            style Inbound1 fill:#e3f2fd,stroke:#1565c0
            WAZ["Wazuh Connector<br/>- API Pull<br/>- Filebeat<br/>- Webhook"]
            ZEK["Zeek Connector<br/>- File Watch<br/>- Kafka<br/>- Redis"]
            SUR["Suricata Connector<br/>- File Watch<br/>- Kafka<br/>- Redis"]
        end
        
        subgraph Inbound2["Data Source Connectors (Inbound) - Row 2"]
            style Inbound2 fill:#e8f5e9,stroke:#2e7d32
            PRW["Prowler Connector<br/>- API Pull<br/>- Scheduled"]
            CTI["OpenCTI Connector<br/>- GraphQL<br/>- STIX/TAXII"]
            MISP["MISP Connector<br/>- REST API<br/>- PyMISP"]
        end
    end
```

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Connectors2["Integration Connectors (cont.)"]
        style Connectors2 fill:#fff3e0,stroke:#ef6c00
        
        subgraph Inbound3["Data Source Connectors - Row 3"]
            style Inbound3 fill:#f3e5f5,stroke:#7b1fa2
            VEL["Velociraptor Connector<br/>- gRPC<br/>- Websocket"]
            OSQ["osquery Connector<br/>- TLS API"]
        end
        
        subgraph Outbound["Response Connectors (Outbound)"]
            style Outbound fill:#e0f2f1,stroke:#00796b
            WRESP["Wazuh Response<br/>- Isolate<br/>- Kill proc<br/>- Restart"]
            FWRESP["Firewall Response<br/>- Block IP<br/>- Block Port<br/>- Allowlist"]
            CLDRESP["Cloud Response<br/>- Disable<br/>- Revoke<br/>- Quarantine"]
        end
    end
```

**Connector Interface (Abstract):**

```python
class Connector(ABC):
    @abstractmethod
    async def connect(self) -> bool
    @abstractmethod
    async def pull_events(self) -> List[RawEvent]
    @abstractmethod
    async def push_action(self, action: Action) -> Result
    @abstractmethod
    def get_ocsf_mapping(self) -> OCSFMapping
```

---

## Sigma Engine Architecture

### Engine Design

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph SigmaEngine["Sigma Engine"]
        style SigmaEngine fill:#fff3e0,stroke:#ef6c00
        
        subgraph Repo["Rule Repository"]
            style Repo fill:#e3f2fd,stroke:#1565c0
            SHQ["SigmaHQ<br/>(Git Sync)"]
            CUST["Custom<br/>Rules"]
            IMP["Imported<br/>Rules"]
        end
        
        subgraph Compiler["Rule Compiler"]
            style Compiler fill:#e8f5e9,stroke:#2e7d32
            C1["1. Parse YAML"]
            C2["2. Validate structure"]
            C3["3. Compile detection logic"]
            C4["4. Map to OCSF fields"]
            C5["5. Generate optimized matcher"]
            C6["6. Cache compiled rule"]
        end
        
        Repo --> Compiler
    end
```

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph SigmaEngine2["Sigma Engine (cont.)"]
        style SigmaEngine2 fill:#fff3e0,stroke:#ef6c00
        
        subgraph Index["Rule Index"]
            style Index fill:#f3e5f5,stroke:#7b1fa2
            IDX1["Indexed by:<br/>- logsource.category<br/>- logsource.product"]
            IDX2["Indexed by:<br/>- ATT&CK technique<br/>- Severity level"]
        end
        
        subgraph Pipeline["Detection Pipeline"]
            style Pipeline fill:#e0f2f1,stroke:#00796b
            EVT["OCSF Event"]
            ROUTE["Route<br/>(by class)"]
            MATCH["Match<br/>(parallel)"]
            GEN["Generate<br/>Alert"]
            
            EVT --> ROUTE --> MATCH --> GEN
        end
        
        Index --> Pipeline
    end
```

**Optimization Strategies:**
- Rules grouped by logsource for O(1) routing
- Parallel evaluation within groups
- Short-circuit on first match (configurable)
- Bloom filter pre-check for keyword rules

### Sigma to OCSF Field Mapping

```yaml
# Logsource to OCSF Class Mapping
logsource_mappings:
  
  process_creation:
    windows:
      ocsf_class_uid: 1007  # Process Activity
      field_map:
        Image: process.file.path
        CommandLine: process.cmd_line
        User: actor.user.name
        ParentImage: parent_process.file.path
        ParentCommandLine: parent_process.cmd_line
        Hashes: process.file.hashes
        ProcessId: process.pid
        ParentProcessId: parent_process.pid
        CurrentDirectory: process.cwd
        IntegrityLevel: process.integrity
        
    linux:
      ocsf_class_uid: 1007
      field_map:
        Image: process.file.path
        CommandLine: process.cmd_line
        User: actor.user.name
        ParentImage: parent_process.file.path
        
  network_connection:
    any:
      ocsf_class_uid: 4001  # Network Activity
      field_map:
        SourceIp: src_endpoint.ip
        SourcePort: src_endpoint.port
        DestinationIp: dst_endpoint.ip
        DestinationPort: dst_endpoint.port
        Protocol: connection_info.protocol_name
        
  file_event:
    windows:
      ocsf_class_uid: 1001  # File Activity
      field_map:
        TargetFilename: file.path
        Image: actor.process.file.path
        User: actor.user.name
```

---

## Correlation Engine Architecture

### Attack Chain Detection

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph CorrEngine["Correlation Engine"]
        style CorrEngine fill:#fff3e0,stroke:#ef6c00
        
        subgraph Buffer["Event Buffer (Redis)"]
            style Buffer fill:#e3f2fd,stroke:#1565c0
            KEY1["Key Structure:<br/>entity:{type}:{value}:events<br/>→ Sorted Set (by timestamp)"]
            KEY2["Examples:<br/>- entity:ip:192.168.1.50:events<br/>- entity:host:web-server-01:events<br/>- entity:user:admin:events"]
            TTL["TTL: Configurable<br/>(default 24 hours)"]
        end
        
        subgraph RuleEngine["Correlation Rule Engine"]
            style RuleEngine fill:#e8f5e9,stroke:#2e7d32
            RT1["1. Sequence Detection<br/>(A then B then C)"]
            RT2["2. Threshold Detection<br/>(N events in time window)"]
            RT3["3. Statistical Anomaly<br/>(deviation from baseline)"]
        end
        
        Buffer --> RuleEngine
    end
```

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph ChainDetector["ATT&CK Chain Detector"]
        style ChainDetector fill:#fff3e0,stroke:#ef6c00
        
        subgraph Patterns["Pre-defined Attack Patterns"]
            style Patterns fill:#f3e5f5,stroke:#7b1fa2
            
            RANSOM["Ransomware Pattern<br/>T1566 → T1204 → T1059 → T1486<br/>(Phishing → User Exec → Script → Encrypt)"]
            
            APT["APT Lateral Movement<br/>T1078 → T1003 → T1021 → T1071<br/>(Valid Acct → Cred Dump → Remote Svc → C2)"]
            
            EXFIL["Data Exfiltration<br/>T1083 → T1560 → T1048<br/>(File Discovery → Archive → Exfil Alt Protocol)"]
        end
    end
```

**Correlation Rule Examples:**

| Rule Type | Example | Parameters |
|-----------|---------|------------|
| Sequence | Initial Access to C2 | T1190 → T1059 → T1071 within 1h |
| Threshold | Brute Force Detection | 10+ auth failures in 5m by IP/user |
| Statistical | Unusual Outbound Data | bytes_out > 3x stddev from 7d baseline |

---

## Deployment Architecture

### Docker Compose (Development/Small)

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Frontend
  ui:
    image: oap/ui:latest
    ports:
      - "443:443"
    depends_on:
      - api
      
  # API Gateway
  api:
    image: oap/api:latest
    ports:
      - "8080:8080"
    depends_on:
      - sigma-engine
      - correlation-engine
      - opensearch
      
  # Core Services
  sigma-engine:
    image: oap/sigma-engine:latest
    depends_on:
      - kafka
      - redis
      
  correlation-engine:
    image: oap/correlation-engine:latest
    depends_on:
      - kafka
      - redis
      
  normalizer:
    image: oap/normalizer:latest
    depends_on:
      - kafka
      
  # Data Processing
  kafka:
    image: bitnami/kafka:latest
    ports:
      - "9092:9092"
      
  # Data Storage
  opensearch:
    image: opensearchproject/opensearch:2
    ports:
      - "9200:9200"
    volumes:
      - opensearch-data:/usr/share/opensearch/data
      
  postgres:
    image: postgres:15
    volumes:
      - postgres-data:/var/lib/postgresql/data
      
  redis:
    image: redis:7
    
volumes:
  opensearch-data:
  postgres-data:
```

### Kubernetes (Production)

```yaml
# Simplified Kubernetes architecture
apiVersion: v1
kind: Namespace
metadata:
  name: open-attck-platform
---
# StatefulSets for stateful components
# - OpenSearch cluster (3 nodes)
# - Kafka cluster (3 brokers)
# - PostgreSQL (primary + replica)
# - Redis (sentinel mode)

# Deployments for stateless components
# - API Gateway (3 replicas, HPA)
# - Sigma Engine (5 replicas, HPA)
# - Correlation Engine (3 replicas)
# - Normalizer (5 replicas, HPA)
# - UI (3 replicas)

# Services
# - LoadBalancer for UI
# - ClusterIP for internal services
# - Headless for StatefulSets

# ConfigMaps & Secrets
# - Application configuration
# - TLS certificates
# - Database credentials
# - API keys
```

---

## Security Architecture

### Authentication & Authorization

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Security["Security Architecture"]
        style Security fill:#fff3e0,stroke:#ef6c00
        
        subgraph Auth["Authentication"]
            style Auth fill:#e3f2fd,stroke:#1565c0
            LOCAL["Local<br/>(bcrypt)"]
            OIDC["OIDC<br/>(Keycloak)"]
            SAML["SAML<br/>(Okta)"]
            JWT["JWT Issuer<br/>(RS256 signed)"]
            
            LOCAL --> JWT
            OIDC --> JWT
            SAML --> JWT
        end
        
        subgraph RBAC["Authorization (RBAC)"]
            style RBAC fill:#e8f5e9,stroke:#2e7d32
            R1["Viewer: Read alerts, events, dashboards"]
            R2["Analyst: + Manage alerts, investigations"]
            R3["Hunter: + Run queries, create rules"]
        end
    end
```

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Security2["Security Architecture (cont.)"]
        style Security2 fill:#fff3e0,stroke:#ef6c00
        
        subgraph RBAC2["Authorization (RBAC) - cont."]
            style RBAC2 fill:#e8f5e9,stroke:#2e7d32
            R4["Engineer: + Manage rules, connectors"]
            R5["Admin: + Manage users, settings, all"]
        end
        
        subgraph DataProt["Data Protection"]
            style DataProt fill:#f3e5f5,stroke:#7b1fa2
            ENC1["Encryption at rest:<br/>AES-256 (OpenSearch, PostgreSQL)"]
            ENC2["Encryption in transit:<br/>TLS 1.3 (all connections)"]
            SEC1["Secret management:<br/>HashiCorp Vault or K8s Secrets"]
            AUD["Audit logging:<br/>All admin actions to immutable store"]
        end
    end
```

---

## API Specification

### Core Endpoints

```yaml
openapi: 3.0.0
info:
  title: Open ATT&CK Platform API
  version: 1.0.0

paths:
  # Alerts
  /api/v1/alerts:
    get:
      summary: List alerts
      parameters:
        - name: severity
        - name: status
        - name: technique
        - name: time_range
    post:
      summary: Create manual alert
      
  /api/v1/alerts/{id}:
    get:
      summary: Get alert details
    patch:
      summary: Update alert (status, assignment)
      
  # Events
  /api/v1/events/search:
    post:
      summary: Search events
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                query: string
                time_range: object
                filters: array
                
  # Rules
  /api/v1/rules:
    get:
      summary: List Sigma rules
    post:
      summary: Create new rule
      
  /api/v1/rules/import:
    post:
      summary: Import rules from SigmaHQ
      
  /api/v1/rules/{id}/test:
    post:
      summary: Test rule against historical data
      
  # ATT&CK Coverage
  /api/v1/coverage:
    get:
      summary: Get ATT&CK coverage metrics
      
  /api/v1/coverage/gaps:
    get:
      summary: Get coverage gaps
      
  /api/v1/coverage/navigator:
    get:
      summary: Export ATT&CK Navigator layer
      
  # Connectors
  /api/v1/connectors:
    get:
      summary: List connectors
    post:
      summary: Add new connector
      
  /api/v1/connectors/{id}/test:
    post:
      summary: Test connector connectivity
      
  # Response
  /api/v1/response/actions:
    get:
      summary: List available actions
    post:
      summary: Execute response action
```

---

## Performance Specifications

### Benchmarks

| Metric | Target | Test Methodology |
|--------|--------|------------------|
| Event Ingestion | 50,000 EPS | Sustained load test, 1 hour |
| Sigma Evaluation | < 10ms per event | 5,000 rules active |
| Search Latency | < 3 seconds | 7-day range, complex query |
| Alert Generation | < 30 seconds E2E | From event to UI |
| Dashboard Load | < 2 seconds | Cold cache |
| API Response | < 200ms P95 | Under load |

### Optimization Strategies

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph PerfOpt["Performance Optimizations"]
        style PerfOpt fill:#fff3e0,stroke:#ef6c00
        
        subgraph Sigma["1. Sigma Engine"]
            style Sigma fill:#e3f2fd,stroke:#1565c0
            S1["Rule compilation at load time"]
            S2["Bloom filter pre-check"]
            S3["Rule indexing by logsource O(1)"]
            S4["Parallel evaluation"]
        end
        
        subgraph Pipeline["2. Data Pipeline"]
            style Pipeline fill:#e8f5e9,stroke:#2e7d32
            P1["Kafka partitioning by entity hash"]
            P2["Batch normalization (100/batch)"]
            P3["Async I/O throughout"]
        end
    end
```

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph PerfOpt2["Performance Optimizations (cont.)"]
        style PerfOpt2 fill:#fff3e0,stroke:#ef6c00
        
        subgraph Storage["3. Storage"]
            style Storage fill:#f3e5f5,stroke:#7b1fa2
            ST1["OpenSearch templates for time-series"]
            ST2["Hot-warm-cold architecture"]
            ST3["Query result caching in Redis"]
        end
        
        subgraph API["4. API"]
            style API fill:#e0f2f1,stroke:#00796b
            A1["Connection pooling"]
            A2["Response compression (gzip)"]
            A3["Cursor-based pagination"]
        end
    end
```

---

## Appendix: Technology Decisions

### Decision Log

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|------------------------|
| Backend Language | Python | Fast development, pySigma ecosystem | Go, Rust |
| Frontend Framework | React | Large ecosystem, team familiarity | Vue, Svelte |
| Event Storage | OpenSearch | Open source, scalable, query flexibility | Elasticsearch, ClickHouse |
| Message Queue | Kafka | Durability, high throughput | Redis Streams, RabbitMQ |
| Cache | Redis | Versatile, pub/sub support | Memcached |
| Metadata DB | PostgreSQL | Reliable, feature-rich | MySQL, CockroachDB |

---

## Additional Architecture Diagrams

> **Note**: This section contains detailed visual architecture references merged from ARCHITECTURE-DIAGRAMS.md

### Complete System Overview

#### High-Level Architecture

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph External["External Systems"]
        style External fill:#e3f2fd,stroke:#1565c0
        WAZ[Wazuh Manager]
        ZEEK[Zeek Sensor]
        SURI[Suricata IDS]
        PROW[Prowler Scanner]
    end

    subgraph Ingestion["Ingestion Layer"]
        style Ingestion fill:#e8f5e9,stroke:#2e7d32
        WC[Wazuh Connector]
        ZC[Zeek Connector]
        SC[Suricata Connector]
        PC[Prowler Connector]
    end

    subgraph Queue["Message Queue"]
        style Queue fill:#fff3e0,stroke:#ef6c00
        RS[Redis Streams]
    end

    subgraph Processing["Processing Layer"]
        style Processing fill:#f3e5f5,stroke:#7b1fa2
        NORM[OCSF Normalizer]
        SIGMA[Sigma Engine]
        CORR[Correlation Engine]
        ALERT[Alert Manager]
    end

    subgraph Storage["Storage Layer"]
        style Storage fill:#e0f2f1,stroke:#00695c
        OS[OpenSearch]
        PG[PostgreSQL]
        REDIS[Redis Cache]
    end

    subgraph Presentation["Presentation Layer"]
        style Presentation fill:#fce4ec,stroke:#ad1457
        API[FastAPI Gateway]
        UI[React Frontend]
    end

    External --> Ingestion --> Queue
    Queue --> Processing --> Storage
    Storage --> Presentation
    Processing --> Presentation
```

### Data Flow Diagrams

#### Event Ingestion to Alert Flow

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart LR
    subgraph Source["Source"]
        style Source fill:#e3f2fd,stroke:#1565c0
        W[Wazuh Alert]
    end

    subgraph Conn["Connector"]
        style Conn fill:#e8f5e9,stroke:#2e7d32
        WC[Wazuh Connector<br/>Pull API]
    end

    subgraph Q1["Raw Queue"]
        style Q1 fill:#fff3e0,stroke:#ef6c00
        RAW[mxtac:raw:wazuh]
    end

    subgraph Norm["Normalize"]
        style Norm fill:#f3e5f5,stroke:#7b1fa2
        PARSE[Parse Wazuh]
        TRANS[Transform OCSF]
        VALID[Validate Schema]
    end

    subgraph Q2["Normalized Queue"]
        style Q2 fill:#fff3e0,stroke:#ef6c00
        NORM_Q[mxtac:normalized]
    end

    subgraph Detect["Detection"]
        style Detect fill:#ffebee,stroke:#c62828
        ROUTE[Route by Class]
        MATCH[Match Rules]
        GEN[Generate Alert]
    end

    subgraph Q3["Alert Queue"]
        style Q3 fill:#fff3e0,stroke:#ef6c00
        ALERT_Q[mxtac:alerts]
    end

    subgraph Store["Storage"]
        style Store fill:#e0f2f1,stroke:#00695c
        OS[OpenSearch]
        PG[PostgreSQL]
    end

    Source --> Conn --> Q1
    Q1 --> Norm
    Norm --> Q2
    Q2 --> Detect
    Q2 --> Store
    Detect --> Q3
    Q3 --> Store
```

### Sequence Diagrams

#### Alert Detection Sequence

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
sequenceDiagram
    participant W as Wazuh
    participant C as Connector
    participant Q as Redis Streams
    participant N as Normalizer
    participant S as Sigma Engine
    participant A as Alert Manager
    participant U as UI

    W->>C: Alert (rule 550)
    C->>Q: Publish to mxtac:raw:wazuh
    Q->>N: Consume raw event
    N->>N: Parse Wazuh JSON
    N->>N: Transform to OCSF
    N->>Q: Publish to mxtac:normalized
    Q->>S: Consume OCSF event
    S->>S: Route by class_uid
    S->>S: Match against rules
    S->>S: Rule matched!
    S->>Q: Publish to mxtac:alerts
    Q->>A: Consume alert
    A->>A: Deduplicate
    A->>A: Enrich with threat intel
    A->>A: Calculate risk score
    A->>U: Send alert (WebSocket)
    U->>U: Display notification
```

#### User Search Sequence

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
sequenceDiagram
    participant U as User
    participant UI as React UI
    participant API as API Gateway
    participant S as Search Service
    participant OS as OpenSearch

    U->>UI: Enter search query
    UI->>UI: Build query DSL
    UI->>API: POST /api/v1/events/search
    API->>API: Validate JWT
    API->>API: Check rate limit
    API->>S: Forward request
    S->>S: Parse query
    S->>OS: Execute search
    OS->>S: Return results (50 events)
    S->>S: Format response
    S->>API: Return formatted results
    API->>UI: JSON response
    UI->>UI: Render results table
    UI->>U: Display results
```

### Deployment Architectures

#### Production Kubernetes

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Internet["Internet"]
        style Internet fill:#e3f2fd,stroke:#1565c0
        USER[Users]
    end

    subgraph K8s["Kubernetes Cluster"]
        style K8s fill:#e8f5e9,stroke:#2e7d32

        subgraph Ingress["Ingress"]
            LB[Cloud LB]
            NGINX[Nginx Ingress]
        end

        subgraph UI_NS["ui namespace"]
            UI1[ui-pod-1]
            UI2[ui-pod-2]
            UI3[ui-pod-3]
        end

        subgraph API_NS["api namespace"]
            API1[api-pod-1]
            API2[api-pod-2]
            API3[api-pod-3]
        end

        subgraph Engine_NS["engine namespace"]
            SIG1[sigma-pod-1]
            SIG2[sigma-pod-2]
            SIG3[sigma-pod-3]
            CORR1[corr-pod-1]
            NORM1[norm-pod-1]
        end

        subgraph Data_NS["data namespace"]
            OS1[opensearch-1]
            OS2[opensearch-2]
            OS3[opensearch-3]
            PG1[postgres-primary]
            PG2[postgres-replica]
            RD1[redis-master]
            RD2[redis-replica]
        end

        subgraph Storage["Persistent Storage"]
            PV1[PV: opensearch-data]
            PV2[PV: postgres-data]
        end
    end

    USER --> LB
    LB --> NGINX
    NGINX --> UI_NS
    UI_NS --> API_NS
    API_NS --> Engine_NS
    Engine_NS --> Data_NS
    Data_NS --> Storage
```

---

*Document maintained by MxTac Project*
*Architecture diagrams updated: 2026-01-19*
