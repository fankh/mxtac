# MxTac - Additional Architecture Diagrams

> **Version**: 1.0
> **Date**: 2026-01-18
> **Purpose**: Visual architecture references for implementation

---

## Table of Contents

1. [Complete System Overview](#1-complete-system-overview)
2. [Data Flow Diagrams](#2-data-flow-diagrams)
3. [Component Interactions](#3-component-interactions)
4. [Deployment Architectures](#4-deployment-architectures)
5. [Sequence Diagrams](#5-sequence-diagrams)

---

## 1. Complete System Overview

### 1.1 High-Level Architecture

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

### 1.2 Layered Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                         │
│  ┌──────────────────┐              ┌──────────────────┐       │
│  │  React Frontend  │◄────────────►│  FastAPI Gateway │       │
│  │  - Dashboard     │   REST/WS    │  - Auth          │       │
│  │  - Alerts        │              │  - Routing       │       │
│  │  - Hunting       │              │  - Rate Limiting │       │
│  └──────────────────┘              └────────┬─────────┘       │
└─────────────────────────────────────────────┼─────────────────┘
                                              │
┌─────────────────────────────────────────────┼─────────────────┐
│                   BUSINESS LOGIC LAYER      │                 │
│  ┌─────────────┐  ┌─────────────┐  ┌───────▼──────┐          │
│  │   Sigma     │  │ Correlation │  │    Alert     │          │
│  │   Engine    │  │   Engine    │  │   Manager    │          │
│  │             │  │             │  │              │          │
│  │ - Matching  │  │ - Sequence  │  │ - Dedupe     │          │
│  │ - Compile   │  │ - Threshold │  │ - Enrich     │          │
│  │ - Index     │  │ - Chain     │  │ - Score      │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘          │
└─────────┼────────────────┼────────────────┼──────────────────┘
          │                │                │
┌─────────┼────────────────┼────────────────┼──────────────────┐
│         │   DATA PROCESSING LAYER         │                  │
│         │                │                │                  │
│  ┌──────▼────────────────▼────────────────▼───────┐          │
│  │           OCSF Normalization Engine            │          │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐     │          │
│  │  │  Wazuh   │  │   Zeek   │  │ Suricata │     │          │
│  │  │  Parser  │  │  Parser  │  │  Parser  │     │          │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘     │          │
│  │       └─────────────┼─────────────┘            │          │
│  │              ┌──────▼───────┐                  │          │
│  │              │ Transformer  │                  │          │
│  │              │ Validator    │                  │          │
│  │              └──────┬───────┘                  │          │
│  └─────────────────────┼──────────────────────────┘          │
└────────────────────────┼─────────────────────────────────────┘
                         │
┌────────────────────────┼─────────────────────────────────────┐
│             MESSAGE QUEUE LAYER       │                      │
│                  ┌─────▼──────────────────┐                  │
│                  │   Redis Streams        │                  │
│                  │  ┌──────────────────┐  │                  │
│                  │  │ mxtac:raw:*      │  │                  │
│                  │  │ mxtac:normalized │  │                  │
│                  │  │ mxtac:alerts     │  │                  │
│                  │  └──────────────────┘  │                  │
│                  └────────────────────────┘                  │
└──────────────────────────────────────────────────────────────┘
                         │
┌────────────────────────┼─────────────────────────────────────┐
│                STORAGE LAYER          │                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │
│  │  OpenSearch    │  │  PostgreSQL    │  │  Redis Cache   │ │
│  │                │  │                │  │                │ │
│  │  - Events      │  │  - Users       │  │  - Sessions    │ │
│  │  - Alerts      │  │  - Rules       │  │  - Metrics     │ │
│  │  - Logs        │  │  - Config      │  │  - Rule Cache  │ │
│  └────────────────┘  └────────────────┘  └────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Data Flow Diagrams

### 2.1 Event Ingestion to Alert Flow

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

### 2.2 Correlation Flow

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Input["Event Input"]
        style Input fill:#e3f2fd,stroke:#1565c0
        E1[Event 1: Exploit Attempt]
        E2[Event 2: Process Creation]
        E3[Event 3: Network Connection]
    end

    subgraph Buffer["Entity Buffer"]
        style Buffer fill:#e8f5e9,stroke:#2e7d32
        IP[Buffer by IP<br/>192.168.1.50]
        TIME[Time Window<br/>5 minutes]
    end

    subgraph Rules["Correlation Rules"]
        style Rules fill:#fff3e0,stroke:#ef6c00
        SEQ[Sequence Rule:<br/>Exploit → Process → C2]
    end

    subgraph Match["Match Engine"]
        style Match fill:#f3e5f5,stroke:#7b1fa2
        CHECK{Sequence<br/>Matched?}
    end

    subgraph Output["Output"]
        style Output fill:#ffebee,stroke:#c62828
        ALERT[Correlated Alert:<br/>Attack Chain Detected]
    end

    Input --> Buffer
    Buffer --> Rules
    Rules --> Match
    Match -->|Yes| Output
    Match -->|No| DROP[Discard]
```

---

## 3. Component Interactions

### 3.1 Sigma Engine Architecture

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Repo["Rule Repository"]
        style Repo fill:#e3f2fd,stroke:#1565c0
        GIT[SigmaHQ GitHub]
        DB[PostgreSQL Rules]
    end

    subgraph Loader["Rule Loader"]
        style Loader fill:#e8f5e9,stroke:#2e7d32
        SYNC[Sync Service<br/>Every 6h]
        PARSE[YAML Parser]
        COMP[Compiler]
    end

    subgraph Index["Rule Index"]
        style Index fill:#fff3e0,stroke:#ef6c00
        CLASS[By OCSF Class]
        TECH[By ATT&CK Technique]
        CACHE[Redis Cache]
    end

    subgraph Match["Matching Engine"]
        style Match fill:#f3e5f5,stroke:#7b1fa2
        BLOOM[Bloom Filter]
        SELECT[Rule Selector]
        EVAL[Parallel Evaluator]
    end

    subgraph Output["Output"]
        style Output fill:#ffebee,stroke:#c62828
        ALERT[Alert Generator]
    end

    Repo --> Loader
    Loader --> Index
    Index --> Match
    Match --> Output

    EVENT[OCSF Event] --> Match
```

### 3.2 API Gateway Flow

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart LR
    subgraph Client["Client"]
        style Client fill:#e3f2fd,stroke:#1565c0
        UI[React App]
    end

    subgraph Gateway["API Gateway"]
        style Gateway fill:#e8f5e9,stroke:#2e7d32
        AUTH{Auth?}
        RATE{Rate<br/>Limit?}
        ROUTE[Router]
    end

    subgraph Services["Backend Services"]
        style Services fill:#fff3e0,stroke:#ef6c00
        ALERTS[Alert Service]
        EVENTS[Event Service]
        RULES[Rule Service]
    end

    subgraph Data["Data Layer"]
        style Data fill:#f3e5f5,stroke:#7b1fa2
        OS[OpenSearch]
        PG[PostgreSQL]
    end

    Client --> AUTH
    AUTH -->|Invalid| ERR401[401 Unauthorized]
    AUTH -->|Valid| RATE
    RATE -->|Exceeded| ERR429[429 Too Many Requests]
    RATE -->|OK| ROUTE
    ROUTE --> Services
    Services --> Data
```

---

## 4. Deployment Architectures

### 4.1 Development Environment

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph Docker["Docker Compose"]
        style Docker fill:#e3f2fd,stroke:#1565c0

        subgraph App["Application"]
            UI[UI Container<br/>:3000]
            API[API Container<br/>:8080]
            SIGMA[Sigma Container<br/>:50051]
        end

        subgraph Data["Data Services"]
            OS[OpenSearch<br/>:9200]
            PG[PostgreSQL<br/>:5432]
            RD[Redis<br/>:6379]
        end

        App --> Data
    end

    DEV[Developer<br/>Laptop] --> Docker
```

### 4.2 Production Kubernetes

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

### 4.3 Multi-Region Deployment

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
flowchart TB
    subgraph GLB["Global Load Balancer"]
        style GLB fill:#e3f2fd,stroke:#1565c0
        DNS[Route 53 / CloudFlare]
    end

    subgraph Region1["Region: US-East"]
        style Region1 fill:#e8f5e9,stroke:#2e7d32
        K8S1[K8s Cluster 1]
        OS1[OpenSearch Cluster 1]
        PG1[PostgreSQL Primary]
    end

    subgraph Region2["Region: EU-West"]
        style Region2 fill:#fff3e0,stroke:#ef6c00
        K8S2[K8s Cluster 2]
        OS2[OpenSearch Cluster 2]
        PG2[PostgreSQL Replica]
    end

    subgraph Sync["Cross-Region Sync"]
        style Sync fill:#f3e5f5,stroke:#7b1fa2
        CCR[Cross-Cluster Replication]
        REP[PostgreSQL Replication]
    end

    DNS --> Region1
    DNS --> Region2
    Region1 --> Sync
    Region2 --> Sync
```

---

## 5. Sequence Diagrams

### 5.1 Alert Detection Sequence

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

### 5.2 User Search Sequence

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

### 5.3 Rule Deployment Sequence

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
sequenceDiagram
    participant E as Engineer
    participant UI as UI
    participant API as API
    participant RS as Rule Service
    participant PG as PostgreSQL
    participant SE as Sigma Engine
    participant R as Redis

    E->>UI: Upload Sigma rule
    UI->>API: POST /api/v1/rules
    API->>RS: Create rule
    RS->>RS: Validate YAML
    RS->>RS: Parse with pySigma
    RS->>PG: Store rule
    PG->>RS: Rule ID
    RS->>SE: Reload rules
    SE->>PG: Fetch all active rules
    PG->>SE: Return rules
    SE->>SE: Compile rules
    SE->>R: Cache compiled rules
    SE->>RS: Reload complete
    RS->>API: Success
    API->>UI: Rule created
    UI->>E: Confirmation
```

### 5.4 Correlation Detection Sequence

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'fontSize': '14px' }, 'flowchart': { 'useMaxWidth': true }}}%%
sequenceDiagram
    participant Q as Event Queue
    participant C as Correlation Engine
    participant B as Entity Buffer
    participant R as Redis
    participant A as Alert Manager

    Q->>C: Event 1: Exploit attempt (192.168.1.50)
    C->>B: Buffer by IP
    B->>R: Store event (TTL 5min)

    Q->>C: Event 2: Process spawn (192.168.1.50)
    C->>B: Buffer by IP
    B->>R: Retrieve events for IP
    R->>B: [Event 1]
    B->>C: Events: [Event 1, Event 2]
    C->>C: Check sequence rule
    Note over C: Not complete yet

    Q->>C: Event 3: C2 beacon (192.168.1.50)
    C->>B: Buffer by IP
    B->>R: Retrieve events for IP
    R->>B: [Event 1, Event 2]
    B->>C: Events: [Event 1, Event 2, Event 3]
    C->>C: Check sequence rule
    Note over C: Sequence matched!
    C->>A: Generate correlated alert
    A->>A: Enrich and score
```

---

## Implementation Notes

### Component Communication

| From | To | Protocol | Port |
|------|-----|----------|------|
| React UI | API Gateway | HTTPS | 443 |
| API Gateway | Backend Services | gRPC | 50051 |
| Backend Services | Redis Streams | TCP | 6379 |
| Backend Services | OpenSearch | HTTPS | 9200 |
| Backend Services | PostgreSQL | TCP | 5432 |

### Service Discovery (Kubernetes)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sigma-engine
spec:
  selector:
    app: sigma-engine
  ports:
    - name: grpc
      port: 50051
      targetPort: 50051
    - name: http
      port: 8080
      targetPort: 8080
  type: ClusterIP
```

### Health Checks

All services expose:
- `GET /health/live` - Liveness probe (service is running)
- `GET /health/ready` - Readiness probe (service is ready to handle requests)
- `GET /metrics` - Prometheus metrics

---

*Architecture diagrams by Claude (Senior AI Research Scientist)*
*Date: 2026-01-18*
