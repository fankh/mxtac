# MxTac — AI Agent Implementation Plan

> **Purpose**: Structured task plan for implementing MxTac using AI coding agents (Claude Code or equivalent).
> Each task is self-contained, has clear inputs/outputs, and can be executed autonomously by an agent.

---

## How to Use This Document

Each task block contains:
- **Context**: What already exists and what the agent needs to know
- **Input files**: Files the agent must read before writing code
- **Deliverables**: Exact files and behaviors expected
- **Acceptance criteria**: How to verify completion
- **Dependencies**: Which tasks must complete first

**Execution model**: Tasks within the same phase can run in parallel (separate agent instances).
Tasks in later phases depend on earlier phases completing.

---

## Current Implementation Status

| Layer | Status | Notes |
|-------|--------|-------|
| Docker dev stack | Done | postgres, redis, opensearch, redpanda all running |
| FastAPI skeleton | Done | 8 endpoint groups, all return mock data |
| React UI | Done | Overview + Detections pages functional |
| Message queue | Done | InMemory / Redis / Kafka backends coded |
| Alert dedup + scoring | Done | MD5 dedup, risk score formula |
| SQLAlchemy models | Done | User, Rule, Detection, Connector defined |
| Alembic migrations | Done | 0001 + 0002 exist |
| Sigma engine | Stub | Data structures only, no evaluation |
| OCSF normalizers | Stub | File structure only |
| Connectors | Stub | Base class only |
| DB persistence | Missing | All endpoints use mock_data.py |
| RBAC enforcement | Missing | No permission checks |
| WebSocket (real-time) | Missing | Framework only |
| Horizontal scaling | Missing | In-process state, no Valkey pub/sub |

---

## Dependency Graph

```
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5
Foundation   Storage     Pipeline    Detection    API/UI       Scale
```

---

## Phase 0 — Foundation Fixes

*Prerequisites: None. Run all tasks in parallel.*

---

### TASK-0.1: Replace Redis with Valkey

**Context**
Redis changed its license to RSALv2/SSPLv1 in March 2024. Valkey is the Linux Foundation
BSD-licensed fork of Redis 7.2.4 — a drop-in replacement with identical wire protocol.
All redis-py clients connect to Valkey without code changes.

**Input files**
- `app/docker-compose.yml`
- `app/docker-compose.prod.yml`
- `app/backend/requirements.txt`

**Deliverables**
1. `docker-compose.yml` — replace `image: redis:7-alpine` with `image: valkey/valkey:8-alpine`
2. `docker-compose.prod.yml` — same substitution
3. `requirements.txt` — replace `redis[hiredis]>=5.2.0` with `valkey[libvalkey]>=6.0.0`
4. Any file importing `import redis` — change to `import valkey as redis` (alias keeps rest of code unchanged)

**Acceptance criteria**
- `docker compose up redis` starts a Valkey 8 container
- `docker compose exec redis valkey-cli ping` returns PONG
- Backend connects successfully (logs show no Redis connection errors)

---

### TASK-0.2: Add Missing Config Fields

**Context**
`app/backend/app/core/config.py` currently defines only basic fields (app_name, secret_key,
database_url, redis_url). The queue, OpenSearch, and Kafka settings are hardcoded in
`docker-compose.yml` env vars but not surfaced as validated config fields.

**Input files**
- `app/backend/app/core/config.py`
- `app/docker-compose.yml`
- `app/backend/app/pipeline/queue.py` (see what settings it reads)
- `app/backend/app/services/opensearch_client.py` (see what settings it reads)

**Deliverables**
Update `config.py` to add:
```python
# Queue
queue_backend: str = "memory"          # "memory" | "redis" | "kafka"
kafka_bootstrap_servers: str = "localhost:9092"
kafka_consumer_group: str = "mxtac"

# OpenSearch
opensearch_host: str = "localhost"
opensearch_port: int = 9200
opensearch_username: str = ""
opensearch_password: str = ""
opensearch_use_ssl: bool = False

# Valkey/Redis (rename from redis_url)
valkey_url: str = "redis://localhost:6379/0"

# JWT
access_token_expire_minutes: int = 60
refresh_token_expire_days: int = 7

# Rate limiting
rate_limit_per_minute: int = 300
```

Also update `app/backend/.env.example` with all new fields and documentation comments.

**Acceptance criteria**
- `python -c "from app.core.config import settings; print(settings.queue_backend)"` works
- All fields have defaults that work for local dev without any .env file

---

### TASK-0.3: Add /ready Endpoint

**Context**
`app/backend/app/main.py` has a `/health` endpoint that always returns `{"status": "ok"}`.
For multi-instance deployment (Docker Swarm, k3s), a `/ready` endpoint is needed that
actually checks downstream dependencies before accepting traffic.

**Input files**
- `app/backend/app/main.py`
- `app/backend/app/core/database.py`
- `app/backend/app/services/opensearch_client.py`
- `app/backend/app/pipeline/queue.py`

**Deliverables**
Add to `main.py`:
```python
@app.get("/ready")
async def readiness():
    checks = {}
    # Check PostgreSQL
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as e:
        checks["postgres"] = f"error: {e}"

    # Check Valkey
    try:
        # ping valkey
        checks["valkey"] = "ok"
    except Exception as e:
        checks["valkey"] = f"error: {e}"

    # Check OpenSearch
    try:
        checks["opensearch"] = "ok"  # ping OS
    except Exception as e:
        checks["opensearch"] = f"error: {e}"

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ready" if all_ok else "degraded", "checks": checks}
    )
```

**Acceptance criteria**
- `GET /ready` returns `200 {"status": "ready"}` when all services up
- `GET /ready` returns `503 {"status": "degraded", "checks": {...}}` when a dependency is down
- Docker Compose `healthcheck` updated to use `/ready` instead of `/health`

---

## Phase 1 — Database Persistence

*Prerequisites: Phase 0 complete. Tasks 1.1 and 1.2 can run in parallel.*

---

### TASK-1.1: Implement Repository Layer

**Context**
All API endpoints currently import from `app/services/mock_data.py` and return hardcoded data.
SQLAlchemy models exist for User, Rule, Detection, Connector. Alembic migrations 0001 and 0002
create the tables. The missing piece is a repository/service layer that queries the real DB.

**Input files**
- `app/backend/app/models/user.py`
- `app/backend/app/models/detection.py`
- `app/backend/app/models/rule.py`
- `app/backend/app/models/connector.py`
- `app/backend/app/core/database.py`
- `app/backend/app/api/v1/endpoints/detections.py`
- `app/backend/app/api/v1/endpoints/rules.py`
- `app/backend/app/api/v1/endpoints/connectors.py`
- `app/backend/app/api/v1/endpoints/users.py`

**Deliverables**
Create `app/backend/app/repositories/`:
- `__init__.py`
- `detection_repo.py` — `list()`, `get()`, `create()`, `update()`, `delete()`, `count()`
- `rule_repo.py` — `list()`, `get_by_id()`, `create()`, `update()`, `enable()`, `disable()`
- `connector_repo.py` — `list()`, `get_by_id()`, `create()`, `update()`, `update_status()`
- `user_repo.py` — `list()`, `get_by_id()`, `get_by_email()`, `create()`, `update()`, `delete()`

Each repository function takes `AsyncSession` as first argument and returns typed model objects.

Update all four endpoint files to use repositories instead of `mock_data.py`.
Keep `mock_data.py` only for seeding initial data on first run.

**Acceptance criteria**
- `GET /detections` returns rows from the `detections` DB table (not mock data)
- Creating a detection via POST persists across API restarts
- All existing filter/sort/pagination behavior works with real data

---

### TASK-1.2: Database Seed Data

**Context**
After switching to real DB queries, the UI will show empty tables. Seed data is needed for
development/demo purposes. Existing mock data in `mock_data.py` should be the seed source.

**Input files**
- `app/backend/app/services/mock_data.py`
- `app/backend/app/models/` (all model files)
- `app/backend/alembic/env.py`

**Deliverables**
Create `app/backend/app/db/seed.py`:
```python
async def seed_database(session: AsyncSession) -> None:
    """Idempotent seed — only runs if tables are empty."""
    # Check if data exists
    count = await session.scalar(select(func.count()).select_from(Detection))
    if count > 0:
        return
    # Insert mock detections, rules, connectors, default admin user
```

Call `seed_database()` in `main.py` `on_startup` after migrations.

Create default admin user:
- email: `admin@mxtac.local`
- password: `mxtac2026` (bcrypt hashed)
- role: `admin`

**Acceptance criteria**
- Fresh `docker compose up` seeds the DB on first start
- Re-running does not duplicate data (idempotent)
- `GET /detections` returns seeded detections immediately

---

## Phase 2 — Event Pipeline

*Prerequisites: Phase 0 complete. Tasks 2.1–2.4 can run in parallel.*

---

### TASK-2.1: Implement OCSF Normalizers

**Context**
`app/backend/app/services/normalizers/` has four skeleton files: `ocsf.py` (schema), `wazuh.py`,
`zeek.py`, `suricata.py`. The `OCSFEvent` Pydantic model is defined. Each normalizer needs
a `normalize(raw: dict) -> OCSFEvent` function that maps source-specific fields to OCSF.

**Input files**
- `app/backend/app/services/normalizers/ocsf.py` (OCSFEvent schema)
- `app/backend/app/services/normalizers/wazuh.py` (skeleton)
- `app/backend/app/services/normalizers/zeek.py` (skeleton)
- `app/backend/app/services/normalizers/suricata.py` (skeleton)
- `app/backend/app/pipeline/queue.py` (Topic constants)
- Specification: `../../08-SIGMA-ENGINE-SPECIFICATION.md` (OCSF field mappings)

**Deliverables**

`wazuh.py` — `WazuhNormalizer.normalize(raw)`:
- `rule.level` → `severity_id` (14→5 Critical, 11→4 High, 7→3 Medium, 4→2 Low, else 1)
- `rule.mitre.technique` → `attacks[].technique_uid`
- `agent.name` + `agent.ip` → `dst_endpoint`
- `data.win.eventdata.ParentImage` / `data.win.eventdata.Image` → `process`
- `timestamp` → `time` (ISO8601 parse)

`zeek.py` — `ZeekNormalizer.normalize(raw)`:
- Dispatch on `_path`: `conn` → NetworkActivity (class_uid 4001), `dns` → DNSActivity (4003),
  `http` → HTTPActivity (4002), `ssl` → NetworkActivity
- `id.orig_h`/`id.orig_p` → `src_endpoint`, `id.resp_h`/`id.resp_p` → `dst_endpoint`
- `ts` → `time`

`suricata.py` — `SuricataNormalizer.normalize(raw)`:
- Dispatch on `event_type`: `alert`, `dns`, `http`, `tls`
- `alert.severity` → `severity_id` (1→4 High, 2→3 Med, 3→2 Low, 4→1 Info)
- `alert.metadata.mitre_technique_id[]` → `attacks[]`
- `src_ip`/`src_port` → `src_endpoint`

Create `app/backend/app/services/normalizers/pipeline.py`:
```python
class NormalizerPipeline:
    async def start(self) -> None:
        # Subscribe to mxtac.raw.* topics
        # Call appropriate normalizer based on topic
        # Publish OCSFEvent to mxtac.normalized
```

**Acceptance criteria**
- Unit test: `WazuhNormalizer().normalize(SAMPLE_WAZUH_ALERT)` returns valid `OCSFEvent`
- Unit test: `ZeekNormalizer().normalize(SAMPLE_ZEEK_CONN_LOG)` returns valid `OCSFEvent`
- Unit test: `SuricataNormalizer().normalize(SAMPLE_SURICATA_ALERT)` returns valid `OCSFEvent`
- Severity mapping is correct for all inputs

---

### TASK-2.2: Implement Sigma Engine

**Context**
`app/backend/app/engine/sigma_engine.py` has `SigmaRule` and `SigmaAlert` dataclasses but no
evaluation logic. The engine must load Sigma YAML rules, compile them, and match against
`OCSFEvent` objects. Use `pySigma` library for rule parsing (add to requirements.txt).

**Input files**
- `app/backend/app/engine/sigma_engine.py` (current stub)
- `app/backend/app/services/normalizers/ocsf.py` (OCSFEvent schema)
- `app/backend/requirements.txt`
- Specification: `../../08-SIGMA-ENGINE-SPECIFICATION.md`

**Deliverables**

Add to `requirements.txt`:
```
pySigma>=0.10.0
pySigma-backend-opensearch>=0.4.0
```

Implement `sigma_engine.py`:
```python
class SigmaEngine:
    async def load_rules_from_dir(self, path: Path) -> int:
        """Load all .yml files, return count loaded."""

    async def load_rule_from_yaml(self, yaml_str: str) -> SigmaRule:
        """Parse single Sigma YAML, validate, index by logsource."""

    def add_rule(self, rule: SigmaRule) -> None:
        """Index rule by logsource (product, category, service)."""

    async def evaluate(self, event: OCSFEvent) -> AsyncGenerator[SigmaAlert, None]:
        """Match event against candidate rules. Yield matches."""

    def _get_candidates(self, event: OCSFEvent) -> list[SigmaRule]:
        """Return rules whose logsource matches event metadata_product."""

    def _matches(self, rule: SigmaRule, event: OCSFEvent) -> bool:
        """Evaluate detection block against flattened event dict."""
```

Field mapping: `OCSFEvent` → flat dict for Sigma field matching:
```python
{
    "Image": event.process.executable,
    "CommandLine": event.process.cmd_line,
    "ParentImage": event.process.parent_process.executable,
    "TargetImage": event.dst_endpoint.hostname,
    "src_ip": event.src_endpoint.ip,
    "dst_port": event.dst_endpoint.port,
    # ... etc per logsource category
}
```

Create `app/backend/sigma_rules/` directory with 5 example Sigma rules:
- `lsass_memory_access.yml`
- `powershell_encoded_command.yml`
- `lateral_movement_smb.yml`
- `dns_tunneling_long_query.yml`
- `new_service_creation.yml`

**Acceptance criteria**
- `SigmaEngine().load_rules_from_dir(Path("sigma_rules/"))` loads 5 rules without error
- Given a matching event, `evaluate()` yields at least one `SigmaAlert`
- Given a non-matching event, `evaluate()` yields nothing
- Unit tests cover: match, no-match, multi-condition AND/OR, NOT

---

### TASK-2.3: Implement Wazuh + Zeek Connectors

**Context**
`app/backend/app/connectors/base.py` defines `BaseConnector`. `wazuh.py` and `zeek.py` have
skeleton classes. These need real API/file-polling logic to pull events and publish to the queue.

**Input files**
- `app/backend/app/connectors/base.py`
- `app/backend/app/connectors/wazuh.py` (skeleton)
- `app/backend/app/connectors/zeek.py` (skeleton)
- `app/backend/app/pipeline/queue.py`
- `app/backend/app/core/config.py`

**Deliverables**

`wazuh.py` — `WazuhConnector`:
```python
class WazuhConnector(BaseConnector):
    """Polls Wazuh Manager REST API for alerts.

    Config keys (from connector.config_json):
      host, port, username, password, verify_ssl, poll_interval_sec
    """
    async def _connect(self) -> None:
        # POST /security/user/authenticate → store JWT
        # GET /manager/info → verify connectivity

    async def _fetch_events(self) -> AsyncGenerator[dict, None]:
        # GET /alerts with q=timestamp>{last_seen}
        # Paginate with offset + limit=500
        # Update last_seen on each batch
        # Yield individual alert dicts

    @property
    def topic(self) -> str:
        return Topic.RAW_WAZUH
```

`zeek.py` — `ZeekConnector`:
```python
class ZeekConnector(BaseConnector):
    """Tails Zeek log files from a directory.

    Config keys:
      log_dir, file_patterns (["conn.log", "dns.log", ...])
      poll_interval_sec
    """
    async def _connect(self) -> None:
        # Verify log_dir exists and is readable
        # Initialize _file_positions dict

    async def _fetch_events(self) -> AsyncGenerator[dict, None]:
        # For each log file: seek to last position
        # Read new lines, parse JSON or TSV
        # Add _path field (filename stem)
        # Yield event dicts

    @property
    def topic(self) -> str:
        return Topic.RAW_ZEEK
```

Create `app/backend/app/connectors/suricata.py` — `SuricataConnector`:
```python
class SuricataConnector(BaseConnector):
    """Tails Suricata EVE JSON log file."""
    # Similar to ZeekConnector but for eve.json format
    # Parse newline-delimited JSON
    @property
    def topic(self) -> str:
        return Topic.RAW_SURICATA
```

Create `app/backend/app/connectors/registry.py`:
```python
CONNECTOR_TYPES = {
    "wazuh": WazuhConnector,
    "zeek": ZeekConnector,
    "suricata": SuricataConnector,
}

async def start_connectors_from_db(session: AsyncSession, queue: MessageQueue) -> list[BaseConnector]:
    """Load enabled connectors from DB and start them."""
```

**Acceptance criteria**
- `WazuhConnector` successfully authenticates and fetches alerts from a live Wazuh instance
- `ZeekConnector` tails a log file and yields new lines as events
- `SuricataConnector` tails `eve.json` and yields events
- On connection failure, connector logs error and retries with exponential backoff (max 60s)
- Connector health is updated in the DB (`status`, `last_seen_at`, `error_message`)

---

### TASK-2.4: Wire Pipeline in main.py Startup

**Context**
The pipeline components (connectors, normalizers, sigma engine, alert manager) exist as
independent services but are never started. `main.py`'s `on_startup` event only logs a message.
Everything needs to be wired together so the data flow is automatic.

**Input files**
- `app/backend/app/main.py`
- `app/backend/app/pipeline/queue.py`
- `app/backend/app/connectors/registry.py` (from Task 2.3)
- `app/backend/app/services/normalizers/pipeline.py` (from Task 2.1)
- `app/backend/app/engine/sigma_engine.py`
- `app/backend/app/services/alert_manager.py`
- `app/backend/app/services/opensearch_client.py`

**Deliverables**
Update `main.py` `on_startup`:
```python
@app.on_event("startup")
async def on_startup() -> None:
    # 1. Init queue
    queue = get_queue()
    await queue.start()

    # 2. Connect OpenSearch
    os_client = get_opensearch()
    await os_client.connect()
    await os_client.ensure_indices()  # create index templates

    # 3. Load Sigma rules
    engine = SigmaEngine()
    n = await engine.load_rules_from_dir(Path("sigma_rules/"))
    logger.info("Loaded %d Sigma rules", n)

    # 4. Start connectors from DB
    async with AsyncSessionLocal() as session:
        connectors = await start_connectors_from_db(session, queue)
    for conn in connectors:
        await conn.start()

    # 5. Start normalizer pipeline
    normalizer = NormalizerPipeline(queue)
    asyncio.create_task(normalizer.start())

    # 6. Start Sigma evaluation consumer
    asyncio.create_task(sigma_consumer(queue, engine))

    # 7. Start alert manager consumer
    alert_mgr = AlertManager(queue)
    asyncio.create_task(alert_mgr.start())

    # 8. Start WebSocket broadcaster (subscribes to mxtac.enriched)
    asyncio.create_task(websocket_broadcaster(queue))
```

Create supporting consumers:
- `sigma_consumer(queue, engine)` — reads `mxtac.normalized`, evaluates, publishes to `mxtac.alerts`
- `websocket_broadcaster(queue)` — reads `mxtac.enriched`, calls `broadcast_alert()`

**Acceptance criteria**
- `docker compose up backend` starts without error
- A synthetic Wazuh event published to `mxtac.raw.wazuh` flows through the full pipeline
- The enriched alert appears in OpenSearch index `mxtac-alerts-YYYY.MM.DD`
- The enriched alert is broadcast over WebSocket to connected UI clients

---

## Phase 3 — Horizontal Scaling

*Prerequisites: Phase 0–2 complete. Tasks 3.1 and 3.2 can run in parallel.*

---

### TASK-3.1: Distributed WebSocket (Valkey Pub/Sub)

**Context**
`app/backend/app/api/v1/endpoints/websocket.py` has `ConnectionManager` that stores
`set[WebSocket]` in process memory. With multiple API instances, clients on different
instances never receive alerts broadcast by another instance. Fix: use Valkey pub/sub
as the cross-instance message bus.

**Input files**
- `app/backend/app/api/v1/endpoints/websocket.py`
- `app/backend/app/core/config.py`
- `app/backend/requirements.txt`

**Deliverables**
Replace `ConnectionManager` with `DistributedConnectionManager`:

```python
PUBSUB_CHANNEL = "mxtac:alerts"

class DistributedConnectionManager:
    def __init__(self) -> None:
        self._local: set[WebSocket] = set()
        self._valkey: valkey.asyncio.Valkey | None = None
        self._pubsub: valkey.asyncio.client.PubSub | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._local.add(ws)
        # If first connection, start subscriber task
        if len(self._local) == 1:
            asyncio.create_task(self._listen())

    async def _listen(self) -> None:
        """Subscribe to Valkey channel, fan-out to local WebSocket clients."""
        client = valkey.asyncio.from_url(settings.valkey_url)
        pubsub = client.pubsub()
        await pubsub.subscribe(PUBSUB_CHANNEL)
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = json.loads(message["data"])
                await self._local_broadcast(data)

    async def _local_broadcast(self, message: dict) -> None:
        dead = set()
        for ws in self._local:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.add(ws)
        self._local -= dead

async def broadcast_alert(alert: dict) -> None:
    """Publish to Valkey — all instances receive it."""
    client = valkey.asyncio.from_url(settings.valkey_url)
    await client.publish(PUBSUB_CHANNEL, json.dumps({"type": "alert", "data": alert}))
```

**Acceptance criteria**
- With 2 API instances behind a load balancer:
  - Client A connected to Instance-1 receives alerts even when alert arrives on Instance-2
  - Client B connected to Instance-2 receives the same alert
- Single instance behavior is unchanged
- No memory leak: closed WebSocket connections removed from `_local`

---

### TASK-3.2: Distributed Dedup Cache (Valkey SETEX)

**Context**
`app/backend/app/services/alert_manager.py` uses `self._dedup_cache: dict[str, datetime]` in
process memory for 5-minute alert deduplication. With multiple instances, the same alert can
be processed twice (once per instance). Fix: move dedup to Valkey with TTL-based keys.

**Input files**
- `app/backend/app/services/alert_manager.py`
- `app/backend/app/core/config.py`

**Deliverables**
Replace in-memory dict with Valkey SETEX:
```python
class AlertManager:
    DEDUP_TTL = 300  # 5 minutes in seconds
    DEDUP_PREFIX = "mxtac:dedup:"

    async def _is_duplicate(self, alert: dict) -> bool:
        key = self._dedup_key(alert)
        valkey_key = f"{self.DEDUP_PREFIX}{key}"

        # SET key NX EX 300 — atomic: set only if not exists
        result = await self._valkey.set(valkey_key, "1", nx=True, ex=self.DEDUP_TTL)
        # result=True means key was set (not a duplicate)
        # result=None means key already existed (duplicate)
        return result is None

    def _dedup_key(self, alert: dict) -> str:
        parts = f"{alert.get('rule_id', '')}|{alert.get('host', '')}"
        return hashlib.md5(parts.encode()).hexdigest()
```

Remove `self._dedup_lock = asyncio.Lock()` — Valkey NX operation is atomic, no lock needed.

**Acceptance criteria**
- With 2 instances processing the same alert simultaneously, only 1 reaches `mxtac.enriched`
- After 5 minutes, the same alert is accepted again (TTL expired)
- Unit test: mock Valkey, verify SET NX EX is called with correct key and TTL

---

### TASK-3.3: Docker Swarm / k3s Deployment Config

**Context**
For on-premises horizontal scaling without cloud auto-scaling, the project needs deployment
manifests for either Docker Swarm (simpler) or k3s (full Kubernetes). HAProxy handles
load balancing. Keepalived provides VIP for HA.

**Input files**
- `app/docker-compose.yml`
- `app/docker-compose.prod.yml`

**Deliverables**
Create `app/deploy/` directory:

`app/deploy/docker-swarm/docker-stack.yml`:
```yaml
version: '3.9'
services:
  backend:
    image: mxtac/backend:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
        failure_action: rollback
      restart_policy:
        condition: on-failure
        max_attempts: 3
    environment:
      - QUEUE_BACKEND=redis
      - VALKEY_URL=redis://valkey:6379/0
    # ... volumes, networks

  frontend:
    image: mxtac/frontend:latest
    deploy:
      replicas: 2

  valkey:
    image: valkey/valkey:8-alpine
    deploy:
      replicas: 1
      placement:
        constraints: [node.role == manager]  # single node, persistent

  # ... postgres, opensearch
```

`app/deploy/haproxy/haproxy.cfg`:
```
frontend mxtac_api
    bind *:8080
    default_backend api_backends

backend api_backends
    balance roundrobin
    option httpchk GET /ready
    server api1 api1:8080 check
    server api2 api2:8080 check
    server api3 api3:8080 check
```

`app/deploy/k3s/` — Kubernetes manifests:
- `namespace.yaml`
- `backend-deployment.yaml` (3 replicas, rolling update)
- `backend-service.yaml` (ClusterIP)
- `frontend-deployment.yaml` (2 replicas)
- `ingress.yaml` (nginx-ingress, routes /api/ → backend, / → frontend)
- `valkey-statefulset.yaml`
- `postgres-statefulset.yaml`
- `opensearch-statefulset.yaml`
- `hpa.yaml` (HorizontalPodAutoscaler for backend: CPU 70%, min=2, max=8)

`app/deploy/README.md`:
- Docker Swarm setup instructions
- k3s setup instructions
- HAProxy + Keepalived VIP setup

**Acceptance criteria**
- `docker stack deploy -c docker-stack.yml mxtac` starts the stack with 3 backend replicas
- `kubectl apply -f k3s/` starts the stack on a k3s cluster
- HAProxy health check uses `/ready` endpoint
- Rolling update: `docker service update --image mxtac/backend:v2 mxtac_backend` drains one replica at a time

---

## Phase 4 — API & UI Completion

*Prerequisites: Phase 1–2 complete. Tasks run in parallel.*

---

### TASK-4.1: Implement RBAC Middleware

**Context**
All API endpoints accept any authenticated user regardless of role. The data model has 5 roles:
`viewer`, `analyst`, `hunter`, `engineer`, `admin`. Endpoint access must be gated by role.

**Input files**
- `app/backend/app/core/security.py`
- `app/backend/app/models/user.py`
- `app/backend/app/api/v1/endpoints/` (all endpoint files)

**Deliverables**
Create `app/backend/app/core/rbac.py`:
```python
PERMISSIONS: dict[str, list[str]] = {
    "detections:read":   ["viewer", "analyst", "hunter", "engineer", "admin"],
    "detections:write":  ["analyst", "hunter", "engineer", "admin"],
    "rules:read":        ["hunter", "engineer", "admin"],
    "rules:write":       ["engineer", "admin"],
    "connectors:read":   ["engineer", "admin"],
    "connectors:write":  ["engineer", "admin"],
    "users:read":        ["admin"],
    "users:write":       ["admin"],
    "events:search":     ["hunter", "engineer", "admin"],
}

def require_permission(permission: str):
    """FastAPI dependency: raises 403 if current user lacks permission."""
    async def check(current_user: User = Depends(get_current_user)):
        allowed_roles = PERMISSIONS.get(permission, [])
        if current_user.role not in allowed_roles:
            raise ForbiddenError(f"Role '{current_user.role}' cannot perform '{permission}'")
        return current_user
    return check
```

Update each endpoint to use `Depends(require_permission("rules:write"))` etc.

**Acceptance criteria**
- `viewer` role: can GET /detections, cannot PATCH /rules
- `analyst` role: can PATCH /detections/{id} (update status), cannot POST /rules
- `engineer` role: can POST /rules, cannot GET /users
- `admin` role: can access all endpoints
- Unit tests cover: each role boundary for each permission group

---

### TASK-4.2: Implement Event Search (OpenSearch)

**Context**
`app/backend/app/api/v1/endpoints/events.py` has endpoints for event search and entity timeline
but they return stub data. `app/backend/app/services/opensearch_client.py` has `search_events()`
implemented. Connect the endpoint to the real OpenSearch client.

**Input files**
- `app/backend/app/api/v1/endpoints/events.py`
- `app/backend/app/services/opensearch_client.py`

**Deliverables**
Update `events.py`:
- `POST /events/search` → call `os_client.search_events(query, filters, time_from, time_to)`
- `GET /events/{id}` → call `os_client.get_event(event_id)`
- `POST /events/aggregate` → call `os_client.aggregate(field, interval, filters)`
- `GET /events/entity/{type}/{value}` → call `os_client.entity_timeline(type, value)`

Add OpenSearch DSL query builder in `opensearch_client.py`:
```python
def _build_query(self, query: str, filters: dict, time_from: str, time_to: str) -> dict:
    must = [{"range": {"time": {"gte": time_from, "lte": time_to}}}]
    if query:
        must.append({"query_string": {"query": query, "default_field": "*"}})
    for field, value in filters.items():
        must.append({"term": {field: value}})
    return {"query": {"bool": {"must": must}}}
```

**Acceptance criteria**
- `POST /events/search {"query": "severity_id:4"}` returns events from OpenSearch
- Response includes `hits`, `total`, `took_ms`
- Empty OpenSearch returns empty hits (not error)

---

### TASK-4.3: Real-time WebSocket Frontend Integration

**Context**
`app/frontend/src/components/features/detections/DetectionsPage.tsx` shows a static list.
The backend WebSocket at `ws://host/api/v1/ws/alerts` streams new alerts. The frontend
should connect and prepend incoming alerts to the list.

**Input files**
- `app/frontend/src/components/features/detections/DetectionsPage.tsx`
- `app/frontend/src/stores/detectionStore.ts`
- `app/backend/app/api/v1/endpoints/websocket.py` (protocol docs)

**Deliverables**
Create `app/frontend/src/hooks/useAlertStream.ts`:
```typescript
export function useAlertStream() {
  const { addLiveAlert } = useDetectionStore()

  useEffect(() => {
    const token = localStorage.getItem('access_token')
    const ws = new WebSocket(`ws://${window.location.host}/api/v1/ws/alerts?token=${token}`)

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      if (msg.type === 'alert') {
        addLiveAlert(msg.data)  // prepend to detection list
      }
    }

    ws.onclose = () => {
      // Reconnect after 5s
      setTimeout(() => { /* re-create */ }, 5000)
    }

    return () => ws.close()
  }, [])
}
```

Add `addLiveAlert(alert)` action to `detectionStore.ts`.

Add live indicator to `DetectionsPage.tsx`:
- Pulsing green dot when WebSocket connected
- "Live" badge on new alerts (fade after 30s)
- Unread count badge on Sidebar Detections link

**Acceptance criteria**
- New alert broadcast from backend appears in UI within 1 second
- Reconnects automatically after network interruption
- WebSocket state (connected/reconnecting/disconnected) visible in UI

---

### TASK-4.4: Sigma Rule Editor Completion

**Context**
`RulesPage.tsx` has a "Save Rule" button that calls `refetch()` but doesn't actually POST
to the API. The backend `POST /rules` endpoint exists but isn't connected.

**Input files**
- `app/frontend/src/components/features/rules/RulesPage.tsx`
- `app/backend/app/api/v1/endpoints/rules.py`
- `app/frontend/src/lib/api.ts`

**Deliverables**
Update `RulesPage.tsx`:
```typescript
const createRule = useMutation({
  mutationFn: (yaml: string) =>
    apiClient.post('/rules', { content: yaml, rule_type: 'sigma' }),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['rules'] })
    setShowEditor(false)
    // show success toast
  },
  onError: (err) => {
    // show error toast with server validation message
  }
})
```

Add YAML validation in the editor:
- Inline error for missing required fields (title, detection, logsource)
- "Test Rule" button that calls `POST /rules/test` with current YAML and shows match result

Add import from file:
- File input button accepts `.yml` / `.yaml`
- Drag-and-drop support for rule files
- `POST /rules/import` for bulk import

**Acceptance criteria**
- Creating a rule via the editor persists to DB and appears in the rules list
- Invalid YAML shows inline error without submitting
- Test button shows "Matches" / "No match" against a sample event

---

## Phase 5 — Agents (MxGuard + MxWatch)

*Prerequisites: Phase 0–4 complete. These are separate Rust projects.*

---

### TASK-5.1: MxGuard Skeleton (Rust EDR Agent)

**Context**
`app/agents/mxguard/` has 9 design documents but no Rust code.
MxGuard is a lightweight Endpoint Detection and Response agent.
Target: <1% CPU, <30 MB RAM, covers 30–40% of ATT&CK techniques.

**Input files** (design docs)
- `agents/mxguard/00-README.md`
- `agents/mxguard/01-ARCHITECTURE.md`
- `agents/mxguard/02-PROJECT-STRUCTURE.md`
- `agents/mxguard/03-CONFIGURATION.md`
- `agents/mxguard/04-DEPLOYMENT.md`
- `agents/mxguard/05-DEVELOPMENT.md`

**Deliverables**
Create `agents/mxguard/` Rust project:
```
agents/mxguard/
├── Cargo.toml
├── Cargo.lock
├── config/
│   └── mxguard.toml.example
├── src/
│   ├── main.rs              # CLI entry, config loading, signal handling
│   ├── config.rs            # Config struct (serde + toml)
│   ├── agent.rs             # Agent orchestrator
│   ├── collectors/
│   │   ├── mod.rs
│   │   ├── process.rs       # Process creation events (procfs / syslog)
│   │   ├── file.rs          # File modification events (inotify)
│   │   └── network.rs       # Network connection events (/proc/net/tcp)
│   ├── events/
│   │   ├── mod.rs
│   │   └── ocsf.rs          # OCSF event serialization
│   ├── transport/
│   │   ├── mod.rs
│   │   └── http.rs          # POST events to MxTac API or Kafka
│   └── health.rs            # Health check HTTP endpoint
├── tests/
│   └── integration_test.rs
└── README.md
```

Core behavior:
- Poll `/proc` for new processes every 500ms
- Watch config-specified directories with `inotify` (Linux) / `kqueue` (macOS)
- Serialize events as OCSF JSON
- POST batches to `http://mxtac-backend/api/v1/events/ingest` every 5s
- Health endpoint at `http://0.0.0.0:9001/health`
- Config via `mxguard.toml` + env var overrides

**Acceptance criteria**
- `cargo build --release` completes without error
- `cargo test` passes
- Running agent on Linux publishes process creation events to MxTac backend
- Memory use under 30 MB in steady state (`/proc/self/status VmRSS`)
- CPU use under 1% on idle system

---

### TASK-5.2: MxWatch Skeleton (Rust NDR Agent)

**Context**
`app/agents/mxwatch/` has design documents but no Rust code.
MxWatch is a lightweight Network Detection and Response agent using zero-copy packet capture.
Target: 1–5 Mpps throughput, <5% CPU.

**Input files** (design docs)
- `agents/mxwatch/00-README.md`
- `agents/mxwatch/01-ARCHITECTURE.md`
- `agents/mxwatch/02-PROJECT-STRUCTURE.md`

**Deliverables**
Create `agents/mxwatch/` Rust project:
```
agents/mxwatch/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── capture/
│   │   ├── mod.rs
│   │   └── pcap.rs      # libpcap / AF_PACKET capture
│   ├── parsers/
│   │   ├── mod.rs
│   │   ├── tcp.rs
│   │   ├── udp.rs
│   │   ├── dns.rs       # Parse DNS queries/responses
│   │   ├── http.rs      # Parse HTTP request/response headers
│   │   └── tls.rs       # Parse TLS ClientHello (SNI extraction)
│   ├── detectors/
│   │   ├── mod.rs
│   │   ├── dns_tunnel.rs    # Long DNS query names, high entropy
│   │   └── port_scan.rs     # Many unique dst_ports from single src
│   ├── events/
│   │   └── ocsf.rs
│   └── transport/
│       └── http.rs
└── README.md
```

Key dependencies (Cargo.toml):
```toml
[dependencies]
pcap = "1.3"              # libpcap bindings
pnet = "0.35"             # Protocol parsing
tokio = { version="1", features=["full"] }
serde = { version="1", features=["derive"] }
serde_json = "1"
reqwest = { version="0.12", features=["json"] }
```

Minimum detections:
1. **DNS tunneling** — query length > 50 chars OR entropy > 3.5
2. **Port scan** — same src IP, >15 unique dst_ports in 60s window
3. **Protocol anomaly** — non-HTTP traffic on port 80/443

**Acceptance criteria**
- `cargo build --release` completes
- `cargo test` passes (unit tests for DNS parser, port scan detector)
- Captures packets from a live interface (requires root/CAP_NET_RAW)
- Publishes `NetworkActivity` OCSF events to MxTac backend

---

## Phase 6 — Observability & Operations

*Prerequisites: Phase 3 complete.*

---

### TASK-6.1: Structured Metrics (Prometheus)

**Context**
No metrics are currently exported. For on-prem multi-instance deployments, Prometheus
scraping is the standard observability approach.

**Deliverables**
Add to `requirements.txt`: `prometheus-fastapi-instrumentator>=7.0.0`

Update `main.py`:
```python
from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app, endpoint="/metrics")
```

Add custom metrics in `alert_manager.py`:
```python
from prometheus_client import Counter, Histogram, Gauge

alerts_processed = Counter("mxtac_alerts_processed_total", "Alerts processed", ["severity"])
alerts_deduplicated = Counter("mxtac_alerts_deduplicated_total", "Alerts deduplicated")
rule_matches = Counter("mxtac_rule_matches_total", "Sigma rule matches", ["rule_id", "level"])
pipeline_latency = Histogram("mxtac_pipeline_latency_seconds", "Event-to-alert latency")
active_websockets = Gauge("mxtac_websocket_connections", "Active WebSocket connections")
```

Add `app/deploy/monitoring/`:
- `prometheus.yml` — scrape config for backend instances
- `grafana/dashboards/mxtac-overview.json` — pre-built dashboard with panels:
  - Alerts/min by severity
  - Rule match rate (top 10 rules)
  - Pipeline latency p50/p95/p99
  - WebSocket connections
  - OpenSearch indexing rate

**Acceptance criteria**
- `GET /metrics` returns Prometheus-format text
- `docker compose up prometheus grafana` shows the MxTac dashboard
- Alert throughput visible in real time

---

### TASK-6.2: Audit Log

**Context**
`AdminPage.tsx` has an "Audit Log" tab that shows "coming soon — requires OpenSearch integration."
Every user action (login, rule create/update/delete, role change, alert status update) should
be recorded in OpenSearch index `mxtac-audit`.

**Deliverables**
Create `app/backend/app/services/audit.py`:
```python
class AuditLogger:
    async def log(self,
                  actor: str,       # user email
                  action: str,      # "rule.created", "user.role_changed", etc.
                  resource_type: str,
                  resource_id: str,
                  details: dict,
                  request: Request) -> None:
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "actor": actor,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details,
            "source_ip": request.client.host,
            "user_agent": request.headers.get("user-agent"),
        }
        await os_client.index_document("mxtac-audit", entry)
```

Update endpoints to call `audit_logger.log()` on write operations.

`GET /admin/audit-log` endpoint — paginated query of `mxtac-audit` index.

Update `AdminPage.tsx` audit tab to call `GET /admin/audit-log` and render results.

**Acceptance criteria**
- Every login attempt (success and failure) creates an audit entry
- Rule create/update/delete creates an audit entry
- User role changes create an audit entry
- Audit log visible in Admin UI with timestamp, actor, action, resource

---

## Summary Table

| Phase | Task | Description | Priority | Depends on |
|-------|------|-------------|----------|------------|
| 0 | 0.1 | Replace Redis → Valkey | P0 | — |
| 0 | 0.2 | Complete config.py fields | P0 | — |
| 0 | 0.3 | Add /ready endpoint | P0 | — |
| 1 | 1.1 | Repository layer + real DB queries | P0 | Phase 0 |
| 1 | 1.2 | DB seed data | P0 | 1.1 |
| 2 | 2.1 | OCSF normalizers | P0 | Phase 0 |
| 2 | 2.2 | Sigma engine | P0 | Phase 0 |
| 2 | 2.3 | Connectors (Wazuh/Zeek/Suricata) | P0 | Phase 0 |
| 2 | 2.4 | Wire pipeline in startup | P0 | 2.1, 2.2, 2.3 |
| 3 | 3.1 | Distributed WebSocket (Valkey pub/sub) | P1 | Phase 0, 2.4 |
| 3 | 3.2 | Distributed dedup cache (Valkey SETEX) | P1 | Phase 0, 2.4 |
| 3 | 3.3 | Docker Swarm / k3s manifests | P1 | 3.1, 3.2 |
| 4 | 4.1 | RBAC middleware | P1 | Phase 1 |
| 4 | 4.2 | Event search (OpenSearch) | P1 | Phase 2 |
| 4 | 4.3 | Real-time WebSocket frontend | P1 | 3.1 |
| 4 | 4.4 | Sigma rule editor completion | P1 | Phase 1 |
| 5 | 5.1 | MxGuard (Rust EDR agent) | P2 | Phase 2 |
| 5 | 5.2 | MxWatch (Rust NDR agent) | P2 | Phase 2 |
| 6 | 6.1 | Prometheus metrics + Grafana | P2 | Phase 3 |
| 6 | 6.2 | Audit log | P2 | Phase 4 |

---

## Agent Execution Notes

When assigning tasks to AI agents:

1. **Always instruct the agent to read all listed input files first** before writing any code.
2. **One task per agent instance** — tasks are designed for single-focus execution.
3. **Parallel execution**: Tasks within the same phase with no shared output files can run simultaneously.
4. **Verification**: Each task has acceptance criteria — the agent should run available tests before marking complete.
5. **Git discipline**: Each task should be a single focused commit with a descriptive message.
6. **No scope creep**: Agents must implement only what the task specifies — do not refactor unrelated code.

---

*Document version: 1.0 — 2026-02-19*
*Next review: After Phase 2 completion*
