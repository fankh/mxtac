# Agent Scheduler

An AI-powered task orchestration system that drives Claude Code to autonomously implement MxTac features. Tasks are defined in YAML, executed sequentially with dependency tracking, and results are streamed in real time.

## Table of Contents

- [Architecture](#architecture)
- [Setup](#setup)
  - [Local development](#local-development)
  - [Docker Compose](#docker-compose)
- [Task YAML format](#task-yaml-format)
- [API reference](#api-reference)
  - [Authentication](#authentication)
  - [Stats](#stats)
  - [Tasks](#tasks)
  - [Runs](#runs)
  - [Scheduler control](#scheduler-control)
  - [Server-Sent Events](#server-sent-events)
- [Configuration reference](#configuration-reference)
- [Data models](#data-models)

---

## Architecture

```
agent-scheduler/
├── backend/           # FastAPI + SQLite (port 13002)
│   └── agent_scheduler/
│       ├── main.py        # App entry, lifespan startup/shutdown
│       ├── config.py      # Pydantic-settings (reads .env)
│       ├── database.py    # SQLAlchemy async session
│       ├── models.py      # ORM models: Task, Run, Log
│       ├── scheduler.py   # Core scheduler loop + SSE broadcaster
│       ├── executor.py    # Subprocess invocation of Claude Code
│       ├── auth.py        # Password hashing helper
│       ├── task_loader.py # Parse YAML task definitions
│       ├── context.py     # Request context helpers
│       └── routes/
│           ├── api.py     # REST endpoints
│           ├── auth.py    # Login endpoint
│           └── sse.py     # Server-Sent Events stream
└── frontend/          # Next.js 15 + React 19 UI (port 13001)
    └── src/
        ├── app/       # Pages: dashboard, tasks, history, settings
        ├── components/# Reusable UI components
        ├── hooks/     # useApi, useSSE
        └── lib/       # api.ts HTTP client, types.ts
```

### How it works

1. **Task definitions** are loaded from YAML files into SQLite.
2. The **scheduler loop** polls every 30 s for `PENDING` tasks whose dependencies are satisfied.
3. Eligible tasks are dispatched to the **executor**, which spawns a `claude` subprocess with the task prompt.
4. On completion the scheduler optionally runs a **test command** and creates a **git commit**.
5. Progress is pushed to all connected clients via **Server-Sent Events**.

```
┌──────────────┐   YAML load    ┌──────────────┐
│  Task YAMLs  │ ─────────────► │   SQLite DB  │
└──────────────┘                └──────┬───────┘
                                       │ poll every 30 s
                                ┌──────▼───────┐
                                │  Scheduler   │ ─── git auto-commit
                                └──────┬───────┘
                                       │ spawn subprocess
                                ┌──────▼───────┐
                                │   Executor   │ ─── claude CLI
                                └──────┬───────┘
                                       │ SSE events
                         ┌─────────────▼──────────────┐
                         │  SSE Broadcaster (in-memory)│
                         └─────────────┬──────────────┘
                                       │
                              ┌────────▼────────┐
                              │  Next.js UI      │
                              └─────────────────┘
```

---

## Setup

### Prerequisites

- Python 3.11+
- Node.js 20+
- `claude` CLI installed and authenticated

### Local development

**Backend**

```bash
cd agent-scheduler/backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env — set AUTH_PASSWORD, MXTAC_PROJECT_ROOT, etc.

# Run
uvicorn agent_scheduler.main:app --host 0.0.0.0 --port 13002 --reload
```

The API is available at `http://localhost:13002`. Interactive docs: `http://localhost:13002/docs`.

**Frontend**

```bash
cd agent-scheduler/frontend

npm install

# Point at the backend (default: http://localhost:13002)
# Set NEXT_PUBLIC_API_URL in .env.local if needed

npm run dev   # http://localhost:13001
```

### Docker Compose

```bash
cd agent-scheduler

# Copy and configure environment
cp .env.example .env
# Set AUTH_PASSWORD in .env

docker compose up --build
```

| Service | URL |
|---------|-----|
| Frontend | http://localhost:13001 |
| Backend API | http://localhost:13002 |
| API docs | http://localhost:13002/docs |

---

## Task YAML format

Tasks are defined in YAML and loaded via `POST /api/tasks/load`.

```yaml
tasks:
  - task_id: mxtac-1.1         # Unique identifier (string, required)
    title: "Implement feature X" # Display name (required)
    category: backend            # Grouping label (optional)
    phase: "phase-1"             # Pipeline phase (optional)
    priority: 100                # Higher runs first (default: 0)
    prompt: |                    # Instruction sent to Claude Code (required)
      Implement X in file Y.
      Follow existing patterns.
    working_directory: /path/to/repo  # CWD for the Claude subprocess
    depends_on:                  # task_ids that must complete first
      - mxtac-1.0
    acceptance_criteria: "Tests pass and X is implemented"
    max_retries: 3               # Retry limit (default: 3)
    model: sonnet                # Override claude_model setting
    allowed_tools: []            # Restrict Claude tool access (empty = all)
    target_files: []             # Informational: files expected to change
```

**Dependency resolution:** a task becomes eligible only when all `depends_on` tasks reach status `completed` or `skipped`. Circular dependencies are not detected — avoid them.

**Retry backoff:** failed tasks are retried with exponential back-off:
`wait = scheduler_retry_backoff × 2^(retry_count - 1)` seconds.

---

## API reference

Base URL: `http://localhost:13002`

All endpoints except `/health`, `/api/auth/check`, and `/api/auth/login` require the `Authorization: Bearer <token>` header when `AUTH_PASSWORD` is set.

### Authentication

#### `GET /api/auth/check`

Returns whether password authentication is enabled.

```json
{ "auth_enabled": true }
```

#### `POST /api/auth/login`

```json
// Request
{ "password": "your-password" }

// Response 200
{ "token": "<hashed-token>" }

// Response 401
{ "detail": "Invalid password" }
```

---

### Stats

#### `GET /api/stats`

Dashboard summary.

```json
{
  "total_tasks": 42,
  "status_counts": {
    "pending": 10,
    "running": 2,
    "completed": 28,
    "failed": 1,
    "skipped": 1,
    "cancelled": 0
  },
  "phase_counts": {
    "phase-1": { "total": 15, "completed": 12, "pending": 3, "failed": 0, "running": 0 }
  },
  "scheduler": { "running": true, "paused": false },
  "executor": { "running_count": 2 }
}
```

---

### Tasks

#### `GET /api/tasks`

List tasks with optional filtering and pagination.

| Query param | Type | Description |
|------------|------|-------------|
| `status` | string | Filter by status (`pending`, `running`, `completed`, `failed`, `skipped`, `cancelled`) |
| `phase` | string | Filter by phase |
| `category` | string | Filter by category |
| `search` | string | Case-insensitive title search |
| `limit` | int | Max results (default: 100, max: 500) |
| `offset` | int | Pagination offset (default: 0) |

```json
{
  "tasks": [ /* Task objects */ ],
  "total": 42,
  "limit": 100,
  "offset": 0
}
```

#### `GET /api/tasks/{id}`

Get a single task by database ID.

```json
{
  "id": 1,
  "task_id": "mxtac-1.1",
  "title": "Implement feature X",
  "category": "backend",
  "phase": "phase-1",
  "priority": 100,
  "status": "completed",
  "prompt": "...",
  "depends_on": ["mxtac-1.0"],
  "working_directory": "/path/to/repo",
  "target_files": [],
  "acceptance_criteria": "Tests pass",
  "retry_count": 0,
  "max_retries": 3,
  "git_commit_sha": "abc1234",
  "model": "sonnet",
  "allowed_tools": [],
  "test_status": "passed",
  "test_output": "...",
  "created_at": "2026-02-21T10:00:00",
  "updated_at": "2026-02-21T10:15:00"
}
```

#### `GET /api/tasks/{id}/runs`

Get all execution runs for a task (most recent first).

#### `POST /api/tasks/load`

Load tasks from a YAML file or directory.

```json
// Request
{ "path": "/path/to/tasks.yml" }

// Response
{ "created": 5, "skipped": 2, "total_parsed": 7 }
```

Tasks with duplicate `task_id` are skipped (not updated).

#### `POST /api/tasks/{id}/trigger`

Manually trigger a pending task immediately (bypasses scheduler timing).

```json
{ "status": "triggered" }
```

#### `POST /api/tasks/{id}/skip`

Mark a task as skipped. Unblocks dependent tasks.

```json
{ "status": "skipped" }
```

#### `POST /api/tasks/{id}/reset`

Reset a completed/failed/skipped task back to `pending`.

```json
{ "status": "reset" }
```

#### `POST /api/tasks/{id}/cancel`

Cancel a running task (sends SIGTERM to the Claude subprocess).

```json
{ "status": "cancelled" }
```

---

### Runs

#### `GET /api/runs`

List execution runs with optional filtering.

| Query param | Type | Description |
|------------|------|-------------|
| `status` | string | Filter by run status (`running`, `completed`, `failed`, `timeout`, `cancelled`) |
| `limit` | int | Max results (default: 50, max: 200) |
| `offset` | int | Pagination offset |

```json
{
  "runs": [
    {
      "id": 1,
      "task_id": 1,
      "attempt": 1,
      "status": "completed",
      "exit_code": 0,
      "pid": 12345,
      "stdout": "...",
      "stderr": "",
      "git_diff": "...",
      "files_changed": ["app/backend/app/main.py"],
      "duration_seconds": 42.3,
      "started_at": "2026-02-21T10:00:00",
      "finished_at": "2026-02-21T10:00:42",
      "task_title": "Implement feature X",
      "task_task_id": "mxtac-1.1",
      "task_phase": "phase-1"
    }
  ],
  "total": 10,
  "limit": 50,
  "offset": 0
}
```

---

### Scheduler control

#### `GET /api/scheduler/status`

```json
{ "running": true, "paused": false }
```

#### `POST /api/scheduler/control`

```json
// Request — action: "start" | "stop" | "pause" | "resume"
{ "action": "start" }

// Response
{
  "status": "ok",
  "scheduler": { "running": true, "paused": false }
}
```

#### `GET /api/scheduler/settings`

Returns current runtime settings (does not persist).

```json
{
  "max_concurrent": 2,
  "spawn_delay": 30,
  "task_timeout": 1800,
  "model": "sonnet",
  "retry_max": 5,
  "retry_backoff": 60,
  "github_repo_url": "https://github.com/...",
  "test_command": "",
  "test_timeout": 300
}
```

#### `PUT /api/scheduler/settings`

Update one or more runtime settings. All fields are optional.

```json
// Request
{
  "max_concurrent": 3,
  "spawn_delay": 60,
  "task_timeout": 3600,
  "model": "opus",
  "retry_max": 3,
  "retry_backoff": 120,
  "github_repo_url": "https://github.com/org/repo",
  "test_command": "pytest tests/ -q",
  "test_timeout": 600
}

// Response
{ "status": "updated" }
```

---

### Phases and categories

#### `GET /api/phases`

Aggregated task counts grouped by pipeline phase.

```json
[
  {
    "phase": "phase-1",
    "total": 15,
    "completed": 12,
    "failed": 0,
    "running": 1,
    "pending": 2,
    "skipped": 0,
    "cancelled": 0
  }
]
```

#### `GET /api/categories`

Aggregated task counts grouped by category, including nested task list.

---

### Server-Sent Events

#### `GET /api/events`

Persistent SSE stream for real-time UI updates. No auth required (browser `EventSource` cannot send headers).

**Connection:**

```js
const es = new EventSource('http://localhost:13002/api/events');

es.addEventListener('task_update', (e) => {
  const task = JSON.parse(e.data);
});

es.addEventListener('run_update', (e) => {
  const run = JSON.parse(e.data);
});

es.addEventListener('log', (e) => {
  const entry = JSON.parse(e.data);
});
```

**Event types:**

| Event | Data | Description |
|-------|------|-------------|
| `connected` | `{ "status": "connected" }` | Sent once on connection |
| `task_update` | Task object | Task status changed |
| `run_update` | Run object | Run started or finished |
| `log` | `{ "run_id", "level", "message", "timestamp" }` | Live log line from running task |
| `keepalive` | `{}` | Sent every 30 s if no other events |

---

## Configuration reference

Copy `.env.example` to `.env` and adjust values. All variables have defaults and are optional unless marked **required**.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULER_DB_URL` | `sqlite+aiosqlite:///./data/scheduler.db` | SQLAlchemy async database URL |
| `SCHEDULER_HOST` | `0.0.0.0` | Bind address for uvicorn |
| `SCHEDULER_PORT` | `13002` | Listen port |
| `MXTAC_PROJECT_ROOT` | `/home/khchoi/development/new-research/mitre-attack/mxtac` | Absolute path to the MxTac repository root |
| `AUTH_PASSWORD` | _(empty)_ | Dashboard password; empty disables auth entirely |

### Scheduler tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULER_MAX_CONCURRENT` | `2` | Max tasks running simultaneously |
| `SCHEDULER_SPAWN_DELAY` | `3` | Seconds between consecutive task spawns |
| `SCHEDULER_TASK_TIMEOUT` | `1800` | Per-task execution timeout (seconds) |
| `SCHEDULER_RETRY_MAX` | `5` | Max retry attempts per task |
| `SCHEDULER_QUALITY_RETRY_MAX` | `10` | Max retries for quality-failure (verifier-rejected) tasks |
| `SCHEDULER_RETRY_BACKOFF` | `60` | Base backoff for exponential retry (seconds) |
| `SCHEDULER_AUTO_START` | `false` | Start scheduler automatically on server boot |
| `SCHEDULER_TEST_COMMAND` | _(empty)_ | Shell command run after each task completes; empty disables |
| `SCHEDULER_TEST_TIMEOUT` | `300` | Test command timeout (seconds) |
| `GITHUB_REPO_URL` | `https://github.com/fankh/mxtac` | Used in git auto-commit messages |

### Claude API

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | _(empty)_ | **Required** for agent features; leave empty to use only the `claude` CLI subprocess mode |
| `CLAUDE_MODEL` | `claude-sonnet-4-20250514` | Default Claude model for task execution and agents |
| `CLAUDE_MAX_TOKENS` | `16384` | Max tokens per Claude API call |

### Autonomous agents

Each agent runs as a background loop inside the scheduler process. All agents default to disabled except `TaskCreatorAgent` and `VerifierAgent`.

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_TASK_CREATOR_ENABLED` | `true` | Enable TaskCreatorAgent (generates new tasks from spec docs) |
| `AGENT_TASK_CREATOR_INTERVAL` | `300` | Polling interval in seconds |
| `AGENT_TASK_CREATOR_MAX_TASKS_PER_CYCLE` | `20` | Max tasks created per cycle |
| `AGENT_TASK_CREATOR_USE_CLAUDE` | `true` | Use Claude API (vs. heuristic) |
| `AGENT_VERIFIER_ENABLED` | `true` | Enable VerifierAgent (validates completed tasks) |
| `AGENT_VERIFIER_INTERVAL` | `180` | Polling interval in seconds |
| `AGENT_VERIFIER_MAX_PER_CYCLE` | `3` | Max tasks verified per cycle |
| `AGENT_VERIFIER_USE_CLAUDE` | `true` | Use Claude API for verification |
| `AGENT_VERIFIER_FAIL_ACTION` | `reset` | Action on failed verification: `reset` (re-queue) or `mark` (mark failed) |
| `AGENT_TEST_ENABLED` | `false` | Enable TestAgent (runs pytest after completions) |
| `AGENT_TEST_INTERVAL` | `300` | Polling interval in seconds |
| `AGENT_TEST_FAIL_ACTION` | `reset` | Action on test failure: `reset` or `mark` |
| `AGENT_TEST_FULL_SUITE_EVERY` | `6` | Run full test suite every Nth cycle (otherwise incremental) |
| `AGENT_TEST_TIMEOUT` | `300` | Test run timeout (seconds) |
| `AGENT_LINT_ENABLED` | `false` | Enable LintAgent (runs ruff/flake8) |
| `AGENT_LINT_INTERVAL` | `600` | Polling interval in seconds |
| `AGENT_LINT_ERROR_THRESHOLD` | `50` | Max lint errors before flagging a task |
| `AGENT_INTEGRATION_ENABLED` | `false` | Enable IntegrationAgent (smoke-tests running service) |
| `AGENT_INTEGRATION_INTERVAL` | `900` | Polling interval in seconds |
| `AGENT_INTEGRATION_SMOKE_URL` | _(empty)_ | URL to probe for smoke test (e.g. `http://localhost:13002/health`) |
| `AGENT_SECURITY_ENABLED` | `false` | Enable SecurityAuditAgent (runs bandit) |
| `AGENT_SECURITY_INTERVAL` | `1800` | Polling interval in seconds |
| `AGENT_SECURITY_BANDIT_SKIP` | _(empty)_ | Comma-separated bandit test IDs to skip |

---

## Data models

### TaskStatus

| Value | Meaning |
|-------|---------|
| `pending` | Waiting to be scheduled |
| `running` | Claude subprocess active |
| `completed` | Exited with code 0 |
| `failed` | Exited non-zero or timed out (may retry) |
| `skipped` | Manually skipped; counts as satisfied dependency |
| `cancelled` | Manually cancelled while running |

### RunStatus

| Value | Meaning |
|-------|---------|
| `running` | Subprocess is active |
| `completed` | Exited with code 0 |
| `failed` | Exited non-zero |
| `timeout` | Exceeded `SCHEDULER_TASK_TIMEOUT` |
| `cancelled` | Killed via cancel action |

### Database tables

**`tasks`** — one row per task definition loaded from YAML

**`runs`** — one row per execution attempt (multiple if retried)

**`logs`** — streaming log lines captured from the Claude subprocess stdout/stderr
