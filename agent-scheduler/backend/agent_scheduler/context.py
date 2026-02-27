"""System context template prepended to every task prompt."""

SYSTEM_CONTEXT = """
# MxTac Agent Context

You are an autonomous AI agent working on MxTac, a MITRE ATT&CK-aligned security platform.

## CRITICAL RULES

1. **NEVER trust previous implementations blindly.** Always read and verify existing code before building on it. Previous agents may have written incorrect, incomplete, or placeholder code. Validate everything yourself.
2. **Read before you write.** Before modifying any file, read it first. Understand the current state. Do not assume any file contains what you expect.
3. **Test your work.** After making changes, run the relevant tests to verify correctness. If tests don't exist, create them. If tests fail, fix them before considering the task complete.
4. **Do not break existing functionality.** Run the existing test suite after your changes. If you break something, fix it.
5. **Follow existing patterns.** Match the code style, naming conventions, and architecture patterns already in the codebase. Do not introduce new patterns without reason.

## Project Structure

```
/home/khchoi/development/new-research/mitre-attack/mxtac/
├── app/
│   ├── backend/                    # FastAPI + Python 3.13
│   │   ├── app/
│   │   │   ├── main.py             # FastAPI app entry
│   │   │   ├── api/v1/             # API endpoints (versioned)
│   │   │   │   ├── router.py       # Main API router
│   │   │   │   └── endpoints/      # Individual endpoint modules
│   │   │   ├── core/               # Config, security, RBAC
│   │   │   │   ├── config.py       # Settings (Pydantic BaseSettings)
│   │   │   │   ├── security.py     # JWT, password hashing
│   │   │   │   └── rbac.py         # Role-based access control
│   │   │   ├── models/             # SQLAlchemy ORM models
│   │   │   ├── schemas/            # Pydantic request/response schemas
│   │   │   ├── repositories/       # Data access layer (repository pattern)
│   │   │   ├── services/           # Business logic layer
│   │   │   ├── engine/             # Sigma detection engine
│   │   │   ├── pipeline/           # Event ingestion pipeline
│   │   │   ├── connectors/         # External connectors (Wazuh, Zeek, etc.)
│   │   │   └── db/                 # Database session, migrations base
│   │   ├── tests/                  # pytest test suite
│   │   │   ├── conftest.py         # Shared fixtures
│   │   │   ├── api/v1/             # API endpoint tests
│   │   │   ├── core/               # Core module tests
│   │   │   ├── repositories/       # Repository tests
│   │   │   ├── services/           # Service tests
│   │   │   └── pipeline/           # Pipeline tests
│   │   ├── alembic/                # DB migrations
│   │   ├── sigma_rules/            # Sigma detection rules (YAML)
│   │   ├── pyproject.toml          # Python dependencies
│   │   └── requirements.txt        # Pinned dependencies
│   │
│   ├── frontend/                   # React 19 + TypeScript + Vite
│   │   └── src/
│   │       ├── App.tsx             # Main app with routing
│   │       ├── components/         # Reusable UI components
│   │       ├── hooks/              # Custom React hooks
│   │       ├── lib/                # Utilities, API client
│   │       ├── stores/             # State management (Zustand)
│   │       ├── types/              # TypeScript type definitions
│   │       └── tests/              # Frontend tests (Vitest)
│   │
│   ├── docker-compose.yml          # Development stack
│   ├── docker-compose.prod.yml     # Production stack
│   └── nginx/                      # Reverse proxy config
│
├── agents/
│   ├── mxguard/                    # EDR agent (Rust)
│   └── mxwatch/                    # NDR agent (Rust)
│
└── docs/                           # Architecture & specs
```

## Tech Stack

**Backend:** Python 3.13, FastAPI, SQLAlchemy 2.x (async), PostgreSQL, Alembic, Pydantic v2, pytest
**Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Zustand, Vitest
**Agents:** Rust (Tokio async runtime)
**Detection:** Sigma rules (YAML), OCSF normalization
**Queue:** Redis / in-memory (MessageQueue ABC)

## Conventions

- **Backend API:** Versioned under `/api/v1/`, repository pattern for data access, service layer for business logic
- **Models:** SQLAlchemy mapped classes in `app/models/`, Pydantic schemas in `app/schemas/`
- **Tests:** pytest with async support (`pytest-asyncio`), fixtures in `conftest.py`, test files mirror source structure
- **Frontend:** Functional components, hooks for logic, Zustand for state, `lib/api.ts` for API calls
- **Git:** No Claude attribution in commits. Author: fankh

## Retry Context

This task may be a **retry after a previous failure**. If so:
- The previous attempt's code changes are still in the working directory
- Those changes may be **partially correct, completely wrong, or conflicting**
- **Do NOT assume the previous attempt was correct** — verify everything independently
- Read the current state of all relevant files before making any changes
- If the previous attempt left broken tests or incomplete code, fix or rewrite as needed

## Task Execution Steps

1. **Explore:** Read relevant existing files to understand current state
2. **Plan:** Determine what needs to change and in what order
3. **Implement:** Make changes following project conventions
4. **Verify:** Run tests (`pytest` for backend, `npx vitest` for frontend)
5. **Fix:** If tests fail, debug and fix until they pass
""".strip()


def build_prompt(task_prompt: str, task_id: str, attempt: int, max_retries: int) -> str:
    """Build the full prompt with system context prepended (legacy, for text mode)."""
    retry_info = ""
    if attempt > 1:
        retry_info = _build_retry_info(attempt, max_retries)
    return f"{SYSTEM_CONTEXT}\n{retry_info}\n---\n\n{task_prompt}"


def _build_retry_info(attempt: int, max_retries: int) -> str:
    return f"""

## ⚠ RETRY ATTEMPT {attempt} of {max_retries}

This is retry attempt {attempt}. The previous {attempt - 1} attempt(s) FAILED.
- The previous agent's changes may still be in the working directory
- **DO NOT trust those changes.** Read every file you plan to modify and verify its current state
- Identify what went wrong in the previous attempt and take a different approach if needed
- Run tests after your changes to make sure they pass
"""


def build_api_messages(
    task_prompt: str, task_id: str, attempt: int, max_retries: int
) -> tuple[str, str]:
    """Build (system, user_message) tuple for the Anthropic Messages API.

    Returns:
        system: The system prompt (project context + conventions).
        user_message: The task-specific user message (retry info + task prompt).
    """
    user_parts = []
    if attempt > 1:
        user_parts.append(_build_retry_info(attempt, max_retries).strip())
    user_parts.append(task_prompt)
    return SYSTEM_CONTEXT, "\n\n---\n\n".join(user_parts)
