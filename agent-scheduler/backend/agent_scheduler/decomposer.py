"""Auto task decomposition via Claude API.

Decomposes a high-level feature description into atomic, dependency-chained
subtasks compatible with the agent scheduler.
"""

import asyncio
import json
import logging
import re

import anthropic
import httpx

from .config import settings
from .context import SYSTEM_CONTEXT

logger = logging.getLogger(__name__)

# Shared client — mirrors BaseAgent._get_claude_client() but decoupled
# so user-initiated decomposition is not blocked by the agent semaphore.
_client: anthropic.AsyncAnthropic | None = None


def _get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        kwargs = {}
        if settings.anthropic_api_key:
            kwargs["api_key"] = settings.anthropic_api_key
        kwargs["timeout"] = httpx.Timeout(
            connect=30.0,
            read=300.0,
            write=30.0,
            pool=30.0,
        )
        _client = anthropic.AsyncAnthropic(**kwargs)
    return _client


DECOMPOSER_ROLE = """
You are a task decomposition specialist for the MxTac agent scheduler.

The scheduler executes tasks autonomously using Claude Code CLI. Each task is a
self-contained unit of work with a prompt, target files, acceptance criteria, and
optional dependency chains (`depends_on`). Tasks run in isolated git branches and
are verified + tested automatically.

Your job: break a high-level feature description into 3-{max_subtasks} atomic subtasks
that the scheduler can execute sequentially (via depends_on chains) or in parallel.
"""

DECOMPOSITION_RULES = """
## Decomposition Rules

1. **Atomic scope**: Each subtask must be completable in a single Claude Code session
   (~20 min). If a subtask would require modifying more than 4-5 files, split it further.
2. **depends_on chains**: Use `depends_on` to express ordering. Later subtasks list
   earlier subtask IDs they depend on. Independent subtasks have empty depends_on.
3. **"Read X as reference" anchors**: When a subtask builds on prior work, its prompt
   should instruct the agent to read the relevant files first.
4. **Narrow acceptance criteria**: Each subtask must have clear, verifiable acceptance
   criteria (e.g., "tests pass", "endpoint returns 200", "file exists with X structure").
5. **target_files**: List the primary files the subtask will create or modify.
6. **working_directory**: Set to the project subdirectory where the agent should work.
   Default: the MxTac project root.
7. **task_id format**: `{prefix}.N` where N is 1-based sequential.
8. **prompt**: Write a detailed, self-contained prompt for the agent. Include specific
   file paths, function signatures, and expected behavior. The agent has no memory of
   other subtasks — it only sees its own prompt + the codebase.
9. **priority**: Higher number = higher priority. First subtask gets highest priority.
10. **category and phase**: Inherit from the parent request unless the subtask clearly
    belongs to a different category.

## Output Format

Return a JSON array of subtask objects. Each object has these fields:
- `task_id` (string): "{prefix}.N"
- `title` (string): Short descriptive title
- `prompt` (string): Full agent prompt
- `depends_on` (array of strings): Task IDs this depends on (empty for first tasks)
- `target_files` (array of strings): Files to create/modify
- `working_directory` (string): Working directory path
- `acceptance_criteria` (string): How to verify completion
- `priority` (integer): Execution priority (descending)
- `category` (string): Task category
- `phase` (string): Project phase

Return ONLY the JSON array, no markdown fences, no commentary.
"""

EXAMPLE_OUTPUT = """
## Example

For prefix "mxtac-syslog" with 3 subtasks:

[
  {
    "task_id": "mxtac-syslog.1",
    "title": "Create syslog UDP listener",
    "prompt": "Implement a UDP syslog listener in app/connectors/syslog.py that...",
    "depends_on": [],
    "target_files": ["app/connectors/syslog.py", "tests/connectors/test_syslog.py"],
    "working_directory": "app/backend",
    "acceptance_criteria": "UDP listener binds to port 514, receives messages, tests pass",
    "priority": 30,
    "category": "connector",
    "phase": "1.0"
  },
  {
    "task_id": "mxtac-syslog.2",
    "title": "Add syslog message parser",
    "prompt": "Read app/connectors/syslog.py as reference. Add RFC 5424 parsing...",
    "depends_on": ["mxtac-syslog.1"],
    "target_files": ["app/connectors/syslog.py", "tests/connectors/test_syslog.py"],
    "working_directory": "app/backend",
    "acceptance_criteria": "Parser extracts facility, severity, timestamp, message; tests pass",
    "priority": 20,
    "category": "connector",
    "phase": "1.0"
  },
  {
    "task_id": "mxtac-syslog.3",
    "title": "Add OCSF normalization for syslog events",
    "prompt": "Read app/connectors/syslog.py and app/pipeline/ocsf.py as reference...",
    "depends_on": ["mxtac-syslog.2"],
    "target_files": ["app/connectors/syslog.py", "app/pipeline/ocsf.py"],
    "working_directory": "app/backend",
    "acceptance_criteria": "Syslog events normalized to OCSF format; integration test passes",
    "priority": 10,
    "category": "connector",
    "phase": "1.0"
  }
]
"""


async def _gather_codebase_context() -> str:
    """Run `find` on the project root to collect ~300 file paths for context."""
    project_root = settings.mxtac_project_root
    cmd = (
        f"find {project_root} "
        "-not -path '*/.git/*' "
        "-not -path '*/node_modules/*' "
        "-not -path '*/__pycache__/*' "
        "-not -path '*/.venv/*' "
        "-not -path '*/venv/*' "
        "-not -path '*/.mypy_cache/*' "
        "-not -path '*/.pytest_cache/*' "
        "-not -path '*/dist/*' "
        "-not -path '*/build/*' "
        "-not -name '*.pyc' "
        "-not -name '*.egg-info' "
        "-type f "
        "| head -300 "
        "| sort"
    )
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        return stdout.decode(errors="replace").strip()
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning("Failed to gather codebase context: %s", e)
        return "(codebase tree unavailable)"


def _build_system_prompt(max_subtasks: int) -> str:
    role = DECOMPOSER_ROLE.replace("{max_subtasks}", str(max_subtasks))
    return f"{SYSTEM_CONTEXT}\n\n{role}"


def _build_user_message(
    description: str,
    prefix: str,
    category: str,
    phase: str,
    max_subtasks: int,
    codebase_tree: str,
) -> str:
    rules = DECOMPOSITION_RULES.replace("{prefix}", prefix)
    return f"""## Feature to Decompose

{description}

## Parameters
- prefix: `{prefix}`
- category: `{category}`
- phase: `{phase}`
- max_subtasks: {max_subtasks}

## Codebase File Tree

```
{codebase_tree}
```

{rules}

{EXAMPLE_OUTPUT}

Now decompose the feature above into {max_subtasks} or fewer atomic subtasks.
Return ONLY the JSON array."""


def _parse_subtasks_response(text: str, prefix: str) -> list[dict]:
    """Extract and validate the JSON subtask array from Claude's response."""
    # Try to find a JSON array in the response
    # First try: direct parse
    text = text.strip()
    if text.startswith("["):
        try:
            subtasks = json.loads(text)
            return _validate_subtasks(subtasks, prefix)
        except json.JSONDecodeError:
            pass

    # Second try: extract from markdown code fence
    match = re.search(r"```(?:json)?\s*\n(\[.*?\])\s*\n```", text, re.DOTALL)
    if match:
        try:
            subtasks = json.loads(match.group(1))
            return _validate_subtasks(subtasks, prefix)
        except json.JSONDecodeError:
            pass

    # Third try: find the first [ ... ] block
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        try:
            subtasks = json.loads(match.group(0))
            return _validate_subtasks(subtasks, prefix)
        except json.JSONDecodeError:
            pass

    raise ValueError("Could not parse subtasks JSON from Claude response")


def _validate_subtasks(subtasks: list, prefix: str) -> list[dict]:
    """Validate required fields and normalize subtask dicts."""
    if not isinstance(subtasks, list) or len(subtasks) == 0:
        raise ValueError("Expected a non-empty JSON array of subtasks")

    required_fields = {"task_id", "title", "prompt"}
    validated = []
    for i, st in enumerate(subtasks):
        if not isinstance(st, dict):
            raise ValueError(f"Subtask {i} is not a dict")
        missing = required_fields - set(st.keys())
        if missing:
            raise ValueError(f"Subtask {i} missing required fields: {missing}")

        # Ensure task_id follows prefix format
        if not st["task_id"].startswith(prefix):
            st["task_id"] = f"{prefix}.{i + 1}"

        # Defaults for optional fields
        st.setdefault("depends_on", [])
        st.setdefault("target_files", [])
        st.setdefault("working_directory", "")
        st.setdefault("acceptance_criteria", "")
        st.setdefault("priority", max(0, 100 - i * 10))
        st.setdefault("category", "")
        st.setdefault("phase", "")

        validated.append(st)

    return validated


async def decompose_task(
    description: str,
    prefix: str,
    category: str = "",
    phase: str = "",
    max_subtasks: int = 8,
) -> list[dict]:
    """Decompose a feature description into atomic subtasks via Claude API.

    Args:
        description: The high-level feature description.
        prefix: Task ID prefix (e.g., "mxtac-syslog").
        category: Category for generated subtasks.
        phase: Phase for generated subtasks.
        max_subtasks: Maximum number of subtasks (3-8).

    Returns:
        List of subtask dicts ready for load_tasks_into_db().

    Raises:
        ValueError: If Claude response cannot be parsed.
        anthropic.APIError: If Claude API call fails.
        asyncio.TimeoutError: If Claude API call times out.
    """
    codebase_tree = await _gather_codebase_context()

    system_prompt = _build_system_prompt(max_subtasks)
    user_message = _build_user_message(
        description, prefix, category, phase, max_subtasks, codebase_tree
    )

    client = _get_client()

    response = await asyncio.wait_for(
        client.messages.create(
            model=settings.claude_model,
            max_tokens=16384,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        ),
        timeout=180,
    )

    text_parts = []
    for block in response.content:
        if block.type == "text":
            text_parts.append(block.text)
    response_text = "\n".join(text_parts)

    subtasks = _parse_subtasks_response(response_text, prefix)

    # Backfill category/phase from request if Claude omitted them
    for st in subtasks:
        if not st.get("category"):
            st["category"] = category
        if not st.get("phase"):
            st["phase"] = phase

    logger.info("Decomposed '%s' into %d subtasks", prefix, len(subtasks))
    return subtasks
