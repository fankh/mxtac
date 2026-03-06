"""System context loaded from per-project context.md file."""

import logging
from pathlib import Path

from .config import settings

logger = logging.getLogger(__name__)


def get_system_context() -> str:
    """Load system context from {project_root}/.agent-scheduler/context.md.

    Falls back to a minimal default if the file doesn't exist.
    """
    context_path = Path(settings.project_root) / ".agent-scheduler" / "context.md"
    if context_path.exists():
        try:
            return context_path.read_text(encoding="utf-8").strip()
        except Exception:
            logger.exception("Failed to read context from %s", context_path)
    return (
        f"You are an autonomous AI agent working on the {settings.project_name} project "
        f"at {settings.project_root}."
    )


def build_prompt(task_prompt: str, task_id: str, attempt: int, max_retries: int) -> str:
    """Build the full prompt with system context prepended (legacy, for text mode)."""
    retry_info = ""
    if attempt > 1:
        retry_info = _build_retry_info(attempt, max_retries)
    return f"{get_system_context()}\n{retry_info}\n---\n\n{task_prompt}"


def _build_retry_info(attempt: int, max_retries: int) -> str:
    return f"""

## RETRY ATTEMPT {attempt} of {max_retries}

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
    return get_system_context(), "\n\n---\n\n".join(user_parts)
