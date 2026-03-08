"""System context loaded from per-project context.md file."""

import logging
from pathlib import Path

from .config import settings

logger = logging.getLogger(__name__)

# Max chars to include per pre-read file (avoid blowing up context)
_MAX_FILE_CHARS = 6000
# Max total chars for all pre-read content
_MAX_TOTAL_CONTEXT = 30000


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


def build_file_context(
    target_files: list[str],
    working_directory: str | None = None,
) -> str:
    """Pre-read target files and their siblings to reduce exploration iterations.

    Reads:
      1. Each target file (if it exists — for modify tasks)
      2. Sibling files in the same directory (to understand patterns)
      3. Parent build file (build.gradle.kts, Cargo.toml, package.json)

    Returns a formatted string to inject into the user message.
    """
    if not target_files:
        return ""

    base = Path(working_directory or settings.project_root)
    sections: list[str] = []
    total_chars = 0
    seen_paths: set[str] = set()

    def _read_file(p: Path, label: str) -> bool:
        nonlocal total_chars
        resolved = str(p.resolve())
        if resolved in seen_paths or not p.exists() or not p.is_file():
            return False
        seen_paths.add(resolved)
        try:
            content = p.read_text(errors="replace")
            if len(content) > _MAX_FILE_CHARS:
                content = content[:_MAX_FILE_CHARS] + "\n... (truncated)"
            if total_chars + len(content) > _MAX_TOTAL_CONTEXT:
                return False
            total_chars += len(content)
            rel = str(p.relative_to(Path(settings.project_root)))
            sections.append(f"### {label}: {rel}\n```\n{content}\n```")
            return True
        except Exception:
            return False

    for tf in target_files:
        p = Path(tf) if Path(tf).is_absolute() else base / tf
        _read_file(p, "Target file")

        # Read sibling files (same directory) to show patterns
        parent = p.parent
        if parent.exists():
            siblings = sorted(parent.glob("*"))
            for sib in siblings[:5]:  # max 5 siblings
                if sib.is_file() and sib.suffix in (
                    ".java", ".rs", ".ts", ".tsx", ".py", ".kt",
                ):
                    _read_file(sib, "Sibling")

    # Find nearest build file
    for tf in target_files[:1]:
        p = Path(tf) if Path(tf).is_absolute() else base / tf
        for parent in p.parents:
            for build_name in (
                "build.gradle.kts", "build.gradle", "Cargo.toml",
                "package.json", "pom.xml",
            ):
                bf = parent / build_name
                if bf.exists():
                    _read_file(bf, "Build file")
                    break
            else:
                continue
            break

    if not sections:
        return ""

    header = (
        "## Pre-loaded File Context\n\n"
        "The following files have been pre-read to save you time. "
        "Use this context instead of reading these files again.\n\n"
    )
    return header + "\n\n".join(sections)


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
    task_prompt: str,
    task_id: str,
    attempt: int,
    max_retries: int,
    target_files: list[str] | None = None,
    working_directory: str | None = None,
) -> tuple[str, str]:
    """Build (system, user_message) tuple for the Anthropic Messages API.

    Returns:
        system: The system prompt (project context + conventions).
        user_message: The task-specific user message (file context + retry info + task prompt).
    """
    user_parts = []

    # Pre-read file context (saves 30-50 read_file iterations)
    if target_files:
        file_ctx = build_file_context(target_files, working_directory)
        if file_ctx:
            user_parts.append(file_ctx)

    if attempt > 1:
        user_parts.append(_build_retry_info(attempt, max_retries).strip())

    user_parts.append(task_prompt)
    return get_system_context(), "\n\n---\n\n".join(user_parts)
