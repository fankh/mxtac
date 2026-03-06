import json
import logging
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .database import async_session
from .models import Task, TaskStatus

logger = logging.getLogger(__name__)


def parse_yaml_tasks(yaml_path: str | Path) -> list[dict]:
    """Parse a YAML task file and return a list of task dicts."""
    yaml_path = Path(yaml_path)
    if not yaml_path.exists():
        raise FileNotFoundError(f"Task file not found: {yaml_path}")

    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)

    if not data:
        return []

    tasks = data.get("tasks", [])
    if not isinstance(tasks, list):
        raise ValueError(f"Expected 'tasks' to be a list in {yaml_path}")

    return tasks


def parse_yaml_directory(dir_path: str | Path) -> list[dict]:
    """Parse all YAML files in a directory."""
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        raise FileNotFoundError(f"Directory not found: {dir_path}")

    all_tasks = []
    for yaml_file in sorted([*dir_path.glob("*.yml"), *dir_path.glob("*.yaml")]):
        try:
            tasks = parse_yaml_tasks(yaml_file)
            all_tasks.extend(tasks)
            logger.info(f"Loaded {len(tasks)} tasks from {yaml_file.name}")
        except Exception:
            logger.exception(f"Failed to parse {yaml_file}")

    return all_tasks


def _ensure_str(value) -> str:
    """Coerce list/dict values to string (handles Claude-generated task defs)."""
    if isinstance(value, list):
        return "\n".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value)
    return str(value) if value else ""


_PRIORITY_MAP = {"critical": 10, "high": 7, "medium": 5, "low": 3}


def _ensure_int_priority(value) -> int:
    """Coerce priority to int (handles 'high', 'medium', etc. from Claude)."""
    if isinstance(value, int):
        return value
    if value is None:
        return 0
    try:
        return int(value)
    except (ValueError, TypeError):
        return _PRIORITY_MAP.get(str(value).lower(), 0)


async def load_tasks_into_db(task_defs: list[dict], auto_split: bool = True) -> tuple[int, int]:
    """Load task definitions into the database. Returns (created, skipped) counts.

    When auto_split=True (default), oversized tasks are split before insertion.
    """
    from .config import settings

    # Auto-split oversized tasks at load time
    if auto_split and settings.scheduler_auto_split_enabled and task_defs:
        from .agents.task_creator import TaskCreatorAgent
        creator = TaskCreatorAgent()
        task_defs = await creator._estimate_and_split(task_defs)

    created = 0
    skipped = 0

    async with async_session() as session:
        for td in task_defs:
            task_id = td.get("task_id", "")
            if not task_id:
                logger.warning(f"Skipping task with no task_id: {td.get('title', '?')}")
                skipped += 1
                continue

            # Check if already exists
            existing = await session.execute(
                select(Task).where(Task.task_id == task_id)
            )
            if existing.scalar_one_or_none() is not None:
                skipped += 1
                continue

            task = Task(
                task_id=task_id,
                title=td.get("title", ""),
                category=td.get("category", ""),
                phase=td.get("phase", ""),
                priority=_ensure_int_priority(td.get("priority", 0)),
                status=TaskStatus.PENDING,
                prompt=td.get("prompt", ""),
                depends_on=json.dumps(td.get("depends_on", [])),
                working_directory=td.get("working_directory", ""),
                target_files=json.dumps(td.get("target_files", [])),
                acceptance_criteria=_ensure_str(td.get("acceptance_criteria", "")),
                max_retries=td.get("max_retries", 3),
                model=td.get("model"),
                allowed_tools=json.dumps(td.get("allowed_tools", [])),
            )
            session.add(task)
            created += 1

        await session.commit()

    logger.info(f"Loaded tasks: {created} created, {skipped} skipped")

    # Wake scheduler to dispatch newly loaded tasks immediately
    if created > 0:
        from .scheduler import scheduler
        scheduler.notify()

    return created, skipped
