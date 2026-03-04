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


async def load_tasks_into_db(task_defs: list[dict]) -> tuple[int, int]:
    """Load task definitions into the database. Returns (created, skipped) counts."""
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
                priority=td.get("priority", 0),
                status=TaskStatus.PENDING,
                prompt=td.get("prompt", ""),
                depends_on=json.dumps(td.get("depends_on", [])),
                working_directory=td.get("working_directory", ""),
                target_files=json.dumps(td.get("target_files", [])),
                acceptance_criteria=td.get("acceptance_criteria", ""),
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
