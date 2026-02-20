import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..config import settings
from ..database import get_session
from ..models import Run, RunStatus, Task, TaskStatus
from ..scheduler import scheduler
from ..task_loader import load_tasks_into_db, parse_yaml_directory, parse_yaml_tasks

router = APIRouter(prefix="/api")


# --- Pydantic request/response models ---

class TaskLoadRequest(BaseModel):
    path: str  # Path to YAML file or directory


class SchedulerControlRequest(BaseModel):
    action: str  # start, stop, pause, resume


class SchedulerSettingsUpdate(BaseModel):
    max_concurrent: Optional[int] = None
    spawn_delay: Optional[int] = None
    task_timeout: Optional[int] = None
    model: Optional[str] = None


# --- Stats ---

@router.get("/stats")
async def get_stats(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Task))
    tasks = result.scalars().all()

    status_counts = {}
    phase_counts = {}
    for t in tasks:
        s = t.status.value
        status_counts[s] = status_counts.get(s, 0) + 1
        p = t.phase or "unknown"
        if p not in phase_counts:
            phase_counts[p] = {"total": 0, "completed": 0, "failed": 0, "running": 0, "pending": 0}
        phase_counts[p]["total"] += 1
        phase_counts[p][s] = phase_counts[p].get(s, 0) + 1

    return {
        "total_tasks": len(tasks),
        "status_counts": status_counts,
        "phase_counts": phase_counts,
        "scheduler": {
            "running": scheduler.is_running,
            "paused": scheduler.is_paused,
        },
        "executor": {
            "running_count": 0,  # Will be filled from executor
        },
    }


# --- Tasks ---

@router.get("/tasks")
async def list_tasks(
    status: Optional[str] = None,
    phase: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    query = select(Task)

    if status:
        query = query.where(Task.status == TaskStatus(status))
    if phase:
        query = query.where(Task.phase == phase)
    if category:
        query = query.where(Task.category == category)
    if search:
        query = query.where(Task.title.ilike(f"%{search}%"))

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar()

    # Apply pagination
    query = query.order_by(Task.phase, Task.priority.desc(), Task.id).offset(offset).limit(limit)
    result = await session.execute(query)
    tasks = result.scalars().all()

    return {
        "tasks": [t.to_dict() for t in tasks],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/tasks/{task_db_id}")
async def get_task(task_db_id: int, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_db_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task.to_dict()


@router.get("/tasks/{task_db_id}/runs")
async def get_task_runs(task_db_id: int, session: AsyncSession = Depends(get_session)):
    result = await session.execute(
        select(Run).where(Run.task_id == task_db_id).order_by(Run.attempt.desc())
    )
    runs = result.scalars().all()
    return [r.to_dict() for r in runs]


# --- Runs (history) ---

@router.get("/runs")
async def list_runs(
    status: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    query = select(Run).options(selectinload(Run.task))

    if status:
        query = query.where(Run.status == RunStatus(status))

    count_query = select(func.count()).select_from(Run)
    if status:
        count_query = count_query.where(Run.status == RunStatus(status))
    total_result = await session.execute(count_query)
    total = total_result.scalar()

    query = query.order_by(Run.started_at.desc()).offset(offset).limit(limit)
    result = await session.execute(query)
    runs = result.scalars().all()

    items = []
    for r in runs:
        d = r.to_dict()
        d["task_title"] = r.task.title if r.task else ""
        d["task_task_id"] = r.task.task_id if r.task else ""
        d["task_phase"] = r.task.phase if r.task else ""
        items.append(d)

    return {"runs": items, "total": total, "limit": limit, "offset": offset}


# --- Task Actions ---

@router.post("/tasks/{task_db_id}/trigger")
async def trigger_task(task_db_id: int):
    ok = await scheduler.trigger_task(task_db_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot trigger task")
    return {"status": "triggered"}


@router.post("/tasks/{task_db_id}/skip")
async def skip_task(task_db_id: int):
    ok = await scheduler.skip_task(task_db_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot skip task")
    return {"status": "skipped"}


@router.post("/tasks/{task_db_id}/reset")
async def reset_task(task_db_id: int):
    ok = await scheduler.reset_task(task_db_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot reset task")
    return {"status": "reset"}


@router.post("/tasks/{task_db_id}/cancel")
async def cancel_task(task_db_id: int):
    ok = await scheduler.cancel_task(task_db_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot cancel task")
    return {"status": "cancelled"}


# --- Task Loading ---

@router.post("/tasks/load")
async def load_tasks(req: TaskLoadRequest):
    path = Path(req.path)
    try:
        if path.is_dir():
            task_defs = parse_yaml_directory(path)
        elif path.is_file():
            task_defs = parse_yaml_tasks(path)
        else:
            raise HTTPException(status_code=400, detail=f"Path not found: {path}")
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e))

    created, skipped = await load_tasks_into_db(task_defs)
    return {"created": created, "skipped": skipped, "total_parsed": len(task_defs)}


# --- Scheduler Control ---

@router.post("/scheduler/control")
async def scheduler_control(req: SchedulerControlRequest):
    actions = {
        "start": scheduler.start,
        "stop": scheduler.stop,
        "pause": scheduler.pause,
        "resume": scheduler.resume,
    }
    action_fn = actions.get(req.action)
    if action_fn is None:
        raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")

    await action_fn()
    return {
        "status": "ok",
        "scheduler": {
            "running": scheduler.is_running,
            "paused": scheduler.is_paused,
        },
    }


@router.get("/scheduler/status")
async def scheduler_status():
    return {
        "running": scheduler.is_running,
        "paused": scheduler.is_paused,
    }


@router.put("/scheduler/settings")
async def update_scheduler_settings(req: SchedulerSettingsUpdate):
    if req.max_concurrent is not None:
        settings.scheduler_max_concurrent = req.max_concurrent
    if req.spawn_delay is not None:
        settings.scheduler_spawn_delay = req.spawn_delay
    if req.task_timeout is not None:
        settings.scheduler_task_timeout = req.task_timeout
    if req.model is not None:
        settings.claude_model = req.model
    return {"status": "updated"}


# --- Phases ---

@router.get("/phases")
async def list_phases(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Task))
    tasks = result.scalars().all()

    phases = {}
    for t in tasks:
        p = t.phase or "unknown"
        if p not in phases:
            phases[p] = {
                "phase": p,
                "total": 0,
                "completed": 0,
                "failed": 0,
                "running": 0,
                "pending": 0,
                "skipped": 0,
                "cancelled": 0,
            }
        phases[p]["total"] += 1
        phases[p][t.status.value] = phases[p].get(t.status.value, 0) + 1

    return list(phases.values())


# --- Categories ---

@router.get("/categories")
async def list_categories(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Task))
    tasks = result.scalars().all()

    categories: dict[str, dict] = {}
    for t in tasks:
        c = t.category or "uncategorized"
        if c not in categories:
            categories[c] = {
                "category": c,
                "total": 0,
                "completed": 0,
                "failed": 0,
                "running": 0,
                "pending": 0,
                "skipped": 0,
                "cancelled": 0,
                "tasks": [],
            }
        categories[c]["total"] += 1
        categories[c][t.status.value] = categories[c].get(t.status.value, 0) + 1
        categories[c]["tasks"].append(t.to_dict())

    return list(categories.values())
