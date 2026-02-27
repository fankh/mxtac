import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..agents import ALL_NEW_AGENTS, get_agent_by_name, get_enabled_agents
from ..config import settings
from ..database import get_session
from ..models import AgentRun, Run, RunStatus, Task, TaskStatus
from ..executor import executor
from ..scheduler import scheduler, retry_agent, watchdog_agent
from ..task_loader import load_tasks_into_db, parse_yaml_directory, parse_yaml_tasks

router = APIRouter(prefix="/api")


# --- Pydantic request/response models ---

class TaskLoadRequest(BaseModel):
    path: str  # Path to YAML file or directory


class SchedulerControlRequest(BaseModel):
    action: str  # start, stop, pause, resume


class SchedulerSettingsUpdate(BaseModel):
    timezone: Optional[str] = None
    max_concurrent: Optional[int] = None
    spawn_delay: Optional[int] = None
    task_timeout: Optional[int] = None
    model: Optional[str] = None
    retry_max: Optional[int] = None
    retry_backoff: Optional[int] = None
    github_repo_url: Optional[str] = None
    test_command: Optional[str] = None
    test_timeout: Optional[int] = None
    quality_retry_max: Optional[int] = None


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

    quality = {
        "test_passed": 0,
        "test_failed": 0,
        "verification_passed": 0,
        "verification_failed": 0,
    }
    for t in tasks:
        if t.test_status == "passed":
            quality["test_passed"] += 1
        elif t.test_status == "failed":
            quality["test_failed"] += 1
        if t.verification_status == "passed":
            quality["verification_passed"] += 1
        elif t.verification_status == "failed":
            quality["verification_failed"] += 1

    return {
        "total_tasks": len(tasks),
        "status_counts": status_counts,
        "phase_counts": phase_counts,
        "quality": quality,
        "scheduler": {
            "running": scheduler.is_running,
            "paused": scheduler.is_paused,
        },
        "executor": {
            "running_count": executor.running_count,
        },
    }


# --- Agents ---

@router.get("/agents")
async def get_agents():
    agents = [
        scheduler.to_dict(),
        retry_agent.to_dict(),
        watchdog_agent.to_dict(),
    ]
    for agent in ALL_NEW_AGENTS:
        agents.append(agent.to_dict())
    return {"agents": agents}


@router.post("/agents/{agent_name}/trigger")
async def trigger_agent(agent_name: str):
    agent = get_agent_by_name(agent_name)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_name}")
    try:
        result = await agent.trigger()
        return {"status": "triggered", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class AgentIntervalUpdate(BaseModel):
    interval: int


@router.put("/agents/{agent_name}/interval")
async def update_agent_interval(agent_name: str, req: AgentIntervalUpdate):
    agent = get_agent_by_name(agent_name)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_name}")
    if req.interval < 10:
        raise HTTPException(status_code=400, detail="Interval must be >= 10 seconds")
    agent._interval = req.interval
    # Also persist to settings so it survives restart
    interval_config_map = {
        "TaskCreatorAgent": "agent_task_creator_interval",
        "VerifierAgent": "agent_verifier_interval",
        "TestAgent": "agent_test_interval",
        "LintAgent": "agent_lint_interval",
        "IntegrationAgent": "agent_integration_interval",
        "SecurityAuditAgent": "agent_security_interval",
    }
    config_key = interval_config_map.get(agent_name)
    if config_key:
        setattr(settings, config_key, req.interval)
    return {"status": "updated", "interval": req.interval}


# --- Per-agent config ---

_AGENT_CONFIG_KEYS: dict[str, list[str]] = {
    "TaskCreatorAgent": [
        "agent_task_creator_enabled",
        "agent_task_creator_interval",
        "agent_task_creator_max_tasks_per_cycle",
        "agent_task_creator_use_claude",
    ],
    "VerifierAgent": [
        "agent_verifier_enabled",
        "agent_verifier_interval",
        "agent_verifier_max_per_cycle",
        "agent_verifier_use_claude",
        "agent_verifier_fail_action",
    ],
    "TestAgent": [
        "agent_test_enabled",
        "agent_test_interval",
        "agent_test_fail_action",
        "agent_test_full_suite_every",
        "agent_test_timeout",
    ],
    "LintAgent": [
        "agent_lint_enabled",
        "agent_lint_interval",
        "agent_lint_error_threshold",
    ],
    "IntegrationAgent": [
        "agent_integration_enabled",
        "agent_integration_interval",
        "agent_integration_smoke_url",
    ],
    "SecurityAuditAgent": [
        "agent_security_enabled",
        "agent_security_interval",
        "agent_security_bandit_skip",
    ],
}


@router.get("/agents/{agent_name}/config")
async def get_agent_config(agent_name: str):
    keys = _AGENT_CONFIG_KEYS.get(agent_name)
    if keys is None:
        raise HTTPException(status_code=404, detail=f"No config for agent: {agent_name}")
    return {k: getattr(settings, k) for k in keys}


@router.put("/agents/{agent_name}/config")
async def update_agent_config(agent_name: str, req: dict):
    keys = _AGENT_CONFIG_KEYS.get(agent_name)
    if keys is None:
        raise HTTPException(status_code=404, detail=f"No config for agent: {agent_name}")
    updated = {}
    agent = get_agent_by_name(agent_name)
    for k, v in req.items():
        if k not in keys:
            continue
        current = getattr(settings, k)
        # Type coerce
        if isinstance(current, bool):
            v = bool(v)
        elif isinstance(current, int):
            v = int(v)
        setattr(settings, k, v)
        updated[k] = v
        # Live-update the agent interval if changed
        if k.endswith("_interval") and agent:
            agent._interval = v
        # Live-update enabled state
        if k.endswith("_enabled") and agent:
            if v and not agent._running:
                import asyncio
                asyncio.create_task(agent.start())
            elif not v and agent._running:
                import asyncio
                asyncio.create_task(agent.stop())
    return {"status": "updated", "updated": updated}


@router.get("/agents/{agent_name}/runs")
async def get_agent_runs(
    agent_name: str,
    limit: int = Query(default=20, le=100),
    session: AsyncSession = Depends(get_session),
):
    agent = get_agent_by_name(agent_name)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_name}")

    result = await session.execute(
        select(AgentRun)
        .where(AgentRun.agent_name == agent_name)
        .order_by(AgentRun.started_at.desc())
        .limit(limit)
    )
    runs = result.scalars().all()
    return [r.to_dict() for r in runs]


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
        d["verification_status"] = r.task.verification_status if r.task else None
        d["test_status"] = r.task.test_status if r.task else None
        d["quality_retry_count"] = r.task.quality_retry_count if r.task else 0
        items.append(d)

    return {"runs": items, "total": total, "limit": limit, "offset": offset}


@router.get("/agent-runs")
async def list_agent_runs(
    agent_name: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    query = select(AgentRun)
    count_query = select(func.count()).select_from(AgentRun)

    if agent_name:
        query = query.where(AgentRun.agent_name == agent_name)
        count_query = count_query.where(AgentRun.agent_name == agent_name)
    if status:
        query = query.where(AgentRun.status == status)
        count_query = count_query.where(AgentRun.status == status)

    total_result = await session.execute(count_query)
    total = total_result.scalar()

    query = query.order_by(AgentRun.started_at.desc()).offset(offset).limit(limit)
    result = await session.execute(query)
    runs = result.scalars().all()

    return {"runs": [r.to_dict() for r in runs], "total": total, "limit": limit, "offset": offset}


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
    if req.action == "start":
        await scheduler.start()
        await retry_agent.start()
        await watchdog_agent.start()
        for agent in get_enabled_agents():
            await agent.start()
    elif req.action == "stop":
        await scheduler.stop()
        await retry_agent.stop()
        await watchdog_agent.stop()
        for agent in ALL_NEW_AGENTS:
            await agent.stop()
    elif req.action == "pause":
        await scheduler.pause()
    elif req.action == "resume":
        await scheduler.resume()
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")

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


@router.get("/scheduler/settings")
async def get_scheduler_settings():
    return {
        "timezone": settings.scheduler_timezone,
        "max_concurrent": settings.scheduler_max_concurrent,
        "spawn_delay": settings.scheduler_spawn_delay,
        "task_timeout": settings.scheduler_task_timeout,
        "model": settings.claude_model,
        "retry_max": settings.scheduler_retry_max,
        "retry_backoff": settings.scheduler_retry_backoff,
        "github_repo_url": settings.github_repo_url,
        "test_command": settings.scheduler_test_command,
        "test_timeout": settings.scheduler_test_timeout,
        "quality_retry_max": settings.scheduler_quality_retry_max,
    }


@router.put("/scheduler/settings")
async def update_scheduler_settings(req: SchedulerSettingsUpdate):
    if req.timezone is not None:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            ZoneInfo(req.timezone)
        except (ZoneInfoNotFoundError, KeyError):
            raise HTTPException(status_code=400, detail=f"Invalid timezone: {req.timezone}")
        settings.scheduler_timezone = req.timezone
    if req.max_concurrent is not None:
        settings.scheduler_max_concurrent = req.max_concurrent
    if req.spawn_delay is not None:
        settings.scheduler_spawn_delay = req.spawn_delay
    if req.task_timeout is not None:
        settings.scheduler_task_timeout = req.task_timeout
    if req.model is not None:
        settings.claude_model = req.model
    if req.retry_max is not None:
        settings.scheduler_retry_max = req.retry_max
    if req.retry_backoff is not None:
        settings.scheduler_retry_backoff = req.retry_backoff
    if req.github_repo_url is not None:
        settings.github_repo_url = req.github_repo_url
    if req.test_command is not None:
        settings.scheduler_test_command = req.test_command
    if req.test_timeout is not None:
        settings.scheduler_test_timeout = req.test_timeout
    if req.quality_retry_max is not None:
        settings.scheduler_quality_retry_max = req.quality_retry_max
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
