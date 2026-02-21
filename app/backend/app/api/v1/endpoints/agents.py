"""Agent registry and management endpoints.

Authentication:
  - POST /agents/register        — X-API-Key (agents self-register)
  - POST /agents/{id}/heartbeat  — X-API-Key (agents send periodic heartbeats)
  - GET/PATCH/DELETE             — JWT RBAC (agents:read / agents:write)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.api_key_auth import get_api_key
from ....core.database import get_db
from ....core.rbac import require_permission
from ....models.api_key import APIKey
from ....repositories.agent_repo import AgentRepo

router = APIRouter(prefix="/agents", tags=["agents"])

AGENT_TYPES = ["mxguard", "mxwatch"]


# ── Request / Response schemas ────────────────────────────────────────────────


class AgentRegister(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    agent_type: str
    version: str = Field(..., min_length=1, max_length=50)
    config: dict[str, Any] = {}


class AgentUpdate(BaseModel):
    version: str | None = None
    config: dict[str, Any] | None = None


class AgentResponse(BaseModel):
    id: str
    hostname: str
    agent_type: str
    version: str
    status: str
    last_heartbeat: str | None
    created_at: str | None
    updated_at: str | None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _agent_to_response(a) -> dict:
    return {
        "id": a.id,
        "hostname": a.hostname,
        "agent_type": a.agent_type,
        "version": a.version,
        "status": a.status,
        "last_heartbeat": a.last_heartbeat.isoformat() if a.last_heartbeat else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


# ── Agent-authenticated endpoints (X-API-Key) ─────────────────────────────────


@router.post("/register", response_model=AgentResponse, status_code=201)
async def register_agent(
    body: AgentRegister,
    db: AsyncSession = Depends(get_db),
    _: APIKey = Depends(get_api_key),
):
    """Register a new agent or re-register an existing one (idempotent by hostname).

    Requires a valid X-API-Key header. On re-registration the agent record is
    updated in-place and its status is set to online.
    """
    if body.agent_type not in AGENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown agent type: {body.agent_type!r}. Valid types: {AGENT_TYPES}",
        )

    existing = await AgentRepo.get_by_hostname(db, body.hostname)
    if existing:
        agent = await AgentRepo.update(
            db,
            existing.id,
            agent_type=body.agent_type,
            version=body.version,
            config_json=json.dumps(body.config),
            status="online",
            last_heartbeat=datetime.now(timezone.utc),
        )
        return _agent_to_response(agent)

    agent = await AgentRepo.create(
        db,
        hostname=body.hostname,
        agent_type=body.agent_type,
        version=body.version,
        config_json=json.dumps(body.config),
        status="online",
        last_heartbeat=datetime.now(timezone.utc),
    )
    return _agent_to_response(agent)


@router.post("/{agent_id}/heartbeat", response_model=AgentResponse)
async def agent_heartbeat(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _: APIKey = Depends(get_api_key),
):
    """Record a heartbeat for the agent, setting status=online and refreshing last_heartbeat.

    Requires a valid X-API-Key header.
    """
    agent = await AgentRepo.update_heartbeat(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_to_response(agent)


# ── User-facing management endpoints (JWT RBAC) ───────────────────────────────


@router.get("", response_model=list[AgentResponse])
async def list_agents(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("agents:read")),
):
    """List all registered agents with their current status."""
    agents = await AgentRepo.list(db)
    return [_agent_to_response(a) for a in agents]


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("agents:read")),
):
    """Retrieve a single agent by ID."""
    agent = await AgentRepo.get_by_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_to_response(agent)


@router.patch("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    body: AgentUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("agents:write")),
):
    """Update agent version and/or config (merges config dict with existing)."""
    updates: dict = {}

    if body.config is not None:
        # Merge incoming config over the existing one
        agent = await AgentRepo.get_by_id(db, agent_id)
        if agent:
            existing = json.loads(agent.config_json) if agent.config_json else {}
            existing.update(body.config)
            updates["config_json"] = json.dumps(existing)

    if body.version is not None:
        updates["version"] = body.version

    agent = await AgentRepo.update(db, agent_id, **updates)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_to_response(agent)


@router.delete("/{agent_id}", status_code=204)
async def deregister_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("agents:write")),
):
    """Permanently remove an agent from the registry."""
    deleted = await AgentRepo.delete(db, agent_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Agent not found")
