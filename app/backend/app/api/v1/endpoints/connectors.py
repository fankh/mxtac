"""Connector management endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.connector_repo import ConnectorRepo

router = APIRouter(prefix="/connectors", tags=["connectors"])

CONNECTOR_TYPES = ["wazuh", "zeek", "suricata", "prowler", "opencti", "velociraptor", "osquery", "generic"]


class ConnectorCreate(BaseModel):
    name: str
    connector_type: str
    config: dict[str, Any]
    enabled: bool = True


class ConnectorUpdate(BaseModel):
    enabled: bool | None = None
    config: dict[str, Any] | None = None


class ConnectorResponse(BaseModel):
    id: str
    name: str
    connector_type: str
    status: str
    enabled: bool
    events_total: int
    errors_total: int
    last_seen_at: str | None
    error_message: str | None


def _conn_to_response(c) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "connector_type": c.connector_type,
        "status": c.status,
        "enabled": c.enabled,
        "events_total": c.events_total,
        "errors_total": c.errors_total,
        "last_seen_at": c.last_seen_at,
        "error_message": c.error_message,
    }


@router.get("", response_model=list[ConnectorResponse])
async def list_connectors(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    connectors = await ConnectorRepo.list(db)
    return [_conn_to_response(c) for c in connectors]


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    conn = await ConnectorRepo.get_by_id(db, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    return _conn_to_response(conn)


@router.post("", response_model=ConnectorResponse, status_code=201)
async def create_connector(
    body: ConnectorCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    if body.connector_type not in CONNECTOR_TYPES:
        raise HTTPException(status_code=422, detail=f"Unknown connector type: {body.connector_type}")
    conn = await ConnectorRepo.create(
        db,
        name=body.name,
        connector_type=body.connector_type,
        config_json=json.dumps(body.config),
        enabled=body.enabled,
    )
    return _conn_to_response(conn)


@router.patch("/{connector_id}", response_model=ConnectorResponse)
async def update_connector(
    connector_id: str,
    body: ConnectorUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    updates = {}
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.config is not None:
        conn = await ConnectorRepo.get_by_id(db, connector_id)
        if conn:
            existing = json.loads(conn.config_json) if conn.config_json else {}
            existing.update(body.config)
            updates["config_json"] = json.dumps(existing)
    conn = await ConnectorRepo.update(db, connector_id, **updates)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    return _conn_to_response(conn)


@router.delete("/{connector_id}", status_code=204)
async def delete_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    deleted = await ConnectorRepo.delete(db, connector_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Connector not found")


@router.post("/{connector_id}/test", response_model=dict)
async def test_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    conn = await ConnectorRepo.get_by_id(db, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    return {
        "connector_id": connector_id,
        "reachable": False,
        "message": "Connection test not yet implemented for this connector type",
    }


@router.get("/{connector_id}/health", response_model=dict)
async def connector_health(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    conn = await ConnectorRepo.get_by_id(db, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    return {
        "id": conn.id,
        "name": conn.name,
        "status": conn.status,
        "events_total": conn.events_total,
        "errors_total": conn.errors_total,
        "last_seen_at": conn.last_seen_at,
        "error_message": conn.error_message,
    }
