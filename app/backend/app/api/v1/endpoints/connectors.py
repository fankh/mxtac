"""Connector management endpoints."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ....core.security import get_current_user

router = APIRouter(prefix="/connectors", tags=["connectors"])

# ── Schemas ──────────────────────────────────────────────────────────────────

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

# ── In-memory store (replace with DB) ────────────────────────────────────────

_connectors: dict[str, dict] = {
    "wazuh-default": {
        "id": "conn-001",
        "name": "Wazuh Manager",
        "connector_type": "wazuh",
        "status": "inactive",
        "enabled": True,
        "config": {"url": "https://wazuh.internal:55000", "username": "wazuh-wui"},
        "events_total": 0,
        "errors_total": 0,
        "last_seen_at": None,
        "error_message": None,
    },
    "zeek-default": {
        "id": "conn-002",
        "name": "Zeek Network Monitor",
        "connector_type": "zeek",
        "status": "inactive",
        "enabled": True,
        "config": {"log_dir": "/opt/zeek/logs/current"},
        "events_total": 0,
        "errors_total": 0,
        "last_seen_at": None,
        "error_message": None,
    },
    "suricata-default": {
        "id": "conn-003",
        "name": "Suricata IDS",
        "connector_type": "suricata",
        "status": "inactive",
        "enabled": True,
        "config": {"eve_file": "/var/log/suricata/eve.json"},
        "events_total": 0,
        "errors_total": 0,
        "last_seen_at": None,
        "error_message": None,
    },
}

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ConnectorResponse])
async def list_connectors(_: str = Depends(get_current_user)):
    return list(_connectors.values())


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(connector_id: str, _: str = Depends(get_current_user)):
    for conn in _connectors.values():
        if conn["id"] == connector_id:
            return conn
    raise HTTPException(status_code=404, detail="Connector not found")


@router.post("", response_model=ConnectorResponse, status_code=201)
async def create_connector(body: ConnectorCreate, _: str = Depends(get_current_user)):
    if body.connector_type not in CONNECTOR_TYPES:
        raise HTTPException(status_code=422, detail=f"Unknown connector type: {body.connector_type}")
    conn_id = str(uuid4())
    conn = {
        "id": conn_id,
        "name": body.name,
        "connector_type": body.connector_type,
        "status": "inactive",
        "enabled": body.enabled,
        "config": body.config,
        "events_total": 0,
        "errors_total": 0,
        "last_seen_at": None,
        "error_message": None,
    }
    _connectors[conn_id] = conn
    return conn


@router.patch("/{connector_id}", response_model=ConnectorResponse)
async def update_connector(connector_id: str, body: ConnectorUpdate, _: str = Depends(get_current_user)):
    conn = next((c for c in _connectors.values() if c["id"] == connector_id), None)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    if body.enabled is not None:
        conn["enabled"] = body.enabled
    if body.config is not None:
        conn["config"] = {**conn["config"], **body.config}
    return conn


@router.delete("/{connector_id}", status_code=204)
async def delete_connector(connector_id: str, _: str = Depends(get_current_user)):
    key = next((k for k, c in _connectors.items() if c["id"] == connector_id), None)
    if not key:
        raise HTTPException(status_code=404, detail="Connector not found")
    del _connectors[key]


@router.post("/{connector_id}/test", response_model=dict)
async def test_connector(connector_id: str, _: str = Depends(get_current_user)):
    """Attempt to connect to the data source and return health status."""
    conn = next((c for c in _connectors.values() if c["id"] == connector_id), None)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    # TODO: instantiate real connector and call _connect()
    return {
        "connector_id": connector_id,
        "reachable": False,
        "message": "Connection test not yet implemented for this connector type",
    }


@router.get("/{connector_id}/health", response_model=dict)
async def connector_health(connector_id: str, _: str = Depends(get_current_user)):
    conn = next((c for c in _connectors.values() if c["id"] == connector_id), None)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    return {
        "id":           conn["id"],
        "name":         conn["name"],
        "status":       conn["status"],
        "events_total": conn["events_total"],
        "errors_total": conn["errors_total"],
        "last_seen_at": conn["last_seen_at"],
        "error_message": conn["error_message"],
    }
