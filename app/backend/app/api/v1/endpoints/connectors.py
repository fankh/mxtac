"""Connector management endpoints."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ....connectors.registry import build_connector
from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.connector_repo import ConnectorRepo

router = APIRouter(prefix="/connectors", tags=["connectors"])

CONNECTOR_TYPES = ["wazuh", "zeek", "suricata", "prowler", "opencti", "velociraptor", "osquery", "generic"]


class ConnectorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
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


class ConnectorHealthResponse(BaseModel):
    id: str
    name: str
    connector_type: str
    status: str
    enabled: bool
    healthy: bool
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
    _: dict = Depends(require_permission("connectors:read")),
):
    connectors = await ConnectorRepo.list(db)
    return [_conn_to_response(c) for c in connectors]


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("connectors:read")),
):
    conn = await ConnectorRepo.get_by_id(db, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    return _conn_to_response(conn)


@router.post("", response_model=ConnectorResponse, status_code=201)
async def create_connector(
    body: ConnectorCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("connectors:write")),
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
    _: dict = Depends(require_permission("connectors:write")),
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
    _: dict = Depends(require_permission("connectors:write")),
):
    deleted = await ConnectorRepo.delete(db, connector_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Connector not found")


# ── Connection test helpers ───────────────────────────────────────────────────


async def _test_wazuh_connection(config: dict) -> tuple[bool, str]:
    """Verify Wazuh API connectivity by attempting JWT authentication."""
    url = config.get("url", "").rstrip("/")
    username = config.get("username", "")
    password = config.get("password", "")
    verify_ssl = config.get("verify_ssl", True)

    if not url:
        return False, "Missing required config key: url"

    try:
        async with httpx.AsyncClient(verify=verify_ssl, timeout=10, follow_redirects=True) as client:
            resp = await client.get(
                f"{url}/security/user/authenticate",
                auth=(username, password),
            )
        if resp.status_code == 200:
            return True, "Wazuh API reachable and credentials valid"
        if resp.status_code == 401:
            return False, "Wazuh API reachable but credentials are invalid"
        return False, f"Wazuh API returned unexpected status {resp.status_code}"
    except httpx.ConnectError as exc:
        return False, f"Cannot connect to Wazuh API: {exc}"
    except Exception as exc:
        return False, f"Connection test failed: {exc}"


async def _test_zeek_connection(config: dict) -> tuple[bool, str]:
    """Verify Zeek connector by checking whether the configured log directory exists."""
    log_dir = config.get("log_dir", "/opt/zeek/logs/current")
    if os.path.isdir(log_dir):
        return True, f"Zeek log directory accessible: {log_dir}"
    return False, f"Zeek log directory not found: {log_dir}"


async def _test_suricata_connection(config: dict) -> tuple[bool, str]:
    """Verify Suricata connector by checking whether the EVE JSON file exists."""
    eve_file = config.get("eve_file", "/var/log/suricata/eve.json")
    if os.path.isfile(eve_file):
        return True, f"Suricata EVE file accessible: {eve_file}"
    return False, f"Suricata EVE file not found: {eve_file}"


async def _test_prowler_connection(config: dict) -> tuple[bool, str]:
    """Verify Prowler API connectivity by probing the health endpoint."""
    api_url = config.get("api_url", "").rstrip("/")
    api_key = config.get("api_key", "")
    verify_ssl = config.get("verify_ssl", True)

    if not api_url:
        return False, "Missing required config key: api_url"
    if not api_key:
        return False, "Missing required config key: api_key"

    try:
        async with httpx.AsyncClient(
            verify=verify_ssl,
            timeout=10,
            follow_redirects=True,
        ) as client:
            resp = await client.get(
                f"{api_url}/api/v1/health",
                headers={"Authorization": f"Bearer {api_key}"},
            )
        if resp.status_code == 200:
            return True, "Prowler API reachable and credentials valid"
        if resp.status_code == 401:
            return False, "Prowler API reachable but API key is invalid"
        return False, f"Prowler API returned unexpected status {resp.status_code}"
    except httpx.ConnectError as exc:
        return False, f"Cannot connect to Prowler API: {exc}"
    except Exception as exc:
        return False, f"Connection test failed: {exc}"


_CONNECTION_TESTERS: dict[str, Any] = {
    "wazuh":    _test_wazuh_connection,
    "zeek":     _test_zeek_connection,
    "suricata": _test_suricata_connection,
    "prowler":  _test_prowler_connection,
}


@router.post("/{connector_id}/test", response_model=dict)
async def test_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("connectors:write")),
):
    conn = await ConnectorRepo.get_by_id(db, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")

    config = json.loads(conn.config_json) if conn.config_json else {}
    tester = _CONNECTION_TESTERS.get(conn.connector_type)

    if tester is None:
        reachable = False
        message = f"Connection test not supported for connector type: {conn.connector_type}"
    else:
        reachable, message = await tester(config)

    new_status = "active" if reachable else "error"
    await ConnectorRepo.update_status(
        db, connector_id, new_status, error_message=None if reachable else message
    )

    return {
        "connector_id": connector_id,
        "reachable": reachable,
        "message": message,
    }


@router.get("/{connector_id}/health", response_model=ConnectorHealthResponse)
async def connector_health(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("connectors:read")),
):
    conn = await ConnectorRepo.get_by_id(db, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    healthy = bool(conn.enabled and conn.status in ("active", "connected"))
    return ConnectorHealthResponse(
        id=conn.id,
        name=conn.name,
        connector_type=conn.connector_type,
        status=conn.status,
        enabled=conn.enabled,
        healthy=healthy,
        events_total=conn.events_total,
        errors_total=conn.errors_total,
        last_seen_at=conn.last_seen_at,
        error_message=conn.error_message,
    )


# ── Runtime start / stop ──────────────────────────────────────────────────────


@router.post("/{connector_id}/start", response_model=ConnectorResponse)
async def start_connector(
    connector_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("connectors:write")),
):
    """Start a connector at runtime without restarting the server.

    Idempotent: if the connector is already running, returns its current state.
    Returns 422 if the connector type has no runtime implementation.
    Returns 503 if the message queue is unavailable.
    """
    conn = await ConnectorRepo.get_by_id(db, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")

    running: dict = getattr(request.app.state, "connectors", {})
    if connector_id not in running:
        queue = getattr(request.app.state, "queue", None)
        if queue is None:
            raise HTTPException(status_code=503, detail="Message queue not available")

        connector = build_connector(conn, queue)
        if connector is None:
            raise HTTPException(
                status_code=422,
                detail=f"Cannot start connector type: {conn.connector_type}",
            )

        asyncio.create_task(connector.start(), name=f"connector-start-{conn.name}")
        running[connector_id] = connector
        await ConnectorRepo.update_status(db, connector_id, "connecting")
        conn = await ConnectorRepo.get_by_id(db, connector_id)

    return _conn_to_response(conn)


@router.post("/{connector_id}/stop", response_model=ConnectorResponse)
async def stop_connector(
    connector_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("connectors:write")),
):
    """Stop a running connector at runtime without restarting the server.

    Idempotent: if the connector is not currently running, its DB status is
    still set to 'inactive' and the current state is returned.
    """
    conn = await ConnectorRepo.get_by_id(db, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")

    running: dict = getattr(request.app.state, "connectors", {})
    connector = running.pop(connector_id, None)
    if connector is not None:
        await connector.stop()

    await ConnectorRepo.update_status(db, connector_id, "inactive")
    conn = await ConnectorRepo.get_by_id(db, connector_id)

    return _conn_to_response(conn)
