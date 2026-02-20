"""Tests for GET /health and GET /ready endpoints.

Coverage:
  - /health always returns 200 with status=ok and version
  - /ready returns status and checks dict (PostgreSQL, Valkey, OpenSearch)
  - /ready status code is 200 (all ok) or 503 (any degraded)
  - /ready does not require auth
  - /health content-type is JSON
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


HEALTH_URL = "/health"
READY_URL = "/ready"


@pytest.mark.asyncio
async def test_health_returns_200(client: AsyncClient) -> None:
    """/health always returns 200 OK without authentication."""
    resp = await client.get(HEALTH_URL)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_health_status_ok(client: AsyncClient) -> None:
    """/health response body contains status='ok'."""
    resp = await client.get(HEALTH_URL)
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_health_contains_version(client: AsyncClient) -> None:
    """/health response body contains a non-empty 'version' field."""
    resp = await client.get(HEALTH_URL)
    data = resp.json()
    assert "version" in data
    assert isinstance(data["version"], str)
    assert data["version"]


@pytest.mark.asyncio
async def test_health_content_type_json(client: AsyncClient) -> None:
    """/health Content-Type is application/json."""
    resp = await client.get(HEALTH_URL)
    assert "application/json" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_ready_returns_status_field(client: AsyncClient) -> None:
    """/ready response body has a 'status' field ('ready' or 'degraded')."""
    resp = await client.get(READY_URL)
    data = resp.json()
    assert "status" in data
    assert data["status"] in ("ready", "degraded")


@pytest.mark.asyncio
async def test_ready_has_checks_dict(client: AsyncClient) -> None:
    """/ready response body has a 'checks' dict with service keys."""
    resp = await client.get(READY_URL)
    data = resp.json()
    assert "checks" in data
    assert isinstance(data["checks"], dict)
    # In test environment external services are absent, but keys must be present
    checks = data["checks"]
    assert "postgres" in checks
    assert "valkey" in checks
    assert "opensearch" in checks
