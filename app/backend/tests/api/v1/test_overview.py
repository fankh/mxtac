"""Tests for GET /api/v1/overview/* endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_kpis(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/kpis", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_detections" in data
    assert "critical_alerts" in data
    assert "attack_covered" in data
    assert "sigma_rules_active" in data


@pytest.mark.asyncio
async def test_timeline(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/timeline", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) > 0
    assert "date" in items[0]
    assert "total" in items[0]
    assert "critical" in items[0]


@pytest.mark.asyncio
async def test_tactics(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/tactics", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) > 0
    assert "tactic" in items[0]
    assert "count" in items[0]


@pytest.mark.asyncio
async def test_heatmap(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    assert resp.status_code == 200
    rows = resp.json()
    assert isinstance(rows, list)
    assert "technique_id" in rows[0]
    assert "cells" in rows[0]


@pytest.mark.asyncio
async def test_integrations(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/integrations", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert "name" in items[0]
    assert "status" in items[0]


@pytest.mark.asyncio
async def test_recent_detections(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/recent-detections", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
