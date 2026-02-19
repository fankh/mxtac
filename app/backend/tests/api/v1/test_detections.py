"""Tests for GET/PATCH /api/v1/detections endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_detections_default(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/detections", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "pagination" in data
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_list_detections_filter_severity(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/detections?severity=critical", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["severity"] == "critical"


@pytest.mark.asyncio
async def test_list_detections_filter_status(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/detections?status=active", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["status"] == "active"


@pytest.mark.asyncio
async def test_list_detections_search(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/detections?search=lsass", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_get_detection_detail(client: AsyncClient, auth_headers: dict) -> None:
    # Get any ID from list
    list_resp = await client.get("/api/v1/detections", headers=auth_headers)
    items = list_resp.json()["items"]
    assert len(items) > 0

    detection_id = items[0]["id"]
    resp = await client.get(f"/api/v1/detections/{detection_id}", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == detection_id
    assert "technique_id" in data


@pytest.mark.asyncio
async def test_get_detection_not_found(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/detections/nonexistent-id", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_detection_status(client: AsyncClient, auth_headers: dict) -> None:
    list_resp = await client.get("/api/v1/detections", headers=auth_headers)
    detection_id = list_resp.json()["items"][0]["id"]

    resp = await client.patch(
        f"/api/v1/detections/{detection_id}",
        headers=auth_headers,
        json={"status": "investigating"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


@pytest.mark.asyncio
async def test_unauthenticated_access(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/detections")
    # Should be 401 or 403 (no auth header)
    assert resp.status_code in (401, 403)
