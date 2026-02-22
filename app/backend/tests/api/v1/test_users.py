"""Tests for /api/v1/users endpoints.

Coverage:
  - List: unauthenticated → 401; non-admin → 403; empty DB → []
  - GET by ID: 200 with correct fields; 404 when not found
  - POST create: 422 on invalid role; 201 on valid payload; 409 on duplicate email
  - PATCH update: 404 when not found; 422 on invalid role
  - DELETE: 404 when not found; 204 on success

Uses in-memory SQLite via the ``client`` fixture (get_db overridden).
``hash_password`` is mocked to avoid passlib/bcrypt incompatibility.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from httpx import AsyncClient

BASE_URL = "/api/v1/users"

_MOCK_HASH = "app.api.v1.endpoints.users.hash_password"
_HASHED_PW = "$2b$12$test_placeholder_hash_not_real"

_VALID_PAYLOAD = {
    "email": "newuser@mxtac.local",
    "full_name": "New User",
    "role": "analyst",
    "password": "secureP@ss1",
}


# ---------------------------------------------------------------------------
# Auth / access control
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_users_unauthenticated(client: AsyncClient) -> None:
    """GET /users without auth → 401 or 403."""
    resp = await client.get(BASE_URL)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_users_analyst_denied(client: AsyncClient, analyst_headers: dict) -> None:
    """GET /users with analyst role → 403 (users:read is admin-only)."""
    resp = await client.get(BASE_URL, headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_users_engineer_denied(client: AsyncClient, engineer_headers: dict) -> None:
    """GET /users with engineer role → 403 (users:read is admin-only)."""
    resp = await client.get(BASE_URL, headers=engineer_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# List users
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_users_empty(client: AsyncClient, admin_headers: dict) -> None:
    """GET /users with admin role and empty DB returns an empty list."""
    resp = await client.get(BASE_URL, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# GET single user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_user_success(client: AsyncClient, admin_headers: dict) -> None:
    """GET /users/{id} for existing user → 200 with correct fields."""
    with patch(_MOCK_HASH, return_value=_HASHED_PW):
        create_resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]

    resp = await client.get(f"{BASE_URL}/{user_id}", headers=admin_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == user_id
    assert data["email"] == _VALID_PAYLOAD["email"]
    assert data["full_name"] == _VALID_PAYLOAD["full_name"]
    assert data["role"] == _VALID_PAYLOAD["role"]
    assert data["is_active"] is True
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_get_user_not_found(client: AsyncClient, admin_headers: dict) -> None:
    """GET /users/{id} for unknown ID → 404."""
    resp = await client.get(f"{BASE_URL}/nonexistent-id", headers=admin_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "User not found"


# ---------------------------------------------------------------------------
# POST create user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_user_invalid_role(client: AsyncClient, admin_headers: dict) -> None:
    """POST /users with invalid role → 422."""
    resp = await client.post(
        BASE_URL,
        headers=admin_headers,
        json={**_VALID_PAYLOAD, "role": "superuser"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_user_success(client: AsyncClient, admin_headers: dict) -> None:
    """POST /users with valid payload → 201, returned object has expected fields."""
    with patch(_MOCK_HASH, return_value=_HASHED_PW):
        resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == _VALID_PAYLOAD["email"]
    assert data["role"] == _VALID_PAYLOAD["role"]
    assert data["is_active"] is True
    assert "hashed_password" not in data
    assert "id" in data


@pytest.mark.asyncio
async def test_create_user_duplicate_email(client: AsyncClient, admin_headers: dict) -> None:
    """POST /users with duplicate email → 409 Conflict."""
    with patch(_MOCK_HASH, return_value=_HASHED_PW):
        await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
        resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
    assert resp.status_code == 409
    assert resp.json()["detail"] == "Email already registered"


@pytest.mark.asyncio
async def test_create_user_appears_in_list(client: AsyncClient, admin_headers: dict) -> None:
    """After creation, the user appears in GET /users list."""
    with patch(_MOCK_HASH, return_value=_HASHED_PW):
        await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
    resp = await client.get(BASE_URL, headers=admin_headers)
    assert resp.status_code == 200
    emails = [u["email"] for u in resp.json()]
    assert _VALID_PAYLOAD["email"] in emails


# ---------------------------------------------------------------------------
# PATCH update user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_user_not_found(client: AsyncClient, admin_headers: dict) -> None:
    """PATCH /users/{id} for unknown ID → 404."""
    resp = await client.patch(
        f"{BASE_URL}/nonexistent-id",
        headers=admin_headers,
        json={"role": "hunter"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_user_invalid_role(client: AsyncClient, admin_headers: dict) -> None:
    """PATCH /users/{id} with invalid role → 422."""
    with patch(_MOCK_HASH, return_value=_HASHED_PW):
        create_resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
    user_id = create_resp.json()["id"]
    resp = await client.patch(
        f"{BASE_URL}/{user_id}",
        headers=admin_headers,
        json={"role": "root"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_update_user_deactivate(client: AsyncClient, admin_headers: dict) -> None:
    """PATCH /users/{id} with is_active=False → user is deactivated."""
    with patch(_MOCK_HASH, return_value=_HASHED_PW):
        create_resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
    user_id = create_resp.json()["id"]
    resp = await client.patch(
        f"{BASE_URL}/{user_id}",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


# ---------------------------------------------------------------------------
# DELETE user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_user_not_found(client: AsyncClient, admin_headers: dict) -> None:
    """DELETE /users/{id} for unknown ID → 404."""
    resp = await client.delete(f"{BASE_URL}/nonexistent-id", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_user_success(client: AsyncClient, admin_headers: dict) -> None:
    """DELETE /users/{id} for existing user → 204."""
    with patch(_MOCK_HASH, return_value=_HASHED_PW):
        create_resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
    user_id = create_resp.json()["id"]
    resp = await client.delete(f"{BASE_URL}/{user_id}", headers=admin_headers)
    assert resp.status_code == 204
