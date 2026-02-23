"""Tests for /api/v1/users endpoints.

RBAC:
  users:read  → admin
  users:write → admin
"""

from __future__ import annotations

import pytest


_BASE = "/api/v1/users"

# A valid password that satisfies default policy constraints.
_VALID_PASSWORD = "SecureP@ss123!"


class TestListUsersRBAC:
    """GET /users — access control."""

    async def test_admin_can_list(self, client, admin_headers) -> None:
        resp = await client.get(_BASE, headers=admin_headers)
        assert resp.status_code == 200

    async def test_engineer_cannot_list(self, client, engineer_headers) -> None:
        resp = await client.get(_BASE, headers=engineer_headers)
        assert resp.status_code == 403

    async def test_hunter_cannot_list(self, client, hunter_headers) -> None:
        resp = await client.get(_BASE, headers=hunter_headers)
        assert resp.status_code == 403

    async def test_analyst_cannot_list(self, client, analyst_headers) -> None:
        resp = await client.get(_BASE, headers=analyst_headers)
        assert resp.status_code == 403

    async def test_viewer_cannot_list(self, client, viewer_headers) -> None:
        resp = await client.get(_BASE, headers=viewer_headers)
        assert resp.status_code == 403

    async def test_unauthenticated_cannot_list(self, client) -> None:
        resp = await client.get(_BASE)
        assert resp.status_code == 401


class TestListUsersResponse:
    """GET /users — response shape."""

    async def test_returns_list(self, client, admin_headers) -> None:
        resp = await client.get(_BASE, headers=admin_headers)
        assert isinstance(resp.json(), list)

    async def test_empty_list_when_no_users(self, client, admin_headers) -> None:
        resp = await client.get(_BASE, headers=admin_headers)
        assert resp.json() == []


class TestCreateUserRBAC:
    """POST /users — access control."""

    _payload = {
        "email": "newuser@mxtac.local",
        "full_name": "New User",
        "role": "analyst",
        "password": _VALID_PASSWORD,
    }

    async def test_admin_can_create_user(self, client, admin_headers) -> None:
        resp = await client.post(_BASE, json=self._payload, headers=admin_headers)
        # Success or conflict (if user exists); not a permission error
        assert resp.status_code not in (401, 403)

    async def test_engineer_cannot_create_user(self, client, engineer_headers) -> None:
        resp = await client.post(_BASE, json=self._payload, headers=engineer_headers)
        assert resp.status_code == 403

    async def test_analyst_cannot_create_user(self, client, analyst_headers) -> None:
        resp = await client.post(_BASE, json=self._payload, headers=analyst_headers)
        assert resp.status_code == 403


class TestCreateUserValidation:
    """POST /users — request validation."""

    async def test_invalid_email_returns_422(self, client, admin_headers) -> None:
        resp = await client.post(
            _BASE,
            json={
                "email": "not-an-email",
                "role": "analyst",
                "password": _VALID_PASSWORD,
            },
            headers=admin_headers,
        )
        assert resp.status_code == 422

    async def test_invalid_role_returns_422(self, client, admin_headers) -> None:
        resp = await client.post(
            _BASE,
            json={
                "email": "user2@mxtac.local",
                "role": "superadmin",  # invalid role
                "password": _VALID_PASSWORD,
            },
            headers=admin_headers,
        )
        assert resp.status_code == 422

    async def test_weak_password_returns_422(self, client, admin_headers) -> None:
        resp = await client.post(
            _BASE,
            json={
                "email": "user3@mxtac.local",
                "role": "analyst",
                "password": "short",  # too short
            },
            headers=admin_headers,
        )
        assert resp.status_code == 422


class TestGetUserById:
    """GET /users/{id} — retrieve a specific user."""

    async def test_nonexistent_user_returns_404(self, client, admin_headers) -> None:
        resp = await client.get(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            headers=admin_headers,
        )
        assert resp.status_code == 404


class TestUpdateUser:
    """PATCH /users/{id} — update a user."""

    async def test_update_nonexistent_user_returns_404(self, client, admin_headers) -> None:
        resp = await client.patch(
            f"{_BASE}/00000000-0000-0000-0000-000000000000",
            json={"role": "hunter"},
            headers=admin_headers,
        )
        assert resp.status_code == 404
