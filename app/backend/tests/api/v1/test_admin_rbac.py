"""Tests for Feature 28.9 — RBAC: admin can manage users.

Verifies that the admin role:
  - Can list all users (GET /users)
  - Can retrieve a single user by ID (GET /users/{id})
  - Can create users with valid roles (POST /users)
  - Can update user attributes including role and active status (PATCH /users/{id})
  - Can delete users (DELETE /users/{id})

Also verifies that every non-admin role (viewer, analyst, hunter, engineer) is
denied access to all user management endpoints with a 403 response whose body
contains the role name.

Unauthenticated requests to all user endpoints return 401 or 403.
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
# 1. Admin can list users
# ---------------------------------------------------------------------------


class TestAdminCanListUsers:
    """Admin receives a 200 with the full user list."""

    @pytest.mark.asyncio
    async def test_admin_list_users_returns_200(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_list_users_empty_db_returns_empty_list(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_admin_list_users_returns_list_type(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=admin_headers)
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_admin_list_users_includes_created_user(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """User created via POST appears in the list returned by GET."""
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
        resp = await client.get(BASE_URL, headers=admin_headers)
        assert resp.status_code == 200
        emails = [u["email"] for u in resp.json()]
        assert _VALID_PAYLOAD["email"] in emails

    @pytest.mark.asyncio
    async def test_admin_list_users_multiple_users(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Creating two users results in both appearing in the list."""
        second_payload = {**_VALID_PAYLOAD, "email": "second@mxtac.local"}
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
            await client.post(BASE_URL, headers=admin_headers, json=second_payload)
        resp = await client.get(BASE_URL, headers=admin_headers)
        assert resp.status_code == 200
        assert len(resp.json()) == 2


# ---------------------------------------------------------------------------
# 2. Admin can retrieve a single user
# ---------------------------------------------------------------------------


class TestAdminCanGetUser:
    """Admin can look up an individual user by ID."""

    @pytest.mark.asyncio
    async def test_admin_get_user_by_id_returns_200(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.get(f"{BASE_URL}/{user_id}", headers=admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_get_user_by_id_correct_fields(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.get(f"{BASE_URL}/{user_id}", headers=admin_headers)
        data = resp.json()
        assert data["id"] == user_id
        assert data["email"] == _VALID_PAYLOAD["email"]
        assert data["role"] == _VALID_PAYLOAD["role"]
        assert data["is_active"] is True

    @pytest.mark.asyncio
    async def test_admin_get_user_not_found_returns_404(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        resp = await client.get(f"{BASE_URL}/nonexistent-id", headers=admin_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_admin_get_user_404_detail(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        resp = await client.get(f"{BASE_URL}/nonexistent-id", headers=admin_headers)
        assert resp.json()["detail"] == "User not found"

    @pytest.mark.asyncio
    async def test_admin_get_user_no_password_in_response(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.get(f"{BASE_URL}/{user_id}", headers=admin_headers)
        assert "hashed_password" not in resp.json()
        assert "password" not in resp.json()


# ---------------------------------------------------------------------------
# 3. Admin can create users
# ---------------------------------------------------------------------------


class TestAdminCanCreateUsers:
    """Admin can create users with any valid role; invalid inputs are rejected."""

    @pytest.mark.asyncio
    async def test_admin_create_user_returns_201(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_admin_create_user_response_shape(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
        data = resp.json()
        assert "id" in data
        assert data["email"] == _VALID_PAYLOAD["email"]
        assert data["full_name"] == _VALID_PAYLOAD["full_name"]
        assert data["role"] == _VALID_PAYLOAD["role"]
        assert data["is_active"] is True

    @pytest.mark.asyncio
    async def test_admin_create_user_no_password_in_response(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
        assert "hashed_password" not in resp.json()
        assert "password" not in resp.json()

    @pytest.mark.asyncio
    async def test_admin_create_user_without_full_name(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        payload = {k: v for k, v in _VALID_PAYLOAD.items() if k != "full_name"}
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            resp = await client.post(BASE_URL, headers=admin_headers, json=payload)
        assert resp.status_code == 201
        assert resp.json()["full_name"] is None

    @pytest.mark.asyncio
    async def test_admin_create_user_invalid_role_returns_422(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            resp = await client.post(
                BASE_URL,
                headers=admin_headers,
                json={**_VALID_PAYLOAD, "role": "superuser"},
            )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_admin_create_user_duplicate_email_returns_409(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
            resp = await client.post(BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD)
        assert resp.status_code == 409
        assert resp.json()["detail"] == "Email already registered"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter", "engineer", "admin"])
    async def test_admin_can_create_user_with_any_valid_role(
        self, client: AsyncClient, admin_headers: dict, role: str
    ) -> None:
        payload = {**_VALID_PAYLOAD, "email": f"{role}@mxtac.local", "role": role}
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            resp = await client.post(BASE_URL, headers=admin_headers, json=payload)
        assert resp.status_code == 201
        assert resp.json()["role"] == role


# ---------------------------------------------------------------------------
# 4. Admin can update users
# ---------------------------------------------------------------------------


class TestAdminCanUpdateUsers:
    """Admin can update user attributes; invalid inputs and missing users are rejected."""

    @pytest.mark.asyncio
    async def test_admin_can_deactivate_user(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.patch(
            f"{BASE_URL}/{user_id}", headers=admin_headers, json={"is_active": False}
        )
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

    @pytest.mark.asyncio
    async def test_admin_can_reactivate_user(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        await client.patch(
            f"{BASE_URL}/{user_id}", headers=admin_headers, json={"is_active": False}
        )
        resp = await client.patch(
            f"{BASE_URL}/{user_id}", headers=admin_headers, json={"is_active": True}
        )
        assert resp.status_code == 200
        assert resp.json()["is_active"] is True

    @pytest.mark.asyncio
    async def test_admin_can_change_user_role(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.patch(
            f"{BASE_URL}/{user_id}", headers=admin_headers, json={"role": "hunter"}
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "hunter"

    @pytest.mark.asyncio
    async def test_admin_can_change_user_full_name(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.patch(
            f"{BASE_URL}/{user_id}",
            headers=admin_headers,
            json={"full_name": "Updated Name"},
        )
        assert resp.status_code == 200
        assert resp.json()["full_name"] == "Updated Name"

    @pytest.mark.asyncio
    async def test_admin_update_invalid_role_returns_422(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.patch(
            f"{BASE_URL}/{user_id}", headers=admin_headers, json={"role": "root"}
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_admin_update_nonexistent_user_returns_404(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        resp = await client.patch(
            f"{BASE_URL}/nonexistent-id",
            headers=admin_headers,
            json={"role": "hunter"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_admin_update_returns_full_user_response(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.patch(
            f"{BASE_URL}/{user_id}", headers=admin_headers, json={"role": "engineer"}
        )
        data = resp.json()
        assert "id" in data
        assert "email" in data
        assert "role" in data
        assert "is_active" in data


# ---------------------------------------------------------------------------
# 5. Admin can delete users
# ---------------------------------------------------------------------------


class TestAdminCanDeleteUsers:
    """Admin can delete users; deleting a non-existent user returns 404."""

    @pytest.mark.asyncio
    async def test_admin_delete_user_returns_204(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.delete(f"{BASE_URL}/{user_id}", headers=admin_headers)
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_admin_delete_user_no_response_body(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        resp = await client.delete(f"{BASE_URL}/{user_id}", headers=admin_headers)
        assert resp.content == b""

    @pytest.mark.asyncio
    async def test_admin_delete_nonexistent_user_returns_404(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        resp = await client.delete(f"{BASE_URL}/nonexistent-id", headers=admin_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_admin_deleted_user_absent_from_list(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        await client.delete(f"{BASE_URL}/{user_id}", headers=admin_headers)
        list_resp = await client.get(BASE_URL, headers=admin_headers)
        ids = [u["id"] for u in list_resp.json()]
        assert user_id not in ids

    @pytest.mark.asyncio
    async def test_admin_deleted_user_get_returns_404(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        with patch(_MOCK_HASH, return_value=_HASHED_PW):
            create_resp = await client.post(
                BASE_URL, headers=admin_headers, json=_VALID_PAYLOAD
            )
        user_id = create_resp.json()["id"]
        await client.delete(f"{BASE_URL}/{user_id}", headers=admin_headers)
        resp = await client.get(f"{BASE_URL}/{user_id}", headers=admin_headers)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 6. Non-admin roles denied read access (users:read is admin-only)
# ---------------------------------------------------------------------------


class TestNonAdminDeniedUserRead:
    """Viewer, analyst, hunter, and engineer cannot read user data (403)."""

    @pytest.mark.asyncio
    async def test_viewer_cannot_list_users(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=viewer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_list_users(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_list_users(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=hunter_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_cannot_list_users(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=engineer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_get_user_by_id(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get(f"{BASE_URL}/some-id", headers=viewer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_get_user_by_id(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get(f"{BASE_URL}/some-id", headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_get_user_by_id(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get(f"{BASE_URL}/some-id", headers=hunter_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_cannot_get_user_by_id(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get(f"{BASE_URL}/some-id", headers=engineer_headers)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 7. Non-admin roles denied write access (users:write is admin-only)
# ---------------------------------------------------------------------------


class TestNonAdminDeniedUserWrite:
    """Viewer, analyst, hunter, and engineer cannot create, update, or delete users."""

    @pytest.mark.asyncio
    async def test_viewer_cannot_create_user(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.post(BASE_URL, headers=viewer_headers, json=_VALID_PAYLOAD)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_create_user(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.post(BASE_URL, headers=analyst_headers, json=_VALID_PAYLOAD)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_create_user(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.post(BASE_URL, headers=hunter_headers, json=_VALID_PAYLOAD)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_cannot_create_user(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.post(BASE_URL, headers=engineer_headers, json=_VALID_PAYLOAD)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_update_user(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.patch(
            f"{BASE_URL}/some-id", headers=viewer_headers, json={"role": "analyst"}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_update_user(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.patch(
            f"{BASE_URL}/some-id", headers=analyst_headers, json={"role": "hunter"}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_update_user(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.patch(
            f"{BASE_URL}/some-id", headers=hunter_headers, json={"role": "analyst"}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_cannot_update_user(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.patch(
            f"{BASE_URL}/some-id", headers=engineer_headers, json={"role": "analyst"}
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_delete_user(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.delete(f"{BASE_URL}/some-id", headers=viewer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_delete_user(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.delete(f"{BASE_URL}/some-id", headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_hunter_cannot_delete_user(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.delete(f"{BASE_URL}/some-id", headers=hunter_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_engineer_cannot_delete_user(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.delete(f"{BASE_URL}/some-id", headers=engineer_headers)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 8. Unauthenticated access
# ---------------------------------------------------------------------------


class TestUnauthenticatedUserAccess:
    """Unauthenticated requests to all user endpoints return 401 or 403."""

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_list_users(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(BASE_URL)
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_get_user(
        self, client: AsyncClient
    ) -> None:
        resp = await client.get(f"{BASE_URL}/some-id")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_create_user(
        self, client: AsyncClient
    ) -> None:
        resp = await client.post(BASE_URL, json=_VALID_PAYLOAD)
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_update_user(
        self, client: AsyncClient
    ) -> None:
        resp = await client.patch(f"{BASE_URL}/some-id", json={"role": "analyst"})
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_delete_user(
        self, client: AsyncClient
    ) -> None:
        resp = await client.delete(f"{BASE_URL}/some-id")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 9. 403 response body contains the denied role
# ---------------------------------------------------------------------------


class TestForbiddenResponseBody:
    """403 responses include the requesting role in the detail message."""

    @pytest.mark.asyncio
    async def test_viewer_forbidden_list_contains_role(
        self, client: AsyncClient, viewer_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=viewer_headers)
        assert resp.status_code == 403
        assert "viewer" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_analyst_forbidden_list_contains_role(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=analyst_headers)
        assert resp.status_code == 403
        assert "analyst" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_hunter_forbidden_list_contains_role(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=hunter_headers)
        assert resp.status_code == 403
        assert "hunter" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_engineer_forbidden_list_contains_role(
        self, client: AsyncClient, engineer_headers: dict
    ) -> None:
        resp = await client.get(BASE_URL, headers=engineer_headers)
        assert resp.status_code == 403
        assert "engineer" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_forbidden_precedes_db_lookup(
        self, client: AsyncClient, analyst_headers: dict
    ) -> None:
        """RBAC check runs before any DB lookup — analyst gets 403 even for nonexistent IDs."""
        resp = await client.get(f"{BASE_URL}/nonexistent-id", headers=analyst_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_forbidden_on_write_precedes_db_lookup(
        self, client: AsyncClient, hunter_headers: dict
    ) -> None:
        """RBAC write check runs before DB lookup — hunter gets 403 even for nonexistent IDs."""
        resp = await client.patch(
            f"{BASE_URL}/nonexistent-id",
            headers=hunter_headers,
            json={"role": "analyst"},
        )
        assert resp.status_code == 403
