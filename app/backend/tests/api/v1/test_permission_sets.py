"""Tests for Feature 3.9 — Scoped API keys (per-permission set).

Covers:
  POST   /api/v1/auth/permission-sets        — create
  GET    /api/v1/auth/permission-sets        — list
  GET    /api/v1/auth/permission-sets/{id}   — get by id
  PUT    /api/v1/auth/permission-sets/{id}   — update
  DELETE /api/v1/auth/permission-sets/{id}   — delete (admin only)

Also covers:
  POST /api/v1/auth/api-keys with permission_set_id
  POST /api/v1/auth/api-keys scopes/permission_set_id mutual exclusion
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.models.permission_set import PermissionSet
from app.models.api_key import APIKey
from app.models.user import User

# ---------------------------------------------------------------------------
# URL constants & patch targets
# ---------------------------------------------------------------------------

PSETS_URL = "/api/v1/auth/permission-sets"
API_KEYS_URL = "/api/v1/auth/api-keys"

MOCK_PS_REPO_CREATE = "app.api.v1.endpoints.permission_sets.PermissionSetRepo.create"
MOCK_PS_REPO_GET_BY_ID = "app.api.v1.endpoints.permission_sets.PermissionSetRepo.get_by_id"
MOCK_PS_REPO_GET_BY_NAME = "app.api.v1.endpoints.permission_sets.PermissionSetRepo.get_by_name"
MOCK_PS_REPO_LIST = "app.api.v1.endpoints.permission_sets.PermissionSetRepo.list_active"
MOCK_PS_REPO_UPDATE = "app.api.v1.endpoints.permission_sets.PermissionSetRepo.update"
MOCK_PS_REPO_DELETE = "app.api.v1.endpoints.permission_sets.PermissionSetRepo.delete"
MOCK_USER_REPO_PS = "app.api.v1.endpoints.permission_sets.UserRepo.get_by_email"

# auth endpoint patches
MOCK_USER_REPO_AUTH = "app.api.v1.endpoints.auth.UserRepo.get_by_email"
MOCK_PS_REPO_GET_BY_ID_AUTH = "app.api.v1.endpoints.auth.PermissionSetRepo.get_by_id"
MOCK_APIKEY_REPO_CREATE = "app.api.v1.endpoints.auth.APIKeyRepo.create"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(
    user_id: str = "user-uuid-1234",
    email: str = "engineer@mxtac.local",
    role: str = "engineer",
) -> User:
    u = User(
        email=email,
        hashed_password="$2b$12$placeholder",
        role=role,
        is_active=True,
    )
    u.id = user_id
    return u


def _make_permission_set(
    set_id: str = "ps-uuid-0001",
    name: str = "read-only",
    permissions: list[str] | None = None,
    description: str | None = "Read-only access",
    created_by: str = "user-uuid-1234",
    is_active: bool = True,
) -> PermissionSet:
    ps = PermissionSet(
        name=name,
        permissions=permissions or ["detections:read", "incidents:read"],
        description=description,
        created_by=created_by,
        is_active=is_active,
    )
    ps.id = set_id
    ps.created_at = datetime.now(timezone.utc)
    ps.updated_at = datetime.now(timezone.utc)
    return ps


def _make_api_key(
    key_id: str = "key-uuid-5678",
    scopes: list[str] | None = None,
    permission_set_id: str | None = None,
) -> APIKey:
    k = APIKey(
        key_hash="fakehash",
        label="test-key",
        is_active=True,
        owner_id="user-uuid-1234",
        scopes=scopes or ["detections:read", "incidents:read"],
        permission_set_id=permission_set_id,
    )
    k.id = key_id
    k.created_at = datetime.now(timezone.utc)
    return k


# ---------------------------------------------------------------------------
# POST /auth/permission-sets — create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_permission_set_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Engineer can create a permission set with valid permissions."""
    user = _make_user(role="engineer")
    ps = _make_permission_set()

    with patch(MOCK_USER_REPO_PS, new=AsyncMock(return_value=user)):
        with patch(MOCK_PS_REPO_GET_BY_NAME, new=AsyncMock(return_value=None)):
            with patch(MOCK_PS_REPO_CREATE, new=AsyncMock(return_value=ps)):
                resp = await client.post(
                    PSETS_URL,
                    json={"name": "read-only", "permissions": ["detections:read", "incidents:read"]},
                    headers=engineer_headers,
                )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_create_permission_set_response_schema(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Response contains all expected fields."""
    user = _make_user(role="engineer")
    ps = _make_permission_set()

    with patch(MOCK_USER_REPO_PS, new=AsyncMock(return_value=user)):
        with patch(MOCK_PS_REPO_GET_BY_NAME, new=AsyncMock(return_value=None)):
            with patch(MOCK_PS_REPO_CREATE, new=AsyncMock(return_value=ps)):
                resp = await client.post(
                    PSETS_URL,
                    json={"name": "read-only", "permissions": ["detections:read"]},
                    headers=engineer_headers,
                )
    data = resp.json()
    assert {"id", "name", "permissions", "is_active", "created_by", "created_at"} <= set(data)


@pytest.mark.asyncio
async def test_create_permission_set_invalid_permission(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Unknown permission string → 422."""
    resp = await client.post(
        PSETS_URL,
        json={"name": "bad-set", "permissions": ["totally:invalid"]},
        headers=engineer_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_permission_set_empty_permissions(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Empty permissions list → 422."""
    resp = await client.post(
        PSETS_URL,
        json={"name": "empty-set", "permissions": []},
        headers=engineer_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_permission_set_scope_exceeds_role(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Analyst cannot create a set with permissions beyond their role → 403."""
    user = _make_user(role="analyst")
    with patch(MOCK_USER_REPO_PS, new=AsyncMock(return_value=user)):
        resp = await client.post(
            PSETS_URL,
            json={"name": "escalate-set", "permissions": ["users:write"]},  # admin-only
            headers=analyst_headers,
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_permission_set_name_conflict(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Duplicate name → 409 Conflict."""
    user = _make_user(role="engineer")
    existing = _make_permission_set()
    with patch(MOCK_USER_REPO_PS, new=AsyncMock(return_value=user)):
        with patch(MOCK_PS_REPO_GET_BY_NAME, new=AsyncMock(return_value=existing)):
            resp = await client.post(
                PSETS_URL,
                json={"name": "read-only", "permissions": ["detections:read"]},
                headers=engineer_headers,
            )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_create_permission_set_unauthenticated(client: AsyncClient) -> None:
    """Missing auth → 401."""
    resp = await client.post(
        PSETS_URL,
        json={"name": "x", "permissions": ["detections:read"]},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_permission_set_viewer_forbidden(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Viewer role lacks connectors:write → 403."""
    resp = await client.post(
        PSETS_URL,
        json={"name": "x", "permissions": ["detections:read"]},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /auth/permission-sets — list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_permission_sets_success(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Authenticated user gets 200 with list of active sets."""
    sets = [
        _make_permission_set(set_id="ps-1", name="alpha"),
        _make_permission_set(set_id="ps-2", name="beta"),
    ]
    with patch(MOCK_PS_REPO_LIST, new=AsyncMock(return_value=sets)):
        resp = await client.get(PSETS_URL, headers=analyst_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_list_permission_sets_empty(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Empty list returned when no sets exist."""
    with patch(MOCK_PS_REPO_LIST, new=AsyncMock(return_value=[])):
        resp = await client.get(PSETS_URL, headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_permission_sets_unauthenticated(client: AsyncClient) -> None:
    """No auth → 401."""
    resp = await client.get(PSETS_URL)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /auth/permission-sets/{id} — get by id
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_permission_set_success(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Valid ID returns 200 with the set."""
    ps = _make_permission_set()
    with patch(MOCK_PS_REPO_GET_BY_ID, new=AsyncMock(return_value=ps)):
        resp = await client.get(f"{PSETS_URL}/ps-uuid-0001", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "read-only"


@pytest.mark.asyncio
async def test_get_permission_set_not_found(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Unknown ID → 404."""
    with patch(MOCK_PS_REPO_GET_BY_ID, new=AsyncMock(return_value=None)):
        resp = await client.get(f"{PSETS_URL}/nonexistent", headers=analyst_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_permission_set_inactive_is_404(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Soft-deleted (inactive) set returns 404."""
    ps = _make_permission_set(is_active=False)
    with patch(MOCK_PS_REPO_GET_BY_ID, new=AsyncMock(return_value=ps)):
        resp = await client.get(f"{PSETS_URL}/ps-uuid-0001", headers=analyst_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PUT /auth/permission-sets/{id} — update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_permission_set_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Engineer can update permissions on an existing set."""
    ps = _make_permission_set()
    updated = _make_permission_set(permissions=["detections:read"])

    with patch(MOCK_PS_REPO_GET_BY_ID, new=AsyncMock(return_value=ps)):
        with patch(MOCK_PS_REPO_UPDATE, new=AsyncMock(return_value=updated)):
            resp = await client.put(
                f"{PSETS_URL}/ps-uuid-0001",
                json={"permissions": ["detections:read"]},
                headers=engineer_headers,
            )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_update_permission_set_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Updating a non-existent set → 404."""
    with patch(MOCK_PS_REPO_GET_BY_ID, new=AsyncMock(return_value=None)):
        resp = await client.put(
            f"{PSETS_URL}/nonexistent",
            json={"permissions": ["detections:read"]},
            headers=engineer_headers,
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_permission_set_scope_escalation(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Non-engineer cannot update to admin-only permissions → 403."""
    ps = _make_permission_set()
    with patch(MOCK_PS_REPO_GET_BY_ID, new=AsyncMock(return_value=ps)):
        resp = await client.put(
            f"{PSETS_URL}/ps-uuid-0001",
            json={"permissions": ["users:write"]},
            headers=analyst_headers,
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_update_permission_set_name_conflict(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Renaming to an already-existing name → 409."""
    ps = _make_permission_set(set_id="ps-1", name="alpha")
    conflict = _make_permission_set(set_id="ps-2", name="beta")

    with patch(MOCK_PS_REPO_GET_BY_ID, new=AsyncMock(return_value=ps)):
        with patch(MOCK_PS_REPO_GET_BY_NAME, new=AsyncMock(return_value=conflict)):
            resp = await client.put(
                f"{PSETS_URL}/ps-1",
                json={"name": "beta"},
                headers=engineer_headers,
            )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# DELETE /auth/permission-sets/{id} — admin only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_permission_set_admin_success(
    client: AsyncClient, admin_headers: dict
) -> None:
    """Admin can delete (soft-delete) a permission set → 204."""
    with patch(MOCK_PS_REPO_DELETE, new=AsyncMock(return_value=True)):
        resp = await client.delete(f"{PSETS_URL}/ps-uuid-0001", headers=admin_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_delete_permission_set_not_found(
    client: AsyncClient, admin_headers: dict
) -> None:
    """Deleting non-existent set → 404."""
    with patch(MOCK_PS_REPO_DELETE, new=AsyncMock(return_value=False)):
        resp = await client.delete(f"{PSETS_URL}/nonexistent", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_permission_set_engineer_forbidden(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Engineer cannot delete (requires users:write / admin) → 403."""
    resp = await client.delete(f"{PSETS_URL}/ps-uuid-0001", headers=engineer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_permission_set_unauthenticated(client: AsyncClient) -> None:
    """No auth → 401."""
    resp = await client.delete(f"{PSETS_URL}/ps-uuid-0001")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /auth/api-keys with permission_set_id (Feature 3.9 integration)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_api_key_with_permission_set_id(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Creating an API key with permission_set_id resolves scopes from the set."""
    user = _make_user(role="engineer")
    ps = _make_permission_set(permissions=["detections:read", "incidents:read"])
    key = _make_api_key(
        scopes=["detections:read", "incidents:read"],
        permission_set_id="ps-uuid-0001",
    )
    key.created_at = datetime.now(timezone.utc)

    with patch(MOCK_PS_REPO_GET_BY_ID_AUTH, new=AsyncMock(return_value=ps)):
        with patch(MOCK_USER_REPO_AUTH, new=AsyncMock(return_value=user)):
            with patch(MOCK_APIKEY_REPO_CREATE, new=AsyncMock(return_value=key)):
                resp = await client.post(
                    API_KEYS_URL,
                    json={"label": "pset-key", "permission_set_id": "ps-uuid-0001"},
                    headers=engineer_headers,
                )
    assert resp.status_code == 201
    data = resp.json()
    assert data["permission_set_id"] == "ps-uuid-0001"
    assert "detections:read" in data["scopes"]


@pytest.mark.asyncio
async def test_create_api_key_permission_set_id_stored(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """APIKeyRepo.create is called with the permission_set_id."""
    user = _make_user(role="engineer")
    ps = _make_permission_set(set_id="ps-uuid-0001", permissions=["detections:read"])
    key = _make_api_key(scopes=["detections:read"], permission_set_id="ps-uuid-0001")
    key.created_at = datetime.now(timezone.utc)

    mock_create = AsyncMock(return_value=key)
    with patch(MOCK_PS_REPO_GET_BY_ID_AUTH, new=AsyncMock(return_value=ps)):
        with patch(MOCK_USER_REPO_AUTH, new=AsyncMock(return_value=user)):
            with patch(MOCK_APIKEY_REPO_CREATE, mock_create):
                await client.post(
                    API_KEYS_URL,
                    json={"label": "pset-key", "permission_set_id": "ps-uuid-0001"},
                    headers=engineer_headers,
                )
    call_kwargs = mock_create.call_args[1]
    assert call_kwargs["permission_set_id"] == "ps-uuid-0001"
    assert call_kwargs["scopes"] == ["detections:read"]


@pytest.mark.asyncio
async def test_create_api_key_permission_set_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Referencing a non-existent permission_set_id → 404."""
    with patch(MOCK_PS_REPO_GET_BY_ID_AUTH, new=AsyncMock(return_value=None)):
        resp = await client.post(
            API_KEYS_URL,
            json={"label": "pset-key", "permission_set_id": "nonexistent"},
            headers=engineer_headers,
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_api_key_permission_set_scope_exceeds_role(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Permission set contains scopes beyond the caller's role → 403."""
    # Set contains admin-only permissions; viewer cannot use these
    ps = _make_permission_set(permissions=["users:write"])
    with patch(MOCK_PS_REPO_GET_BY_ID_AUTH, new=AsyncMock(return_value=ps)):
        resp = await client.post(
            API_KEYS_URL,
            json={"label": "bad-key", "permission_set_id": "ps-uuid-0001"},
            headers=viewer_headers,
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_api_key_both_scopes_and_permission_set_id(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Providing both scopes and permission_set_id → 422 (mutually exclusive)."""
    resp = await client.post(
        API_KEYS_URL,
        json={
            "label": "bad-key",
            "scopes": ["detections:read"],
            "permission_set_id": "ps-uuid-0001",
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_api_key_neither_scopes_nor_permission_set_id(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Providing neither scopes nor permission_set_id → 422."""
    resp = await client.post(
        API_KEYS_URL,
        json={"label": "bad-key"},
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_api_keys_includes_permission_set_id(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Listed API keys include permission_set_id field."""
    from app.repositories.api_key_repo import APIKeyRepo
    from app.repositories.user_repo import UserRepo

    user = _make_user(role="analyst")
    key = _make_api_key(permission_set_id="ps-uuid-0001")

    with patch("app.api.v1.endpoints.auth.UserRepo.get_by_email", new=AsyncMock(return_value=user)):
        with patch("app.api.v1.endpoints.auth.APIKeyRepo.list_by_owner", new=AsyncMock(return_value=[key])):
            resp = await client.get(API_KEYS_URL, headers=analyst_headers)
    assert resp.status_code == 200
    item = resp.json()[0]
    assert item["permission_set_id"] == "ps-uuid-0001"


# ---------------------------------------------------------------------------
# Permission set deduplication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_permission_set_deduplicates_permissions(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """Duplicate permission entries in the request are silently deduplicated."""
    user = _make_user(role="engineer")
    ps = _make_permission_set(permissions=["detections:read"])

    mock_create = AsyncMock(return_value=ps)
    with patch(MOCK_USER_REPO_PS, new=AsyncMock(return_value=user)):
        with patch(MOCK_PS_REPO_GET_BY_NAME, new=AsyncMock(return_value=None)):
            with patch(MOCK_PS_REPO_CREATE, mock_create):
                resp = await client.post(
                    PSETS_URL,
                    json={
                        "name": "dedup-set",
                        "permissions": ["detections:read", "detections:read"],
                    },
                    headers=engineer_headers,
                )
    assert resp.status_code == 201
    call_kwargs = mock_create.call_args[1]
    assert call_kwargs["permissions"].count("detections:read") == 1
