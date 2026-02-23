"""Tests for Feature 1.11 — API key creation and scoped access.

Endpoints:
  POST   /api/v1/auth/api-keys          — create a scoped API key
  GET    /api/v1/auth/api-keys          — list own API keys
  DELETE /api/v1/auth/api-keys/{key_id} — revoke an API key

Coverage:
  - Happy path: create, list, revoke
  - Schema validation: missing fields, invalid scopes, past expiry
  - Scope enforcement: scopes must be within caller's role permissions
  - Admin bypass: admin can revoke any key
  - Non-admin isolation: users can only see/revoke their own keys
  - Secret key never re-exposed after creation
  - get_api_key dependency: expiry rejection, last_used_at update
  - require_api_key_scope dependency: scope enforcement
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.models.api_key import APIKey
from app.models.user import User

# ---------------------------------------------------------------------------
# URL constants
# ---------------------------------------------------------------------------

API_KEYS_URL = "/api/v1/auth/api-keys"

# Patch targets
MOCK_USER_REPO = "app.api.v1.endpoints.auth.UserRepo.get_by_email"
MOCK_APIKEY_REPO_CREATE = "app.api.v1.endpoints.auth.APIKeyRepo.create"
MOCK_APIKEY_REPO_LIST = "app.api.v1.endpoints.auth.APIKeyRepo.list_by_owner"
MOCK_APIKEY_REPO_REVOKE = "app.api.v1.endpoints.auth.APIKeyRepo.revoke"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(
    user_id: str = "user-uuid-1234",
    email: str = "analyst@mxtac.local",
    role: str = "analyst",
) -> User:
    u = User(
        email=email,
        hashed_password="$2b$12$placeholder",
        role=role,
        is_active=True,
    )
    u.id = user_id
    return u


def _make_api_key(
    key_id: str = "key-uuid-5678",
    label: str = "test-key",
    scopes: list[str] | None = None,
    owner_id: str = "user-uuid-1234",
    is_active: bool = True,
    expires_at: datetime | None = None,
    last_used_at: datetime | None = None,
) -> APIKey:
    k = APIKey(
        key_hash="fakehash",
        label=label,
        is_active=is_active,
        owner_id=owner_id,
        scopes=scopes or ["events:search"],
        expires_at=expires_at,
        last_used_at=last_used_at,
    )
    k.id = key_id
    k.created_at = datetime.now(timezone.utc)
    return k


# ---------------------------------------------------------------------------
# POST /auth/api-keys — create
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_api_key_success(client: AsyncClient, analyst_headers: dict) -> None:
    """Valid request from analyst with a permitted scope → 201 Created."""
    user = _make_user(role="analyst")
    key = _make_api_key(scopes=["detections:read"])
    key.created_at = datetime.now(timezone.utc)

    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_CREATE, new=AsyncMock(return_value=key)):
            resp = await client.post(
                API_KEYS_URL,
                json={"label": "ci-token", "scopes": ["detections:read"]},
                headers=analyst_headers,
            )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_create_api_key_returns_raw_key(client: AsyncClient, analyst_headers: dict) -> None:
    """Response must include the raw key string."""
    user = _make_user(role="analyst")
    key = _make_api_key(scopes=["detections:read"])
    key.created_at = datetime.now(timezone.utc)

    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_CREATE, new=AsyncMock(return_value=key)):
            resp = await client.post(
                API_KEYS_URL,
                json={"label": "ci-token", "scopes": ["detections:read"]},
                headers=analyst_headers,
            )
    data = resp.json()
    assert "key" in data
    assert data["key"].startswith("mxtac_")


@pytest.mark.asyncio
async def test_create_api_key_response_schema(client: AsyncClient, analyst_headers: dict) -> None:
    """Response contains all expected fields."""
    user = _make_user(role="analyst")
    key = _make_api_key(scopes=["detections:read"])
    key.created_at = datetime.now(timezone.utc)

    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_CREATE, new=AsyncMock(return_value=key)):
            resp = await client.post(
                API_KEYS_URL,
                json={"label": "ci-token", "scopes": ["detections:read"]},
                headers=analyst_headers,
            )
    data = resp.json()
    assert {"id", "label", "scopes", "is_active", "created_at", "key"} <= set(data)


@pytest.mark.asyncio
async def test_create_api_key_scopes_stored(client: AsyncClient, hunter_headers: dict) -> None:
    """Requested scopes appear in the response (hunter role has events:search + rules:read)."""
    user = _make_user(role="hunter")
    key = _make_api_key(scopes=["events:search", "rules:read"])
    key.created_at = datetime.now(timezone.utc)

    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_CREATE, new=AsyncMock(return_value=key)):
            resp = await client.post(
                API_KEYS_URL,
                json={"label": "hunt-key", "scopes": ["events:search", "rules:read"]},
                headers=hunter_headers,
            )
    data = resp.json()
    assert set(data["scopes"]) == {"events:search", "rules:read"}


@pytest.mark.asyncio
async def test_create_api_key_passes_owner_id_to_repo(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """APIKeyRepo.create is called with the user's UUID as owner_id."""
    user = _make_user(user_id="specific-uuid-999", role="analyst")
    key = _make_api_key(owner_id="specific-uuid-999", scopes=["detections:read"])
    key.created_at = datetime.now(timezone.utc)

    mock_create = AsyncMock(return_value=key)
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_CREATE, mock_create):
            await client.post(
                API_KEYS_URL,
                json={"label": "ci-token", "scopes": ["detections:read"]},
                headers=analyst_headers,
            )
    call_kwargs = mock_create.call_args[1]
    assert call_kwargs["owner_id"] == "specific-uuid-999"


@pytest.mark.asyncio
async def test_create_api_key_unauthenticated(client: AsyncClient) -> None:
    """Missing Authorization header → 401."""
    resp = await client.post(
        API_KEYS_URL,
        json={"label": "ci-token", "scopes": ["events:search"]},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_api_key_missing_label(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Missing label field → 422 Unprocessable Entity."""
    resp = await client.post(
        API_KEYS_URL,
        json={"scopes": ["events:search"]},
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_api_key_missing_scopes(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Missing scopes field → 422 Unprocessable Entity."""
    resp = await client.post(
        API_KEYS_URL,
        json={"label": "ci-token"},
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_api_key_empty_scopes(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Empty scopes list → 422 (min_length=1)."""
    resp = await client.post(
        API_KEYS_URL,
        json={"label": "ci-token", "scopes": []},
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_api_key_invalid_scope(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Unrecognised scope string → 422 Unprocessable Entity."""
    resp = await client.post(
        API_KEYS_URL,
        json={"label": "ci-token", "scopes": ["nonexistent:scope"]},
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_api_key_scope_exceeds_role(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """Requesting a scope that the caller's role cannot use → 403."""
    user = _make_user(role="viewer")
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(
            API_KEYS_URL,
            json={"label": "bad-key", "scopes": ["users:write"]},  # admin-only
            headers=viewer_headers,
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_api_key_scope_exceeds_role_detail(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """403 response body names the forbidden scope(s)."""
    user = _make_user(role="viewer")
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(
            API_KEYS_URL,
            json={"label": "bad-key", "scopes": ["users:write"]},
            headers=viewer_headers,
        )
    assert "users:write" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_create_api_key_admin_can_assign_any_scope(
    client: AsyncClient, admin_headers: dict
) -> None:
    """Admin may request any valid scope including admin-only ones."""
    user = _make_user(role="admin")
    key = _make_api_key(scopes=["users:write", "audit_logs:read"])
    key.created_at = datetime.now(timezone.utc)

    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_CREATE, new=AsyncMock(return_value=key)):
            resp = await client.post(
                API_KEYS_URL,
                json={"label": "admin-key", "scopes": ["users:write", "audit_logs:read"]},
                headers=admin_headers,
            )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_create_api_key_with_expiry(client: AsyncClient, analyst_headers: dict) -> None:
    """expires_at in the future is accepted and stored."""
    future_ts = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    user = _make_user(role="analyst")
    key = _make_api_key(scopes=["detections:read"])
    key.created_at = datetime.now(timezone.utc)

    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_CREATE, new=AsyncMock(return_value=key)):
            resp = await client.post(
                API_KEYS_URL,
                json={"label": "exp-key", "scopes": ["detections:read"], "expires_at": future_ts},
                headers=analyst_headers,
            )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_create_api_key_with_past_expiry_rejected(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """expires_at in the past → 422 Unprocessable Entity."""
    past_ts = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    resp = await client.post(
        API_KEYS_URL,
        json={"label": "exp-key", "scopes": ["events:search"], "expires_at": past_ts},
        headers=analyst_headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_api_key_user_not_found(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """UserRepo returns None (ghost token) → 404."""
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=None)):
        resp = await client.post(
            API_KEYS_URL,
            json={"label": "ci-token", "scopes": ["detections:read"]},
            headers=analyst_headers,
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /auth/api-keys — list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_api_keys_success(client: AsyncClient, analyst_headers: dict) -> None:
    """Authenticated user gets 200 with a list of their keys."""
    user = _make_user(role="analyst")
    keys = [
        _make_api_key(key_id="k1", label="key-one"),
        _make_api_key(key_id="k2", label="key-two"),
    ]
    for k in keys:
        k.created_at = datetime.now(timezone.utc)

    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_LIST, new=AsyncMock(return_value=keys)):
            resp = await client.get(API_KEYS_URL, headers=analyst_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_list_api_keys_empty(client: AsyncClient, analyst_headers: dict) -> None:
    """User with no keys gets an empty list."""
    user = _make_user(role="analyst")
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_LIST, new=AsyncMock(return_value=[])):
            resp = await client.get(API_KEYS_URL, headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_api_keys_response_schema(client: AsyncClient, analyst_headers: dict) -> None:
    """Each item in the list has the expected fields (no raw key exposed)."""
    user = _make_user(role="analyst")
    key = _make_api_key()
    key.created_at = datetime.now(timezone.utc)

    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_LIST, new=AsyncMock(return_value=[key])):
            resp = await client.get(API_KEYS_URL, headers=analyst_headers)
    item = resp.json()[0]
    assert {"id", "label", "scopes", "is_active", "created_at"} <= set(item)
    # Raw key must never be returned in list endpoint
    assert "key" not in item


@pytest.mark.asyncio
async def test_list_api_keys_unauthenticated(client: AsyncClient) -> None:
    """Missing Authorization header → 401."""
    resp = await client.get(API_KEYS_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_api_keys_filters_by_owner(client: AsyncClient, analyst_headers: dict) -> None:
    """list_by_owner is called with the authenticated user's UUID."""
    user = _make_user(user_id="owner-uuid-abc", role="analyst")
    mock_list = AsyncMock(return_value=[])
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_LIST, mock_list):
            await client.get(API_KEYS_URL, headers=analyst_headers)
    mock_list.assert_awaited_once()
    args, _ = mock_list.call_args
    # Second positional argument is owner_id; first is the db session
    assert args[1] == "owner-uuid-abc"


@pytest.mark.asyncio
async def test_list_api_keys_user_not_found(client: AsyncClient, analyst_headers: dict) -> None:
    """Ghost token (user deleted after JWT issued) → 404."""
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=None)):
        resp = await client.get(API_KEYS_URL, headers=analyst_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /auth/api-keys/{key_id} — revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_api_key_success(client: AsyncClient, analyst_headers: dict) -> None:
    """Valid key ID belonging to the caller → 204 No Content."""
    user = _make_user(role="analyst")
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_REVOKE, new=AsyncMock(return_value=True)):
            resp = await client.delete(
                f"{API_KEYS_URL}/key-uuid-5678", headers=analyst_headers
            )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_revoke_api_key_not_found(client: AsyncClient, analyst_headers: dict) -> None:
    """Key not found (or belongs to another user) → 404."""
    user = _make_user(role="analyst")
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_REVOKE, new=AsyncMock(return_value=False)):
            resp = await client.delete(
                f"{API_KEYS_URL}/nonexistent-key", headers=analyst_headers
            )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_revoke_api_key_unauthenticated(client: AsyncClient) -> None:
    """Missing Authorization header → 401."""
    resp = await client.delete(f"{API_KEYS_URL}/some-key-id")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_revoke_non_admin_passes_owner_filter(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Non-admin: revoke is called with owner_id=user.id to enforce ownership."""
    user = _make_user(user_id="owner-uuid-123", role="analyst")
    mock_revoke = AsyncMock(return_value=True)
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_REVOKE, mock_revoke):
            await client.delete(f"{API_KEYS_URL}/key-uuid-5678", headers=analyst_headers)
    mock_revoke.assert_awaited_once()
    _, kwargs = mock_revoke.call_args
    assert kwargs["owner_id"] == "owner-uuid-123"


@pytest.mark.asyncio
async def test_revoke_admin_passes_no_owner_filter(
    client: AsyncClient, admin_headers: dict
) -> None:
    """Admin: revoke is called with owner_id=None (can revoke any key)."""
    user = _make_user(user_id="admin-uuid-789", role="admin")
    mock_revoke = AsyncMock(return_value=True)
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_REVOKE, mock_revoke):
            await client.delete(f"{API_KEYS_URL}/key-uuid-5678", headers=admin_headers)
    mock_revoke.assert_awaited_once()
    _, kwargs = mock_revoke.call_args
    assert kwargs["owner_id"] is None


@pytest.mark.asyncio
async def test_revoke_api_key_user_not_found(client: AsyncClient, analyst_headers: dict) -> None:
    """Ghost token (user deleted) → 404 when trying to revoke."""
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=None)):
        resp = await client.delete(f"{API_KEYS_URL}/key-uuid-5678", headers=analyst_headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# get_api_key dependency — expiry and last_used_at
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_api_key_expired_key_rejected(client: AsyncClient) -> None:
    """An expired API key (expires_at in the past) → 403 on ingest endpoint."""
    from app.repositories.api_key_repo import APIKeyRepo
    expired_key = _make_api_key(
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
    )
    # get_by_raw_key already rejects expired keys and returns None
    with patch.object(APIKeyRepo, "get_by_raw_key", new=AsyncMock(return_value=None)):
        resp = await client.post(
            "/api/v1/events/ingest/test",
            headers={"X-API-Key": "mxtac_expired"},
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_api_key_updates_last_used_at(client: AsyncClient) -> None:
    """A valid API key triggers an update_last_used call."""
    from app.repositories.api_key_repo import APIKeyRepo
    valid_key = _make_api_key()
    mock_update = AsyncMock()
    with patch.object(APIKeyRepo, "get_by_raw_key", new=AsyncMock(return_value=valid_key)):
        with patch.object(APIKeyRepo, "update_last_used", mock_update):
            await client.post(
                "/api/v1/events/ingest/test",
                headers={"X-API-Key": "mxtac_valid"},
            )
    mock_update.assert_awaited_once()


# ---------------------------------------------------------------------------
# require_api_key_scope dependency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_api_key_scope_none_scopes_passes(client: AsyncClient) -> None:
    """A key with scopes=None (unrestricted) passes any scope check."""
    from app.repositories.api_key_repo import APIKeyRepo
    unrestricted_key = _make_api_key()
    unrestricted_key.scopes = None  # pre-1.11 key

    with patch.object(APIKeyRepo, "get_by_raw_key", new=AsyncMock(return_value=unrestricted_key)):
        with patch.object(APIKeyRepo, "update_last_used", new=AsyncMock()):
            resp = await client.post(
                "/api/v1/events/ingest/test",
                headers={"X-API-Key": "mxtac_unrestricted"},
            )
    # /events/ingest/test uses get_api_key (no specific scope required), so we just
    # validate the key passes validation at all.
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_require_api_key_scope_valid_scope_passes(client: AsyncClient) -> None:
    """A key whose scopes include the required scope passes the check."""
    from app.core.api_key_auth import require_api_key_scope, get_api_key
    from app.repositories.api_key_repo import APIKeyRepo

    scoped_key = _make_api_key(scopes=["events:search"])
    dep = require_api_key_scope("events:search")

    with patch.object(APIKeyRepo, "get_by_raw_key", new=AsyncMock(return_value=scoped_key)):
        with patch.object(APIKeyRepo, "update_last_used", new=AsyncMock()):
            # Directly test the dependency function
            from fastapi import HTTPException
            result = await dep(api_key=scoped_key)
    assert result is scoped_key


@pytest.mark.asyncio
async def test_require_api_key_scope_missing_scope_raises_403() -> None:
    """A key that lacks the required scope raises 403 Forbidden."""
    from app.core.api_key_auth import require_api_key_scope
    from fastapi import HTTPException

    scoped_key = _make_api_key(scopes=["events:search"])
    dep = require_api_key_scope("rules:write")

    with pytest.raises(HTTPException) as exc_info:
        await dep(api_key=scoped_key)
    assert exc_info.value.status_code == 403
    assert "rules:write" in exc_info.value.detail


@pytest.mark.asyncio
async def test_require_api_key_scope_unknown_scope_raises_at_import() -> None:
    """Passing an unknown scope string raises ValueError at definition time."""
    from app.core.api_key_auth import require_api_key_scope

    with pytest.raises(ValueError, match="Unknown scope"):
        require_api_key_scope("totally:invalid")


# ---------------------------------------------------------------------------
# Scope deduplication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_api_key_deduplicates_scopes(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """Duplicate scope entries in the request are silently deduplicated."""
    user = _make_user(role="analyst")
    key = _make_api_key(scopes=["detections:read"])
    key.created_at = datetime.now(timezone.utc)

    mock_create = AsyncMock(return_value=key)
    with patch(MOCK_USER_REPO, new=AsyncMock(return_value=user)):
        with patch(MOCK_APIKEY_REPO_CREATE, mock_create):
            resp = await client.post(
                API_KEYS_URL,
                json={
                    "label": "dup-key",
                    "scopes": ["detections:read", "detections:read"],
                },
                headers=analyst_headers,
            )
    assert resp.status_code == 201
    call_kwargs = mock_create.call_args[1]
    assert call_kwargs["scopes"].count("detections:read") == 1
