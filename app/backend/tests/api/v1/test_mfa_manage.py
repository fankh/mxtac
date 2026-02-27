"""Tests for Feature 32.3 — MFA management endpoints.

GET  /auth/me           — return authenticated user's profile (incl. mfa_enabled)
POST /auth/mfa/disable  — admin-only: disable MFA for a target user

All tests mock UserRepo so the suite runs without a live database.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.security import create_access_token
from app.models.user import User

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ME_URL = "/api/v1/auth/me"
DISABLE_URL = "/api/v1/auth/mfa/disable"

MOCK_REPO_BY_EMAIL = "app.api.v1.endpoints.auth.UserRepo.get_by_email"
MOCK_REPO_BY_ID = "app.api.v1.endpoints.auth.UserRepo.get_by_id"

_TEST_USER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TARGET_USER_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_headers(email: str = "analyst@mxtac.local", role: str = "analyst") -> dict:
    token = create_access_token({"sub": email, "role": role})
    return {"Authorization": f"Bearer {token}"}


def _admin_headers(email: str = "admin@mxtac.local") -> dict:
    return _auth_headers(email=email, role="admin")


def _make_user(
    email: str = "analyst@mxtac.local",
    role: str = "analyst",
    full_name: str | None = None,
    mfa_enabled: bool = False,
    mfa_secret: str | None = None,
    mfa_backup_codes: list | None = None,
    is_active: bool = True,
) -> User:
    user = User(
        email=email,
        hashed_password="$2b$12$placeholder",
        role=role,
        is_active=is_active,
    )
    user.id = _TEST_USER_ID
    user.full_name = full_name
    user.mfa_enabled = mfa_enabled
    user.mfa_secret = mfa_secret
    user.mfa_backup_codes = mfa_backup_codes
    return user


def _make_target_user(
    mfa_enabled: bool = True,
    mfa_secret: str | None = "encrypted-secret",
    mfa_backup_codes: list | None = None,
) -> User:
    user = User(
        email="target@mxtac.local",
        hashed_password="$2b$12$placeholder",
        role="analyst",
        is_active=True,
    )
    user.id = _TARGET_USER_ID
    user.full_name = None
    user.mfa_enabled = mfa_enabled
    user.mfa_secret = mfa_secret
    user.mfa_backup_codes = mfa_backup_codes or []
    return user


# ===========================================================================
# GET /auth/me
# ===========================================================================


@pytest.mark.asyncio
async def test_me_returns_200(client: AsyncClient) -> None:
    """Authenticated request → 200 OK."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.get(ME_URL, headers=_auth_headers())
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_me_returns_email(client: AsyncClient) -> None:
    """Response contains the correct email."""
    user = _make_user(email="analyst@mxtac.local")
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.get(ME_URL, headers=_auth_headers(email="analyst@mxtac.local"))
    assert resp.json()["email"] == "analyst@mxtac.local"


@pytest.mark.asyncio
async def test_me_returns_role(client: AsyncClient) -> None:
    """Response contains the correct role."""
    user = _make_user(role="engineer")
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.get(ME_URL, headers=_auth_headers(role="engineer"))
    assert resp.json()["role"] == "engineer"


@pytest.mark.asyncio
async def test_me_returns_full_name_when_set(client: AsyncClient) -> None:
    """Response includes full_name when present."""
    user = _make_user(full_name="Alice Smith")
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.get(ME_URL, headers=_auth_headers())
    assert resp.json()["full_name"] == "Alice Smith"


@pytest.mark.asyncio
async def test_me_returns_null_full_name(client: AsyncClient) -> None:
    """Response includes full_name=null when not set."""
    user = _make_user(full_name=None)
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.get(ME_URL, headers=_auth_headers())
    assert resp.json()["full_name"] is None


@pytest.mark.asyncio
async def test_me_returns_mfa_enabled_true(client: AsyncClient) -> None:
    """Response contains mfa_enabled=true when MFA is active."""
    user = _make_user(mfa_enabled=True)
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.get(ME_URL, headers=_auth_headers())
    assert resp.json()["mfa_enabled"] is True


@pytest.mark.asyncio
async def test_me_returns_mfa_enabled_false(client: AsyncClient) -> None:
    """Response contains mfa_enabled=false when MFA is not configured."""
    user = _make_user(mfa_enabled=False)
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.get(ME_URL, headers=_auth_headers())
    assert resp.json()["mfa_enabled"] is False


@pytest.mark.asyncio
async def test_me_response_schema(client: AsyncClient) -> None:
    """Response contains exactly the expected keys."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.get(ME_URL, headers=_auth_headers())
    assert {"email", "role", "full_name", "mfa_enabled"} == set(resp.json())


@pytest.mark.asyncio
async def test_me_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated request → 401."""
    resp = await client.get(ME_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_me_user_not_found_returns_404(client: AsyncClient) -> None:
    """If the token is valid but the user no longer exists in DB → 404."""
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=None)):
        resp = await client.get(ME_URL, headers=_auth_headers())
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_me_get_method_required(client: AsyncClient) -> None:
    """POST /auth/me → 405 Method Not Allowed (only GET is defined)."""
    resp = await client.post(ME_URL)
    assert resp.status_code in (405, 401)  # 401 if auth check fires first


# ===========================================================================
# POST /auth/mfa/disable
# ===========================================================================


@pytest.mark.asyncio
async def test_mfa_disable_returns_200(client: AsyncClient) -> None:
    """Admin calling disable with a valid user_id → 200 OK."""
    target = _make_target_user()
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=target)):
        resp = await client.post(
            DISABLE_URL,
            json={"user_id": _TARGET_USER_ID},
            headers=_admin_headers(),
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mfa_disable_returns_message(client: AsyncClient) -> None:
    """Successful disable returns {'message': 'MFA disabled'}."""
    target = _make_target_user()
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=target)):
        resp = await client.post(
            DISABLE_URL,
            json={"user_id": _TARGET_USER_ID},
            headers=_admin_headers(),
        )
    assert resp.json()["message"] == "MFA disabled"


@pytest.mark.asyncio
async def test_mfa_disable_clears_mfa_enabled(client: AsyncClient) -> None:
    """After disable, mfa_enabled is set to False on the user object."""
    target = _make_target_user(mfa_enabled=True)
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=target)):
        await client.post(
            DISABLE_URL,
            json={"user_id": _TARGET_USER_ID},
            headers=_admin_headers(),
        )
    assert target.mfa_enabled is False


@pytest.mark.asyncio
async def test_mfa_disable_clears_mfa_secret(client: AsyncClient) -> None:
    """After disable, mfa_secret is set to None."""
    target = _make_target_user(mfa_secret="encrypted-secret-xyz")
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=target)):
        await client.post(
            DISABLE_URL,
            json={"user_id": _TARGET_USER_ID},
            headers=_admin_headers(),
        )
    assert target.mfa_secret is None


@pytest.mark.asyncio
async def test_mfa_disable_clears_backup_codes(client: AsyncClient) -> None:
    """After disable, mfa_backup_codes is set to None."""
    target = _make_target_user(mfa_backup_codes=["hash1", "hash2"])
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=target)):
        await client.post(
            DISABLE_URL,
            json={"user_id": _TARGET_USER_ID},
            headers=_admin_headers(),
        )
    assert target.mfa_backup_codes is None


@pytest.mark.asyncio
async def test_mfa_disable_non_admin_returns_403(client: AsyncClient) -> None:
    """Non-admin user (analyst role) → 403 Forbidden."""
    resp = await client.post(
        DISABLE_URL,
        json={"user_id": _TARGET_USER_ID},
        headers=_auth_headers(role="analyst"),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_mfa_disable_engineer_returns_403(client: AsyncClient) -> None:
    """Engineer role does not have users:write → 403."""
    resp = await client.post(
        DISABLE_URL,
        json={"user_id": _TARGET_USER_ID},
        headers=_auth_headers(role="engineer"),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_mfa_disable_hunter_returns_403(client: AsyncClient) -> None:
    """Hunter role does not have users:write → 403."""
    resp = await client.post(
        DISABLE_URL,
        json={"user_id": _TARGET_USER_ID},
        headers=_auth_headers(role="hunter"),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_mfa_disable_viewer_returns_403(client: AsyncClient) -> None:
    """Viewer role does not have users:write → 403."""
    resp = await client.post(
        DISABLE_URL,
        json={"user_id": _TARGET_USER_ID},
        headers=_auth_headers(role="viewer"),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_mfa_disable_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated request → 401."""
    resp = await client.post(DISABLE_URL, json={"user_id": _TARGET_USER_ID})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mfa_disable_user_not_found_returns_404(client: AsyncClient) -> None:
    """Target user does not exist → 404."""
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=None)):
        resp = await client.post(
            DISABLE_URL,
            json={"user_id": _TARGET_USER_ID},
            headers=_admin_headers(),
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_mfa_disable_user_not_found_detail(client: AsyncClient) -> None:
    """Target user not found returns 'User not found' detail."""
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=None)):
        resp = await client.post(
            DISABLE_URL,
            json={"user_id": _TARGET_USER_ID},
            headers=_admin_headers(),
        )
    assert resp.json()["detail"] == "User not found"


@pytest.mark.asyncio
async def test_mfa_disable_missing_user_id_returns_422(client: AsyncClient) -> None:
    """Request without user_id field → 422 Unprocessable Entity."""
    resp = await client.post(DISABLE_URL, json={}, headers=_admin_headers())
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_mfa_disable_null_user_id_returns_422(client: AsyncClient) -> None:
    """Null user_id → 422 Unprocessable Entity."""
    resp = await client.post(DISABLE_URL, json={"user_id": None}, headers=_admin_headers())
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_mfa_disable_already_disabled_user(client: AsyncClient) -> None:
    """Disabling MFA for a user who already has it off is a no-op → 200."""
    target = _make_target_user(mfa_enabled=False, mfa_secret=None, mfa_backup_codes=None)
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=target)):
        resp = await client.post(
            DISABLE_URL,
            json={"user_id": _TARGET_USER_ID},
            headers=_admin_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["message"] == "MFA disabled"
