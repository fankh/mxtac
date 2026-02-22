"""Tests for Feature 2.3 — Password expiry (90-day policy).

Coverage:
  login — fresh password (changed < 90 days ago) → 200 + tokens
  login — expired password (changed > 90 days ago) → PasswordChangeRequiredResponse
  login — null password_changed_at → not expired (safe migration for existing accounts)
  login — exactly 90 days old → not expired (boundary: expires AFTER 90 days)
  login — 91 days old → expired
  login — expiry disabled (password_expiry_days=0) → not expired regardless of age
  login — expired password, also has MFA → expiry fires before MFA check
  change-password → password_changed_at set to now
  change-password → returned token has password_change purpose (same as feature 1.8)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from jose import jwt

from app.core.config import settings
from app.models.user import User

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOGIN_URL = "/api/v1/auth/login"
CHANGE_PW_URL = "/api/v1/auth/change-password"

MOCK_REPO_BY_EMAIL = "app.api.v1.endpoints.auth.UserRepo.get_by_email"
MOCK_REPO_BY_ID = "app.api.v1.endpoints.auth.UserRepo.get_by_id"
MOCK_VERIFY_PW = "app.api.v1.endpoints.auth.verify_password"

ALGORITHM = "HS256"
_TEST_USER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TEST_EMAIL = "analyst@mxtac.local"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(
    *,
    is_active: bool = True,
    mfa_enabled: bool = False,
    must_change_password: bool = False,
    password_changed_at: datetime | None = None,
) -> User:
    user = User(
        email=_TEST_EMAIL,
        hashed_password="$2b$12$placeholder",
        role="analyst",
        is_active=is_active,
    )
    user.id = _TEST_USER_ID
    user.mfa_enabled = mfa_enabled
    user.must_change_password = must_change_password
    user.password_changed_at = password_changed_at
    user.last_login_at = None
    user.inactive_locked_at = None
    return user


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _days_ago(n: int) -> datetime:
    return _now() - timedelta(days=n)


def _decode(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])


# ---------------------------------------------------------------------------
# Login — fresh password (not expired)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_fresh_password_returns_tokens(client: AsyncClient) -> None:
    """Password changed 10 days ago — not expired; login returns access + refresh tokens."""
    user = _make_user(password_changed_at=_days_ago(10))
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_login_null_password_changed_at_returns_tokens(client: AsyncClient) -> None:
    """password_changed_at=None (never set) — expiry check skipped; login succeeds.

    Safe migration path: existing accounts without a recorded change date are
    not immediately forced to change password.
    """
    user = _make_user(password_changed_at=None)
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data


@pytest.mark.asyncio
async def test_login_exactly_90_days_not_expired(client: AsyncClient) -> None:
    """Password changed exactly 90 days ago — at the boundary, not yet expired."""
    user = _make_user(password_changed_at=_days_ago(90))
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data


# ---------------------------------------------------------------------------
# Login — expired password
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_expired_password_returns_password_change_required(
    client: AsyncClient,
) -> None:
    """Password changed 91 days ago — expired; login returns password_change_required."""
    user = _make_user(password_changed_at=_days_ago(91))
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("password_change_required") is True
    assert "password_change_token" in data
    assert "access_token" not in data


@pytest.mark.asyncio
async def test_login_expired_password_token_has_correct_purpose(
    client: AsyncClient,
) -> None:
    """The password_change_token issued for an expired password has purpose=password_change."""
    user = _make_user(password_changed_at=_days_ago(91))
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    token = resp.json()["password_change_token"]
    payload = _decode(token)
    assert payload.get("purpose") == "password_change"


@pytest.mark.asyncio
async def test_login_expired_password_token_sub_is_user_id(
    client: AsyncClient,
) -> None:
    """The password_change_token sub claim is the user's ID."""
    user = _make_user(password_changed_at=_days_ago(91))
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    token = resp.json()["password_change_token"]
    payload = _decode(token)
    assert payload.get("sub") == _TEST_USER_ID


@pytest.mark.asyncio
async def test_login_very_old_password_expired(client: AsyncClient) -> None:
    """Password changed 365 days ago — definitely expired."""
    user = _make_user(password_changed_at=_days_ago(365))
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("password_change_required") is True


# ---------------------------------------------------------------------------
# Login — expiry disabled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_expiry_disabled_ignores_old_password(client: AsyncClient) -> None:
    """When password_expiry_days=0, an old password is not treated as expired."""
    user = _make_user(password_changed_at=_days_ago(500))
    with patch.object(settings, "password_expiry_days", 0):
        with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY_PW, return_value=True):
                resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data


# ---------------------------------------------------------------------------
# Login — expiry fires before MFA
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_expired_password_with_mfa_returns_password_change_first(
    client: AsyncClient,
) -> None:
    """Expired password check fires before the MFA step — user gets password_change_required,
    not mfa_required, so the flow is consistent with feature 1.8."""
    user = _make_user(password_changed_at=_days_ago(91), mfa_enabled=True)
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("password_change_required") is True
    assert "mfa_required" not in data


# ---------------------------------------------------------------------------
# change-password — sets password_changed_at
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_change_password_sets_password_changed_at(client: AsyncClient) -> None:
    """After /auth/change-password, the user's password_changed_at is updated to now."""
    from app.core.security import create_password_change_token

    user = _make_user(password_changed_at=None)
    pc_token = create_password_change_token(_TEST_USER_ID)

    before = _now()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        resp = await client.post(
            CHANGE_PW_URL,
            json={
                "password_change_token": pc_token,
                "new_password": "NewSecure1!",
                "confirm_password": "NewSecure1!",
            },
        )

    after = _now()

    assert resp.status_code == 200
    # The user object was mutated in-place by the endpoint
    assert user.password_changed_at is not None
    assert before <= user.password_changed_at <= after


@pytest.mark.asyncio
async def test_change_password_clears_must_change_password_and_sets_timestamp(
    client: AsyncClient,
) -> None:
    """change-password clears must_change_password AND sets password_changed_at."""
    from app.core.security import create_password_change_token

    user = _make_user(must_change_password=True, password_changed_at=None)
    pc_token = create_password_change_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        resp = await client.post(
            CHANGE_PW_URL,
            json={
                "password_change_token": pc_token,
                "new_password": "NewSecure1!",
                "confirm_password": "NewSecure1!",
            },
        )

    assert resp.status_code == 200
    assert user.must_change_password is False
    assert user.password_changed_at is not None


@pytest.mark.asyncio
async def test_change_password_returns_tokens_after_update(client: AsyncClient) -> None:
    """change-password (expired flow) succeeds and returns access + refresh tokens."""
    from app.core.security import create_password_change_token

    user = _make_user(password_changed_at=_days_ago(91))
    pc_token = create_password_change_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        resp = await client.post(
            CHANGE_PW_URL,
            json={
                "password_change_token": pc_token,
                "new_password": "NewSecure1!",
                "confirm_password": "NewSecure1!",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
