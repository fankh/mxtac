"""Feature 1.5 — JWT expiry: 60-minute access token, 7-day refresh token.

Verifies that:
  - access_token exp claim is ~60 minutes from now (within 5 s tolerance)
  - refresh_token exp claim is ~7 days from now (within 10 s tolerance)
  - expires_in response field equals settings.access_token_expire_minutes * 60
  - expires_in stays consistent with the actual token expiry duration
  - Token expiry values are driven by config, not hard-coded magic numbers

All tests mock UserRepo and verify_password so they run without a live DB.
"""

from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from jose import jwt

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token
from app.models.user import User

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOGIN_URL = "/api/v1/auth/login"
REFRESH_URL = "/api/v1/auth/refresh"
VALID_CREDS = {"email": "analyst@mxtac.local", "password": "mxtac2026"}

MOCK_REPO = "app.api.v1.endpoints.auth.UserRepo.get_by_email"
MOCK_VERIFY = "app.api.v1.endpoints.auth.verify_password"

ACCESS_TOKEN_SECONDS = settings.access_token_expire_minutes * 60  # 3600
REFRESH_TOKEN_SECONDS = settings.refresh_token_expire_days * 86400  # 604800

# Tolerance window for clock drift during test execution
ACCESS_TOLERANCE = 5   # seconds
REFRESH_TOLERANCE = 10  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


def _active_user(email: str = "analyst@mxtac.local", role: str = "analyst") -> User:
    return User(
        email=email,
        hashed_password="$2b$12$placeholder_not_used_in_tests",
        full_name="Test User",
        role=role,
        is_active=True,
    )


# ---------------------------------------------------------------------------
# Access token expiry — 60 minutes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_access_token_expires_in_field_matches_config(
    client: AsyncClient,
) -> None:
    """expires_in equals settings.access_token_expire_minutes * 60 (not hard-coded)."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 200
    assert resp.json()["expires_in"] == ACCESS_TOKEN_SECONDS


@pytest.mark.asyncio
async def test_access_token_exp_claim_is_60_minutes(client: AsyncClient) -> None:
    """access_token exp claim is approximately now + 60 minutes."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    now = time.time()
    payload = _decode(resp.json()["access_token"])
    expected_exp = now + ACCESS_TOKEN_SECONDS
    assert abs(payload["exp"] - expected_exp) <= ACCESS_TOLERANCE, (
        f"access_token exp={payload['exp']}, expected ~{expected_exp} "
        f"(±{ACCESS_TOLERANCE}s)"
    )


@pytest.mark.asyncio
async def test_access_token_exp_not_less_than_60_minutes(client: AsyncClient) -> None:
    """access_token exp must be at least 60 minutes from now."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    now = time.time()
    payload = _decode(resp.json()["access_token"])
    min_exp = now + ACCESS_TOKEN_SECONDS - ACCESS_TOLERANCE
    assert payload["exp"] >= min_exp, (
        f"access_token exp={payload['exp']} is less than expected minimum {min_exp}"
    )


@pytest.mark.asyncio
async def test_access_token_exp_not_more_than_60_minutes(client: AsyncClient) -> None:
    """access_token exp must not exceed 60 minutes from now (no runaway expiry)."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    now = time.time()
    payload = _decode(resp.json()["access_token"])
    max_exp = now + ACCESS_TOKEN_SECONDS + ACCESS_TOLERANCE
    assert payload["exp"] <= max_exp, (
        f"access_token exp={payload['exp']} exceeds expected maximum {max_exp}"
    )


# ---------------------------------------------------------------------------
# Refresh token expiry — 7 days
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_token_exp_claim_is_7_days(client: AsyncClient) -> None:
    """refresh_token exp claim is approximately now + 7 days."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    now = time.time()
    payload = _decode(resp.json()["refresh_token"])
    expected_exp = now + REFRESH_TOKEN_SECONDS
    assert abs(payload["exp"] - expected_exp) <= REFRESH_TOLERANCE, (
        f"refresh_token exp={payload['exp']}, expected ~{expected_exp} "
        f"(±{REFRESH_TOLERANCE}s)"
    )


@pytest.mark.asyncio
async def test_refresh_token_exp_not_less_than_7_days(client: AsyncClient) -> None:
    """refresh_token exp must be at least 7 days from now."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    now = time.time()
    payload = _decode(resp.json()["refresh_token"])
    min_exp = now + REFRESH_TOKEN_SECONDS - REFRESH_TOLERANCE
    assert payload["exp"] >= min_exp


@pytest.mark.asyncio
async def test_refresh_token_exp_not_more_than_7_days(client: AsyncClient) -> None:
    """refresh_token exp must not exceed 7 days from now."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    now = time.time()
    payload = _decode(resp.json()["refresh_token"])
    max_exp = now + REFRESH_TOKEN_SECONDS + REFRESH_TOLERANCE
    assert payload["exp"] <= max_exp


@pytest.mark.asyncio
async def test_refresh_token_longer_lived_than_access_token(
    client: AsyncClient,
) -> None:
    """refresh_token exp must be significantly later than access_token exp."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    access_exp = _decode(data["access_token"])["exp"]
    refresh_exp = _decode(data["refresh_token"])["exp"]
    # refresh must outlive access by at least 6 days
    assert refresh_exp - access_exp >= timedelta(days=6).total_seconds()


# ---------------------------------------------------------------------------
# expires_in is config-driven, not hard-coded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expires_in_equals_access_token_expire_minutes_times_60(
    client: AsyncClient,
) -> None:
    """expires_in = settings.access_token_expire_minutes * 60 (config-driven)."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.json()["expires_in"] == settings.access_token_expire_minutes * 60


@pytest.mark.asyncio
async def test_expires_in_consistent_with_actual_token_lifetime(
    client: AsyncClient,
) -> None:
    """expires_in is consistent with the access_token's actual exp claim."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    now = time.time()
    data = resp.json()
    expires_in = data["expires_in"]
    access_exp = _decode(data["access_token"])["exp"]
    remaining = access_exp - now
    assert abs(remaining - expires_in) <= ACCESS_TOLERANCE, (
        f"expires_in={expires_in} does not match token remaining lifetime={remaining:.1f}s"
    )


# ---------------------------------------------------------------------------
# Rotated refresh token — expiry preserved
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotated_refresh_token_exp_is_7_days(client: AsyncClient) -> None:
    """POST /auth/refresh issues a new refresh token with a fresh 7-day expiry."""
    original_refresh = create_refresh_token({"sub": "analyst@mxtac.local"})
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": original_refresh})
    assert resp.status_code == 200
    now = time.time()
    new_refresh_payload = _decode(resp.json()["refresh_token"])
    expected_exp = now + REFRESH_TOKEN_SECONDS
    assert abs(new_refresh_payload["exp"] - expected_exp) <= REFRESH_TOLERANCE


@pytest.mark.asyncio
async def test_rotated_access_token_exp_is_60_minutes(client: AsyncClient) -> None:
    """POST /auth/refresh issues a new access token with a fresh 60-minute expiry."""
    original_refresh = create_refresh_token({"sub": "analyst@mxtac.local"})
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": original_refresh})
    assert resp.status_code == 200
    now = time.time()
    access_payload = _decode(resp.json()["access_token"])
    expected_exp = now + ACCESS_TOKEN_SECONDS
    assert abs(access_payload["exp"] - expected_exp) <= ACCESS_TOLERANCE


@pytest.mark.asyncio
async def test_refresh_endpoint_expires_in_matches_config(client: AsyncClient) -> None:
    """POST /auth/refresh expires_in equals settings.access_token_expire_minutes * 60."""
    original_refresh = create_refresh_token({"sub": "analyst@mxtac.local"})
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": original_refresh})
    assert resp.json()["expires_in"] == settings.access_token_expire_minutes * 60


# ---------------------------------------------------------------------------
# Unit tests — create_access_token / create_refresh_token expiry
# ---------------------------------------------------------------------------


def test_create_access_token_exp_is_60_minutes() -> None:
    """create_access_token sets exp to now + access_token_expire_minutes."""
    token = create_access_token({"sub": "user@test.local"})
    payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    now = time.time()
    expected = now + ACCESS_TOKEN_SECONDS
    assert abs(payload["exp"] - expected) <= ACCESS_TOLERANCE


def test_create_refresh_token_exp_is_7_days() -> None:
    """create_refresh_token sets exp to now + refresh_token_expire_days."""
    token = create_refresh_token({"sub": "user@test.local"})
    payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    now = time.time()
    expected = now + REFRESH_TOKEN_SECONDS
    assert abs(payload["exp"] - expected) <= REFRESH_TOLERANCE


def test_access_token_shorter_than_refresh_token() -> None:
    """access_token expiry is shorter than refresh_token expiry."""
    access = create_access_token({"sub": "user@test.local"})
    refresh = create_refresh_token({"sub": "user@test.local"})
    access_exp = jwt.decode(access, settings.secret_key, algorithms=["HS256"])["exp"]
    refresh_exp = jwt.decode(refresh, settings.secret_key, algorithms=["HS256"])["exp"]
    assert access_exp < refresh_exp


def test_config_access_token_expire_minutes_is_60() -> None:
    """settings.access_token_expire_minutes equals 60."""
    assert settings.access_token_expire_minutes == 60


def test_config_refresh_token_expire_days_is_7() -> None:
    """settings.refresh_token_expire_days equals 7."""
    assert settings.refresh_token_expire_days == 7
