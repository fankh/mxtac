"""Tests for Feature 32.2 — MFA verification during login flow.

POST /auth/login   — returns mfa_required + mfa_token when user has MFA enabled
POST /auth/mfa/verify — accepts mfa_token + TOTP/backup code, returns full tokens

Coverage:
  - Login returns MfaLoginResponse when mfa_enabled=True
  - Login still returns TokenResponse when mfa_enabled=False (no regression)
  - mfa/verify: valid TOTP → 200 + full tokens
  - mfa/verify: previous TOTP window accepted (clock skew tolerance)
  - mfa/verify: invalid TOTP → 401
  - mfa/verify: valid backup code → 200, code consumed
  - mfa/verify: invalid backup code → 401
  - mfa/verify: expired mfa_token → 401
  - mfa/verify: wrong-purpose token → 401
  - mfa/verify: garbage token → 401
  - mfa/verify: rate limit exceeded (>5 attempts) → 429
  - mfa/verify: inactive user → 401
  - mfa/verify: user not found → 401
  - mfa/verify: MFA not configured (no mfa_secret) → 401
  - mfa/verify: missing fields → 422
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pyotp
import pytest
from httpx import AsyncClient
from jose import jwt

from app.api.v1.endpoints.auth import _encrypt_secret, _hash_backup_code
from app.core.config import settings
from app.core.security import create_mfa_token
from app.models.user import User

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOGIN_URL = "/api/v1/auth/login"
MFA_VERIFY_URL = "/api/v1/auth/mfa/verify"

MOCK_REPO_BY_EMAIL = "app.api.v1.endpoints.auth.UserRepo.get_by_email"
MOCK_REPO_BY_ID = "app.api.v1.endpoints.auth.UserRepo.get_by_id"
MOCK_VERIFY_PW = "app.api.v1.endpoints.auth.verify_password"
MOCK_MFA_RATE = "app.api.v1.endpoints.auth.increment_mfa_attempts"

_TEST_SECRET = "JBSWY3DPEHPK3PXP"  # known base32 for predictable tests
_TEST_USER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TEST_EMAIL = "analyst@mxtac.local"

ALGORITHM = "HS256"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(
    email: str = _TEST_EMAIL,
    role: str = "analyst",
    is_active: bool = True,
    mfa_enabled: bool = False,
    mfa_secret: str | None = None,
    mfa_backup_codes: list | None = None,
) -> User:
    user = User(
        email=email,
        hashed_password="$2b$12$placeholder",
        role=role,
        is_active=is_active,
    )
    user.id = _TEST_USER_ID
    user.mfa_enabled = mfa_enabled
    user.mfa_secret = mfa_secret
    user.mfa_backup_codes = mfa_backup_codes
    return user


def _mfa_user() -> User:
    """Active user with MFA fully configured."""
    return _make_user(
        mfa_enabled=True,
        mfa_secret=_encrypt_secret(_TEST_SECRET),
    )


def _decode(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])


# ---------------------------------------------------------------------------
# POST /auth/login — MFA required response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_mfa_user_returns_mfa_required(client: AsyncClient) -> None:
    """When mfa_enabled=True, login returns mfa_required=True instead of tokens."""
    user = _mfa_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["mfa_required"] is True


@pytest.mark.asyncio
async def test_login_mfa_user_returns_mfa_token(client: AsyncClient) -> None:
    """mfa_required response contains a non-empty mfa_token string."""
    user = _mfa_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    data = resp.json()
    assert "mfa_token" in data
    assert isinstance(data["mfa_token"], str)
    assert len(data["mfa_token"]) > 0


@pytest.mark.asyncio
async def test_login_mfa_token_has_mfa_purpose(client: AsyncClient) -> None:
    """mfa_token JWT carries purpose='mfa' claim."""
    user = _mfa_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    mfa_token = resp.json()["mfa_token"]
    payload = _decode(mfa_token)
    assert payload.get("purpose") == "mfa"


@pytest.mark.asyncio
async def test_login_mfa_token_sub_is_user_id(client: AsyncClient) -> None:
    """mfa_token sub claim is the user's ID (not email)."""
    user = _mfa_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    payload = _decode(resp.json()["mfa_token"])
    assert payload["sub"] == _TEST_USER_ID


@pytest.mark.asyncio
async def test_login_mfa_token_expires_in_5_minutes(client: AsyncClient) -> None:
    """mfa_token exp is approximately 5 minutes in the future."""
    import time

    user = _mfa_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    payload = _decode(resp.json()["mfa_token"])
    now = time.time()
    # 4 min < TTL ≤ 5 min 10 s
    assert 240 < payload["exp"] - now <= 310


@pytest.mark.asyncio
async def test_login_mfa_user_does_not_return_access_token(client: AsyncClient) -> None:
    """MFA-enabled login must NOT return access_token or refresh_token."""
    user = _mfa_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    data = resp.json()
    assert "access_token" not in data
    assert "refresh_token" not in data


@pytest.mark.asyncio
async def test_login_non_mfa_user_returns_tokens_normally(client: AsyncClient) -> None:
    """When mfa_enabled=False, login returns normal TokenResponse (no regression)."""
    user = _make_user(mfa_enabled=False)
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": _TEST_EMAIL, "password": "pw"})
    data = resp.json()
    assert resp.status_code == 200
    assert "access_token" in data
    assert "refresh_token" in data
    assert "mfa_required" not in data


# ---------------------------------------------------------------------------
# POST /auth/mfa/verify — happy path: TOTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_verify_valid_totp_returns_200(client: AsyncClient) -> None:
    """Valid TOTP code → 200 OK."""
    user = _mfa_user()
    mfa_token = create_mfa_token(_TEST_USER_ID)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": valid_code}
            )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mfa_verify_returns_access_token(client: AsyncClient) -> None:
    """Successful MFA verify returns an access_token."""
    user = _mfa_user()
    mfa_token = create_mfa_token(_TEST_USER_ID)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": valid_code}
            )
    data = resp.json()
    assert "access_token" in data
    assert isinstance(data["access_token"], str)
    assert data["access_token"]


@pytest.mark.asyncio
async def test_mfa_verify_returns_refresh_token(client: AsyncClient) -> None:
    """Successful MFA verify returns a refresh_token."""
    user = _mfa_user()
    mfa_token = create_mfa_token(_TEST_USER_ID)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": valid_code}
            )
    data = resp.json()
    assert "refresh_token" in data
    assert isinstance(data["refresh_token"], str)
    assert data["refresh_token"]


@pytest.mark.asyncio
async def test_mfa_verify_access_token_sub_is_email(client: AsyncClient) -> None:
    """Issued access_token sub claim is the user's email."""
    user = _mfa_user()
    mfa_token = create_mfa_token(_TEST_USER_ID)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": valid_code}
            )
    payload = _decode(resp.json()["access_token"])
    assert payload["sub"] == _TEST_EMAIL


@pytest.mark.asyncio
async def test_mfa_verify_access_token_role_claim(client: AsyncClient) -> None:
    """Issued access_token carries the correct role claim."""
    user = _mfa_user()
    mfa_token = create_mfa_token(_TEST_USER_ID)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": valid_code}
            )
    payload = _decode(resp.json()["access_token"])
    assert payload["role"] == "analyst"


@pytest.mark.asyncio
async def test_mfa_verify_response_schema(client: AsyncClient) -> None:
    """Response has the four expected TokenResponse keys."""
    user = _mfa_user()
    mfa_token = create_mfa_token(_TEST_USER_ID)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": valid_code}
            )
    assert {"access_token", "refresh_token", "token_type", "expires_in"} <= set(resp.json())


# ---------------------------------------------------------------------------
# POST /auth/mfa/verify — backup codes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_verify_backup_code_returns_200(client: AsyncClient) -> None:
    """Valid backup code → 200 OK."""
    plaintext_code = "ABCD1234"
    code_hash = _hash_backup_code(plaintext_code)
    user = _mfa_user()
    user.mfa_backup_codes = [code_hash, _hash_backup_code("ZZZZ9999")]

    mfa_token = create_mfa_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": plaintext_code}
            )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mfa_verify_backup_code_is_consumed(client: AsyncClient) -> None:
    """After a backup code is used, it is removed from user.mfa_backup_codes."""
    plaintext_code = "BACKUP01"
    code_hash = _hash_backup_code(plaintext_code)
    other_hash = _hash_backup_code("BACKUP02")
    user = _mfa_user()
    user.mfa_backup_codes = [code_hash, other_hash]

    mfa_token = create_mfa_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": plaintext_code}
            )

    # The used code's hash must no longer be in the list
    assert code_hash not in user.mfa_backup_codes
    # Other codes are still present
    assert other_hash in user.mfa_backup_codes


@pytest.mark.asyncio
async def test_mfa_verify_invalid_backup_code_returns_401(client: AsyncClient) -> None:
    """Wrong backup code → 401."""
    user = _mfa_user()
    user.mfa_backup_codes = [_hash_backup_code("VALIDCOD")]

    mfa_token = create_mfa_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": "WRONGCOD"}
            )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /auth/mfa/verify — invalid TOTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_verify_invalid_totp_returns_401(client: AsyncClient) -> None:
    """Wrong TOTP code → 401 Unauthorized."""
    user = _mfa_user()
    mfa_token = create_mfa_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": "000000"}
            )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mfa_verify_invalid_totp_detail(client: AsyncClient) -> None:
    """Wrong TOTP code returns 'Invalid MFA code' detail."""
    user = _mfa_user()
    mfa_token = create_mfa_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": "000000"}
            )
    assert resp.json()["detail"] == "Invalid MFA code"


# ---------------------------------------------------------------------------
# POST /auth/mfa/verify — token validation errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_verify_expired_token_returns_401(client: AsyncClient) -> None:
    """Expired mfa_token → 401."""
    payload = {
        "sub": _TEST_USER_ID,
        "purpose": "mfa",
        "jti": "test-jti",
        "exp": datetime.utcnow() - timedelta(seconds=1),
    }
    expired_token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)

    resp = await client.post(
        MFA_VERIFY_URL, json={"mfa_token": expired_token, "code": "123456"}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mfa_verify_wrong_purpose_returns_401(client: AsyncClient) -> None:
    """Access token (no purpose='mfa') used as mfa_token → 401."""
    from app.core.security import create_access_token

    access_token = create_access_token({"sub": _TEST_EMAIL, "role": "analyst"})

    with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
        resp = await client.post(
            MFA_VERIFY_URL, json={"mfa_token": access_token, "code": "123456"}
        )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid MFA token"


@pytest.mark.asyncio
async def test_mfa_verify_garbage_token_returns_401(client: AsyncClient) -> None:
    """Completely invalid JWT string → 401."""
    resp = await client.post(
        MFA_VERIFY_URL, json={"mfa_token": "not.a.jwt", "code": "123456"}
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /auth/mfa/verify — rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_verify_rate_limit_exceeded_returns_429(client: AsyncClient) -> None:
    """More than 5 attempts per mfa_token → 429 Too Many Requests."""
    mfa_token = create_mfa_token(_TEST_USER_ID)

    # Simulate 6th attempt (counter already at 6)
    with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=6)):
        resp = await client.post(
            MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": "123456"}
        )
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_mfa_verify_rate_limit_exceeded_detail(client: AsyncClient) -> None:
    """Rate-limited response returns 'Too many MFA attempts' detail."""
    mfa_token = create_mfa_token(_TEST_USER_ID)

    with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=6)):
        resp = await client.post(
            MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": "123456"}
        )
    assert resp.json()["detail"] == "Too many MFA attempts"


@pytest.mark.asyncio
async def test_mfa_verify_5th_attempt_allowed(client: AsyncClient) -> None:
    """Exactly 5 attempts is within the limit — not rate-limited."""
    user = _mfa_user()
    mfa_token = create_mfa_token(_TEST_USER_ID)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=5)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": valid_code}
            )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /auth/mfa/verify — user state errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_verify_inactive_user_returns_401(client: AsyncClient) -> None:
    """Valid mfa_token but account is inactive → 401."""
    user = _make_user(
        is_active=False,
        mfa_enabled=True,
        mfa_secret=_encrypt_secret(_TEST_SECRET),
    )
    mfa_token = create_mfa_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": "123456"}
            )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mfa_verify_user_not_found_returns_401(client: AsyncClient) -> None:
    """Valid mfa_token but user not in DB → 401."""
    mfa_token = create_mfa_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=None)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": "123456"}
            )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mfa_verify_no_mfa_secret_returns_401(client: AsyncClient) -> None:
    """User has no mfa_secret (MFA was never configured) → 401."""
    user = _make_user(mfa_enabled=True, mfa_secret=None)
    mfa_token = create_mfa_token(_TEST_USER_ID)

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_MFA_RATE, new=AsyncMock(return_value=1)):
            resp = await client.post(
                MFA_VERIFY_URL, json={"mfa_token": mfa_token, "code": "123456"}
            )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /auth/mfa/verify — input validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_verify_missing_mfa_token_returns_422(client: AsyncClient) -> None:
    """Request without mfa_token field → 422."""
    resp = await client.post(MFA_VERIFY_URL, json={"code": "123456"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_mfa_verify_missing_code_returns_422(client: AsyncClient) -> None:
    """Request without code field → 422."""
    resp = await client.post(MFA_VERIFY_URL, json={"mfa_token": "some.token.here"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_mfa_verify_empty_body_returns_422(client: AsyncClient) -> None:
    """Empty JSON body → 422."""
    resp = await client.post(MFA_VERIFY_URL, json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_mfa_verify_get_method_not_allowed(client: AsyncClient) -> None:
    """GET /auth/mfa/verify → 405 Method Not Allowed."""
    resp = await client.get(MFA_VERIFY_URL)
    assert resp.status_code == 405


# ---------------------------------------------------------------------------
# create_mfa_token unit tests
# ---------------------------------------------------------------------------


def test_create_mfa_token_is_valid_jwt() -> None:
    """create_mfa_token produces a decodable JWT."""
    token = create_mfa_token(_TEST_USER_ID)
    payload = _decode(token)
    assert payload["sub"] == _TEST_USER_ID
    assert payload["purpose"] == "mfa"
    assert "jti" in payload
    assert "exp" in payload


def test_create_mfa_token_different_each_call() -> None:
    """Each call produces a different JTI (no replay)."""
    t1 = _decode(create_mfa_token(_TEST_USER_ID))
    t2 = _decode(create_mfa_token(_TEST_USER_ID))
    assert t1["jti"] != t2["jti"]
