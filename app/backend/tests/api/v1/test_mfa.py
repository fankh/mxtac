"""Tests for TOTP MFA setup — Feature 32.1

POST /auth/mfa/setup   — generate secret + QR code URI + backup codes
POST /auth/mfa/verify-setup — verify TOTP code, enable MFA

All tests mock UserRepo and pyotp so the suite runs without a live database.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pyotp
import pytest
from httpx import AsyncClient

from app.core.security import create_access_token
from app.models.user import User

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MFA_SETUP_URL = "/api/v1/auth/mfa/setup"
MFA_VERIFY_URL = "/api/v1/auth/mfa/verify-setup"

MOCK_REPO_BY_EMAIL = "app.api.v1.endpoints.auth.UserRepo.get_by_email"

_TEST_SECRET = "JBSWY3DPEHPK3PXP"  # known base32 secret for predictable tests


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_headers(email: str = "analyst@mxtac.local", role: str = "analyst") -> dict:
    token = create_access_token({"sub": email, "role": role})
    return {"Authorization": f"Bearer {token}"}


def _make_user(
    email: str = "analyst@mxtac.local",
    mfa_secret: str | None = None,
    mfa_enabled: bool = False,
    mfa_backup_codes: list | None = None,
) -> User:
    user = User(
        email=email,
        hashed_password="$2b$12$placeholder",
        role="analyst",
        is_active=True,
    )
    user.id = "user-uuid-1234"
    user.mfa_secret = mfa_secret
    user.mfa_enabled = mfa_enabled
    user.mfa_backup_codes = mfa_backup_codes
    return user


# ---------------------------------------------------------------------------
# POST /auth/mfa/setup — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_setup_returns_200(client: AsyncClient) -> None:
    """Authenticated user → 200 OK from setup endpoint."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mfa_setup_returns_secret(client: AsyncClient) -> None:
    """Response contains a non-empty 'secret' field."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    data = resp.json()
    assert "secret" in data
    assert isinstance(data["secret"], str)
    assert len(data["secret"]) > 0


@pytest.mark.asyncio
async def test_mfa_setup_secret_is_valid_base32(client: AsyncClient) -> None:
    """The returned secret is a valid base32 string (pyotp-compatible)."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    secret = resp.json()["secret"]
    # If it's valid base32, pyotp.TOTP should create a working TOTP without error
    totp = pyotp.TOTP(secret)
    code = totp.now()
    assert len(code) == 6


@pytest.mark.asyncio
async def test_mfa_setup_returns_qr_code_uri(client: AsyncClient) -> None:
    """Response contains a 'qr_code_uri' field."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    data = resp.json()
    assert "qr_code_uri" in data
    assert isinstance(data["qr_code_uri"], str)


@pytest.mark.asyncio
async def test_mfa_setup_qr_code_uri_format(client: AsyncClient) -> None:
    """qr_code_uri starts with otpauth://totp/ and contains the issuer."""
    user = _make_user(email="analyst@mxtac.local")
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    uri = resp.json()["qr_code_uri"]
    assert uri.startswith("otpauth://totp/")
    assert "MxTac" in uri
    assert "analyst%40mxtac.local" in uri or "analyst@mxtac.local" in uri


@pytest.mark.asyncio
async def test_mfa_setup_qr_code_uri_contains_secret(client: AsyncClient) -> None:
    """qr_code_uri query string contains the secret."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    data = resp.json()
    assert f"secret={data['secret']}" in data["qr_code_uri"]


@pytest.mark.asyncio
async def test_mfa_setup_returns_backup_codes(client: AsyncClient) -> None:
    """Response contains a 'backup_codes' list."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    data = resp.json()
    assert "backup_codes" in data
    assert isinstance(data["backup_codes"], list)


@pytest.mark.asyncio
async def test_mfa_setup_eight_backup_codes(client: AsyncClient) -> None:
    """Exactly 8 backup codes are returned."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    assert len(resp.json()["backup_codes"]) == 8


@pytest.mark.asyncio
async def test_mfa_setup_backup_codes_are_8_chars(client: AsyncClient) -> None:
    """Each backup code is exactly 8 characters."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    for code in resp.json()["backup_codes"]:
        assert len(code) == 8


@pytest.mark.asyncio
async def test_mfa_setup_backup_codes_are_alphanumeric(client: AsyncClient) -> None:
    """Each backup code contains only uppercase letters and digits."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    import string
    valid_chars = set(string.ascii_uppercase + string.digits)
    for code in resp.json()["backup_codes"]:
        assert all(c in valid_chars for c in code), f"Non-alphanumeric code: {code}"


@pytest.mark.asyncio
async def test_mfa_setup_backup_codes_are_unique(client: AsyncClient) -> None:
    """All 8 backup codes are distinct."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    codes = resp.json()["backup_codes"]
    assert len(codes) == len(set(codes))


@pytest.mark.asyncio
async def test_mfa_setup_stores_encrypted_secret(client: AsyncClient) -> None:
    """After setup, user.mfa_secret is set and is NOT the plaintext secret."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    data = resp.json()
    # The secret stored on the user object should be encrypted (different from plaintext)
    assert user.mfa_secret is not None
    assert user.mfa_secret != data["secret"]


@pytest.mark.asyncio
async def test_mfa_setup_stores_hashed_backup_codes(client: AsyncClient) -> None:
    """After setup, user.mfa_backup_codes is a list of hashed values, not plaintext."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=_auth_headers())
    plaintext_codes = resp.json()["backup_codes"]
    assert user.mfa_backup_codes is not None
    assert len(user.mfa_backup_codes) == 8
    # Stored codes must differ from plaintext (they are hashed)
    for plaintext, stored in zip(plaintext_codes, user.mfa_backup_codes):
        assert plaintext != stored


@pytest.mark.asyncio
async def test_mfa_setup_does_not_enable_mfa(client: AsyncClient) -> None:
    """Setup endpoint does NOT set mfa_enabled=True — that requires verify-setup."""
    user = _make_user()
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        await client.post(MFA_SETUP_URL, headers=_auth_headers())
    assert user.mfa_enabled is False


@pytest.mark.asyncio
async def test_mfa_setup_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated request → 401."""
    resp = await client.post(MFA_SETUP_URL)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /auth/mfa/verify-setup — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_verify_setup_returns_200(client: AsyncClient) -> None:
    """Valid TOTP code → 200 OK."""
    from app.api.v1.endpoints.auth import _encrypt_secret

    encrypted = _encrypt_secret(_TEST_SECRET)
    user = _make_user(mfa_secret=encrypted)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(
            MFA_VERIFY_URL, json={"code": valid_code}, headers=_auth_headers()
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mfa_verify_setup_enables_mfa(client: AsyncClient) -> None:
    """After successful verify, user.mfa_enabled is True."""
    from app.api.v1.endpoints.auth import _encrypt_secret

    encrypted = _encrypt_secret(_TEST_SECRET)
    user = _make_user(mfa_secret=encrypted)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        await client.post(
            MFA_VERIFY_URL, json={"code": valid_code}, headers=_auth_headers()
        )
    assert user.mfa_enabled is True


@pytest.mark.asyncio
async def test_mfa_verify_setup_returns_message(client: AsyncClient) -> None:
    """Successful verify returns {'message': 'MFA enabled'}."""
    from app.api.v1.endpoints.auth import _encrypt_secret

    encrypted = _encrypt_secret(_TEST_SECRET)
    user = _make_user(mfa_secret=encrypted)
    valid_code = pyotp.TOTP(_TEST_SECRET).now()

    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(
            MFA_VERIFY_URL, json={"code": valid_code}, headers=_auth_headers()
        )
    assert resp.json()["message"] == "MFA enabled"


# ---------------------------------------------------------------------------
# POST /auth/mfa/verify-setup — error cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mfa_verify_setup_invalid_code_returns_400(client: AsyncClient) -> None:
    """Wrong TOTP code → 400 Bad Request."""
    from app.api.v1.endpoints.auth import _encrypt_secret

    encrypted = _encrypt_secret(_TEST_SECRET)
    user = _make_user(mfa_secret=encrypted)

    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(
            MFA_VERIFY_URL, json={"code": "000000"}, headers=_auth_headers()
        )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_mfa_verify_setup_invalid_code_detail(client: AsyncClient) -> None:
    """Wrong TOTP code returns 'Invalid TOTP code' detail."""
    from app.api.v1.endpoints.auth import _encrypt_secret

    encrypted = _encrypt_secret(_TEST_SECRET)
    user = _make_user(mfa_secret=encrypted)

    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(
            MFA_VERIFY_URL, json={"code": "000000"}, headers=_auth_headers()
        )
    assert resp.json()["detail"] == "Invalid TOTP code"


@pytest.mark.asyncio
async def test_mfa_verify_setup_invalid_code_does_not_enable_mfa(client: AsyncClient) -> None:
    """Wrong TOTP code must NOT set mfa_enabled=True."""
    from app.api.v1.endpoints.auth import _encrypt_secret

    encrypted = _encrypt_secret(_TEST_SECRET)
    user = _make_user(mfa_secret=encrypted)

    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        await client.post(
            MFA_VERIFY_URL, json={"code": "000000"}, headers=_auth_headers()
        )
    assert user.mfa_enabled is False


@pytest.mark.asyncio
async def test_mfa_verify_setup_no_secret_returns_400(client: AsyncClient) -> None:
    """User who never called setup (mfa_secret=None) → 400."""
    user = _make_user(mfa_secret=None)
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(
            MFA_VERIFY_URL, json={"code": "123456"}, headers=_auth_headers()
        )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_mfa_verify_setup_no_secret_detail(client: AsyncClient) -> None:
    """No mfa_secret returns 'MFA setup not initiated' detail."""
    user = _make_user(mfa_secret=None)
    with patch(MOCK_REPO_BY_EMAIL, new=AsyncMock(return_value=user)):
        resp = await client.post(
            MFA_VERIFY_URL, json={"code": "123456"}, headers=_auth_headers()
        )
    assert resp.json()["detail"] == "MFA setup not initiated"


@pytest.mark.asyncio
async def test_mfa_verify_setup_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated request → 401."""
    resp = await client.post(MFA_VERIFY_URL, json={"code": "123456"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mfa_verify_setup_missing_code_returns_422(client: AsyncClient) -> None:
    """Request without 'code' field → 422 Unprocessable Entity."""
    resp = await client.post(MFA_VERIFY_URL, json={}, headers=_auth_headers())
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_mfa_verify_setup_null_code_returns_422(client: AsyncClient) -> None:
    """Null 'code' field → 422 Unprocessable Entity."""
    resp = await client.post(MFA_VERIFY_URL, json={"code": None}, headers=_auth_headers())
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Encryption round-trip
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_round_trip() -> None:
    """_encrypt_secret / _decrypt_secret are inverses of each other."""
    from app.api.v1.endpoints.auth import _decrypt_secret, _encrypt_secret

    original = pyotp.random_base32()
    encrypted = _encrypt_secret(original)
    assert encrypted != original
    assert _decrypt_secret(encrypted) == original
