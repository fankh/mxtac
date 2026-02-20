"""Tests for app/core/security.py — Feature 1.4: JWT validation on every protected request

``get_current_user`` is the FastAPI dependency that enforces JWT authentication on
every protected endpoint.  These tests exercise it both as a direct async function
(unit tests) and via HTTP requests through the test client (integration tests).

Coverage:
  get_current_user — missing / empty Authorization header → 401
  get_current_user — Bearer prefix variants (Bearer, bearer, BEARER, raw token)
  get_current_user — malformed / tampered JWT strings → 401
  get_current_user — wrong secret signature → 401
  get_current_user — expired token → 401
  get_current_user — token missing 'sub' claim → 401 "Invalid token payload"
  get_current_user — token without 'jti' skips blacklist check
  get_current_user — token with jti in blacklist → 401 "Token has been revoked"
  get_current_user — Valkey unavailable (fail-open) → passes authentication
  get_current_user — missing 'role' claim defaults to 'viewer'
  get_current_user — returns dict with exactly {email, role}
  decode_token — valid token → payload dict with expected claims
  decode_token — any JWTError → HTTPException 401 "Invalid or expired token"
  Integration — GET /api/v1/detections without auth → 401
  Integration — GET /api/v1/detections with valid token → not 401
  Integration — GET /api/v1/detections with blacklisted jti → 401
  Integration — raw token (no Bearer prefix) accepted on protected endpoints
  Integration — all valid roles pass JWT validation (RBAC is a separate layer)
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from jose import jwt

from app.core.config import settings
from app.core.security import create_access_token, decode_token, get_current_user

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM = "HS256"
PROTECTED_URL = "/api/v1/detections"

# Patch targets — names as imported inside the security module
MOCK_IS_BLACKLISTED = "app.core.security.is_token_blacklisted"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token(
    sub: str = "user@mxtac.local",
    role: str = "analyst",
    *,
    include_jti: bool = True,
    include_role: bool = True,
) -> str:
    """Create a valid access token for testing."""
    if include_jti and include_role:
        return create_access_token({"sub": sub, "role": role})
    payload: dict = {
        "sub": sub,
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    if include_role:
        payload["role"] = role
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def _make_token_without_sub() -> str:
    """Create a valid JWT that has no 'sub' claim."""
    payload = {
        "role": "analyst",
        "exp": datetime.utcnow() + timedelta(hours=1),
        "jti": "test-jti-no-sub",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def _make_expired_token() -> str:
    """Create a JWT whose exp is 1 second in the past."""
    payload = {
        "sub": "user@mxtac.local",
        "role": "analyst",
        "exp": datetime.utcnow() - timedelta(seconds=1),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def _make_wrong_secret_token() -> str:
    """Create a JWT signed with the wrong secret key."""
    payload = {
        "sub": "user@mxtac.local",
        "role": "analyst",
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    return jwt.encode(payload, "completely-wrong-secret-key", algorithm=ALGORITHM)


def _decode(token: str) -> dict:
    """Decode a token without verification (for extracting claims in tests)."""
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])


# ---------------------------------------------------------------------------
# get_current_user — missing / empty Authorization header
# ---------------------------------------------------------------------------


class TestGetCurrentUserMissingHeader:
    """No Authorization header at all → 401 "Authorization header required"."""

    async def test_none_raises_http_exception(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=None)
        assert exc_info.value.status_code == 401

    async def test_none_returns_correct_detail(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=None)
        assert exc_info.value.detail == "Authorization header required"

    async def test_empty_string_raises_401(self) -> None:
        """Empty string is falsy — treated identically to None."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="")
        assert exc_info.value.status_code == 401

    async def test_empty_string_returns_correct_detail(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="")
        assert exc_info.value.detail == "Authorization header required"


# ---------------------------------------------------------------------------
# get_current_user — Bearer prefix parsing
# ---------------------------------------------------------------------------


class TestGetCurrentUserBearerParsing:
    """Various 'Authorization' header formats are all accepted."""

    async def test_canonical_bearer_prefix(self) -> None:
        """'Bearer <token>' (capitalised) is the canonical RFC 6750 format."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["email"] == "user@mxtac.local"

    async def test_lowercase_bearer_prefix(self) -> None:
        """'bearer <token>' (all lowercase) is accepted — parsing is case-insensitive."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"bearer {token}")
        assert result["email"] == "user@mxtac.local"

    async def test_uppercase_bearer_prefix(self) -> None:
        """'BEARER <token>' (all uppercase) is accepted."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"BEARER {token}")
        assert result["email"] == "user@mxtac.local"

    async def test_mixed_case_bearer_prefix(self) -> None:
        """'BeArEr <token>' (mixed case) is accepted."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"BeArEr {token}")
        assert result["email"] == "user@mxtac.local"

    async def test_raw_token_without_prefix(self) -> None:
        """A raw JWT string (no scheme prefix) is accepted as a fallback."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=token)
        assert result["email"] == "user@mxtac.local"


# ---------------------------------------------------------------------------
# get_current_user — invalid token signatures and structure
# ---------------------------------------------------------------------------


class TestGetCurrentUserInvalidToken:
    """Malformed or untrustworthy tokens all produce 401 "Invalid or expired token"."""

    async def test_garbage_string_raises_401(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="not.a.jwt")
        assert exc_info.value.status_code == 401

    async def test_garbage_string_detail(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="not.a.jwt")
        assert exc_info.value.detail == "Invalid or expired token"

    async def test_bearer_with_garbage_value(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="Bearer garbage-not-jwt")
        assert exc_info.value.status_code == 401

    async def test_wrong_secret_raises_401(self) -> None:
        """Token signed with a different secret key is rejected."""
        token = _make_wrong_secret_token()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401

    async def test_wrong_secret_detail(self) -> None:
        token = _make_wrong_secret_token()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.detail == "Invalid or expired token"

    async def test_expired_token_raises_401(self) -> None:
        token = _make_expired_token()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401

    async def test_expired_token_detail(self) -> None:
        token = _make_expired_token()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.detail == "Invalid or expired token"

    async def test_tampered_payload_raises_401(self) -> None:
        """Flipping bytes in the payload section destroys the signature → 401."""
        token = _make_token()
        header, payload, sig = token.split(".")
        corrupted = f"{header}.{payload[:-2]}XX.{sig}"
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {corrupted}")
        assert exc_info.value.status_code == 401

    async def test_epoch_exp_is_rejected(self) -> None:
        """Token with exp at Unix epoch (far in the past) → 401."""
        payload = {
            "sub": "user@mxtac.local",
            "role": "analyst",
            "exp": datetime(1970, 1, 1),
        }
        ancient = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {ancient}")
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# get_current_user — payload claim validation
# ---------------------------------------------------------------------------


class TestGetCurrentUserPayloadValidation:
    """Specific payload claim requirements enforced after successful signature check."""

    async def test_missing_sub_raises_401(self) -> None:
        token = _make_token_without_sub()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401

    async def test_missing_sub_detail(self) -> None:
        token = _make_token_without_sub()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.detail == "Invalid token payload"

    async def test_role_absent_defaults_to_viewer(self) -> None:
        """Token with no 'role' claim → returned user dict has role='viewer'."""
        token = _make_token(include_role=False, include_jti=False)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["role"] == "viewer"

    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter", "engineer", "admin"])
    async def test_each_role_claim_is_preserved(self, role: str) -> None:
        """The 'role' claim from the token is surfaced unchanged in the user dict."""
        token = _make_token(role=role)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["role"] == role


# ---------------------------------------------------------------------------
# get_current_user — JTI blacklist behaviour
# ---------------------------------------------------------------------------


class TestGetCurrentUserBlacklist:
    """JTI blacklist is checked when the claim is present; absent jti skips the check."""

    async def test_blacklisted_jti_raises_401(self) -> None:
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=True)):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401

    async def test_blacklisted_jti_detail(self) -> None:
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=True)):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.detail == "Token has been revoked"

    async def test_non_blacklisted_jti_passes(self) -> None:
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert "email" in result

    async def test_blacklist_called_with_correct_jti(self) -> None:
        """is_token_blacklisted receives exactly the JTI embedded in the token."""
        token = _make_token()
        expected_jti = _decode(token)["jti"]
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)) as mock_bl:
            await get_current_user(authorization=f"Bearer {token}")
        mock_bl.assert_awaited_once_with(expected_jti)

    async def test_no_jti_skips_blacklist_check(self) -> None:
        """Token without 'jti' claim → is_token_blacklisted is never awaited."""
        token = _make_token(include_jti=False)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)) as mock_bl:
            await get_current_user(authorization=f"Bearer {token}")
        mock_bl.assert_not_awaited()

    async def test_valkey_unavailable_fails_open(self) -> None:
        """When Valkey is unreachable, is_token_blacklisted returns False (fail-open).

        The authentication succeeds so that a Valkey outage does not lock out
        all users — the token will expire naturally at its 'exp' time.
        """
        token = _make_token()
        # Simulate Valkey connection failure inside is_token_blacklisted
        with patch("app.core.valkey.get_valkey_client", new=AsyncMock(side_effect=ConnectionError("Valkey down"))):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert "email" in result

    async def test_blacklist_called_exactly_once_per_request(self) -> None:
        """is_token_blacklisted is called exactly once per get_current_user call."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)) as mock_bl:
            await get_current_user(authorization=f"Bearer {token}")
        assert mock_bl.await_count == 1


# ---------------------------------------------------------------------------
# get_current_user — return value shape
# ---------------------------------------------------------------------------


class TestGetCurrentUserReturnValue:
    """Successful calls return a dict with exactly the keys 'email' and 'role'."""

    async def test_returns_a_dict(self) -> None:
        token = _make_token(sub="analyst@mxtac.local", role="analyst")
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert isinstance(result, dict)

    async def test_email_key_present(self) -> None:
        token = _make_token(sub="analyst@mxtac.local", role="analyst")
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert "email" in result

    async def test_role_key_present(self) -> None:
        token = _make_token(sub="analyst@mxtac.local", role="analyst")
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert "role" in result

    async def test_only_email_and_role_keys(self) -> None:
        """No raw JWT claims (exp, jti, sub) leak into the returned user dict."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert set(result.keys()) == {"email", "role"}

    async def test_email_matches_sub_claim(self) -> None:
        token = _make_token(sub="hunter@mxtac.local", role="hunter")
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["email"] == "hunter@mxtac.local"

    async def test_role_matches_role_claim(self) -> None:
        token = _make_token(sub="engineer@mxtac.local", role="engineer")
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["role"] == "engineer"

    async def test_admin_email_and_role(self) -> None:
        token = _make_token(sub="admin@mxtac.local", role="admin")
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result == {"email": "admin@mxtac.local", "role": "admin"}


# ---------------------------------------------------------------------------
# decode_token — unit tests
# ---------------------------------------------------------------------------


class TestDecodeToken:
    """decode_token wraps jose.jwt.decode and normalises all JWTErrors to 401."""

    def test_valid_token_returns_dict(self) -> None:
        token = create_access_token({"sub": "user@mxtac.local", "role": "analyst"})
        payload = decode_token(token)
        assert isinstance(payload, dict)

    def test_valid_token_sub_claim(self) -> None:
        token = create_access_token({"sub": "user@mxtac.local", "role": "analyst"})
        payload = decode_token(token)
        assert payload["sub"] == "user@mxtac.local"

    def test_valid_token_role_claim(self) -> None:
        token = create_access_token({"sub": "user@mxtac.local", "role": "admin"})
        payload = decode_token(token)
        assert payload["role"] == "admin"

    def test_valid_token_has_exp_claim(self) -> None:
        token = create_access_token({"sub": "user@mxtac.local"})
        payload = decode_token(token)
        assert "exp" in payload

    def test_valid_token_has_jti_claim(self) -> None:
        token = create_access_token({"sub": "user@mxtac.local"})
        payload = decode_token(token)
        assert "jti" in payload
        assert payload["jti"]

    def test_malformed_token_raises_http_exception(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            decode_token("bad.token.value")
        assert exc_info.value.status_code == 401

    def test_malformed_token_detail(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            decode_token("bad.token.value")
        assert exc_info.value.detail == "Invalid or expired token"

    def test_expired_token_raises_http_exception(self) -> None:
        token = _make_expired_token()
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        assert exc_info.value.status_code == 401

    def test_wrong_secret_raises_http_exception(self) -> None:
        token = _make_wrong_secret_token()
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        assert exc_info.value.status_code == 401

    def test_empty_string_raises_http_exception(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            decode_token("")
        assert exc_info.value.status_code == 401

    def test_plain_string_raises_http_exception(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            decode_token("not-even-dot-separated")
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Integration tests — GET /api/v1/detections via HTTP test client
# ---------------------------------------------------------------------------


class TestProtectedEndpointRequiresAuth:
    """Every call to a Depends(get_current_user) endpoint without a valid token is rejected."""

    async def test_no_auth_header_returns_401(self, client) -> None:
        resp = await client.get(PROTECTED_URL)
        assert resp.status_code == 401

    async def test_no_auth_header_detail(self, client) -> None:
        resp = await client.get(PROTECTED_URL)
        assert resp.json()["detail"] == "Authorization header required"

    async def test_malformed_jwt_returns_401(self, client) -> None:
        resp = await client.get(PROTECTED_URL, headers={"Authorization": "Bearer notajwt"})
        assert resp.status_code == 401

    async def test_malformed_jwt_detail(self, client) -> None:
        resp = await client.get(PROTECTED_URL, headers={"Authorization": "Bearer notajwt"})
        assert resp.json()["detail"] == "Invalid or expired token"

    async def test_wrong_secret_returns_401(self, client) -> None:
        token = _make_wrong_secret_token()
        resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    async def test_token_missing_sub_returns_401(self, client) -> None:
        token = _make_token_without_sub()
        resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    async def test_token_missing_sub_detail(self, client) -> None:
        token = _make_token_without_sub()
        resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
        assert resp.json()["detail"] == "Invalid token payload"

    async def test_blacklisted_jti_returns_401(self, client) -> None:
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=True)):
            resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    async def test_blacklisted_jti_detail(self, client) -> None:
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=True)):
            resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
        assert resp.json()["detail"] == "Token has been revoked"

    async def test_valid_token_is_not_rejected(self, client) -> None:
        """A valid, non-blacklisted token passes JWT validation (status is not 401)."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code != 401

    async def test_raw_token_without_bearer_prefix_accepted(self, client) -> None:
        """Token submitted without 'Bearer ' scheme still passes JWT validation."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            resp = await client.get(PROTECTED_URL, headers={"Authorization": token})
        assert resp.status_code != 401

    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter", "engineer", "admin"])
    async def test_all_roles_pass_jwt_validation(self, client, role: str) -> None:
        """JWT validation accepts any role claim — RBAC enforcement is separate."""
        token = _make_token(sub=f"{role}@mxtac.local", role=role)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code != 401, f"Role '{role}' was incorrectly rejected by JWT validation"

    async def test_expired_token_via_http_returns_401(self, client) -> None:
        token = _make_expired_token()
        resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
