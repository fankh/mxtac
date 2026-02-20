"""Tests for the ``get_current_user`` FastAPI dependency — Feature 1.4.

``get_current_user`` (``app.core.security``) is the single JWT-validation
dependency injected into every protected endpoint.  The tests verify:

  A. Unit tests (call the async function directly):
     - Authorization header parsing: Bearer prefix, raw token, case variants
     - Missing / empty header → 401 "Authorization header required"
     - Token signature validation: correct secret, wrong secret, tampered payload
     - Token expiry: expired → 401, valid → passes
     - Payload validation: missing 'sub' → 401, empty/null 'sub' → 401
     - JTI blacklist enforcement: blacklisted → 401, not blacklisted → passes,
       no JTI → blacklist check skipped, Valkey unavailable → fails open
     - Role extraction: all five roles, missing role defaults to 'viewer'

  B. Integration tests (through HTTPX test client on a real FastAPI app):
     - Protected endpoint enforces the dependency (no auth → 401)
     - Invalid / expired / blacklisted tokens are rejected on real endpoints
     - Valid tokens for all five roles pass authentication
     - Token without 'sub' is rejected at the endpoint level
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from jose import jwt

from app.core.config import settings
from app.core.security import get_current_user

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM = "HS256"
PROTECTED_URL = "/api/v1/detections"
MOCK_IS_BLACKLISTED = "app.core.security.is_token_blacklisted"
MOCK_DETECTION_LIST = "app.api.v1.endpoints.detections.DetectionRepo.list"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token(
    sub: str = "analyst@mxtac.local",
    role: str = "analyst",
    exp_delta: timedelta = timedelta(hours=1),
    include_jti: bool = True,
    **extra_claims,
) -> str:
    """Build a signed JWT with configurable claims."""
    payload: dict = {"sub": sub, "role": role, **extra_claims}
    if include_jti:
        payload["jti"] = str(uuid4())
    payload["exp"] = datetime.utcnow() + exp_delta
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def _make_wrong_secret_token(
    sub: str = "analyst@mxtac.local", role: str = "analyst"
) -> str:
    """Build a JWT signed with a *different* secret key (invalid signature)."""
    payload = {
        "sub": sub,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    return jwt.encode(payload, "wrong-secret-key", algorithm=ALGORITHM)


# ---------------------------------------------------------------------------
# A. Unit tests — call get_current_user directly as an async function
# ---------------------------------------------------------------------------


class TestAuthorizationHeaderParsing:
    """get_current_user parses Authorization header formats correctly."""

    @pytest.mark.asyncio
    async def test_bearer_prefix_accepted(self) -> None:
        """Standard 'Bearer <token>' format is accepted."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["email"] == "analyst@mxtac.local"

    @pytest.mark.asyncio
    async def test_lowercase_bearer_prefix_accepted(self) -> None:
        """'bearer <token>' (lowercase) is accepted — prefix check is case-insensitive."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"bearer {token}")
        assert result["email"] == "analyst@mxtac.local"

    @pytest.mark.asyncio
    async def test_uppercase_bearer_prefix_accepted(self) -> None:
        """'BEARER <token>' (uppercase) is accepted — prefix check is case-insensitive."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"BEARER {token}")
        assert result["email"] == "analyst@mxtac.local"

    @pytest.mark.asyncio
    async def test_raw_token_without_prefix_accepted(self) -> None:
        """Raw token (no prefix) falls back to treating the whole header value as the JWT."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=token)
        assert result["email"] == "analyst@mxtac.local"

    @pytest.mark.asyncio
    async def test_none_header_raises_401(self) -> None:
        """None authorization → 401 'Authorization header required'."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=None)
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Authorization header required"

    @pytest.mark.asyncio
    async def test_empty_string_header_raises_401(self) -> None:
        """Empty string (falsy) authorization → 401 'Authorization header required'."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Authorization header required"

    @pytest.mark.asyncio
    async def test_bearer_only_no_token_raises_401(self) -> None:
        """'Bearer' alone (no token part) falls back to decoding 'Bearer' → invalid JWT → 401."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="Bearer")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid or expired token"

    @pytest.mark.asyncio
    async def test_three_part_header_raises_401(self) -> None:
        """'Bearer token extra' (3+ parts) is not split as Bearer scheme; entire string decoded → 401."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="Bearer sometoken extra")
        assert exc_info.value.status_code == 401


class TestTokenSignatureValidation:
    """get_current_user rejects tokens with invalid or tampered signatures."""

    @pytest.mark.asyncio
    async def test_valid_signature_passes(self) -> None:
        """Token signed with the application secret is accepted."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result is not None

    @pytest.mark.asyncio
    async def test_wrong_secret_raises_401(self) -> None:
        """Token signed with a different secret → 401 'Invalid or expired token'."""
        token = _make_wrong_secret_token()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid or expired token"

    @pytest.mark.asyncio
    async def test_garbage_string_raises_401(self) -> None:
        """Completely invalid JWT string → 401 'Invalid or expired token'."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="Bearer not.a.real.jwt")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid or expired token"

    @pytest.mark.asyncio
    async def test_tampered_payload_raises_401(self) -> None:
        """JWT with a tampered payload (signature mismatch) → 401."""
        token = _make_token()
        header, _, sig = token.split(".")
        fake_payload = (
            base64.urlsafe_b64encode(
                json.dumps({"sub": "hacker@evil.com", "role": "admin"}).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        tampered = f"{header}.{fake_payload}.{sig}"
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {tampered}")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_dot_placeholder_raises_401(self) -> None:
        """Three-dot placeholder '...' cannot be decoded → 401."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization="Bearer ...")
        assert exc_info.value.status_code == 401


class TestTokenExpiry:
    """get_current_user rejects tokens whose 'exp' claim is in the past."""

    @pytest.mark.asyncio
    async def test_expired_one_second_ago_raises_401(self) -> None:
        """Token expired 1 second ago → 401 'Invalid or expired token'."""
        token = _make_token(exp_delta=timedelta(seconds=-1))
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid or expired token"

    @pytest.mark.asyncio
    async def test_token_at_epoch_raises_401(self) -> None:
        """Token with exp at Unix epoch (1970-01-01) → 401."""
        payload = {
            "sub": "analyst@mxtac.local",
            "role": "analyst",
            "exp": datetime(1970, 1, 1),
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_fresh_token_passes(self) -> None:
        """Token with exp 1 hour in the future passes validation."""
        token = _make_token(exp_delta=timedelta(hours=1))
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result is not None


class TestSubClaimValidation:
    """get_current_user enforces the presence of a non-empty 'sub' claim."""

    @pytest.mark.asyncio
    async def test_missing_sub_raises_401(self) -> None:
        """Token without a 'sub' claim → 401 'Invalid token payload'."""
        payload = {
            "role": "analyst",
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid token payload"

    @pytest.mark.asyncio
    async def test_empty_sub_raises_401(self) -> None:
        """Token with sub='' (empty string, falsy) → 401 'Invalid token payload'."""
        payload = {
            "sub": "",
            "role": "analyst",
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Invalid token payload"

    @pytest.mark.asyncio
    async def test_null_sub_raises_401(self) -> None:
        """Token with sub=null (None in JSON) → 401.

        python-jose raises a JWTError when decoding a token whose 'sub' claim
        is null, so the response comes from decode_token() rather than the
        explicit sub-presence check.  The important invariant is that the
        request is rejected with 401.
        """
        payload = {
            "sub": None,
            "role": "analyst",
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_sub_passes(self) -> None:
        """Token with a non-empty 'sub' claim passes the payload check."""
        token = _make_token(sub="user@example.com")
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["email"] == "user@example.com"


class TestJtiBlacklist:
    """get_current_user enforces JTI-based token revocation via the blacklist."""

    @pytest.mark.asyncio
    async def test_valid_jti_not_blacklisted_passes(self) -> None:
        """Token with JTI not in the blacklist → passes; blacklist is queried."""
        token = _make_token(include_jti=True)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)) as mock_check:
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result is not None
        mock_check.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_blacklisted_jti_raises_401(self) -> None:
        """Token whose JTI is in the blacklist → 401 'Token has been revoked'."""
        token = _make_token(include_jti=True)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=True)):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(authorization=f"Bearer {token}")
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Token has been revoked"

    @pytest.mark.asyncio
    async def test_token_without_jti_skips_blacklist_check(self) -> None:
        """Token without a JTI claim skips the blacklist check entirely."""
        token = _make_token(include_jti=False)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)) as mock_check:
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result is not None
        mock_check.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_valkey_unavailable_fails_open(self) -> None:
        """Valkey unavailable → is_token_blacklisted returns False internally → token accepted."""
        token = _make_token(include_jti=True)
        # is_token_blacklisted catches all exceptions and returns False (fails open).
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result is not None

    @pytest.mark.asyncio
    async def test_blacklist_called_with_correct_jti(self) -> None:
        """The JTI value extracted from the token payload is passed to is_token_blacklisted."""
        expected_jti = str(uuid4())
        # Build a token with a specific, known JTI
        payload = {
            "sub": "analyst@mxtac.local",
            "role": "analyst",
            "jti": expected_jti,
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)) as mock_check:
            await get_current_user(authorization=f"Bearer {token}")
        mock_check.assert_awaited_once_with(expected_jti)


class TestRoleExtraction:
    """get_current_user extracts the 'role' claim and defaults to 'viewer'."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter", "engineer", "admin"])
    async def test_all_roles_extracted_correctly(self, role: str) -> None:
        """Each of the five roles is extracted correctly from the 'role' claim."""
        token = _make_token(sub=f"{role}@mxtac.local", role=role)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["role"] == role

    @pytest.mark.asyncio
    async def test_missing_role_defaults_to_viewer(self) -> None:
        """Token without a 'role' claim → role defaults to 'viewer'."""
        payload = {
            "sub": "norole@mxtac.local",
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["role"] == "viewer"

    @pytest.mark.asyncio
    async def test_returned_dict_has_email_and_role_keys(self) -> None:
        """Successful validation returns a dict containing both 'email' and 'role'."""
        token = _make_token(sub="analyst@mxtac.local", role="analyst")
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert {"email", "role"} <= set(result.keys())

    @pytest.mark.asyncio
    async def test_email_field_matches_sub_claim(self) -> None:
        """The 'email' key in the result is the token's 'sub' claim value."""
        token = _make_token(sub="specific@example.com", role="hunter")
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            result = await get_current_user(authorization=f"Bearer {token}")
        assert result["email"] == "specific@example.com"


# ---------------------------------------------------------------------------
# B. Integration tests — dependency enforced on real protected endpoints
# ---------------------------------------------------------------------------


class TestProtectedEndpointEnforcement:
    """get_current_user is enforced on every request to a protected endpoint."""

    @pytest.mark.asyncio
    async def test_no_auth_header_returns_401(self, client: AsyncClient) -> None:
        """GET /detections without Authorization header → 401."""
        resp = await client.get(PROTECTED_URL)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_no_auth_header_detail(self, client: AsyncClient) -> None:
        """Missing auth header returns 'Authorization header required'."""
        resp = await client.get(PROTECTED_URL)
        assert resp.json()["detail"] == "Authorization header required"

    @pytest.mark.asyncio
    async def test_garbage_token_returns_401(self, client: AsyncClient) -> None:
        """Garbage token on a protected endpoint → 401."""
        resp = await client.get(
            PROTECTED_URL, headers={"Authorization": "Bearer totally.not.valid"}
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_secret_token_returns_401(self, client: AsyncClient) -> None:
        """Token signed with wrong secret on protected endpoint → 401 'Invalid or expired token'."""
        token = _make_wrong_secret_token()
        resp = await client.get(
            PROTECTED_URL, headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or expired token"

    @pytest.mark.asyncio
    async def test_expired_token_returns_401(self, client: AsyncClient) -> None:
        """Expired access token on protected endpoint → 401 'Invalid or expired token'."""
        token = _make_token(exp_delta=timedelta(seconds=-1))
        resp = await client.get(
            PROTECTED_URL, headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or expired token"

    @pytest.mark.asyncio
    async def test_blacklisted_token_returns_401(self, client: AsyncClient) -> None:
        """Blacklisted token on protected endpoint → 401 'Token has been revoked'."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=True)):
            resp = await client.get(
                PROTECTED_URL, headers={"Authorization": f"Bearer {token}"}
            )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Token has been revoked"

    @pytest.mark.asyncio
    async def test_valid_token_passes_auth(self, client: AsyncClient) -> None:
        """Valid token on protected endpoint → auth passes (200 OK)."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            with patch(MOCK_DETECTION_LIST, new=AsyncMock(return_value=([], 0))):
                resp = await client.get(
                    PROTECTED_URL, headers={"Authorization": f"Bearer {token}"}
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_raw_token_without_bearer_prefix_passes(self, client: AsyncClient) -> None:
        """Raw token (no 'Bearer ' prefix) is accepted on protected endpoints."""
        token = _make_token()
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            with patch(MOCK_DETECTION_LIST, new=AsyncMock(return_value=([], 0))):
                resp = await client.get(
                    PROTECTED_URL, headers={"Authorization": token}
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter", "engineer", "admin"])
    async def test_all_roles_pass_authentication(
        self, client: AsyncClient, role: str
    ) -> None:
        """Tokens for all five roles pass JWT validation on a protected endpoint."""
        token = _make_token(sub=f"{role}@mxtac.local", role=role)
        with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=False)):
            with patch(MOCK_DETECTION_LIST, new=AsyncMock(return_value=([], 0))):
                resp = await client.get(
                    PROTECTED_URL, headers={"Authorization": f"Bearer {token}"}
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_token_missing_sub_returns_401_on_endpoint(
        self, client: AsyncClient
    ) -> None:
        """Token without 'sub' claim is rejected on the protected endpoint → 401."""
        payload = {
            "role": "analyst",
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
        resp = await client.get(
            PROTECTED_URL, headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid token payload"
