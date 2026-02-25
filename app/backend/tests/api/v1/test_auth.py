"""Tests for POST /api/v1/auth/login — Feature 1.1
Tests for expired token → 401 — Feature 28.4
Tests for token refresh — Feature 28.5
Tests for refresh token rotation — Feature 1.2
Tests for account lockout (5 failed attempts → 30 min) — Feature 1.6
Tests for inactive account lock (90 days no login) — Feature 1.7
Tests for password expiry (90 days) — Feature 2.3

Coverage:
  - Happy path: status code, response schema, JWT claims
  - Role coverage: all four seeded roles appear in the token
  - Wrong credentials: bad password, unknown email (both → 401, same detail)
  - Inactive account: 403 + detail
  - Input validation: missing/null/malformed fields → 422
  - Email format edge cases: whitespace, missing TLD
  - JWT structure: exp in future, refresh type claim, access lacks type claim
  - Security: no password in response, access ≠ refresh token, wrong method → 405
  - Short-circuit: inactive + wrong password → 401 (not 403)
  - Expired token: past exp claim on protected endpoint → 401 (Feature 28.4)
  - Expired refresh token: POST /auth/refresh with expired token → 401
  - Token refresh: happy path, invalid token, access token rejected, inactive user (Feature 28.5)
  - Refresh token rotation: new refresh token issued on each call, never echoes old token (Feature 1.2)

All tests that exercise business logic mock ``UserRepo.get_by_email`` and
``verify_password`` so the suite runs without a live database or a working
bcrypt backend (passlib 1.7.4 + bcrypt ≥ 4 have an incompatibility during
backend initialisation that breaks runtime hash computation).
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
VALID_CREDS = {"email": "analyst@mxtac.local", "password": "mxtac2026"}

# Patch targets — names as imported inside the endpoint module.
MOCK_REPO = "app.api.v1.endpoints.auth.UserRepo.get_by_email"
MOCK_VERIFY = "app.api.v1.endpoints.auth.verify_password"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


def _active_user(email: str = "analyst@mxtac.local", role: str = "analyst") -> User:
    """Return an active User ORM object.  hashed_password is a placeholder
    because verify_password is always patched in tests that use this helper."""
    return User(
        email=email,
        hashed_password="$2b$12$placeholder_not_used_in_tests",
        full_name="Test User",
        role=role,
        is_active=True,
    )


def _inactive_user() -> User:
    return User(
        email="inactive@mxtac.local",
        hashed_password="$2b$12$placeholder_not_used_in_tests",
        role="analyst",
        is_active=False,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_analyst():
    """UserRepo returns an active analyst user; password check succeeds."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            yield


@pytest.fixture
def mock_wrong_password():
    """UserRepo returns an active user; password check fails."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            yield


@pytest.fixture
def mock_no_user():
    """UserRepo returns None — unknown email."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        yield


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_success_status(client: AsyncClient, mock_analyst) -> None:
    """Valid credentials → 200 OK."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_login_returns_access_token(client: AsyncClient, mock_analyst) -> None:
    """Response contains a non-empty access_token string."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert "access_token" in data
    assert isinstance(data["access_token"], str)
    assert data["access_token"]


@pytest.mark.asyncio
async def test_login_returns_refresh_token(client: AsyncClient, mock_analyst) -> None:
    """Response contains a non-empty refresh_token string."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert "refresh_token" in data
    assert isinstance(data["refresh_token"], str)
    assert data["refresh_token"]


@pytest.mark.asyncio
async def test_login_token_type_is_bearer(client: AsyncClient, mock_analyst) -> None:
    """token_type must equal 'bearer'."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.json()["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_expires_in(client: AsyncClient, mock_analyst) -> None:
    """expires_in must be 3600 seconds."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.json()["expires_in"] == 3600


@pytest.mark.asyncio
async def test_login_response_schema_keys(client: AsyncClient, mock_analyst) -> None:
    """Successful response includes exactly the four expected keys."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert {"access_token", "refresh_token", "token_type", "expires_in"} <= set(resp.json())


@pytest.mark.asyncio
async def test_login_content_type_json(client: AsyncClient, mock_analyst) -> None:
    """Response Content-Type is application/json."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert "application/json" in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# JWT claim validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_access_token_sub_is_email(client: AsyncClient, mock_analyst) -> None:
    """access_token 'sub' claim matches the authenticated user's email."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    payload = _decode(resp.json()["access_token"])
    assert payload["sub"] == VALID_CREDS["email"]


@pytest.mark.asyncio
async def test_access_token_role_claim(client: AsyncClient, mock_analyst) -> None:
    """access_token carries the correct 'role' claim for the analyst account."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    payload = _decode(resp.json()["access_token"])
    assert payload["role"] == "analyst"


@pytest.mark.asyncio
async def test_access_token_has_exp(client: AsyncClient, mock_analyst) -> None:
    """access_token must contain an 'exp' (expiry) claim."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    payload = _decode(resp.json()["access_token"])
    assert "exp" in payload


@pytest.mark.asyncio
async def test_refresh_token_sub_is_email(client: AsyncClient, mock_analyst) -> None:
    """refresh_token 'sub' claim matches the authenticated user's email."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    payload = _decode(resp.json()["refresh_token"])
    assert payload["sub"] == VALID_CREDS["email"]


@pytest.mark.asyncio
async def test_tokens_are_distinct(client: AsyncClient, mock_analyst) -> None:
    """access_token and refresh_token must be different strings."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert data["access_token"] != data["refresh_token"]


# ---------------------------------------------------------------------------
# Role coverage — all seeded accounts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "email,expected_role",
    [
        ("admin@mxtac.local", "admin"),
        ("analyst@mxtac.local", "analyst"),
        ("hunter@mxtac.local", "hunter"),
        ("engineer@mxtac.local", "engineer"),
    ],
)
async def test_login_role_in_token(
    client: AsyncClient, email: str, expected_role: str
) -> None:
    """Each seeded user's role is embedded in their access_token."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user(email=email, role=expected_role))):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(LOGIN_URL, json={"email": email, "password": "mxtac2026"})
    assert resp.status_code == 200
    payload = _decode(resp.json()["access_token"])
    assert payload["role"] == expected_role


# ---------------------------------------------------------------------------
# Wrong credentials
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient, mock_wrong_password) -> None:
    """Wrong password → 401."""
    resp = await client.post(LOGIN_URL, json={"email": "analyst@mxtac.local", "password": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(client: AsyncClient, mock_no_user) -> None:
    """Unknown email → 401."""
    resp = await client.post(LOGIN_URL, json={"email": "nobody@example.com", "password": "whatever"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_wrong_password_detail(client: AsyncClient, mock_wrong_password) -> None:
    """Wrong password returns 'Invalid credentials' — no hint about which field failed."""
    resp = await client.post(LOGIN_URL, json={"email": "analyst@mxtac.local", "password": "wrong"})
    assert resp.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_login_unknown_user_detail(client: AsyncClient, mock_no_user) -> None:
    """Unknown email returns the same 'Invalid credentials' detail (no user enumeration)."""
    resp = await client.post(LOGIN_URL, json={"email": "nobody@example.com", "password": "whatever"})
    assert resp.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_login_empty_password(client: AsyncClient, mock_wrong_password) -> None:
    """Empty string password → verify_password returns False → 401."""
    resp = await client.post(LOGIN_URL, json={"email": "analyst@mxtac.local", "password": ""})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Inactive account
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_inactive_account_status(client: AsyncClient) -> None:
    """Correct credentials for a disabled account → 403 Forbidden."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_inactive_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(
                LOGIN_URL,
                json={"email": "inactive@mxtac.local", "password": "mxtac2026"},
            )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_login_inactive_account_detail(client: AsyncClient) -> None:
    """Disabled account response body contains 'Account is disabled'."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_inactive_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(
                LOGIN_URL,
                json={"email": "inactive@mxtac.local", "password": "mxtac2026"},
            )
    assert resp.json()["detail"] == "Account is disabled"


# ---------------------------------------------------------------------------
# Input validation (Pydantic → 422)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_missing_email(client: AsyncClient) -> None:
    """Request without email field → 422 Unprocessable Entity."""
    resp = await client.post(LOGIN_URL, json={"password": "mxtac2026"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_missing_password(client: AsyncClient) -> None:
    """Request without password field → 422 Unprocessable Entity."""
    resp = await client.post(LOGIN_URL, json={"email": "analyst@mxtac.local"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_empty_body(client: AsyncClient) -> None:
    """Empty JSON object → 422 Unprocessable Entity."""
    resp = await client.post(LOGIN_URL, json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_invalid_email_format(client: AsyncClient) -> None:
    """String without '@' in email field → 422 (format validation)."""
    resp = await client.post(LOGIN_URL, json={"email": "not-an-email", "password": "mxtac2026"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_null_email(client: AsyncClient) -> None:
    """Null email → 422 Unprocessable Entity."""
    resp = await client.post(LOGIN_URL, json={"email": None, "password": "mxtac2026"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_null_password(client: AsyncClient) -> None:
    """Null password → 422 Unprocessable Entity."""
    resp = await client.post(LOGIN_URL, json={"email": "analyst@mxtac.local", "password": None})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_form_data_rejected(client: AsyncClient) -> None:
    """Form-encoded body (not JSON) → 422; endpoint only accepts application/json."""
    resp = await client.post(
        LOGIN_URL,
        data="email=analyst%40mxtac.local&password=mxtac2026",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_no_password_in_response(client: AsyncClient, mock_analyst) -> None:
    """Response body must not leak the plaintext password or hashed_password field."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    body = resp.text
    assert VALID_CREDS["password"] not in body
    assert "hashed_password" not in body


@pytest.mark.asyncio
async def test_login_multiple_calls_all_succeed(client: AsyncClient, mock_analyst) -> None:
    """Repeated logins with valid credentials all return 200 (no one-shot token)."""
    for _ in range(3):
        resp = await client.post(LOGIN_URL, json=VALID_CREDS)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# JWT token structure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_token_has_type_claim(client: AsyncClient, mock_analyst) -> None:
    """refresh_token carries type='refresh' to distinguish it from access tokens."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    payload = _decode(resp.json()["refresh_token"])
    assert payload.get("type") == "refresh"


@pytest.mark.asyncio
async def test_access_token_has_no_type_claim(client: AsyncClient, mock_analyst) -> None:
    """access_token must NOT carry a 'type' claim (only refresh tokens do)."""
    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    payload = _decode(resp.json()["access_token"])
    assert "type" not in payload


@pytest.mark.asyncio
async def test_access_token_exp_is_in_future(client: AsyncClient, mock_analyst) -> None:
    """access_token exp claim is a Unix timestamp strictly greater than now."""
    import time

    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    payload = _decode(resp.json()["access_token"])
    assert payload["exp"] > time.time()


# ---------------------------------------------------------------------------
# Email format edge cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_email_with_leading_whitespace(client: AsyncClient) -> None:
    """Email with leading whitespace fails regex → 422 (no DB call needed)."""
    resp = await client.post(LOGIN_URL, json={"email": "  analyst@mxtac.local", "password": "mxtac2026"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_email_without_tld(client: AsyncClient) -> None:
    """Email with no dot in domain part (missing TLD) → 422."""
    resp = await client.post(LOGIN_URL, json={"email": "analyst@mxtac", "password": "mxtac2026"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Short-circuit: wrong password on inactive account
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_inactive_user_wrong_password_is_401(client: AsyncClient) -> None:
    """Inactive account + wrong password → 401, not 403.

    The password check is evaluated before the is_active check; the endpoint
    short-circuits on the credential failure so the account status is never
    reached.
    """
    with patch(MOCK_REPO, new=AsyncMock(return_value=_inactive_user())):
        with patch(MOCK_VERIFY, return_value=False):
            resp = await client.post(
                LOGIN_URL,
                json={"email": "inactive@mxtac.local", "password": "wrong"},
            )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials"


# ---------------------------------------------------------------------------
# Wrong HTTP method
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_get_method_not_allowed(client: AsyncClient) -> None:
    """GET /auth/login is not defined → 405 Method Not Allowed."""
    resp = await client.get(LOGIN_URL)
    assert resp.status_code == 405


# ---------------------------------------------------------------------------
# Feature 28.4 — Expired token → 401
# ---------------------------------------------------------------------------

ALGORITHM = "HS256"
PROTECTED_URL = "/api/v1/detections"


def _make_expired_token(sub: str = "analyst@mxtac.local", role: str = "analyst") -> str:
    """Create a JWT whose exp is 1 second in the past."""
    payload = {
        "sub": sub,
        "role": role,
        "exp": datetime.utcnow() - timedelta(seconds=1),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def _make_expired_refresh_token(sub: str = "analyst@mxtac.local") -> str:
    """Create a refresh JWT whose exp is 1 second in the past."""
    payload = {
        "sub": sub,
        "type": "refresh",
        "exp": datetime.utcnow() - timedelta(seconds=1),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


@pytest.mark.asyncio
async def test_expired_access_token_returns_401(client: AsyncClient) -> None:
    """Expired access token on a protected endpoint → 401 Unauthorized."""
    token = _make_expired_token()
    resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_expired_access_token_detail(client: AsyncClient) -> None:
    """Expired access token response body signals 'Invalid or expired token'."""
    token = _make_expired_token()
    resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.json()["detail"] == "Invalid or expired token"


@pytest.mark.asyncio
async def test_expired_token_without_bearer_prefix_returns_401(client: AsyncClient) -> None:
    """Raw expired token (no 'Bearer ' prefix) still triggers 401."""
    token = _make_expired_token()
    resp = await client.get(PROTECTED_URL, headers={"Authorization": token})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_expired_token_is_rejected_regardless_of_role(client: AsyncClient) -> None:
    """Expired token for an admin account is still rejected with 401."""
    token = _make_expired_token(sub="admin@mxtac.local", role="admin")
    resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_expired_refresh_token_on_refresh_endpoint_returns_401(client: AsyncClient) -> None:
    """POST /auth/refresh with an expired refresh token → 401."""
    expired_refresh = _make_expired_refresh_token()
    resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": expired_refresh})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_valid_token_after_expiry_window_is_rejected(client: AsyncClient) -> None:
    """Token with exp set to the epoch (far past) is rejected with 401."""
    payload = {
        "sub": "analyst@mxtac.local",
        "role": "analyst",
        "exp": datetime(1970, 1, 1),  # Unix epoch — always expired
    }
    ancient_token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
    resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {ancient_token}"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Feature 28.5 — Token refresh
# ---------------------------------------------------------------------------

from app.core.security import create_refresh_token  # noqa: E402

REFRESH_URL = "/api/v1/auth/refresh"


def _make_refresh_token(sub: str = "analyst@mxtac.local") -> str:
    """Create a valid refresh token (type='refresh', 7-day expiry)."""
    return create_refresh_token({"sub": sub})


def _make_access_token_only(sub: str = "analyst@mxtac.local", role: str = "analyst") -> str:
    """Create a plain access token (no type claim) — must NOT be usable as a refresh token."""
    from app.core.security import create_access_token
    return create_access_token({"sub": sub, "role": role})


# --- Happy path ---


@pytest.mark.asyncio
async def test_refresh_success_status(client: AsyncClient) -> None:
    """Valid refresh token → 200 OK."""
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_refresh_returns_new_access_token(client: AsyncClient) -> None:
    """Successful refresh returns a non-empty access_token string."""
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    data = resp.json()
    assert "access_token" in data
    assert isinstance(data["access_token"], str)
    assert data["access_token"]


@pytest.mark.asyncio
async def test_refresh_rotation_issues_new_token(client: AsyncClient) -> None:
    """Rotation: response refresh_token is a NEW token, different from the submitted one."""
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    assert resp.json()["refresh_token"] != token


@pytest.mark.asyncio
async def test_refresh_token_type_is_bearer(client: AsyncClient) -> None:
    """token_type in refresh response is 'bearer'."""
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    assert resp.json()["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_refresh_expires_in(client: AsyncClient) -> None:
    """expires_in in refresh response is 3600."""
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    assert resp.json()["expires_in"] == 3600


@pytest.mark.asyncio
async def test_refresh_response_schema_keys(client: AsyncClient) -> None:
    """Refresh response includes the four expected keys."""
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    assert {"access_token", "refresh_token", "token_type", "expires_in"} <= set(resp.json())


@pytest.mark.asyncio
async def test_refresh_new_access_token_sub(client: AsyncClient) -> None:
    """New access_token sub claim matches the user's email."""
    token = _make_refresh_token(sub="analyst@mxtac.local")
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user(email="analyst@mxtac.local"))):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    payload = _decode(resp.json()["access_token"])
    assert payload["sub"] == "analyst@mxtac.local"


@pytest.mark.asyncio
async def test_refresh_new_access_token_role(client: AsyncClient) -> None:
    """New access_token role claim matches the user's role from the DB."""
    token = _make_refresh_token(sub="analyst@mxtac.local")
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user(role="analyst"))):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    payload = _decode(resp.json()["access_token"])
    assert payload["role"] == "analyst"


@pytest.mark.asyncio
async def test_refresh_new_access_token_has_no_type_claim(client: AsyncClient) -> None:
    """New access_token must not carry a 'type' claim."""
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    payload = _decode(resp.json()["access_token"])
    assert "type" not in payload


@pytest.mark.asyncio
async def test_refresh_new_access_token_differs_from_refresh_token(client: AsyncClient) -> None:
    """The new access_token must be different from the submitted refresh_token."""
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    data = resp.json()
    assert data["access_token"] != data["refresh_token"]


@pytest.mark.asyncio
async def test_refresh_new_access_token_exp_in_future(client: AsyncClient) -> None:
    """New access_token exp claim is strictly in the future."""
    import time
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    payload = _decode(resp.json()["access_token"])
    assert payload["exp"] > time.time()


# --- Error cases ---


@pytest.mark.asyncio
async def test_refresh_with_access_token_rejected(client: AsyncClient) -> None:
    """An access token (no type='refresh') submitted to /refresh → 401."""
    access_token = _make_access_token_only()
    resp = await client.post(REFRESH_URL, json={"refresh_token": access_token})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_access_token_detail(client: AsyncClient) -> None:
    """Access token used as refresh token returns 'Invalid refresh token' detail."""
    access_token = _make_access_token_only()
    resp = await client.post(REFRESH_URL, json={"refresh_token": access_token})
    assert resp.json()["detail"] == "Invalid refresh token"


@pytest.mark.asyncio
async def test_refresh_with_garbage_token_returns_401(client: AsyncClient) -> None:
    """Completely invalid JWT string → 401."""
    resp = await client.post(REFRESH_URL, json={"refresh_token": "not.a.jwt"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_inactive_user_returns_401(client: AsyncClient) -> None:
    """Valid refresh token but account is inactive → 401."""
    token = _make_refresh_token(sub="inactive@mxtac.local")
    with patch(MOCK_REPO, new=AsyncMock(return_value=_inactive_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_unknown_user_returns_401(client: AsyncClient) -> None:
    """Valid refresh token for a user not in the DB → 401."""
    token = _make_refresh_token(sub="ghost@mxtac.local")
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_missing_field_returns_422(client: AsyncClient) -> None:
    """Request with no refresh_token field → 422 Unprocessable Entity."""
    resp = await client.post(REFRESH_URL, json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_refresh_null_token_returns_422(client: AsyncClient) -> None:
    """Null refresh_token → 422 Unprocessable Entity."""
    resp = await client.post(REFRESH_URL, json={"refresh_token": None})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_refresh_get_method_not_allowed(client: AsyncClient) -> None:
    """GET /auth/refresh → 405 Method Not Allowed."""
    resp = await client.get(REFRESH_URL)
    assert resp.status_code == 405


# ---------------------------------------------------------------------------
# Feature 1.2 — Refresh token rotation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotation_new_refresh_token_has_type_claim(client: AsyncClient) -> None:
    """Rotated refresh_token carries type='refresh' claim."""
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    new_token = resp.json()["refresh_token"]
    payload = _decode(new_token)
    assert payload.get("type") == "refresh"


@pytest.mark.asyncio
async def test_rotation_new_refresh_token_sub(client: AsyncClient) -> None:
    """Rotated refresh_token sub claim matches the authenticated user's email."""
    token = _make_refresh_token(sub="analyst@mxtac.local")
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user(email="analyst@mxtac.local"))):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    payload = _decode(resp.json()["refresh_token"])
    assert payload["sub"] == "analyst@mxtac.local"


@pytest.mark.asyncio
async def test_rotation_new_refresh_token_exp_in_future(client: AsyncClient) -> None:
    """Rotated refresh_token exp claim is strictly in the future."""
    import time
    token = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp = await client.post(REFRESH_URL, json={"refresh_token": token})
    payload = _decode(resp.json()["refresh_token"])
    assert payload["exp"] > time.time()


@pytest.mark.asyncio
async def test_rotation_chained_refresh_each_token_differs(client: AsyncClient) -> None:
    """Two successive refreshes each produce a distinct refresh token (no re-use)."""
    token1 = _make_refresh_token()
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp1 = await client.post(REFRESH_URL, json={"refresh_token": token1})
    token2 = resp1.json()["refresh_token"]

    assert token2 != token1

    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        resp2 = await client.post(REFRESH_URL, json={"refresh_token": token2})
    token3 = resp2.json()["refresh_token"]

    assert token3 != token2
    assert token3 != token1


# ---------------------------------------------------------------------------
# Feature 1.3 — POST /auth/logout — invalidate token
# ---------------------------------------------------------------------------

LOGOUT_URL = "/api/v1/auth/logout"

# Patch targets for the logout feature
MOCK_BLACKLIST = "app.api.v1.endpoints.auth.blacklist_token"
MOCK_IS_BLACKLISTED = "app.core.security.is_token_blacklisted"


# _make_access_token_only() (defined above) produces a valid access token; reuse it.


@pytest.mark.asyncio
async def test_logout_success_returns_200(client: AsyncClient) -> None:
    """Valid access token → 200 OK."""
    token = _make_access_token_only()
    with patch(MOCK_BLACKLIST, new=AsyncMock()):
        resp = await client.post(LOGOUT_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_logout_response_message(client: AsyncClient) -> None:
    """Successful logout returns {'message': 'Logged out'}."""
    token = _make_access_token_only()
    with patch(MOCK_BLACKLIST, new=AsyncMock()):
        resp = await client.post(LOGOUT_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.json()["message"] == "Logged out"


@pytest.mark.asyncio
async def test_logout_without_auth_header_returns_401(client: AsyncClient) -> None:
    """Missing Authorization header → 401."""
    resp = await client.post(LOGOUT_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_with_invalid_token_returns_401(client: AsyncClient) -> None:
    """Malformed / non-JWT string → 401."""
    resp = await client.post(LOGOUT_URL, headers={"Authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_with_expired_token_returns_401(client: AsyncClient) -> None:
    """Expired access token → 401 (nothing to revoke; token is already dead)."""
    expired = _make_expired_token()
    resp = await client.post(LOGOUT_URL, headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_blacklists_token_jti(client: AsyncClient) -> None:
    """Logout calls blacklist_token with the token's JTI and a positive TTL."""
    token = _make_access_token_only()
    jti = _decode(token)["jti"]

    with patch(MOCK_BLACKLIST, new=AsyncMock()) as mock_bl:
        await client.post(LOGOUT_URL, headers={"Authorization": f"Bearer {token}"})

    mock_bl.assert_awaited_once()
    called_jti, called_ttl = mock_bl.call_args[0]
    assert called_jti == jti
    assert called_ttl > 0


@pytest.mark.asyncio
async def test_logout_blacklisted_token_rejected_on_protected_endpoint(
    client: AsyncClient,
) -> None:
    """After logout, a blacklisted token on any protected endpoint → 401."""
    token = _make_access_token_only()
    with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=True)):
        resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_blacklisted_token_detail(client: AsyncClient) -> None:
    """A blacklisted token returns 'Token has been revoked' detail."""
    token = _make_access_token_only()
    with patch(MOCK_IS_BLACKLISTED, new=AsyncMock(return_value=True)):
        resp = await client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.json()["detail"] == "Token has been revoked"


@pytest.mark.asyncio
async def test_logout_get_method_not_allowed(client: AsyncClient) -> None:
    """GET /auth/logout → 405 Method Not Allowed."""
    resp = await client.get(LOGOUT_URL)
    assert resp.status_code == 405


@pytest.mark.asyncio
async def test_logout_token_without_bearer_prefix_succeeds(client: AsyncClient) -> None:
    """Raw token (no 'Bearer ' prefix) is also accepted on logout."""
    token = _make_access_token_only()
    with patch(MOCK_BLACKLIST, new=AsyncMock()):
        resp = await client.post(LOGOUT_URL, headers={"Authorization": token})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Account lockout — Feature 1.6
# ---------------------------------------------------------------------------

MOCK_IS_LOCKED = "app.api.v1.endpoints.auth.is_account_locked"
MOCK_INCREMENT = "app.api.v1.endpoints.auth.increment_login_attempts"
MOCK_CLEAR = "app.api.v1.endpoints.auth.clear_login_attempts"


@pytest.mark.asyncio
async def test_lockout_returns_429_when_locked(client: AsyncClient) -> None:
    """A locked account returns 429 before checking credentials."""
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=True)):
        resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_lockout_detail_message(client: AsyncClient) -> None:
    """Lockout response detail mentions the lock duration."""
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=True)):
        resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert "30 minutes" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_lockout_increments_on_wrong_password(client: AsyncClient) -> None:
    """Failed login increments the attempt counter."""
    mock_incr = AsyncMock(return_value=1)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
            with patch(MOCK_VERIFY, return_value=False):
                with patch(MOCK_INCREMENT, mock_incr):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 401
    mock_incr.assert_awaited_once_with(VALID_CREDS["email"])


@pytest.mark.asyncio
async def test_lockout_increments_on_unknown_user(client: AsyncClient) -> None:
    """Unknown email also increments the counter (consistent behaviour)."""
    mock_incr = AsyncMock(return_value=1)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
            with patch(MOCK_INCREMENT, mock_incr):
                resp = await client.post(LOGIN_URL, json={"email": "unknown@x.com", "password": "x"})
    assert resp.status_code == 401
    mock_incr.assert_awaited_once_with("unknown@x.com")


@pytest.mark.asyncio
async def test_lockout_clears_on_success(client: AsyncClient) -> None:
    """Successful login clears the attempt counter."""
    mock_clear = AsyncMock()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, mock_clear):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 200
    mock_clear.assert_awaited_once_with(VALID_CREDS["email"])


@pytest.mark.asyncio
async def test_lockout_not_cleared_on_wrong_password(client: AsyncClient) -> None:
    """Counter is NOT cleared on failed login — only incremented."""
    mock_clear = AsyncMock()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
            with patch(MOCK_VERIFY, return_value=False):
                with patch(MOCK_INCREMENT, new=AsyncMock(return_value=1)):
                    with patch(MOCK_CLEAR, mock_clear):
                        resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 401
    mock_clear.assert_not_awaited()


@pytest.mark.asyncio
async def test_lockout_does_not_increment_when_already_locked(client: AsyncClient) -> None:
    """When the account is already locked, increment is never called."""
    mock_incr = AsyncMock()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=True)):
        with patch(MOCK_INCREMENT, mock_incr):
            resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 429
    mock_incr.assert_not_awaited()


@pytest.mark.asyncio
async def test_lockout_not_cleared_on_inactive_account(client: AsyncClient) -> None:
    """Counter is NOT cleared when the account is disabled (no successful auth)."""
    mock_clear = AsyncMock()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=_inactive_user())):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, mock_clear):
                    resp = await client.post(
                        LOGIN_URL,
                        json={"email": "inactive@mxtac.local", "password": "mxtac2026"},
                    )
    assert resp.status_code == 403
    mock_clear.assert_not_awaited()


@pytest.mark.asyncio
async def test_lockout_check_uses_request_email(client: AsyncClient) -> None:
    """is_account_locked is called with the exact email from the request body."""
    mock_locked = AsyncMock(return_value=True)
    target_email = "victim@corp.example"
    with patch(MOCK_IS_LOCKED, mock_locked):
        await client.post(LOGIN_URL, json={"email": target_email, "password": "any"})
    mock_locked.assert_awaited_once_with(target_email)


@pytest.mark.asyncio
async def test_lockout_unlocked_account_proceeds_normally(client: AsyncClient) -> None:
    """is_account_locked returning False allows the login attempt to proceed."""
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Inactive account lock — Feature 1.7
# ---------------------------------------------------------------------------


def _user_with_last_login(days_ago: int) -> User:
    """Return an active user whose last_login_at is ``days_ago`` days in the past."""
    return User(
        email="analyst@mxtac.local",
        hashed_password="$2b$12$placeholder_not_used_in_tests",
        full_name="Test User",
        role="analyst",
        is_active=True,
        last_login_at=datetime.now(timezone.utc) - timedelta(days=days_ago),
    )


def _user_never_logged_in() -> User:
    """Return an active user who has never logged in (last_login_at=None)."""
    return User(
        email="analyst@mxtac.local",
        hashed_password="$2b$12$placeholder_not_used_in_tests",
        full_name="Test User",
        role="analyst",
        is_active=True,
        last_login_at=None,
    )


@pytest.mark.asyncio
async def test_inactivity_lock_91_days_returns_403(client: AsyncClient) -> None:
    """Account inactive for 91 days → 403 Forbidden."""
    user = _user_with_last_login(91)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_inactivity_lock_90_days_exact_returns_403(client: AsyncClient) -> None:
    """Account inactive for exactly 90 days → 403 (boundary: cutoff is exclusive)."""
    user = _user_with_last_login(90)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_inactivity_lock_detail_mentions_inactivity(client: AsyncClient) -> None:
    """Inactivity lock response body indicates the reason."""
    user = _user_with_last_login(91)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert "inactivity" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_inactivity_lock_89_days_returns_200(client: AsyncClient) -> None:
    """Account inactive for only 89 days → 200 (not yet eligible for lock)."""
    user = _user_with_last_login(89)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_inactivity_lock_never_logged_in_returns_200(client: AsyncClient) -> None:
    """User with last_login_at=None (never logged in) is not locked by inactivity rule."""
    user = _user_never_logged_in()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_inactivity_lock_wrong_password_not_locked(client: AsyncClient) -> None:
    """Wrong password on an inactive account → 401, not 403 (credential check first)."""
    user = _user_with_last_login(120)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=False):
                resp = await client.post(LOGIN_URL, json={"email": "analyst@mxtac.local", "password": "wrong"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_inactivity_lock_sets_is_active_false(client: AsyncClient) -> None:
    """After inactivity lock, the user object has is_active=False."""
    user = _user_with_last_login(91)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                await client.post(LOGIN_URL, json=VALID_CREDS)
    assert user.is_active is False


@pytest.mark.asyncio
async def test_inactivity_lock_sets_inactive_locked_at(client: AsyncClient) -> None:
    """After inactivity lock, inactive_locked_at is populated on the user object."""
    user = _user_with_last_login(91)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                await client.post(LOGIN_URL, json=VALID_CREDS)
    assert user.inactive_locked_at is not None


@pytest.mark.asyncio
async def test_successful_login_updates_last_login_at(client: AsyncClient) -> None:
    """Successful login sets last_login_at to a recent datetime on the user object."""
    before = datetime.now(timezone.utc)
    user = _user_with_last_login(10)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 200
    assert user.last_login_at is not None
    assert user.last_login_at >= before


# ---------------------------------------------------------------------------
# Feature 1.8 — First-login forced password change
# ---------------------------------------------------------------------------

from app.core.security import create_password_change_token  # noqa: E402

CHANGE_PASSWORD_URL = "/api/v1/auth/change-password"
MOCK_REPO_BY_ID = "app.api.v1.endpoints.auth.UserRepo.get_by_id"
MOCK_HASH = "app.api.v1.endpoints.auth.hash_password"

_FORCED_USER_ID = "forced-user-id-1234"


def _user_must_change_password(mfa_enabled: bool = False) -> User:
    """Return an active user with must_change_password=True."""
    u = User(
        email="newuser@mxtac.local",
        hashed_password="$2b$12$placeholder_not_used_in_tests",
        full_name="New User",
        role="analyst",
        is_active=True,
        must_change_password=True,
    )
    u.id = _FORCED_USER_ID
    u.mfa_enabled = mfa_enabled
    return u


# --- Login with must_change_password=True ---


@pytest.mark.asyncio
async def test_must_change_password_login_returns_200(client: AsyncClient) -> None:
    """Login with must_change_password=True → 200 OK (not 401/403)."""
    user = _user_must_change_password()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_must_change_password_login_response_flag(client: AsyncClient) -> None:
    """Response contains password_change_required=True."""
    user = _user_must_change_password()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert data.get("password_change_required") is True


@pytest.mark.asyncio
async def test_must_change_password_login_response_has_token(client: AsyncClient) -> None:
    """Response contains a non-empty password_change_token string."""
    user = _user_must_change_password()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert "password_change_token" in data
    assert isinstance(data["password_change_token"], str)
    assert data["password_change_token"]


@pytest.mark.asyncio
async def test_must_change_password_login_no_access_token(client: AsyncClient) -> None:
    """Response must NOT contain access_token or refresh_token."""
    user = _user_must_change_password()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert "access_token" not in data
    assert "refresh_token" not in data


@pytest.mark.asyncio
async def test_must_change_password_token_has_correct_purpose(client: AsyncClient) -> None:
    """The password_change_token JWT carries purpose='password_change'."""
    user = _user_must_change_password()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    token = resp.json()["password_change_token"]
    payload = _decode(token)
    assert payload.get("purpose") == "password_change"


@pytest.mark.asyncio
async def test_must_change_password_token_sub_is_user_id(client: AsyncClient) -> None:
    """The password_change_token sub claim equals the user's id."""
    user = _user_must_change_password()
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    token = resp.json()["password_change_token"]
    payload = _decode(token)
    assert payload["sub"] == _FORCED_USER_ID


@pytest.mark.asyncio
async def test_normal_user_login_unaffected_by_flag(client: AsyncClient) -> None:
    """Users with must_change_password=False get normal token response."""
    user = _active_user()  # must_change_password defaults to False
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert resp.status_code == 200
    assert "access_token" in data
    assert "password_change_required" not in data


# --- POST /auth/change-password ---


@pytest.mark.asyncio
async def test_change_password_success_returns_200(client: AsyncClient) -> None:
    """Valid password_change_token + matching passwords → 200 OK."""
    token = create_password_change_token(_FORCED_USER_ID)
    user = _user_must_change_password()
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY, return_value=False):
            with patch(MOCK_HASH, return_value="$2b$12$newhash"):
                resp = await client.post(
                    CHANGE_PASSWORD_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_change_password_returns_access_token(client: AsyncClient) -> None:
    """Successful change returns access_token."""
    token = create_password_change_token(_FORCED_USER_ID)
    user = _user_must_change_password()
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY, return_value=False):
            with patch(MOCK_HASH, return_value="$2b$12$newhash"):
                resp = await client.post(
                    CHANGE_PASSWORD_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_change_password_clears_must_change_flag(client: AsyncClient) -> None:
    """After successful change, must_change_password is False on the user object."""
    token = create_password_change_token(_FORCED_USER_ID)
    user = _user_must_change_password()
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY, return_value=False):
            with patch(MOCK_HASH, return_value="$2b$12$newhash"):
                await client.post(
                    CHANGE_PASSWORD_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )
    assert user.must_change_password is False


@pytest.mark.asyncio
async def test_change_password_updates_hashed_password(client: AsyncClient) -> None:
    """After successful change, user.hashed_password is updated to the new hash."""
    token = create_password_change_token(_FORCED_USER_ID)
    user = _user_must_change_password()
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY, return_value=False):
            with patch(MOCK_HASH, return_value="$2b$12$newhash") as mock_h:
                await client.post(
                    CHANGE_PASSWORD_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )
    mock_h.assert_called_once_with("NewSecure1!")
    assert user.hashed_password == "$2b$12$newhash"


@pytest.mark.asyncio
async def test_change_password_invalid_token_returns_401(client: AsyncClient) -> None:
    """Garbage token string → 401."""
    resp = await client.post(
        CHANGE_PASSWORD_URL,
        json={
            "password_change_token": "not.a.valid.jwt",
            "new_password": "NewSecure1!",
            "confirm_password": "NewSecure1!",
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_change_password_wrong_purpose_token_returns_401(client: AsyncClient) -> None:
    """An access token (purpose != 'password_change') → 401."""
    from app.core.security import create_access_token as _cat
    access_token = _cat({"sub": "analyst@mxtac.local", "role": "analyst"})
    resp = await client.post(
        CHANGE_PASSWORD_URL,
        json={
            "password_change_token": access_token,
            "new_password": "NewSecure1!",
            "confirm_password": "NewSecure1!",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid password change token"


@pytest.mark.asyncio
async def test_change_password_mismatched_passwords_returns_422(client: AsyncClient) -> None:
    """new_password != confirm_password → 422 Unprocessable Entity."""
    token = create_password_change_token(_FORCED_USER_ID)
    resp = await client.post(
        CHANGE_PASSWORD_URL,
        json={
            "password_change_token": token,
            "new_password": "NewSecure1!",
            "confirm_password": "DifferentPass!",
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_change_password_too_short_returns_422(client: AsyncClient) -> None:
    """new_password below minimum length → 422 Unprocessable Entity."""
    token = create_password_change_token(_FORCED_USER_ID)
    resp = await client.post(
        CHANGE_PASSWORD_URL,
        json={
            "password_change_token": token,
            "new_password": "short",
            "confirm_password": "short",
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_change_password_inactive_user_returns_401(client: AsyncClient) -> None:
    """Valid token but user is inactive → 401."""
    token = create_password_change_token(_FORCED_USER_ID)
    inactive = User(
        email="newuser@mxtac.local",
        hashed_password="$2b$12$placeholder_not_used_in_tests",
        role="analyst",
        is_active=False,
        must_change_password=True,
    )
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=inactive)):
        resp = await client.post(
            CHANGE_PASSWORD_URL,
            json={
                "password_change_token": token,
                "new_password": "NewSecure1!",
                "confirm_password": "NewSecure1!",
            },
        )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_change_password_unknown_user_returns_401(client: AsyncClient) -> None:
    """Valid token but user not found in DB → 401."""
    token = create_password_change_token(_FORCED_USER_ID)
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=None)):
        resp = await client.post(
            CHANGE_PASSWORD_URL,
            json={
                "password_change_token": token,
                "new_password": "NewSecure1!",
                "confirm_password": "NewSecure1!",
            },
        )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_change_password_with_mfa_enabled_returns_mfa_token(client: AsyncClient) -> None:
    """When user also has MFA enabled, change-password returns mfa_required + mfa_token."""
    token = create_password_change_token(_FORCED_USER_ID)
    user = _user_must_change_password(mfa_enabled=True)
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY, return_value=False):
            with patch(MOCK_HASH, return_value="$2b$12$newhash"):
                resp = await client.post(
                    CHANGE_PASSWORD_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )
    data = resp.json()
    assert resp.status_code == 200
    assert data.get("mfa_required") is True
    assert "mfa_token" in data


@pytest.mark.asyncio
async def test_change_password_missing_fields_returns_422(client: AsyncClient) -> None:
    """Missing required fields → 422 Unprocessable Entity."""
    token = create_password_change_token(_FORCED_USER_ID)
    resp = await client.post(
        CHANGE_PASSWORD_URL,
        json={"password_change_token": token},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_change_password_get_method_not_allowed(client: AsyncClient) -> None:
    """GET /auth/change-password is not defined → 405 Method Not Allowed."""
    resp = await client.get(CHANGE_PASSWORD_URL)
    assert resp.status_code == 405


# ---------------------------------------------------------------------------
# Feature 2.3 — Password expiry (90 days)
# ---------------------------------------------------------------------------

_EXPIRY_USER_ID = "expiry-user-id-5678"


def _user_with_password_age(days: int | None, mfa_enabled: bool = False) -> User:
    """Return an active user whose password_changed_at is ``days`` days ago.

    Pass ``days=None`` to simulate a user whose clock has not yet started
    (password_changed_at is None — e.g., an account created before this
    feature was deployed).
    """
    u = User(
        email="analyst@mxtac.local",
        hashed_password="$2b$12$placeholder_not_used_in_tests",
        full_name="Test User",
        role="analyst",
        is_active=True,
        must_change_password=False,
    )
    u.id = _EXPIRY_USER_ID
    u.mfa_enabled = mfa_enabled
    u.password_changed_at = (
        datetime.now(timezone.utc) - timedelta(days=days) if days is not None else None
    )
    return u


# --- Login with expired password ---


@pytest.mark.asyncio
async def test_expired_password_login_returns_200(client: AsyncClient) -> None:
    """Password older than 90 days → 200 OK (forced change, not an error)."""
    user = _user_with_password_age(days=91)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_expired_password_response_flag(client: AsyncClient) -> None:
    """Expired password login response includes password_change_required=True."""
    user = _user_with_password_age(days=91)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert resp.json().get("password_change_required") is True


@pytest.mark.asyncio
async def test_expired_password_response_has_token(client: AsyncClient) -> None:
    """Expired password login response includes a non-empty password_change_token."""
    user = _user_with_password_age(days=91)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert "password_change_token" in data
    assert isinstance(data["password_change_token"], str)
    assert data["password_change_token"]


@pytest.mark.asyncio
async def test_expired_password_no_access_token(client: AsyncClient) -> None:
    """Expired password response must NOT include access_token or refresh_token."""
    user = _user_with_password_age(days=91)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert "access_token" not in data
    assert "refresh_token" not in data


@pytest.mark.asyncio
async def test_expired_password_token_has_correct_purpose(client: AsyncClient) -> None:
    """The password_change_token JWT carries purpose='password_change'."""
    user = _user_with_password_age(days=91)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    token = resp.json()["password_change_token"]
    payload = _decode(token)
    assert payload.get("purpose") == "password_change"


# --- Recent password: still valid ---


@pytest.mark.asyncio
async def test_password_89_days_old_allows_login(client: AsyncClient) -> None:
    """Password changed 89 days ago (within 90-day window) → normal login."""
    user = _user_with_password_age(days=89)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert "access_token" in data
    assert data.get("password_change_required") is None


# --- password_changed_at is None (clock not started) ---


@pytest.mark.asyncio
async def test_null_password_changed_at_allows_login(client: AsyncClient) -> None:
    """password_changed_at=None (clock not started) → normal login, no forced change."""
    user = _user_with_password_age(days=None)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    data = resp.json()
    assert "access_token" in data
    assert data.get("password_change_required") is None


# --- Disabled (password_expiry_days=0) ---


@pytest.mark.asyncio
async def test_expiry_disabled_skips_check(client: AsyncClient) -> None:
    """When password_expiry_days=0, expiry check is skipped even for old passwords."""
    user = _user_with_password_age(days=365)
    with patch(MOCK_IS_LOCKED, new=AsyncMock(return_value=False)):
        with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
            with patch(MOCK_VERIFY, return_value=True):
                with patch(MOCK_CLEAR, new=AsyncMock()):
                    with patch.object(settings, "password_expiry_days", 0):
                        resp = await client.post(LOGIN_URL, json=VALID_CREDS)
    assert "access_token" in resp.json()


# --- change-password resets the expiry clock ---


@pytest.mark.asyncio
async def test_change_password_updates_password_changed_at(client: AsyncClient) -> None:
    """Calling change-password sets password_changed_at to approximately now."""
    user = _user_with_password_age(days=91)
    token = create_password_change_token(_EXPIRY_USER_ID)
    before = datetime.now(timezone.utc)
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY, return_value=False):
            with patch(MOCK_HASH, return_value="$2b$12$newhash"):
                resp = await client.post(
                    CHANGE_PASSWORD_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )
    assert resp.status_code == 200
    assert user.password_changed_at is not None
    assert user.password_changed_at >= before


@pytest.mark.asyncio
async def test_change_password_for_expired_returns_access_token(client: AsyncClient) -> None:
    """After a successful change-password (expiry case), access + refresh tokens are returned."""
    user = _user_with_password_age(days=91)
    token = create_password_change_token(_EXPIRY_USER_ID)
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY, return_value=False):
            with patch(MOCK_HASH, return_value="$2b$12$newhash"):
                resp = await client.post(
                    CHANGE_PASSWORD_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


# ---------------------------------------------------------------------------
# Feature 32.1 — TOTP MFA setup
# POST /api/v1/auth/mfa/setup
# POST /api/v1/auth/mfa/verify-setup
# ---------------------------------------------------------------------------

import pyotp  # noqa: E402
from app.api.v1.endpoints.auth import _encrypt_secret  # noqa: E402

MFA_SETUP_URL = "/api/v1/auth/mfa/setup"
MFA_VERIFY_SETUP_URL = "/api/v1/auth/mfa/verify-setup"

_MFA_USER_EMAIL = "analyst@mxtac.local"


def _mfa_base_user(
    email: str = _MFA_USER_EMAIL,
    mfa_secret: str | None = None,
    mfa_enabled: bool = False,
) -> User:
    """Return an active User for MFA setup tests."""
    u = User(
        email=email,
        hashed_password="$2b$12$placeholder_not_used_in_tests",
        full_name="Analyst User",
        role="analyst",
        is_active=True,
    )
    u.mfa_secret = mfa_secret
    u.mfa_enabled = mfa_enabled
    return u


def _mfa_user_with_secret(secret: str, email: str = _MFA_USER_EMAIL) -> User:
    """Return an active User with an encrypted TOTP secret already stored."""
    return _mfa_base_user(email=email, mfa_secret=_encrypt_secret(secret))


# --- POST /auth/mfa/setup ---


@pytest.mark.asyncio
async def test_mfa_setup_returns_200(client: AsyncClient, analyst_headers: dict) -> None:
    """Authenticated user gets 200 from the MFA setup endpoint."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mfa_setup_response_has_secret(client: AsyncClient, analyst_headers: dict) -> None:
    """Response contains a non-empty secret field."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    data = resp.json()
    assert "secret" in data
    assert len(data["secret"]) > 0


@pytest.mark.asyncio
async def test_mfa_setup_secret_is_valid_base32(client: AsyncClient, analyst_headers: dict) -> None:
    """The returned secret is a valid pyotp base32 string (generates a 6-digit code)."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    secret = resp.json()["secret"]
    code = pyotp.TOTP(secret).now()
    assert len(code) == 6


@pytest.mark.asyncio
async def test_mfa_setup_response_has_qr_code_uri(client: AsyncClient, analyst_headers: dict) -> None:
    """Response contains a non-empty qr_code_uri field."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    data = resp.json()
    assert "qr_code_uri" in data
    assert len(data["qr_code_uri"]) > 0


@pytest.mark.asyncio
async def test_mfa_setup_qr_code_uri_format(client: AsyncClient, analyst_headers: dict) -> None:
    """QR code URI uses the otpauth://totp/MxTac: scheme."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    uri = resp.json()["qr_code_uri"]
    assert uri.startswith("otpauth://totp/MxTac:")


@pytest.mark.asyncio
async def test_mfa_setup_qr_code_uri_contains_user_email(client: AsyncClient, analyst_headers: dict) -> None:
    """QR code URI contains the user's email address."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    assert _MFA_USER_EMAIL in resp.json()["qr_code_uri"]


@pytest.mark.asyncio
async def test_mfa_setup_qr_code_uri_contains_issuer(client: AsyncClient, analyst_headers: dict) -> None:
    """QR code URI specifies MxTac as the issuer."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    assert "issuer=MxTac" in resp.json()["qr_code_uri"]


@pytest.mark.asyncio
async def test_mfa_setup_returns_eight_backup_codes(client: AsyncClient, analyst_headers: dict) -> None:
    """Response contains exactly 8 backup codes."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    codes = resp.json()["backup_codes"]
    assert len(codes) == 8


@pytest.mark.asyncio
async def test_mfa_setup_backup_codes_are_eight_chars(client: AsyncClient, analyst_headers: dict) -> None:
    """Each backup code is exactly 8 alphanumeric characters."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    for code in resp.json()["backup_codes"]:
        assert len(code) == 8
        assert code.isalnum()


@pytest.mark.asyncio
async def test_mfa_setup_secret_stored_on_user(client: AsyncClient, analyst_headers: dict) -> None:
    """After setup, user.mfa_secret is set to an encrypted value (not the plain secret)."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    plain_secret = resp.json()["secret"]
    assert user.mfa_secret is not None
    assert user.mfa_secret != plain_secret


@pytest.mark.asyncio
async def test_mfa_setup_does_not_enable_mfa(client: AsyncClient, analyst_headers: dict) -> None:
    """Setup stores the secret but does not activate MFA — verify-setup must be called next."""
    user = _mfa_base_user()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        await client.post(MFA_SETUP_URL, headers=analyst_headers)
    assert user.mfa_enabled is False


@pytest.mark.asyncio
async def test_mfa_setup_unauthenticated_returns_401(client: AsyncClient) -> None:
    """Request without an Authorization header returns 401."""
    resp = await client.post(MFA_SETUP_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mfa_setup_user_not_found_returns_404(client: AsyncClient, analyst_headers: dict) -> None:
    """When the resolved user is not found in the DB, returns 404."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        resp = await client.post(MFA_SETUP_URL, headers=analyst_headers)
    assert resp.status_code == 404


# --- POST /auth/mfa/verify-setup ---


@pytest.mark.asyncio
async def test_mfa_verify_setup_valid_code_returns_200(client: AsyncClient, analyst_headers: dict) -> None:
    """Correct TOTP code activates MFA and returns 200."""
    secret = pyotp.random_base32()
    user = _mfa_user_with_secret(secret)
    code = pyotp.TOTP(secret).now()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_VERIFY_SETUP_URL, headers=analyst_headers, json={"code": code})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_mfa_verify_setup_response_message(client: AsyncClient, analyst_headers: dict) -> None:
    """Response body contains message='MFA enabled'."""
    secret = pyotp.random_base32()
    user = _mfa_user_with_secret(secret)
    code = pyotp.TOTP(secret).now()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_VERIFY_SETUP_URL, headers=analyst_headers, json={"code": code})
    assert resp.json()["message"] == "MFA enabled"


@pytest.mark.asyncio
async def test_mfa_verify_setup_enables_mfa_flag(client: AsyncClient, analyst_headers: dict) -> None:
    """After successful verify-setup, user.mfa_enabled is set to True."""
    secret = pyotp.random_base32()
    user = _mfa_user_with_secret(secret)
    code = pyotp.TOTP(secret).now()
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        await client.post(MFA_VERIFY_SETUP_URL, headers=analyst_headers, json={"code": code})
    assert user.mfa_enabled is True


@pytest.mark.asyncio
async def test_mfa_verify_setup_invalid_code_returns_400(client: AsyncClient, analyst_headers: dict) -> None:
    """Wrong TOTP code returns 400 Bad Request."""
    secret = pyotp.random_base32()
    user = _mfa_user_with_secret(secret)
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_VERIFY_SETUP_URL, headers=analyst_headers, json={"code": "000000"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_mfa_verify_setup_no_secret_returns_400(client: AsyncClient, analyst_headers: dict) -> None:
    """If MFA setup was never initiated (no mfa_secret stored), returns 400."""
    user = _mfa_base_user(mfa_secret=None)
    with patch(MOCK_REPO, new=AsyncMock(return_value=user)):
        resp = await client.post(MFA_VERIFY_SETUP_URL, headers=analyst_headers, json={"code": "123456"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_mfa_verify_setup_unauthenticated_returns_401(client: AsyncClient) -> None:
    """Request without an Authorization header returns 401."""
    resp = await client.post(MFA_VERIFY_SETUP_URL, json={"code": "123456"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mfa_verify_setup_user_not_found_returns_400(client: AsyncClient, analyst_headers: dict) -> None:
    """When the user cannot be resolved, returns 400 (MFA setup not initiated path)."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        resp = await client.post(MFA_VERIFY_SETUP_URL, headers=analyst_headers, json={"code": "123456"})
    assert resp.status_code == 400
