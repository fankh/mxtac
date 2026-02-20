"""Tests for POST /api/v1/auth/login — Feature 1.1
Tests for expired token → 401 — Feature 28.4
Tests for token refresh — Feature 28.5
Tests for refresh token rotation — Feature 1.2

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

from datetime import datetime, timedelta
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
