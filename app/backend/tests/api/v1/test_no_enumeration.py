"""Tests for Feature 1.12 — Generic login error (no user enumeration).

Security requirement: POST /api/v1/auth/login must return an IDENTICAL
response for:
  - Unknown email address (user not in database)
  - Wrong password for a known email address

An attacker must not be able to distinguish between these two failure
modes from the HTTP response (status code, body, or headers).

Coverage:
  1. Status code equivalence — both failures → 401
  2. Error message identity — both failures → "Invalid credentials"
  3. Response body structure equivalence — same JSON shape for both
  4. No discriminating headers between the two failure modes
  5. Multiple unknown email variants → same 401 + same detail
  6. Multiple wrong password variants → same 401 + same detail
  7. Empty password treated as wrong password → 401 (no DB hit short-circuit)
  8. Inactive user + wrong password → 401 (short-circuit, no 403)
  9. Inactive user + correct password → 403 (account status only revealed post-auth)
  10. Response body contains no hints about which field failed
  11. Success response is structurally different from failure responses
  12. Repeated failures for same unknown email → consistently 401
  13. Repeated failures for same wrong password → consistently 401
  14. Mixed unknown-email / wrong-password alternation → always 401

All tests mock ``UserRepo.get_by_email`` and ``verify_password`` so the
suite runs without a live database or working bcrypt backend.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.models.user import User

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOGIN_URL = "/api/v1/auth/login"

MOCK_REPO = "app.api.v1.endpoints.auth.UserRepo.get_by_email"
MOCK_VERIFY = "app.api.v1.endpoints.auth.verify_password"

KNOWN_EMAIL = "analyst@mxtac.local"
KNOWN_PASSWORD = "mxtac2026"

EXPECTED_STATUS = 401
EXPECTED_DETAIL = "Invalid credentials"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _active_user(email: str = KNOWN_EMAIL, role: str = "analyst") -> User:
    """Active user ORM object; hashed_password is a placeholder (verify_password is mocked)."""
    return User(
        email=email,
        hashed_password="$2b$12$placeholder",
        full_name="Analyst",
        role=role,
        is_active=True,
    )


def _inactive_user(email: str = "inactive@mxtac.local") -> User:
    """Inactive user ORM object."""
    return User(
        email=email,
        hashed_password="$2b$12$placeholder",
        full_name="Inactive User",
        role="analyst",
        is_active=False,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_unknown_email():
    """Simulate unknown email: UserRepo returns None."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        yield


@pytest.fixture
def mock_wrong_password():
    """Simulate wrong password: UserRepo returns a user, verify_password → False."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            yield


# ---------------------------------------------------------------------------
# 1. Status code equivalence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_email_returns_401(client: AsyncClient, mock_unknown_email) -> None:
    """Unknown email → 401 Unauthorized (not 404 or 400)."""
    resp = await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
    assert resp.status_code == EXPECTED_STATUS


@pytest.mark.asyncio
async def test_wrong_password_returns_401(client: AsyncClient, mock_wrong_password) -> None:
    """Correct email, wrong password → 401 Unauthorized."""
    resp = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong-password"})
    assert resp.status_code == EXPECTED_STATUS


@pytest.mark.asyncio
async def test_both_failures_return_same_status(client: AsyncClient) -> None:
    """Unknown email and wrong password produce identical HTTP status codes."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        resp_unknown = await client.post(
            LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD}
        )
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            resp_wrong_pw = await client.post(
                LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong"}
            )
    assert resp_unknown.status_code == resp_wrong_pw.status_code == EXPECTED_STATUS


# ---------------------------------------------------------------------------
# 2. Error message identity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_email_detail_is_generic(client: AsyncClient, mock_unknown_email) -> None:
    """Unknown email → detail is exactly 'Invalid credentials' (no 'user not found' hint)."""
    resp = await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
    assert resp.json()["detail"] == EXPECTED_DETAIL


@pytest.mark.asyncio
async def test_wrong_password_detail_is_generic(client: AsyncClient, mock_wrong_password) -> None:
    """Wrong password → detail is exactly 'Invalid credentials' (no 'bad password' hint)."""
    resp = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong-password"})
    assert resp.json()["detail"] == EXPECTED_DETAIL


@pytest.mark.asyncio
async def test_both_failures_return_identical_detail(client: AsyncClient) -> None:
    """The 'detail' message is byte-for-byte identical regardless of which credential failed."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        detail_unknown = (
            await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
        ).json()["detail"]

    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            detail_wrong_pw = (
                await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong"})
            ).json()["detail"]

    assert detail_unknown == detail_wrong_pw == EXPECTED_DETAIL


# ---------------------------------------------------------------------------
# 3. Response body structure equivalence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_both_failures_have_same_body_keys(client: AsyncClient) -> None:
    """Both failure modes return a JSON body with exactly the same top-level keys."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        body_unknown = (
            await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
        ).json()

    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            body_wrong_pw = (
                await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong"})
            ).json()

    assert set(body_unknown.keys()) == set(body_wrong_pw.keys())


@pytest.mark.asyncio
async def test_both_failures_produce_identical_bodies(client: AsyncClient) -> None:
    """Both failure modes return byte-for-byte identical JSON bodies."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        body_unknown = (
            await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
        ).json()

    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            body_wrong_pw = (
                await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong"})
            ).json()

    assert body_unknown == body_wrong_pw


# ---------------------------------------------------------------------------
# 4. No discriminating headers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_email_content_type_is_json(client: AsyncClient, mock_unknown_email) -> None:
    """Unknown email error response Content-Type is application/json."""
    resp = await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
    assert "application/json" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_wrong_password_content_type_is_json(client: AsyncClient, mock_wrong_password) -> None:
    """Wrong password error response Content-Type is application/json."""
    resp = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong"})
    assert "application/json" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_both_failures_same_content_type(client: AsyncClient) -> None:
    """Both failure modes return the same Content-Type header."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        ct_unknown = (
            await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
        ).headers["content-type"]

    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            ct_wrong_pw = (
                await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong"})
            ).headers["content-type"]

    assert ct_unknown == ct_wrong_pw


@pytest.mark.asyncio
async def test_failure_response_has_no_enumeration_headers(client: AsyncClient, mock_unknown_email) -> None:
    """Error response must not expose user-revealing custom headers (e.g. X-User-Exists)."""
    resp = await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    forbidden_headers = {"x-user-exists", "x-user-found", "x-email-found", "x-hint"}
    assert not forbidden_headers.intersection(headers_lower)


# ---------------------------------------------------------------------------
# 5. Multiple unknown email variants → same 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "email",
    [
        "ghost@example.com",
        "nobody@mxtac.local",
        "hacker@attacker.io",
        "admin@evil.org",
        "test+tag@sub.domain.example.com",
    ],
)
async def test_various_unknown_emails_all_return_401(client: AsyncClient, email: str) -> None:
    """Any unknown email address, regardless of format, returns 401."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        resp = await client.post(LOGIN_URL, json={"email": email, "password": KNOWN_PASSWORD})
    assert resp.status_code == EXPECTED_STATUS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "email",
    [
        "ghost@example.com",
        "nobody@mxtac.local",
        "hacker@attacker.io",
        "admin@evil.org",
        "test+tag@sub.domain.example.com",
    ],
)
async def test_various_unknown_emails_all_return_generic_detail(client: AsyncClient, email: str) -> None:
    """Any unknown email address returns the exact generic detail string."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        resp = await client.post(LOGIN_URL, json={"email": email, "password": KNOWN_PASSWORD})
    assert resp.json()["detail"] == EXPECTED_DETAIL


# ---------------------------------------------------------------------------
# 6. Multiple wrong password variants → same 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "password",
    [
        "wrong",
        "Password1!",
        "' OR '1'='1",           # SQL injection attempt
        "a" * 100,               # Oversized password
        "\x00\x01\x02",         # Null bytes
        "🔑🔓🔒",                # Unicode
        " ",                     # Single space
    ],
)
async def test_various_wrong_passwords_all_return_401(client: AsyncClient, password: str) -> None:
    """Any wrong password string, regardless of content, returns 401."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            resp = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": password})
    assert resp.status_code == EXPECTED_STATUS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "password",
    [
        "wrong",
        "Password1!",
        "' OR '1'='1",
        "a" * 100,
        "🔑🔓🔒",
    ],
)
async def test_various_wrong_passwords_all_return_generic_detail(client: AsyncClient, password: str) -> None:
    """Any wrong password string returns the exact generic detail string."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            resp = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": password})
    assert resp.json()["detail"] == EXPECTED_DETAIL


# ---------------------------------------------------------------------------
# 7. Empty password treated as wrong password → 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_password_known_user_returns_401(client: AsyncClient) -> None:
    """Known email with empty-string password → 401 (verify_password returns False)."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            resp = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": ""})
    assert resp.status_code == EXPECTED_STATUS


@pytest.mark.asyncio
async def test_empty_password_known_user_generic_detail(client: AsyncClient) -> None:
    """Known email with empty-string password → generic detail, no 'empty password' hint."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            resp = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": ""})
    assert resp.json()["detail"] == EXPECTED_DETAIL


@pytest.mark.asyncio
async def test_empty_password_unknown_user_returns_401(client: AsyncClient) -> None:
    """Unknown email with empty-string password → also 401 (user not found short-circuits)."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        resp = await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": ""})
    assert resp.status_code == EXPECTED_STATUS


# ---------------------------------------------------------------------------
# 8. Inactive user + wrong password → 401 (short-circuit, no 403)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inactive_user_wrong_password_returns_401(client: AsyncClient) -> None:
    """Inactive account + wrong password → 401, not 403.

    The credential check (password) runs before the account-status check.
    An attacker cannot learn the account is inactive via the error code.
    """
    with patch(MOCK_REPO, new=AsyncMock(return_value=_inactive_user())):
        with patch(MOCK_VERIFY, return_value=False):
            resp = await client.post(
                LOGIN_URL,
                json={"email": "inactive@mxtac.local", "password": "wrong"},
            )
    assert resp.status_code == EXPECTED_STATUS


@pytest.mark.asyncio
async def test_inactive_user_wrong_password_detail_is_generic(client: AsyncClient) -> None:
    """Inactive account + wrong password → generic 'Invalid credentials' (not 'Account is disabled')."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_inactive_user())):
        with patch(MOCK_VERIFY, return_value=False):
            resp = await client.post(
                LOGIN_URL,
                json={"email": "inactive@mxtac.local", "password": "wrong"},
            )
    assert resp.json()["detail"] == EXPECTED_DETAIL


# ---------------------------------------------------------------------------
# 9. Inactive user + correct password → 403 (account status only revealed post-auth)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inactive_user_correct_password_returns_403(client: AsyncClient) -> None:
    """Inactive account + correct password → 403 Forbidden (credential check passed, account disabled)."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_inactive_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(
                LOGIN_URL,
                json={"email": "inactive@mxtac.local", "password": KNOWN_PASSWORD},
            )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_inactive_user_correct_password_detail(client: AsyncClient) -> None:
    """Inactive account + correct password → 'Account is disabled' (account status visible only after auth)."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_inactive_user())):
        with patch(MOCK_VERIFY, return_value=True):
            resp = await client.post(
                LOGIN_URL,
                json={"email": "inactive@mxtac.local", "password": KNOWN_PASSWORD},
            )
    assert resp.json()["detail"] == "Account is disabled"


# ---------------------------------------------------------------------------
# 10. Response body contains no enumeration hints
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_email_body_has_no_enumeration_words(client: AsyncClient, mock_unknown_email) -> None:
    """Error body for unknown email must not mention 'user', 'email', 'found', 'exist', 'register'."""
    resp = await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
    body_text = resp.text.lower()
    forbidden_phrases = ["user not found", "email not found", "no account", "not registered", "does not exist"]
    for phrase in forbidden_phrases:
        assert phrase not in body_text, f"Enumeration hint '{phrase}' found in response body"


@pytest.mark.asyncio
async def test_wrong_password_body_has_no_password_hints(client: AsyncClient, mock_wrong_password) -> None:
    """Error body for wrong password must not mention 'password', 'incorrect', 'wrong'."""
    resp = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong-password"})
    body_text = resp.text.lower()
    forbidden_phrases = ["wrong password", "incorrect password", "bad password", "password mismatch"]
    for phrase in forbidden_phrases:
        assert phrase not in body_text, f"Password hint '{phrase}' found in response body"


@pytest.mark.asyncio
async def test_failure_body_does_not_echo_submitted_email(client: AsyncClient, mock_unknown_email) -> None:
    """The submitted email address must not appear verbatim in the error response body."""
    test_email = "ghost@example.com"
    resp = await client.post(LOGIN_URL, json={"email": test_email, "password": KNOWN_PASSWORD})
    assert test_email not in resp.text


@pytest.mark.asyncio
async def test_failure_body_does_not_echo_submitted_password(client: AsyncClient, mock_wrong_password) -> None:
    """The submitted password must not appear verbatim in the error response body."""
    test_password = "super-secret-wrong-pass"
    resp = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": test_password})
    assert test_password not in resp.text


# ---------------------------------------------------------------------------
# 11. Success response is structurally different from failure responses
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_success_differs_from_failure_status(client: AsyncClient) -> None:
    """Successful login (200) is distinguishable from credential failures (401) by status code."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            success = await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": KNOWN_PASSWORD})

    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        failure = await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})

    assert success.status_code == 200
    assert failure.status_code == 401
    assert success.status_code != failure.status_code


@pytest.mark.asyncio
async def test_success_body_has_tokens_failure_has_detail(client: AsyncClient) -> None:
    """Success body contains token fields; failure body contains only 'detail'."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=True):
            success_body = (
                await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": KNOWN_PASSWORD})
            ).json()

    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        failure_body = (
            await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
        ).json()

    # Success has tokens
    assert "access_token" in success_body
    assert "refresh_token" in success_body
    # Failure has only 'detail'
    assert "detail" in failure_body
    assert "access_token" not in failure_body
    assert "refresh_token" not in failure_body


# ---------------------------------------------------------------------------
# 12. Repeated failures for same unknown email → consistently 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_repeated_unknown_email_consistently_returns_401(client: AsyncClient) -> None:
    """Five consecutive requests with the same unknown email all return 401."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        for _ in range(5):
            resp = await client.post(
                LOGIN_URL, json={"email": "persistent@example.com", "password": KNOWN_PASSWORD}
            )
            assert resp.status_code == EXPECTED_STATUS
            assert resp.json()["detail"] == EXPECTED_DETAIL


# ---------------------------------------------------------------------------
# 13. Repeated failures for same wrong password → consistently 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_repeated_wrong_password_consistently_returns_401(client: AsyncClient) -> None:
    """Five consecutive requests with wrong password for the same user all return 401."""
    with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
        with patch(MOCK_VERIFY, return_value=False):
            for _ in range(5):
                resp = await client.post(
                    LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "always-wrong"}
                )
                assert resp.status_code == EXPECTED_STATUS
                assert resp.json()["detail"] == EXPECTED_DETAIL


# ---------------------------------------------------------------------------
# 14. Alternating unknown-email / wrong-password → always 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alternating_failure_modes_always_return_401(client: AsyncClient) -> None:
    """Alternating unknown-email and wrong-password requests all yield 401 with same detail."""
    for i in range(4):
        if i % 2 == 0:
            # Unknown email
            with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
                resp = await client.post(
                    LOGIN_URL, json={"email": f"ghost{i}@example.com", "password": KNOWN_PASSWORD}
                )
        else:
            # Wrong password
            with patch(MOCK_REPO, new=AsyncMock(return_value=_active_user())):
                with patch(MOCK_VERIFY, return_value=False):
                    resp = await client.post(
                        LOGIN_URL, json={"email": KNOWN_EMAIL, "password": f"wrong-{i}"}
                    )
        assert resp.status_code == EXPECTED_STATUS, f"Request {i} returned {resp.status_code}"
        assert resp.json()["detail"] == EXPECTED_DETAIL, f"Request {i} detail was '{resp.json()['detail']}'"


# ---------------------------------------------------------------------------
# 15. UserRepo called for unknown email (no early exit on format)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_repo_called_once_for_unknown_email(client: AsyncClient) -> None:
    """UserRepo.get_by_email is called exactly once even when the user does not exist."""
    mock_get = AsyncMock(return_value=None)
    with patch(MOCK_REPO, new=mock_get):
        await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
    mock_get.assert_awaited_once()


@pytest.mark.asyncio
async def test_repo_called_once_for_wrong_password(client: AsyncClient) -> None:
    """UserRepo.get_by_email is called exactly once on wrong-password attempts."""
    mock_get = AsyncMock(return_value=_active_user())
    with patch(MOCK_REPO, new=mock_get):
        with patch(MOCK_VERIFY, return_value=False):
            await client.post(LOGIN_URL, json={"email": KNOWN_EMAIL, "password": "wrong"})
    mock_get.assert_awaited_once()


# ---------------------------------------------------------------------------
# 16. verify_password NOT called when user is not found (security / efficiency)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_password_not_called_for_unknown_user(client: AsyncClient) -> None:
    """verify_password must not be called when the user lookup returns None.

    Calling verify_password with a None hash could leak information about
    the hashing algorithm or cause unexpected exceptions.
    """
    with patch(MOCK_REPO, new=AsyncMock(return_value=None)):
        with patch(MOCK_VERIFY) as mock_verify:
            await client.post(LOGIN_URL, json={"email": "ghost@example.com", "password": KNOWN_PASSWORD})
    mock_verify.assert_not_called()
