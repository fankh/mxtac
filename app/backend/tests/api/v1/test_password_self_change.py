"""Tests for POST /api/v1/auth/password — a signed-in user changes their own password.

Coverage:
  - success: 200 with a new session, new password works, old one does not
  - success: history rotated, password_changed_at set, must_change_password cleared
  - wrong current password: 400, password unchanged, lockout counter incremented
  - locked account: 429 before the password is even checked
  - policy violations on the new password: 422
  - history reuse (current and previous password): 400
  - unauthenticated / unknown / inactive user: 401
  - the token-based POST /auth/change-password still works and shares the history rule
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    create_password_change_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from tests.auth_cookies import refresh_token_of

URL = "/api/v1/auth/password"
LOGIN_URL = "/api/v1/auth/login"
CHANGE_PW_URL = "/api/v1/auth/change-password"

EMAIL = "selfchange@mxtac.local"
CURRENT_PASSWORD = "Current-Passw0rd"
PREVIOUS_PASSWORD = "Previous-Passw0rd"
NEW_PASSWORD = "Brand-New-Passw0rd"

MOCK_LOCKED = "app.api.v1.endpoints.auth.is_account_locked"
MOCK_INCREMENT = "app.api.v1.endpoints.auth.increment_login_attempts"
MOCK_CLEAR = "app.api.v1.endpoints.auth.clear_login_attempts"


def _headers(email: str = EMAIL, role: str = "analyst") -> dict[str, str]:
    token = create_access_token({"sub": email, "role": role}, expires_delta=timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def user(db_session: AsyncSession) -> User:
    """An active analyst with a current password and one previous password."""
    row = User(
        email=EMAIL,
        hashed_password=hash_password(CURRENT_PASSWORD),
        full_name="Self Change",
        role="analyst",
        is_active=True,
        password_history=[hash_password(PREVIOUS_PASSWORD)],
    )
    db_session.add(row)
    await db_session.flush()
    return row


@pytest.fixture
def lockout():
    """Replace the Valkey-backed lockout helpers with mocks (not locked)."""
    with (
        patch(MOCK_LOCKED, new=AsyncMock(return_value=False)) as locked,
        patch(MOCK_INCREMENT, new=AsyncMock(return_value=1)) as increment,
        patch(MOCK_CLEAR, new=AsyncMock()) as clear,
    ):
        yield {"locked": locked, "increment": increment, "clear": clear}


def _body(current: str = CURRENT_PASSWORD, new: str = NEW_PASSWORD) -> dict[str, str]:
    return {"current_password": current, "new_password": new}


# ---------------------------------------------------------------------------
# Success
# ---------------------------------------------------------------------------


class TestSuccess:
    async def test_returns_200_with_a_new_session(self, client: AsyncClient, user: User, lockout) -> None:
        """The change ends every session of the account; the caller gets a new one."""
        resp = await client.post(URL, json=_body(), headers=_headers())

        assert resp.status_code == 200
        assert set(resp.json()) == {"access_token", "token_type", "expires_in", "email", "role"}
        assert resp.json()["email"] == EMAIL
        assert refresh_token_of(resp)

    async def test_password_is_replaced(self, client: AsyncClient, user: User, lockout) -> None:
        await client.post(URL, json=_body(), headers=_headers())

        assert verify_password(NEW_PASSWORD, user.hashed_password)
        assert not verify_password(CURRENT_PASSWORD, user.hashed_password)

    async def test_login_works_with_new_password_only(self, client: AsyncClient, user: User, lockout) -> None:
        await client.post(URL, json=_body(), headers=_headers())

        new_login = await client.post(LOGIN_URL, json={"email": EMAIL, "password": NEW_PASSWORD})
        old_login = await client.post(LOGIN_URL, json={"email": EMAIL, "password": CURRENT_PASSWORD})

        assert new_login.status_code == 200
        assert "access_token" in new_login.json()
        assert old_login.status_code == 401

    async def test_history_and_timestamps_updated(self, client: AsyncClient, user: User, lockout) -> None:
        old_hash = user.hashed_password
        user.must_change_password = True

        resp = await client.post(URL, json=_body(), headers=_headers())

        assert resp.status_code == 200
        assert user.password_history == [old_hash]
        assert user.password_changed_at is not None
        assert user.must_change_password is False

    async def test_clears_the_failed_attempt_counter(self, client: AsyncClient, user: User, lockout) -> None:
        await client.post(URL, json=_body(), headers=_headers())

        lockout["clear"].assert_awaited_once_with(EMAIL)
        lockout["increment"].assert_not_awaited()

    async def test_no_password_or_refresh_token_in_response(self, client: AsyncClient, user: User, lockout) -> None:
        resp = await client.post(URL, json=_body(), headers=_headers())

        assert NEW_PASSWORD not in resp.text
        assert "refresh_token" not in resp.text
        assert "hashed_password" not in resp.text


# ---------------------------------------------------------------------------
# Wrong current password / lockout
# ---------------------------------------------------------------------------


class TestWrongCurrentPassword:
    async def test_returns_400(self, client: AsyncClient, user: User, lockout) -> None:
        resp = await client.post(URL, json=_body(current="Not-The-Passw0rd"), headers=_headers())

        assert resp.status_code == 400
        assert resp.json()["detail"] == "Current password is incorrect"

    async def test_password_is_not_changed(self, client: AsyncClient, user: User, lockout) -> None:
        old_hash = user.hashed_password
        old_history = list(user.password_history)

        await client.post(URL, json=_body(current="Not-The-Passw0rd"), headers=_headers())

        assert user.hashed_password == old_hash
        assert user.password_history == old_history
        assert user.password_changed_at is None

    async def test_counts_towards_the_login_lockout(self, client: AsyncClient, user: User, lockout) -> None:
        await client.post(URL, json=_body(current="Not-The-Passw0rd"), headers=_headers())

        lockout["increment"].assert_awaited_once_with(EMAIL)
        lockout["clear"].assert_not_awaited()

    async def test_locked_account_returns_429_even_with_correct_password(
        self, client: AsyncClient, user: User, lockout
    ) -> None:
        lockout["locked"].return_value = True
        old_hash = user.hashed_password

        resp = await client.post(URL, json=_body(), headers=_headers())

        assert resp.status_code == 429
        assert "locked" in resp.json()["detail"].lower()
        assert user.hashed_password == old_hash

    async def test_empty_current_password_returns_422(self, client: AsyncClient, user: User, lockout) -> None:
        resp = await client.post(URL, json=_body(current=""), headers=_headers())

        assert resp.status_code == 422

    async def test_missing_current_password_returns_422(self, client: AsyncClient, user: User, lockout) -> None:
        resp = await client.post(URL, json={"new_password": NEW_PASSWORD}, headers=_headers())

        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Policy and history
# ---------------------------------------------------------------------------


class TestPolicy:
    @pytest.mark.parametrize(
        "weak",
        [
            "Ab1!",              # shorter than 8
            "alllowercase",      # one character type
            "lowercase123",      # two character types
            "Abcd1111efgh",      # four identical characters in a row
            "Aa1!" + "x" * 125,  # longer than 128
        ],
    )
    async def test_policy_violation_returns_422(
        self, client: AsyncClient, user: User, lockout, weak: str
    ) -> None:
        old_hash = user.hashed_password

        resp = await client.post(URL, json=_body(new=weak), headers=_headers())

        assert resp.status_code == 422
        assert user.hashed_password == old_hash

    async def test_policy_message_is_returned(self, client: AsyncClient, user: User, lockout) -> None:
        resp = await client.post(URL, json=_body(new="lowercase123"), headers=_headers())

        assert "at least 3 of the following character types" in str(resp.json())


class TestHistory:
    async def test_reusing_current_password_returns_400(self, client: AsyncClient, user: User, lockout) -> None:
        resp = await client.post(URL, json=_body(new=CURRENT_PASSWORD), headers=_headers())

        assert resp.status_code == 400
        assert resp.json()["detail"] == "Cannot reuse one of your last 2 passwords"

    async def test_reusing_previous_password_returns_400(self, client: AsyncClient, user: User, lockout) -> None:
        old_hash = user.hashed_password

        resp = await client.post(URL, json=_body(new=PREVIOUS_PASSWORD), headers=_headers())

        assert resp.status_code == 400
        assert resp.json()["detail"] == "Cannot reuse one of your last 2 passwords"
        assert user.hashed_password == old_hash

    async def test_password_before_the_previous_one_is_allowed_again(
        self, client: AsyncClient, user: User, lockout
    ) -> None:
        first = await client.post(URL, json=_body(), headers=_headers())
        # PREVIOUS_PASSWORD has now scrolled out of the 2-password window.  The
        # first change ended the old session, so the second uses the new one.
        second = await client.post(
            URL,
            json=_body(current=NEW_PASSWORD, new=PREVIOUS_PASSWORD),
            headers={"Authorization": f"Bearer {first.json()['access_token']}"},
        )

        assert first.status_code == 200
        assert second.status_code == 200

    async def test_token_flow_shares_the_history_rule(self, client: AsyncClient, user: User, lockout) -> None:
        """POST /auth/change-password rejects a password set through POST /auth/password."""
        await client.post(URL, json=_body(), headers=_headers())

        resp = await client.post(
            CHANGE_PW_URL,
            json={
                "password_change_token": create_password_change_token(str(user.id)),
                "new_password": CURRENT_PASSWORD,
                "confirm_password": CURRENT_PASSWORD,
            },
        )

        assert resp.status_code == 400
        assert resp.json()["detail"] == "Cannot reuse one of your last 2 passwords"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestAuthentication:
    async def test_unauthenticated_returns_401(self, client: AsyncClient, user: User) -> None:
        resp = await client.post(URL, json=_body())

        assert resp.status_code == 401

    async def test_invalid_token_returns_401(self, client: AsyncClient, user: User) -> None:
        resp = await client.post(URL, json=_body(), headers={"Authorization": "Bearer not-a-jwt"})

        assert resp.status_code == 401

    async def test_password_change_token_is_not_a_session(self, client: AsyncClient, user: User, lockout) -> None:
        """The one-time token of the forced flow carries the user id, not a session."""
        token = create_password_change_token(str(user.id))

        resp = await client.post(URL, json=_body(), headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 401
        assert verify_password(CURRENT_PASSWORD, user.hashed_password)

    async def test_unknown_user_returns_401(self, client: AsyncClient, lockout) -> None:
        resp = await client.post(URL, json=_body(), headers=_headers("ghost@mxtac.local"))

        assert resp.status_code == 401

    async def test_inactive_user_returns_401(self, client: AsyncClient, user: User, lockout) -> None:
        user.is_active = False

        resp = await client.post(URL, json=_body(), headers=_headers())

        assert resp.status_code == 401
        assert verify_password(CURRENT_PASSWORD, user.hashed_password)

    async def test_user_can_only_change_their_own_password(
        self, client: AsyncClient, user: User, db_session: AsyncSession, lockout
    ) -> None:
        """The account comes from the session; the body cannot name another one."""
        other = User(
            email="other@mxtac.local",
            hashed_password=hash_password("Other-Passw0rd"),
            role="admin",
            is_active=True,
        )
        db_session.add(other)
        await db_session.flush()
        other_hash = other.hashed_password

        resp = await client.post(
            URL,
            json={**_body(), "email": "other@mxtac.local", "user_id": other.id},
            headers=_headers(),
        )

        assert resp.status_code == 200
        assert other.hashed_password == other_hash
        assert verify_password(NEW_PASSWORD, user.hashed_password)
