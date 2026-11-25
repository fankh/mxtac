"""Session lifecycle: refresh cookie, rotation, reuse detection, logout and
password change.

Coverage:
  - the refresh token is an HttpOnly, Secure, SameSite=Strict cookie scoped to
    POST /auth/refresh and is never part of a response body
  - REFRESH_COOKIE_SECURE=false drops only the Secure attribute
  - POST /auth/refresh rotates: new access token, new refresh cookie, same session
  - a refresh token works once; presenting it again is refused and ends the
    session, including the token that replaced it
  - every refusal deletes the cookie
  - logout ends the session: the access token and the refresh token stop working
    and the cookie is deleted; other sessions of the account continue
  - a password change ends every other session of the account (access and
    refresh tokens) and answers with a new session for the caller
  - tokens issued before the token version existed keep working until the first
    password change
  - without Valkey the single-use check is skipped (fail-open, as documented)
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient, Response
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    REFRESH_COOKIE_NAME,
    REFRESH_COOKIE_PATH,
    create_access_token,
    create_refresh_token,
    hash_password,
)
from app.core.valkey import consume_token
from app.models.user import User
from tests.auth_cookies import refresh_cookie, refresh_cookie_morsel, refresh_token_of

LOGIN_URL = "/api/v1/auth/login"
REFRESH_URL = "/api/v1/auth/refresh"
LOGOUT_URL = "/api/v1/auth/logout"
PASSWORD_URL = "/api/v1/auth/password"
ME_URL = "/api/v1/auth/me"

EMAIL = "session@mxtac.local"
PASSWORD = "Current-Passw0rd"
NEW_PASSWORD = "Brand-New-Passw0rd"


class FakeValkey:
    """The few Valkey commands the auth code uses, kept in a dict."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> bool | None:
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.store[key] = value

    async def delete(self, key: str) -> None:
        self.store.pop(key, None)

    async def incr(self, key: str) -> int:
        self.store[key] = str(int(self.store.get(key, "0")) + 1)
        return int(self.store[key])

    async def expire(self, key: str, ttl: int) -> None:
        return None


@pytest.fixture(autouse=True)
def _token_only_principals():
    """Production behaviour: a token is only valid for a user that exists."""
    yield


@pytest.fixture
def valkey() -> Iterator[FakeValkey]:
    fake = FakeValkey()
    with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=fake)):
        yield fake


@pytest.fixture
async def user(db_session: AsyncSession) -> User:
    row = User(
        email=EMAIL,
        hashed_password=hash_password(PASSWORD),
        role="analyst",
        is_active=True,
    )
    db_session.add(row)
    await db_session.commit()
    return row


def _claims(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(client: AsyncClient, password: str = PASSWORD) -> Response:
    resp = await client.post(LOGIN_URL, json={"email": EMAIL, "password": password})
    assert resp.status_code == 200, resp.text
    return resp


async def _refresh(client: AsyncClient, token: str) -> Response:
    return await client.post(REFRESH_URL, headers=refresh_cookie(token))


def _deletes_cookie(resp: Response) -> bool:
    morsel = refresh_cookie_morsel(resp)
    return morsel is not None and morsel.value == "" and morsel["max-age"] == "0"


# ---------------------------------------------------------------------------
# Where the refresh token lives
# ---------------------------------------------------------------------------


class TestRefreshCookie:
    async def test_login_sets_an_httponly_secure_strict_cookie_on_the_refresh_path(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        morsel = refresh_cookie_morsel(await _login(client))

        assert morsel is not None
        assert morsel.key == REFRESH_COOKIE_NAME
        assert morsel["httponly"] is True
        assert morsel["secure"] is True
        assert morsel["samesite"].lower() == "strict"
        assert morsel["path"] == REFRESH_COOKIE_PATH == "/api/v1/auth/refresh"
        assert int(morsel["max-age"]) == settings.refresh_token_expire_days * 86400

    async def test_refresh_token_is_not_in_the_body(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        resp = await _login(client)

        assert "refresh_token" not in resp.json()
        assert refresh_token_of(resp) not in resp.text

    async def test_secure_attribute_can_be_switched_off(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        with patch.object(settings, "refresh_cookie_secure", False):
            morsel = refresh_cookie_morsel(await _login(client))

        assert morsel is not None
        assert morsel["secure"] == ""
        assert morsel["httponly"] is True
        assert morsel["samesite"].lower() == "strict"

    async def test_access_and_refresh_token_share_a_session_id(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        resp = await _login(client)
        access = _claims(resp.json()["access_token"])
        refresh = _claims(refresh_token_of(resp))

        assert access["sid"] == refresh["sid"]
        assert access["tv"] == refresh["tv"] == 0
        assert "type" not in access and refresh["type"] == "refresh"

    async def test_each_login_starts_its_own_session(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        first = _claims(refresh_token_of(await _login(client)))
        second = _claims(refresh_token_of(await _login(client)))

        assert first["sid"] != second["sid"]


# ---------------------------------------------------------------------------
# Rotation and reuse
# ---------------------------------------------------------------------------


class TestRotation:
    async def test_refresh_returns_a_new_access_token_and_a_new_cookie(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        login = await _login(client)
        old_refresh = refresh_token_of(login)

        resp = await _refresh(client, old_refresh)

        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"] != login.json()["access_token"]
        assert body["email"] == EMAIL and body["role"] == "analyst"
        assert "refresh_token" not in body
        new_refresh = refresh_token_of(resp)
        assert new_refresh and new_refresh != old_refresh
        assert _claims(new_refresh)["sid"] == _claims(old_refresh)["sid"]
        assert _claims(body["access_token"])["sid"] == _claims(old_refresh)["sid"]

    async def test_new_access_token_is_accepted(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        resp = await _refresh(client, refresh_token_of(await _login(client)))

        me = await client.get(ME_URL, headers=_bearer(resp.json()["access_token"]))
        assert me.status_code == 200

    async def test_rotated_token_chain_keeps_working(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        token = refresh_token_of(await _login(client))
        for _ in range(3):
            resp = await _refresh(client, token)
            assert resp.status_code == 200
            token = refresh_token_of(resp)

    async def test_old_refresh_token_is_refused_after_rotation(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        old_refresh = refresh_token_of(await _login(client))
        assert (await _refresh(client, old_refresh)).status_code == 200

        again = await _refresh(client, old_refresh)

        assert again.status_code == 401
        assert again.json()["detail"] == "Session has ended. Sign in again."
        assert _deletes_cookie(again)

    async def test_reuse_ends_the_session_including_the_newest_token(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        old_refresh = refresh_token_of(await _login(client))
        newest = refresh_token_of(await _refresh(client, old_refresh))
        assert (await _refresh(client, old_refresh)).status_code == 401   # reuse

        resp = await _refresh(client, newest)

        assert resp.status_code == 401
        assert _deletes_cookie(resp)

    async def test_reuse_in_one_session_leaves_other_sessions_alone(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        other_session = refresh_token_of(await _login(client))
        stolen = refresh_token_of(await _login(client))
        await _refresh(client, stolen)
        assert (await _refresh(client, stolen)).status_code == 401

        assert (await _refresh(client, other_session)).status_code == 200

    async def test_used_token_is_listed_until_it_would_have_expired(
        self, client: AsyncClient, user: User
    ) -> None:
        fake = AsyncMock()
        fake.get.return_value = None
        fake.set.return_value = True
        token = refresh_token_of(await _login(client))
        with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=fake)):
            await _refresh(client, token)

        key, value = fake.set.await_args.args
        assert key == f"blacklist:{_claims(token)['jti']}"
        assert fake.set.await_args.kwargs["nx"] is True
        lifetime = settings.refresh_token_expire_days * 86400
        assert lifetime - 60 <= fake.set.await_args.kwargs["ex"] <= lifetime

    async def test_without_valkey_rotation_is_not_enforced(
        self, client: AsyncClient, user: User
    ) -> None:
        """Fail-open like every other Valkey-backed check: the request is allowed."""
        with patch(
            "app.core.valkey.get_valkey_client", new=AsyncMock(side_effect=ConnectionError("down"))
        ):
            token = refresh_token_of(await _login(client))
            assert (await _refresh(client, token)).status_code == 200
            assert (await _refresh(client, token)).status_code == 200


class TestRefreshRefusals:
    async def test_no_cookie(self, client: AsyncClient, valkey: FakeValkey) -> None:
        resp = await client.post(REFRESH_URL)

        assert resp.status_code == 401
        assert _deletes_cookie(resp)

    async def test_garbage_cookie(self, client: AsyncClient, valkey: FakeValkey) -> None:
        resp = await _refresh(client, "not.a.jwt")

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid refresh token"
        assert _deletes_cookie(resp)

    async def test_access_token_in_the_cookie(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        access = (await _login(client)).json()["access_token"]

        resp = await _refresh(client, access)

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid refresh token"

    async def test_refresh_token_is_not_an_access_token(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        refresh = refresh_token_of(await _login(client))

        assert (await client.get(ME_URL, headers=_bearer(refresh))).status_code == 401

    async def test_deactivated_user(
        self, client: AsyncClient, user: User, db_session: AsyncSession, valkey: FakeValkey
    ) -> None:
        token = refresh_token_of(await _login(client))
        user.is_active = False
        await db_session.commit()

        resp = await _refresh(client, token)

        assert resp.status_code == 401
        assert _deletes_cookie(resp)

    async def test_token_without_session_id_from_an_older_version_still_refreshes(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        legacy = create_refresh_token({"sub": EMAIL})

        resp = await _refresh(client, legacy)

        assert resp.status_code == 200
        assert _claims(refresh_token_of(resp))["sid"]


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


class TestLogout:
    async def test_logout_ends_access_and_refresh_token_and_deletes_the_cookie(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        login = await _login(client)
        access = login.json()["access_token"]
        refresh = refresh_token_of(login)

        resp = await client.post(LOGOUT_URL, headers=_bearer(access))

        assert resp.status_code == 200
        assert _deletes_cookie(resp)
        assert (await client.get(ME_URL, headers=_bearer(access))).status_code == 401
        refused = await _refresh(client, refresh)
        assert refused.status_code == 401
        assert refused.json()["detail"] == "Session has ended. Sign in again."

    async def test_logout_ends_tokens_obtained_by_an_earlier_refresh(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        refreshed = await _refresh(client, refresh_token_of(await _login(client)))

        await client.post(LOGOUT_URL, headers=_bearer(refreshed.json()["access_token"]))

        assert (await _refresh(client, refresh_token_of(refreshed))).status_code == 401

    async def test_logout_leaves_other_sessions_of_the_account(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        other = await _login(client)
        mine = await _login(client)

        await client.post(LOGOUT_URL, headers=_bearer(mine.json()["access_token"]))

        assert (await client.get(ME_URL, headers=_bearer(other.json()["access_token"]))).status_code == 200
        assert (await _refresh(client, refresh_token_of(other))).status_code == 200


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------


class TestPasswordChange:
    async def _change(self, client: AsyncClient, access: str) -> Response:
        return await client.post(
            PASSWORD_URL,
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            headers=_bearer(access),
        )

    async def test_other_sessions_lose_access_and_refresh(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        other = await _login(client)
        mine = await _login(client)
        assert (await client.get(ME_URL, headers=_bearer(other.json()["access_token"]))).status_code == 200

        assert (await self._change(client, mine.json()["access_token"])).status_code == 200

        ended = await client.get(ME_URL, headers=_bearer(other.json()["access_token"]))
        assert ended.status_code == 401
        assert ended.json()["detail"] == "Session has ended. Sign in again."
        refused = await _refresh(client, refresh_token_of(other))
        assert refused.status_code == 401
        assert _deletes_cookie(refused)

    async def test_caller_gets_a_new_session_and_stays_signed_in(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        mine = await _login(client)

        resp = await self._change(client, mine.json()["access_token"])

        body = resp.json()
        assert body["email"] == EMAIL
        assert "refresh_token" not in body and NEW_PASSWORD not in resp.text
        assert _claims(body["access_token"])["tv"] == 1
        assert (await client.get(ME_URL, headers=_bearer(body["access_token"]))).status_code == 200
        assert (await _refresh(client, refresh_token_of(resp))).status_code == 200

    async def test_callers_old_tokens_stop_working_too(
        self, client: AsyncClient, user: User, valkey: FakeValkey
    ) -> None:
        mine = await _login(client)

        await self._change(client, mine.json()["access_token"])

        assert (await client.get(ME_URL, headers=_bearer(mine.json()["access_token"]))).status_code == 401
        assert (await _refresh(client, refresh_token_of(mine))).status_code == 401

    async def test_password_change_does_not_depend_on_valkey(
        self, client: AsyncClient, user: User
    ) -> None:
        """The token version is checked in the database, so it holds without Valkey."""
        with patch(
            "app.core.valkey.get_valkey_client", new=AsyncMock(side_effect=ConnectionError("down"))
        ):
            other = await _login(client)
            mine = await _login(client)
            await self._change(client, mine.json()["access_token"])

            assert (await client.get(ME_URL, headers=_bearer(other.json()["access_token"]))).status_code == 401
            assert (await _refresh(client, refresh_token_of(other))).status_code == 401

    async def test_token_version_is_stored(
        self, client: AsyncClient, user: User, db_session: AsyncSession, valkey: FakeValkey
    ) -> None:
        assert user.token_version == 0

        await self._change(client, (await _login(client)).json()["access_token"])

        await db_session.refresh(user)
        assert user.token_version == 1

    async def test_tokens_from_before_the_token_version_work_until_a_password_change(
        self, client: AsyncClient, user: User, db_session: AsyncSession, valkey: FakeValkey
    ) -> None:
        legacy = create_access_token({"sub": EMAIL, "role": "analyst"})   # no "tv" claim
        assert (await client.get(ME_URL, headers=_bearer(legacy))).status_code == 200

        user.token_version = 1
        await db_session.commit()

        assert (await client.get(ME_URL, headers=_bearer(legacy))).status_code == 401


# ---------------------------------------------------------------------------
# consume_token
# ---------------------------------------------------------------------------


class TestConsumeToken:
    async def test_first_use_true_second_use_false(self, valkey: FakeValkey) -> None:
        assert await consume_token("jti-1", 60) is True
        assert await consume_token("jti-1", 60) is False
        assert await consume_token("jti-2", 60) is True

    async def test_ttl_is_at_least_one_second(self) -> None:
        fake = AsyncMock()
        fake.set.return_value = True
        with patch("app.core.valkey.get_valkey_client", new=AsyncMock(return_value=fake)):
            await consume_token("jti-1", -5)

        assert fake.set.await_args.kwargs == {"nx": True, "ex": 1}

    async def test_fails_open_without_valkey(self) -> None:
        with patch(
            "app.core.valkey.get_valkey_client", new=AsyncMock(side_effect=ConnectionError("down"))
        ):
            assert await consume_token("jti-1", 60) is True
