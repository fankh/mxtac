"""The auth dependency reads role and active status from the database on every
request, and only accepts access tokens."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    create_mfa_token,
    create_password_change_token,
    create_refresh_token,
)
from app.repositories.user_repo import UserRepo

DETECTIONS_URL = "/api/v1/detections"   # needs detections:read (every role)
RULES_URL = "/api/v1/rules"             # needs rules:read (hunter and above)
USERS_URL = "/api/v1/users"             # needs users:read (admin)

EMAIL = "casey@mxtac.local"


@pytest.fixture(autouse=True)
def _token_only_principals():
    """Override the conftest shim: these tests use production behaviour, where a
    token is only valid for a user that exists and is active."""
    yield


@pytest.fixture(autouse=True)
def _no_valkey():
    """No Valkey in unit tests: skip the revocation lookup (it would time out)."""
    with patch("app.core.security.is_token_blacklisted", new=AsyncMock(return_value=False)):
        yield


async def _create_user(db: AsyncSession, role: str = "hunter", **kwargs):
    user = await UserRepo.create(
        db, email=EMAIL, hashed_password="not-used", role=role, **kwargs
    )
    await db.commit()
    return user


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _access(role: str = "hunter") -> dict[str, str]:
    return _bearer(create_access_token({"sub": EMAIL, "role": role}))


# ── Active status ────────────────────────────────────────────────────────────


async def test_active_user_is_accepted(client: AsyncClient, db_session: AsyncSession) -> None:
    await _create_user(db_session)
    assert (await client.get(DETECTIONS_URL, headers=_access())).status_code == 200


async def test_deactivated_user_loses_access_immediately(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _create_user(db_session)
    headers = _access()                      # token issued while the user was active
    assert (await client.get(DETECTIONS_URL, headers=headers)).status_code == 200

    user.is_active = False
    await db_session.commit()

    resp = await client.get(DETECTIONS_URL, headers=headers)
    assert resp.status_code == 401
    assert "disabled" in resp.json()["detail"]


async def test_reactivated_user_regains_access(client: AsyncClient, db_session: AsyncSession) -> None:
    user = await _create_user(db_session, is_active=False)
    headers = _access()
    assert (await client.get(DETECTIONS_URL, headers=headers)).status_code == 401

    user.is_active = True
    await db_session.commit()
    assert (await client.get(DETECTIONS_URL, headers=headers)).status_code == 200


async def test_token_of_unknown_user_is_rejected(client: AsyncClient) -> None:
    assert (await client.get(DETECTIONS_URL, headers=_access())).status_code == 401


# ── Role ─────────────────────────────────────────────────────────────────────


async def test_role_comes_from_database_not_from_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A token that claims admin does not grant admin to a viewer."""
    await _create_user(db_session, role="viewer")
    headers = _access(role="admin")

    assert (await client.get(DETECTIONS_URL, headers=headers)).status_code == 200
    assert (await client.get(USERS_URL, headers=headers)).status_code == 403
    assert (await client.get(RULES_URL, headers=headers)).status_code == 403


async def test_demotion_takes_effect_on_the_next_request(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _create_user(db_session, role="hunter")
    headers = _access(role="hunter")
    assert (await client.get(RULES_URL, headers=headers)).status_code == 200

    user.role = "viewer"
    await db_session.commit()
    assert (await client.get(RULES_URL, headers=headers)).status_code == 403


async def test_promotion_takes_effect_on_the_next_request(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await _create_user(db_session, role="viewer")
    headers = _access(role="viewer")
    assert (await client.get(RULES_URL, headers=headers)).status_code == 403

    user.role = "engineer"
    await db_session.commit()
    assert (await client.get(RULES_URL, headers=headers)).status_code == 200


# ── Only access tokens ───────────────────────────────────────────────────────


async def test_non_access_tokens_are_rejected(client: AsyncClient, db_session: AsyncSession) -> None:
    user = await _create_user(db_session, role="admin")
    tokens = {
        "refresh": create_refresh_token({"sub": EMAIL}),
        "mfa": create_mfa_token(user.id),
        "password_change": create_password_change_token(user.id),
    }

    for kind, token in tokens.items():
        resp = await client.get(DETECTIONS_URL, headers=_bearer(token))
        assert resp.status_code == 401, kind

    assert (await client.get(DETECTIONS_URL, headers=_access())).status_code == 200
