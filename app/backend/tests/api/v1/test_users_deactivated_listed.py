"""A deactivated account stays in the user list.

Found while driving the real UI against the real backend: after "Deactivate"
the account vanished from the Users tab, so it could not be reactivated there,
and adding the same email again failed with "Email already registered" for an
account the administrator could no longer see.
"""

from __future__ import annotations

from app.models.user import User
from app.repositories.user_repo import UserRepo

USERS = "/api/v1/users"
NEW_USER = {"email": "victor.viewer@example.org", "full_name": "Victor Viewer", "role": "viewer", "password": "Temp-Victor#2026"}


async def test_deactivated_user_is_listed_and_can_be_reactivated(client, admin_headers, db_session) -> None:
    created = await client.post(USERS, json=NEW_USER, headers=admin_headers)
    assert created.status_code == 201
    user_id = created.json()["id"]

    deactivated = await client.delete(f"{USERS}/{user_id}", headers=admin_headers)
    assert deactivated.status_code in (200, 204)

    listed = await client.get(USERS, headers=admin_headers)
    row = next(u for u in listed.json() if u["id"] == user_id)
    assert row["is_active"] is False

    reactivated = await client.patch(f"{USERS}/{user_id}", json={"is_active": True}, headers=admin_headers)
    assert reactivated.status_code == 200
    assert reactivated.json()["is_active"] is True


async def test_repository_hides_inactive_users_unless_asked(db_session) -> None:
    db_session.add(User(email="a@example.org", hashed_password="x", role="viewer", is_active=True))
    db_session.add(User(email="b@example.org", hashed_password="x", role="viewer", is_active=False))
    await db_session.flush()

    assert [u.email for u in await UserRepo.list(db_session)] == ["a@example.org"]
    assert [u.email for u in await UserRepo.list(db_session, include_inactive=True)] == ["a@example.org", "b@example.org"]
