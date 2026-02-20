"""Tests for UserRepo — async DB operations for the users table.

Feature 18.8 — Repository layer — UserRepo

Approach:
  - All session interactions are mocked (no live DB needed)
  - AsyncMock used for awaitable session methods (execute, flush, scalar, delete)
  - MagicMock used for synchronous session methods (add)
  - get_by_id is patched internally for methods that call it (update, delete)

Coverage:
  - list(): returns all users ordered by email, session.execute called once
  - list(): empty result returns empty list
  - list(): result is list type
  - list(): returns multiple users
  - get_by_id(): found → returns User; not found → returns None
  - get_by_id(): calls session.execute once
  - get_by_email(): found → returns User; not found → returns None
  - get_by_email(): calls session.execute once
  - create(): User added to session, flushed, returned with correct attributes
  - create(): add receives User object
  - update(): found → sets attributes, flushes, returns User
  - update(): not found → returns None without flush
  - update(): None kwarg values are skipped
  - update(): False value (is_active=False) is not skipped
  - delete(): found → deletes, flushes, returns True
  - delete(): not found → returns False without delete/flush
  - count(): returns scalar result; None result → 0
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.repositories.user_repo import UserRepo


# ---------------------------------------------------------------------------
# Session factory helpers
# ---------------------------------------------------------------------------


def _make_session() -> MagicMock:
    """Sync MagicMock for the session with async methods patched."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.delete = AsyncMock()
    session.scalar = AsyncMock()
    return session


def _scalars_result(items: list) -> MagicMock:
    """Result mock whose .scalars().all() returns items."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    return result


def _scalar_one_result(item) -> MagicMock:
    """Result mock whose .scalar_one_or_none() returns item."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = item
    return result


def _make_user(**kwargs) -> MagicMock:
    """Minimal User-like mock."""
    user = MagicMock()
    user.id = kwargs.get("id", "user-abc")
    user.email = kwargs.get("email", "analyst@example.com")
    user.hashed_password = kwargs.get("hashed_password", "hashed-secret")
    user.full_name = kwargs.get("full_name", "Test Analyst")
    user.role = kwargs.get("role", "analyst")
    user.is_active = kwargs.get("is_active", True)
    return user


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


class TestUserRepoList:
    """UserRepo.list() returns users from session.execute."""

    @pytest.mark.asyncio
    async def test_returns_all_users(self) -> None:
        u1 = _make_user(id="u1", email="alice@example.com")
        u2 = _make_user(id="u2", email="bob@example.com")
        session = _make_session()
        session.execute.return_value = _scalars_result([u1, u2])

        result = await UserRepo.list(session)

        assert result == [u1, u2]

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        await UserRepo.list(session)

        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_users(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        result = await UserRepo.list(session)

        assert result == []

    @pytest.mark.asyncio
    async def test_result_is_list_type(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([_make_user()])

        result = await UserRepo.list(session)

        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_returns_multiple_users(self) -> None:
        users = [_make_user(id=f"u{i}", email=f"user{i}@example.com") for i in range(4)]
        session = _make_session()
        session.execute.return_value = _scalars_result(users)

        result = await UserRepo.list(session)

        assert len(result) == 4


# ---------------------------------------------------------------------------
# get_by_id()
# ---------------------------------------------------------------------------


class TestUserRepoGetById:
    """UserRepo.get_by_id() returns a User or None."""

    @pytest.mark.asyncio
    async def test_returns_user_when_found(self) -> None:
        user = _make_user(id="user-1")
        session = _make_session()
        session.execute.return_value = _scalar_one_result(user)

        result = await UserRepo.get_by_id(session, "user-1")

        assert result is user

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await UserRepo.get_by_id(session, "nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await UserRepo.get_by_id(session, "user-1")

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# get_by_email()
# ---------------------------------------------------------------------------


class TestUserRepoGetByEmail:
    """UserRepo.get_by_email() returns a User or None."""

    @pytest.mark.asyncio
    async def test_returns_user_when_found(self) -> None:
        user = _make_user(email="alice@example.com")
        session = _make_session()
        session.execute.return_value = _scalar_one_result(user)

        result = await UserRepo.get_by_email(session, "alice@example.com")

        assert result is user

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await UserRepo.get_by_email(session, "nobody@example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await UserRepo.get_by_email(session, "alice@example.com")

        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_correct_user_for_email(self) -> None:
        user = _make_user(email="admin@example.com", role="admin")
        session = _make_session()
        session.execute.return_value = _scalar_one_result(user)

        result = await UserRepo.get_by_email(session, "admin@example.com")

        assert result.email == "admin@example.com"
        assert result.role == "admin"


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


class TestUserRepoCreate:
    """UserRepo.create() constructs and persists a User."""

    @pytest.mark.asyncio
    async def test_returns_user_instance(self) -> None:
        session = _make_session()

        result = await UserRepo.create(
            session,
            id="user-new",
            email="new@example.com",
            hashed_password="hashed-pw",
        )

        assert result is not None

    @pytest.mark.asyncio
    async def test_calls_session_add(self) -> None:
        session = _make_session()

        await UserRepo.create(
            session,
            email="new@example.com",
            hashed_password="hashed-pw",
        )

        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_calls_session_flush(self) -> None:
        session = _make_session()

        await UserRepo.create(
            session,
            email="new@example.com",
            hashed_password="hashed-pw",
        )

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_created_user_has_correct_email(self) -> None:
        session = _make_session()

        result = await UserRepo.create(
            session,
            email="analyst@corp.com",
            hashed_password="hashed-pw",
            role="analyst",
        )

        assert result.email == "analyst@corp.com"

    @pytest.mark.asyncio
    async def test_created_user_has_correct_role(self) -> None:
        session = _make_session()

        result = await UserRepo.create(
            session,
            email="admin@corp.com",
            hashed_password="hashed-pw",
            role="admin",
        )

        assert result.role == "admin"

    @pytest.mark.asyncio
    async def test_add_receives_user_object(self) -> None:
        from app.models.user import User
        session = _make_session()

        await UserRepo.create(
            session,
            email="new@example.com",
            hashed_password="hashed-pw",
        )

        added = session.add.call_args[0][0]
        assert isinstance(added, User)


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestUserRepoUpdate:
    """UserRepo.update() modifies an existing User or returns None."""

    @pytest.mark.asyncio
    async def test_returns_updated_user_when_found(self) -> None:
        user = _make_user(id="user-1")
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=user)):
            result = await UserRepo.update(session, "user-1", full_name="Updated Name")

        assert result is user

    @pytest.mark.asyncio
    async def test_sets_attribute_on_user(self) -> None:
        user = MagicMock()
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=user)):
            await UserRepo.update(session, "user-1", full_name="New Name", role="admin")

        assert user.full_name == "New Name"
        assert user.role == "admin"

    @pytest.mark.asyncio
    async def test_skips_none_kwarg_values(self) -> None:
        user = MagicMock()
        user.full_name = "Original Name"
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=user)):
            await UserRepo.update(session, "user-1", full_name=None, role="admin")

        # None values must not overwrite the attribute
        assert user.full_name == "Original Name"
        assert user.role == "admin"

    @pytest.mark.asyncio
    async def test_flushes_session_when_found(self) -> None:
        user = _make_user()
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=user)):
            await UserRepo.update(session, "user-1", role="admin")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await UserRepo.update(session, "nonexistent", role="admin")

        assert result is None

    @pytest.mark.asyncio
    async def test_does_not_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await UserRepo.update(session, "nonexistent", role="admin")

        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_false_value_is_not_skipped(self) -> None:
        """False is not None — is_active=False must be set, not skipped."""
        user = MagicMock()
        user.is_active = True
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=user)):
            await UserRepo.update(session, "user-1", is_active=False)

        assert user.is_active is False


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestUserRepoDelete:
    """UserRepo.delete() removes an existing User or returns False."""

    @pytest.mark.asyncio
    async def test_returns_true_when_found(self) -> None:
        user = _make_user()
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=user)):
            result = await UserRepo.delete(session, "user-1")

        assert result is True

    @pytest.mark.asyncio
    async def test_calls_session_delete_when_found(self) -> None:
        user = _make_user()
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=user)):
            await UserRepo.delete(session, "user-1")

        session.delete.assert_awaited_once_with(user)

    @pytest.mark.asyncio
    async def test_calls_session_flush_when_found(self) -> None:
        user = _make_user()
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=user)):
            await UserRepo.delete(session, "user-1")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await UserRepo.delete(session, "nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_no_session_delete_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await UserRepo.delete(session, "nonexistent")

        session.delete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(UserRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await UserRepo.delete(session, "nonexistent")

        session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# count()
# ---------------------------------------------------------------------------


class TestUserRepoCount:
    """UserRepo.count() returns total user count."""

    @pytest.mark.asyncio
    async def test_returns_count_from_scalar(self) -> None:
        session = _make_session()
        session.scalar.return_value = 5

        result = await UserRepo.count(session)

        assert result == 5

    @pytest.mark.asyncio
    async def test_returns_zero_when_scalar_is_none(self) -> None:
        """None result from scalar (empty table) maps to 0."""
        session = _make_session()
        session.scalar.return_value = None

        result = await UserRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_returns_zero_when_table_is_empty(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0

        result = await UserRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_calls_session_scalar_once(self) -> None:
        session = _make_session()
        session.scalar.return_value = 3

        await UserRepo.count(session)

        session.scalar.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_integer(self) -> None:
        session = _make_session()
        session.scalar.return_value = 4

        result = await UserRepo.count(session)

        assert isinstance(result, int)

    @pytest.mark.parametrize("count_val", [0, 1, 10, 250])
    @pytest.mark.asyncio
    async def test_returns_exact_count(self, count_val: int) -> None:
        session = _make_session()
        session.scalar.return_value = count_val

        result = await UserRepo.count(session)

        assert result == count_val
