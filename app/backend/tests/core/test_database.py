"""Tests for app/core/database.py — Feature 18.1 PostgreSQL async engine (asyncpg)

Coverage:
  - Engine configuration: pool_pre_ping, pool_size, max_overflow, echo, database URL
  - AsyncSessionLocal configuration: class_, expire_on_commit, autoflush, autocommit, bind
  - get_db() normal flow: yields session, commits on success, no rollback, one yield
  - get_db() error flow: rolls back on exception, no commit, re-raises original exception
  - get_db() lifecycle: session context manager is exited, independent sessions per call
  - get_db() generator semantics: isasyncgenfunction, exhaustion after iteration

All tests mock AsyncSessionLocal to avoid a live database connection.
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import app.core.database as db_module
from app.core.database import AsyncSessionLocal, engine, get_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cm(mock_session: AsyncMock) -> MagicMock:
    """Return an async context manager mock that yields *mock_session*."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_session)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_factory(mock_session: AsyncMock) -> MagicMock:
    """Return a callable mock that acts as AsyncSessionLocal(session as cm)."""
    factory = MagicMock(return_value=_make_cm(mock_session))
    return factory


# ---------------------------------------------------------------------------
# Engine configuration
# ---------------------------------------------------------------------------


class TestEngineConfiguration:
    """Module-level engine is created with correct async pool settings."""

    def test_engine_is_async_engine(self) -> None:
        assert isinstance(engine, AsyncEngine)

    def test_pool_pre_ping_enabled(self) -> None:
        # QueuePool stores the flag as _pre_ping
        assert engine.pool._pre_ping is True

    def test_pool_size_is_ten(self) -> None:
        assert engine.pool.size() == 10

    def test_max_overflow_is_twenty(self) -> None:
        assert engine.pool._max_overflow == 20

    def test_database_url_matches_settings(self) -> None:
        from app.core.config import settings

        # render_as_string(hide_password=False) returns the full URL including
        # the password, which SQLAlchemy otherwise masks with *** in __str__.
        assert engine.url.render_as_string(hide_password=False) == settings.database_url

    def test_echo_matches_debug_setting(self) -> None:
        from app.core.config import settings

        assert engine.echo == settings.debug


# ---------------------------------------------------------------------------
# AsyncSessionLocal configuration
# ---------------------------------------------------------------------------


class TestAsyncSessionLocalConfiguration:
    """Session factory carries the correct keyword arguments."""

    def test_is_async_sessionmaker_instance(self) -> None:
        assert isinstance(AsyncSessionLocal, async_sessionmaker)

    def test_session_class_is_async_session(self) -> None:
        assert AsyncSessionLocal.class_ is AsyncSession

    def test_expire_on_commit_is_false(self) -> None:
        # expire_on_commit=False keeps ORM objects usable after commit
        assert AsyncSessionLocal.kw["expire_on_commit"] is False

    def test_autoflush_is_false(self) -> None:
        # autoflush=False gives callers explicit flush control
        assert AsyncSessionLocal.kw["autoflush"] is False

    def test_autocommit_is_false(self) -> None:
        # autocommit=False is the default; transactions are explicit
        assert AsyncSessionLocal.kw.get("autocommit", False) is False

    def test_bound_to_module_engine(self) -> None:
        assert AsyncSessionLocal.kw.get("bind") is engine


# ---------------------------------------------------------------------------
# get_db() — normal operation
# ---------------------------------------------------------------------------


class TestGetDbNormalOperation:
    """get_db() yields the session and commits when no exception is raised."""

    async def test_yields_the_session(self) -> None:
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            gen = get_db()
            yielded = await gen.__anext__()
            await gen.aclose()

        assert yielded is mock_session

    async def test_commits_on_clean_exit(self) -> None:
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            async for _ in get_db():
                pass

        mock_session.commit.assert_awaited_once()

    async def test_no_rollback_on_clean_exit(self) -> None:
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            async for _ in get_db():
                pass

        mock_session.rollback.assert_not_awaited()

    async def test_yields_exactly_one_item(self) -> None:
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)
        items: list = []

        with patch.object(db_module, "AsyncSessionLocal", factory):
            async for s in get_db():
                items.append(s)

        assert len(items) == 1

    async def test_session_context_manager_is_exited(self) -> None:
        """__aexit__ is called on the session cm after normal completion."""
        mock_session = AsyncMock(spec=AsyncSession)
        cm = _make_cm(mock_session)
        factory = MagicMock(return_value=cm)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            async for _ in get_db():
                pass

        cm.__aexit__.assert_awaited_once()

    async def test_generator_raises_stop_after_iteration(self) -> None:
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            gen = get_db()
            await gen.__anext__()
            with pytest.raises(StopAsyncIteration):
                await gen.__anext__()


# ---------------------------------------------------------------------------
# get_db() — exception handling
# ---------------------------------------------------------------------------


class TestGetDbExceptionHandling:
    """get_db() rolls back and re-raises any exception thrown into it."""

    async def test_rolls_back_on_exception(self) -> None:
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            gen = get_db()
            await gen.__anext__()
            with pytest.raises(ValueError):
                await gen.athrow(ValueError("simulated failure"))

        mock_session.rollback.assert_awaited_once()

    async def test_does_not_commit_on_exception(self) -> None:
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            gen = get_db()
            await gen.__anext__()
            with pytest.raises(RuntimeError):
                await gen.athrow(RuntimeError("db failure"))

        mock_session.commit.assert_not_awaited()

    async def test_reraises_original_exception_identity(self) -> None:
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)
        original = ValueError("must propagate unchanged")

        with patch.object(db_module, "AsyncSessionLocal", factory):
            gen = get_db()
            await gen.__anext__()
            with pytest.raises(ValueError) as exc_info:
                await gen.athrow(original)

        assert exc_info.value is original

    async def test_session_cm_exited_on_exception(self) -> None:
        """__aexit__ is called even when an exception propagates."""
        mock_session = AsyncMock(spec=AsyncSession)
        cm = _make_cm(mock_session)
        factory = MagicMock(return_value=cm)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            gen = get_db()
            await gen.__anext__()
            with pytest.raises(IOError):
                await gen.athrow(IOError("disk error"))

        cm.__aexit__.assert_awaited_once()

    async def test_rollback_called_before_exception_escapes(self) -> None:
        """rollback() must complete before the exception propagates."""
        call_log: list[str] = []
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        async def _track() -> None:
            call_log.append("rollback")

        mock_session.rollback.side_effect = _track

        with patch.object(db_module, "AsyncSessionLocal", factory):
            gen = get_db()
            await gen.__anext__()
            with pytest.raises(ValueError):
                await gen.athrow(ValueError("ordering check"))

        assert call_log == ["rollback"]

    @pytest.mark.parametrize(
        "exc_type", [ValueError, RuntimeError, KeyError, TypeError, IOError]
    )
    async def test_rolls_back_for_various_exception_types(
        self, exc_type: type
    ) -> None:
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            gen = get_db()
            await gen.__anext__()
            with pytest.raises(exc_type):
                await gen.athrow(exc_type("test"))

        mock_session.rollback.assert_awaited_once()


# ---------------------------------------------------------------------------
# get_db() — generator semantics and session isolation
# ---------------------------------------------------------------------------


class TestGetDbGeneratorSemantics:
    """get_db() is an async generator that isolates sessions across calls."""

    def test_get_db_is_async_generator_function(self) -> None:
        assert inspect.isasyncgenfunction(get_db)

    async def test_independent_sessions_per_call(self) -> None:
        """Each get_db() invocation receives its own session from the factory."""
        sessions = [AsyncMock(spec=AsyncSession) for _ in range(3)]
        call_count = [-1]

        def _side_effect(*args: object, **kwargs: object) -> MagicMock:
            call_count[0] += 1
            return _make_cm(sessions[call_count[0]])

        factory = MagicMock(side_effect=_side_effect)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            collected = []
            for _ in range(3):
                async for s in get_db():
                    collected.append(s)

        assert len(collected) == 3
        assert collected[0] is sessions[0]
        assert collected[1] is sessions[1]
        assert collected[2] is sessions[2]

    async def test_each_invocation_calls_factory_once(self) -> None:
        """AsyncSessionLocal is called exactly once per get_db() call."""
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            for _ in range(4):
                async for _ in get_db():
                    pass

        assert factory.call_count == 4

    async def test_no_commit_when_session_not_consumed(self) -> None:
        """If caller closes the generator early, no commit is issued."""
        mock_session = AsyncMock(spec=AsyncSession)
        factory = _make_factory(mock_session)

        with patch.object(db_module, "AsyncSessionLocal", factory):
            gen = get_db()
            await gen.__anext__()
            await gen.aclose()

        mock_session.commit.assert_not_awaited()
