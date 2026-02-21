"""Tests for ioc_expiry background task and IOCRepo.expire_stale — feature 29.8.

Coverage:

  IOCRepo.expire_stale():
  - days > 0, count > 0 → executes update and flush, returns count
  - days > 0, count = 0 → skips update, returns 0
  - days > 0, scalar returns None → treated as 0, skips update
  - days = 0 → returns 0 immediately, no DB calls

  ioc_expiry_task():
  - Calls expire_old and expire_stale, commits, increments counter on match
  - Zero total → counter not incremented, debug logged
  - Exceptions in loop body are caught and task continues
  - asyncio.CancelledError is re-raised (not swallowed)
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from app.repositories.ioc_repo import IOCRepo
from app.services.ioc_expiry import ioc_expiry_task


# ---------------------------------------------------------------------------
# Session factory helper
# ---------------------------------------------------------------------------


def _make_session() -> MagicMock:
    """Sync MagicMock for the session with async methods patched."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.scalar = AsyncMock()
    session.commit = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# IOCRepo.expire_stale()
# ---------------------------------------------------------------------------


class TestIOCRepoExpireStale:

    @pytest.mark.asyncio
    async def test_returns_count_and_updates_when_stale_found(self) -> None:
        session = _make_session()
        session.scalar.return_value = 5  # 5 stale IOCs

        result = await IOCRepo.expire_stale(session, days=90)

        assert result == 5
        session.scalar.assert_awaited_once()
        session.execute.assert_awaited_once()
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_zero_count_skips_update(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0

        result = await IOCRepo.expire_stale(session, days=90)

        assert result == 0
        session.scalar.assert_awaited_once()
        session.execute.assert_not_awaited()
        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_none_scalar_treated_as_zero(self) -> None:
        session = _make_session()
        session.scalar.return_value = None

        result = await IOCRepo.expire_stale(session, days=90)

        assert result == 0
        session.execute.assert_not_awaited()
        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_days_zero_returns_immediately(self) -> None:
        session = _make_session()

        result = await IOCRepo.expire_stale(session, days=0)

        assert result == 0
        session.scalar.assert_not_awaited()
        session.execute.assert_not_awaited()
        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_days_negative_returns_immediately(self) -> None:
        session = _make_session()

        result = await IOCRepo.expire_stale(session, days=-1)

        assert result == 0
        session.scalar.assert_not_awaited()
        session.execute.assert_not_awaited()
        session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# ioc_expiry_task()
# ---------------------------------------------------------------------------


class TestIocExpiryTask:

    @pytest.mark.asyncio
    async def test_expires_iocs_and_increments_counter(self) -> None:
        """Task calls both repo methods, commits, increments Prometheus counter."""
        mock_session = _make_session()
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("app.services.ioc_expiry.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.ioc_expiry.AsyncSessionLocal", return_value=mock_ctx),
            patch("app.services.ioc_expiry.IOCRepo.expire_old", new_callable=AsyncMock, return_value=3) as mock_expire_old,
            patch("app.services.ioc_expiry.IOCRepo.expire_stale", new_callable=AsyncMock, return_value=2) as mock_expire_stale,
            patch("app.services.ioc_expiry.metrics") as mock_metrics,
            patch("app.services.ioc_expiry.settings") as mock_settings,
        ):
            mock_settings.ioc_no_hit_expiry_days = 90
            # Make sleep raise CancelledError after one iteration to stop the loop
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await ioc_expiry_task()

        mock_expire_old.assert_awaited_once_with(mock_session)
        mock_expire_stale.assert_awaited_once_with(mock_session, days=90)
        mock_session.commit.assert_awaited_once()
        mock_metrics.iocs_expired.inc.assert_called_once_with(5)  # 3 + 2

    @pytest.mark.asyncio
    async def test_zero_total_does_not_increment_counter(self) -> None:
        """When no IOCs expire, the counter is not incremented."""
        mock_session = _make_session()
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("app.services.ioc_expiry.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.ioc_expiry.AsyncSessionLocal", return_value=mock_ctx),
            patch("app.services.ioc_expiry.IOCRepo.expire_old", new_callable=AsyncMock, return_value=0),
            patch("app.services.ioc_expiry.IOCRepo.expire_stale", new_callable=AsyncMock, return_value=0),
            patch("app.services.ioc_expiry.metrics") as mock_metrics,
            patch("app.services.ioc_expiry.settings") as mock_settings,
        ):
            mock_settings.ioc_no_hit_expiry_days = 90
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await ioc_expiry_task()

        mock_metrics.iocs_expired.inc.assert_not_called()

    @pytest.mark.asyncio
    async def test_exception_in_iteration_is_caught_and_loop_continues(self) -> None:
        """Non-CancelledError exceptions are logged and the task keeps running."""
        with (
            patch("app.services.ioc_expiry.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.ioc_expiry.AsyncSessionLocal", side_effect=RuntimeError("db down")),
            patch("app.services.ioc_expiry.metrics"),
            patch("app.services.ioc_expiry.settings") as mock_settings,
        ):
            mock_settings.ioc_no_hit_expiry_days = 90
            # First sleep returns (triggers the error), second raises Cancelled to stop
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await ioc_expiry_task()

        # Reached here = exception was caught and loop continued until Cancelled
        assert mock_sleep.await_count == 2

    @pytest.mark.asyncio
    async def test_cancelled_error_propagates(self) -> None:
        """asyncio.CancelledError raised in sleep propagates out of the task."""
        with (
            patch("app.services.ioc_expiry.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.ioc_expiry.metrics"),
            patch("app.services.ioc_expiry.settings") as mock_settings,
        ):
            mock_settings.ioc_no_hit_expiry_days = 90
            mock_sleep.side_effect = asyncio.CancelledError()

            with pytest.raises(asyncio.CancelledError):
                await ioc_expiry_task()

    @pytest.mark.asyncio
    async def test_uses_configured_no_hit_expiry_days(self) -> None:
        """expire_stale() is called with the value from settings."""
        mock_session = _make_session()
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("app.services.ioc_expiry.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
            patch("app.services.ioc_expiry.AsyncSessionLocal", return_value=mock_ctx),
            patch("app.services.ioc_expiry.IOCRepo.expire_old", new_callable=AsyncMock, return_value=0),
            patch("app.services.ioc_expiry.IOCRepo.expire_stale", new_callable=AsyncMock, return_value=0) as mock_expire_stale,
            patch("app.services.ioc_expiry.metrics"),
            patch("app.services.ioc_expiry.settings") as mock_settings,
        ):
            mock_settings.ioc_no_hit_expiry_days = 30  # custom value
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await ioc_expiry_task()

        mock_expire_stale.assert_awaited_once_with(mock_session, days=30)
