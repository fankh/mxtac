"""Tests for the inactive account lock background task — feature 1.7.

Coverage:

  inactive_account_lock_task():
  - Returns immediately when account_inactivity_days <= 0 (disabled)
  - Sleeps with a positive duration before the first iteration
  - Sleep duration is approximately correct for times before and after 03:00 UTC
  - asyncio.CancelledError raised during sleep propagates out of the task
  - asyncio.CancelledError raised during DB work propagates out of the task
  - Issues SELECT + UPDATE when eligible accounts exist
  - Issues SELECT only (no UPDATE) when no accounts are eligible
  - commit() is called after each DB iteration regardless of lock count
  - Non-CancelledError exceptions in the loop body are caught and loop continues
  - Audit log is written with correct fields when accounts are locked
  - Audit log is not written when no accounts are locked
  - Audit log failure is non-fatal; task continues normally
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.inactive_account import inactive_account_lock_task


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _make_session(locked_emails: list[str] | None = None) -> MagicMock:
    """Build a mock AsyncSession.

    ``session.execute`` is configured so that the first call (SELECT) returns a
    result whose ``.scalars().all()`` produces ``locked_emails``.  When
    ``locked_emails`` is non-empty a second call (UPDATE) is expected; its
    return value is a plain MagicMock.
    """
    session = MagicMock()
    session.commit = AsyncMock()

    select_result = MagicMock()
    select_result.scalars.return_value.all.return_value = list(locked_emails or [])

    update_result = MagicMock()
    session.execute = AsyncMock(side_effect=[select_result, update_result])
    return session


def _make_session_ctx(session: MagicMock) -> MagicMock:
    """Wrap a session mock in an async context manager."""
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


# ---------------------------------------------------------------------------
# Tests: task disabled
# ---------------------------------------------------------------------------


class TestDisabled:

    @pytest.mark.asyncio
    async def test_returns_immediately_when_zero_days(self) -> None:
        """Task returns immediately when account_inactivity_days == 0."""
        with patch("app.services.inactive_account.settings") as mock_cfg:
            mock_cfg.account_inactivity_days = 0
            # Must complete without sleeping or touching the DB
            await inactive_account_lock_task()

    @pytest.mark.asyncio
    async def test_returns_immediately_when_negative_days(self) -> None:
        """Task returns immediately when account_inactivity_days < 0."""
        with patch("app.services.inactive_account.settings") as mock_cfg:
            mock_cfg.account_inactivity_days = -5
            await inactive_account_lock_task()


# ---------------------------------------------------------------------------
# Tests: sleep scheduling
# ---------------------------------------------------------------------------


class TestSleepScheduling:

    @pytest.mark.asyncio
    async def test_sleep_called_with_positive_duration(self) -> None:
        """asyncio.sleep is invoked with a positive value on every iteration."""
        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            mock_sleep.side_effect = asyncio.CancelledError()
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        assert mock_sleep.await_count == 1
        sleep_duration = mock_sleep.call_args.args[0]
        assert sleep_duration > 0

    @pytest.mark.asyncio
    async def test_sleep_duration_before_3am_utc(self) -> None:
        """When now is 02:00 UTC, sleep ≈ 3 600 s (1 hour until 03:00)."""
        fake_now = datetime(2024, 6, 15, 2, 0, 0, tzinfo=timezone.utc)

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.settings") as mock_cfg,
            patch("app.services.inactive_account.datetime") as mock_dt,
        ):
            mock_sleep.side_effect = asyncio.CancelledError()
            mock_cfg.account_inactivity_days = 90
            # Return a *real* datetime so that .replace() and arithmetic work
            mock_dt.now.return_value = fake_now

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        sleep_duration = mock_sleep.call_args.args[0]
        # Expect ~3600 s; allow ±2 s tolerance
        assert abs(sleep_duration - 3600.0) < 2.0

    @pytest.mark.asyncio
    async def test_sleep_duration_after_3am_utc(self) -> None:
        """When now is 04:00 UTC, sleep ≈ 82 800 s (23 hours to next 03:00)."""
        fake_now = datetime(2024, 6, 15, 4, 0, 0, tzinfo=timezone.utc)

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.settings") as mock_cfg,
            patch("app.services.inactive_account.datetime") as mock_dt,
        ):
            mock_sleep.side_effect = asyncio.CancelledError()
            mock_cfg.account_inactivity_days = 90
            mock_dt.now.return_value = fake_now

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        sleep_duration = mock_sleep.call_args.args[0]
        assert abs(sleep_duration - 82800.0) < 2.0

    @pytest.mark.asyncio
    async def test_sleep_duration_exactly_at_3am_utc(self) -> None:
        """When now is exactly 03:00 UTC, next run is pushed to next day (≈86400 s)."""
        fake_now = datetime(2024, 6, 15, 3, 0, 0, tzinfo=timezone.utc)

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.settings") as mock_cfg,
            patch("app.services.inactive_account.datetime") as mock_dt,
        ):
            mock_sleep.side_effect = asyncio.CancelledError()
            mock_cfg.account_inactivity_days = 90
            mock_dt.now.return_value = fake_now

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        sleep_duration = mock_sleep.call_args.args[0]
        assert abs(sleep_duration - 86400.0) < 2.0


# ---------------------------------------------------------------------------
# Tests: cancellation propagation
# ---------------------------------------------------------------------------


class TestCancellation:

    @pytest.mark.asyncio
    async def test_cancelled_during_sleep_propagates(self) -> None:
        """CancelledError raised by asyncio.sleep propagates out of the task."""
        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            mock_sleep.side_effect = asyncio.CancelledError()
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        assert mock_sleep.await_count == 1

    @pytest.mark.asyncio
    async def test_cancelled_during_db_work_propagates(self) -> None:
        """CancelledError raised during the DB execute propagates out of the task."""
        session = MagicMock()
        session.execute = AsyncMock(side_effect=asyncio.CancelledError())
        session.commit = AsyncMock()
        ctx = _make_session_ctx(session)

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.AsyncSessionLocal", return_value=ctx),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            # First sleep passes so that the iteration body starts
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        # Only one sleep: CancelledError from the DB execute stopped the loop
        assert mock_sleep.await_count == 1


# ---------------------------------------------------------------------------
# Tests: locking behaviour
# ---------------------------------------------------------------------------


class TestLockingBehavior:

    @pytest.mark.asyncio
    async def test_select_and_update_executed_when_accounts_eligible(self) -> None:
        """Two execute() calls are issued (SELECT + UPDATE) when accounts qualify."""
        locked_emails = ["alice@corp.com", "bob@corp.com"]
        session = _make_session(locked_emails=locked_emails)
        ctx = _make_session_ctx(session)
        mock_audit = MagicMock()
        mock_audit.log = AsyncMock()

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.AsyncSessionLocal", return_value=ctx),
            patch("app.services.inactive_account.get_audit_logger", return_value=mock_audit),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        assert session.execute.await_count == 2  # SELECT + UPDATE
        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_only_select_executed_when_no_eligible_accounts(self) -> None:
        """Only the SELECT execute() is issued when no accounts qualify."""
        session = _make_session(locked_emails=[])
        ctx = _make_session_ctx(session)

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.AsyncSessionLocal", return_value=ctx),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        assert session.execute.await_count == 1  # SELECT only
        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_commit_called_even_when_no_accounts_locked(self) -> None:
        """commit() is always called after the DB block, even with zero locks."""
        session = _make_session(locked_emails=[])
        ctx = _make_session_ctx(session)

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.AsyncSessionLocal", return_value=ctx),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_exception_in_iteration_is_caught_and_loop_continues(self) -> None:
        """Non-CancelledError exceptions during DB work are caught; loop continues."""
        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch(
                "app.services.inactive_account.AsyncSessionLocal",
                side_effect=RuntimeError("db connection lost"),
            ),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            # First sleep passes → iteration fails → loop sleeps again → Cancelled
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        # Two sleep calls confirm the loop recovered and ran a second iteration
        assert mock_sleep.await_count == 2

    @pytest.mark.asyncio
    async def test_multiple_iterations_each_run_db_work(self) -> None:
        """Over two full iterations, execute() and commit() are each called twice."""
        session = _make_session(locked_emails=[])
        # Re-configure execute side_effect to handle 2 iterations (2 SELECTs)
        select_result = MagicMock()
        select_result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=select_result)

        ctx = _make_session_ctx(session)

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.AsyncSessionLocal", return_value=ctx),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            # Two normal sleeps, then cancel
            mock_sleep.side_effect = [None, None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        assert session.execute.await_count == 2
        assert session.commit.await_count == 2


# ---------------------------------------------------------------------------
# Tests: audit logging
# ---------------------------------------------------------------------------


class TestAuditLogging:

    @pytest.mark.asyncio
    async def test_audit_logged_when_accounts_locked(self) -> None:
        """Audit log is written when at least one account is locked."""
        locked_emails = ["idle-user@corp.com"]
        session = _make_session(locked_emails=locked_emails)
        ctx = _make_session_ctx(session)
        mock_audit = MagicMock()
        mock_audit.log = AsyncMock()

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.AsyncSessionLocal", return_value=ctx),
            patch(
                "app.services.inactive_account.get_audit_logger",
                return_value=mock_audit,
            ),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        mock_audit.log.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_audit_log_contains_correct_fields(self) -> None:
        """Audit log entry carries the expected actor, action, resource and details."""
        locked_emails = ["victim@example.com"]
        session = _make_session(locked_emails=locked_emails)
        ctx = _make_session_ctx(session)
        mock_audit = MagicMock()
        mock_audit.log = AsyncMock()

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.AsyncSessionLocal", return_value=ctx),
            patch(
                "app.services.inactive_account.get_audit_logger",
                return_value=mock_audit,
            ),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        kw = mock_audit.log.call_args.kwargs
        assert kw["actor"] == "system"
        assert kw["action"] == "inactive_account_lock"
        assert kw["resource_type"] == "user"
        assert kw["details"]["locked_count"] == 1
        assert "victim@example.com" in kw["details"]["locked_emails"]
        assert kw["details"]["inactivity_days"] == 90
        assert "cutoff" in kw["details"]

    @pytest.mark.asyncio
    async def test_audit_not_logged_when_no_accounts_locked(self) -> None:
        """Audit log is NOT written when no accounts were locked this cycle."""
        session = _make_session(locked_emails=[])
        ctx = _make_session_ctx(session)
        mock_audit = MagicMock()
        mock_audit.log = AsyncMock()

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.AsyncSessionLocal", return_value=ctx),
            patch(
                "app.services.inactive_account.get_audit_logger",
                return_value=mock_audit,
            ),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        mock_audit.log.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_audit_failure_is_nonfatal_task_continues(self) -> None:
        """An exception in audit.log() is swallowed; the loop continues to next sleep."""
        locked_emails = ["affected@example.com"]
        session = _make_session(locked_emails=locked_emails)
        ctx = _make_session_ctx(session)
        mock_audit = MagicMock()
        mock_audit.log = AsyncMock(side_effect=Exception("audit service down"))

        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.AsyncSessionLocal", return_value=ctx),
            patch(
                "app.services.inactive_account.get_audit_logger",
                return_value=mock_audit,
            ),
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            # First sleep → iteration runs → audit fails (non-fatal) → second sleep
            mock_sleep.side_effect = [None, asyncio.CancelledError()]
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        # Two sleep calls prove the loop continued after the audit failure
        assert mock_sleep.await_count == 2

    @pytest.mark.asyncio
    async def test_startup_log_emitted(self) -> None:
        """The task logs an info message on startup before the first sleep."""
        with (
            patch(
                "app.services.inactive_account.asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
            patch("app.services.inactive_account.logger") as mock_logger,
            patch("app.services.inactive_account.settings") as mock_cfg,
        ):
            mock_sleep.side_effect = asyncio.CancelledError()
            mock_cfg.account_inactivity_days = 90

            with pytest.raises(asyncio.CancelledError):
                await inactive_account_lock_task()

        # At least one info log call containing "started"
        startup_calls = [
            c for c in mock_logger.info.call_args_list if "started" in str(c)
        ]
        assert len(startup_calls) == 1
