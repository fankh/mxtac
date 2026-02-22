"""Tests for agent_monitor background task.

Coverage:

  agent_status_monitor():
  - Calls AgentRepo.degrade_stale_agents() and commits each iteration
  - Logs when newly degraded or offline agents are found
  - Does not log when both counts are zero
  - Sleep interval is _CHECK_INTERVAL_SECS (60 seconds)
  - Exceptions in the loop body are caught and the task continues
  - asyncio.CancelledError is re-raised (not swallowed)
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.agent_monitor import agent_status_monitor


# ---------------------------------------------------------------------------
# Session factory helper
# ---------------------------------------------------------------------------


def _make_session() -> MagicMock:
    """Sync MagicMock for the session with async methods patched."""
    session = MagicMock()
    session.commit = AsyncMock()
    return session


def _make_session_ctx(session: MagicMock) -> MagicMock:
    """Async context manager wrapping the given session mock."""
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


# ---------------------------------------------------------------------------
# agent_status_monitor()
# ---------------------------------------------------------------------------


class TestAgentStatusMonitor:

    @pytest.mark.asyncio
    async def test_calls_degrade_stale_agents_and_commits(self) -> None:
        """Each iteration calls degrade_stale_agents and commits the session."""
        mock_session = _make_session()
        mock_ctx = _make_session_ctx(mock_session)

        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                return_value=mock_ctx,
            ),
            patch(
                "app.services.agent_monitor.AgentRepo.degrade_stale_agents",
                new_callable=AsyncMock,
                return_value=(0, 0),
            ) as mock_degrade,
        ):
            # Stop after one iteration
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        mock_degrade.assert_awaited_once_with(mock_session)
        mock_session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_logs_when_agents_degraded_or_offline(self) -> None:
        """Logs an info message when degraded or offline count is non-zero."""
        mock_session = _make_session()
        mock_ctx = _make_session_ctx(mock_session)

        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                return_value=mock_ctx,
            ),
            patch(
                "app.services.agent_monitor.AgentRepo.degrade_stale_agents",
                new_callable=AsyncMock,
                return_value=(2, 1),
            ),
            patch("app.services.agent_monitor.logger") as mock_logger,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        # Startup log + iteration log expected
        assert mock_logger.info.call_count >= 2
        # The iteration log must carry the counts
        iteration_calls = [
            call
            for call in mock_logger.info.call_args_list
            if "newly degraded" in str(call)
        ]
        assert len(iteration_calls) == 1

    @pytest.mark.asyncio
    async def test_no_iteration_log_when_counts_are_zero(self) -> None:
        """When degraded=0 and offline=0, no iteration-level info log is emitted."""
        mock_session = _make_session()
        mock_ctx = _make_session_ctx(mock_session)

        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                return_value=mock_ctx,
            ),
            patch(
                "app.services.agent_monitor.AgentRepo.degrade_stale_agents",
                new_callable=AsyncMock,
                return_value=(0, 0),
            ),
            patch("app.services.agent_monitor.logger") as mock_logger,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        iteration_calls = [
            call
            for call in mock_logger.info.call_args_list
            if "newly degraded" in str(call)
        ]
        assert len(iteration_calls) == 0

    @pytest.mark.asyncio
    async def test_logs_when_only_degraded_count_nonzero(self) -> None:
        """Logs iteration info when degraded > 0, even if offline == 0."""
        mock_session = _make_session()
        mock_ctx = _make_session_ctx(mock_session)

        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                return_value=mock_ctx,
            ),
            patch(
                "app.services.agent_monitor.AgentRepo.degrade_stale_agents",
                new_callable=AsyncMock,
                return_value=(3, 0),
            ),
            patch("app.services.agent_monitor.logger") as mock_logger,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        iteration_calls = [
            call
            for call in mock_logger.info.call_args_list
            if "newly degraded" in str(call)
        ]
        assert len(iteration_calls) == 1

    @pytest.mark.asyncio
    async def test_logs_when_only_offline_count_nonzero(self) -> None:
        """Logs iteration info when offline > 0, even if degraded == 0."""
        mock_session = _make_session()
        mock_ctx = _make_session_ctx(mock_session)

        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                return_value=mock_ctx,
            ),
            patch(
                "app.services.agent_monitor.AgentRepo.degrade_stale_agents",
                new_callable=AsyncMock,
                return_value=(0, 5),
            ),
            patch("app.services.agent_monitor.logger") as mock_logger,
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        iteration_calls = [
            call
            for call in mock_logger.info.call_args_list
            if "newly degraded" in str(call)
        ]
        assert len(iteration_calls) == 1

    @pytest.mark.asyncio
    async def test_sleep_interval_is_60_seconds(self) -> None:
        """asyncio.sleep is called with the configured 60-second interval."""
        mock_session = _make_session()
        mock_ctx = _make_session_ctx(mock_session)

        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                return_value=mock_ctx,
            ),
            patch(
                "app.services.agent_monitor.AgentRepo.degrade_stale_agents",
                new_callable=AsyncMock,
                return_value=(0, 0),
            ),
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        # Both calls must be with 60 seconds
        for call_args in mock_sleep.call_args_list:
            assert call_args.args[0] == 60

    @pytest.mark.asyncio
    async def test_exception_in_iteration_is_caught_and_loop_continues(self) -> None:
        """Non-CancelledError exceptions are logged and the task keeps running."""
        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                side_effect=RuntimeError("db connection failed"),
            ),
        ):
            # First sleep returns → triggers the error, second raises Cancelled
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        # Two sleeps means the loop continued after the exception
        assert mock_sleep.await_count == 2

    @pytest.mark.asyncio
    async def test_exception_does_not_commit(self) -> None:
        """When the repository raises, commit is never called."""
        mock_session = _make_session()
        mock_ctx = _make_session_ctx(mock_session)

        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                return_value=mock_ctx,
            ),
            patch(
                "app.services.agent_monitor.AgentRepo.degrade_stale_agents",
                new_callable=AsyncMock,
                side_effect=RuntimeError("query failed"),
            ),
        ):
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        mock_session.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cancelled_error_in_sleep_propagates(self) -> None:
        """asyncio.CancelledError raised during sleep propagates out of the task."""
        with patch(
            "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
        ) as mock_sleep:
            mock_sleep.side_effect = asyncio.CancelledError()

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

    @pytest.mark.asyncio
    async def test_cancelled_error_in_repo_propagates(self) -> None:
        """asyncio.CancelledError raised inside the iteration body propagates."""
        mock_session = _make_session()
        mock_ctx = _make_session_ctx(mock_session)

        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                return_value=mock_ctx,
            ),
            patch(
                "app.services.agent_monitor.AgentRepo.degrade_stale_agents",
                new_callable=AsyncMock,
                side_effect=asyncio.CancelledError(),
            ),
        ):
            mock_sleep.return_value = None  # first sleep returns normally

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        # Only one sleep call because CancelledError stops the second iteration
        assert mock_sleep.await_count == 1

    @pytest.mark.asyncio
    async def test_startup_log_emitted(self) -> None:
        """The monitor logs an info message on startup before the first sleep."""
        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch("app.services.agent_monitor.logger") as mock_logger,
        ):
            mock_sleep.side_effect = asyncio.CancelledError()

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        # Startup info log should have been called before the CancelledError
        mock_logger.info.assert_called()
        startup_calls = [
            call
            for call in mock_logger.info.call_args_list
            if "started" in str(call)
        ]
        assert len(startup_calls) == 1

    @pytest.mark.asyncio
    async def test_multiple_iterations_each_call_repo(self) -> None:
        """Over two iterations, degrade_stale_agents is called twice."""
        mock_session = _make_session()
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(
                "app.services.agent_monitor.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep,
            patch(
                "app.services.agent_monitor.AsyncSessionLocal",
                return_value=mock_ctx,
            ),
            patch(
                "app.services.agent_monitor.AgentRepo.degrade_stale_agents",
                new_callable=AsyncMock,
                return_value=(1, 0),
            ) as mock_degrade,
        ):
            # Two normal sleeps, then cancel
            mock_sleep.side_effect = [None, None, asyncio.CancelledError()]

            with pytest.raises(asyncio.CancelledError):
                await agent_status_monitor()

        assert mock_degrade.await_count == 2
        assert mock_session.commit.await_count == 2
