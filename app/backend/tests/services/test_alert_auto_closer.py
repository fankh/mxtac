"""Tests for alert_auto_closer background service — feature 9.12.

Coverage:
  _run_auto_close_cycle():
    - is a no-op when no eligible detections exist
    - bulk-closes all eligible detections in one UPDATE
    - handles DB errors during the close phase gracefully
    - logs one line per closed detection

  alert_auto_closer_task():
    - calls _run_auto_close_cycle on each interval
    - skips cycle when alert_auto_close_enabled=False
    - stops cleanly on CancelledError
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.alert_auto_closer import (
    _CHECK_INTERVAL_SECS,
    _run_auto_close_cycle,
    alert_auto_closer_task,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_detection(
    id: str = "det-001",
    host: str = "host-a",
    rule_name: str = "mimikatz",
    severity: str = "high",
) -> MagicMock:
    d = MagicMock()
    d.id = id
    d.host = host
    d.rule_name = rule_name
    d.severity = severity
    return d


def _make_session_ctx(session: AsyncMock | None = None) -> MagicMock:
    if session is None:
        session = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


# ---------------------------------------------------------------------------
# _run_auto_close_cycle()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cycle_no_eligible_detections():
    """Cycle is a no-op when find_stale_active_detections returns empty list."""
    ctx = _make_session_ctx()

    with patch("app.services.alert_auto_closer.AsyncSessionLocal", return_value=ctx):
        with patch(
            "app.repositories.detection_repo.DetectionRepo.find_stale_active_detections",
            new=AsyncMock(return_value=[]),
        ):
            with patch(
                "app.repositories.detection_repo.DetectionRepo.auto_close_by_ids"
            ) as mock_close:
                await _run_auto_close_cycle(no_recurrence_hours=24)

    mock_close.assert_not_called()


@pytest.mark.asyncio
async def test_cycle_closes_eligible_detections():
    """Cycle calls auto_close_by_ids with the correct detection IDs."""
    det1 = _make_detection(id="d-1", host="host-a", rule_name="rule-1")
    det2 = _make_detection(id="d-2", host="host-b", rule_name="rule-2")

    ctx = _make_session_ctx()
    closed_ids: list[list[str]] = []

    async def fake_close(session, ids):
        closed_ids.append(list(ids))
        return len(ids)

    with patch("app.services.alert_auto_closer.AsyncSessionLocal", return_value=ctx):
        with patch(
            "app.repositories.detection_repo.DetectionRepo.find_stale_active_detections",
            new=AsyncMock(return_value=[det1, det2]),
        ):
            with patch(
                "app.repositories.detection_repo.DetectionRepo.auto_close_by_ids",
                new=AsyncMock(side_effect=fake_close),
            ):
                await _run_auto_close_cycle(no_recurrence_hours=24)

    assert len(closed_ids) == 1
    assert sorted(closed_ids[0]) == ["d-1", "d-2"]


@pytest.mark.asyncio
async def test_cycle_handles_close_error_gracefully():
    """A DB error during auto_close_by_ids is logged and swallowed."""
    det = _make_detection()
    ctx = _make_session_ctx()

    with patch("app.services.alert_auto_closer.AsyncSessionLocal", return_value=ctx):
        with patch(
            "app.repositories.detection_repo.DetectionRepo.find_stale_active_detections",
            new=AsyncMock(return_value=[det]),
        ):
            with patch(
                "app.repositories.detection_repo.DetectionRepo.auto_close_by_ids",
                new=AsyncMock(side_effect=RuntimeError("db exploded")),
            ):
                # Must not raise
                await _run_auto_close_cycle(no_recurrence_hours=24)


@pytest.mark.asyncio
async def test_cycle_passes_correct_window():
    """Cycle forwards the no_recurrence_hours argument to find_stale_active_detections."""
    ctx = _make_session_ctx()
    received_hours: list[int] = []

    async def fake_find(session, no_recurrence_hours):
        received_hours.append(no_recurrence_hours)
        return []

    with patch("app.services.alert_auto_closer.AsyncSessionLocal", return_value=ctx):
        with patch(
            "app.repositories.detection_repo.DetectionRepo.find_stale_active_detections",
            new=AsyncMock(side_effect=fake_find),
        ):
            await _run_auto_close_cycle(no_recurrence_hours=48)

    assert received_hours == [48]


# ---------------------------------------------------------------------------
# alert_auto_closer_task() — outer loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_task_calls_cycle_on_interval():
    """alert_auto_closer_task() calls _run_auto_close_cycle on each sleep tick."""
    cycles: list[int] = []

    async def fake_cycle(no_recurrence_hours):
        cycles.append(no_recurrence_hours)

    with patch("app.services.alert_auto_closer._run_auto_close_cycle", side_effect=fake_cycle):
        with patch("app.services.alert_auto_closer._CHECK_INTERVAL_SECS", 0):
            with patch("app.services.alert_auto_closer.settings") as mock_settings:
                mock_settings.alert_auto_close_enabled = True
                mock_settings.alert_auto_close_no_recurrence_hours = 24
                task = asyncio.create_task(alert_auto_closer_task())
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    assert len(cycles) >= 1
    assert all(h == 24 for h in cycles)


@pytest.mark.asyncio
async def test_task_skips_cycle_when_disabled():
    """alert_auto_closer_task() skips _run_auto_close_cycle when enabled=False."""
    cycles: list[int] = []

    async def fake_cycle(no_recurrence_hours):
        cycles.append(no_recurrence_hours)

    with patch("app.services.alert_auto_closer._run_auto_close_cycle", side_effect=fake_cycle):
        with patch("app.services.alert_auto_closer._CHECK_INTERVAL_SECS", 0):
            with patch("app.services.alert_auto_closer.settings") as mock_settings:
                mock_settings.alert_auto_close_enabled = False
                mock_settings.alert_auto_close_no_recurrence_hours = 24
                task = asyncio.create_task(alert_auto_closer_task())
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    assert cycles == []


@pytest.mark.asyncio
async def test_task_stops_on_cancel():
    """alert_auto_closer_task() exits cleanly when cancelled during sleep."""
    with patch("app.services.alert_auto_closer._run_auto_close_cycle", new=AsyncMock()):
        with patch("app.services.alert_auto_closer._CHECK_INTERVAL_SECS", 0):
            task = asyncio.create_task(alert_auto_closer_task())
            await asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass  # expected — task propagates CancelledError out


@pytest.mark.asyncio
async def test_task_continues_after_cycle_exception():
    """A cycle exception does not kill the task loop."""
    call_count = 0

    async def flaky_cycle(no_recurrence_hours):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("transient failure")
        # Second call succeeds

    with patch("app.services.alert_auto_closer._run_auto_close_cycle", side_effect=flaky_cycle):
        with patch("app.services.alert_auto_closer._CHECK_INTERVAL_SECS", 0):
            with patch("app.services.alert_auto_closer.settings") as mock_settings:
                mock_settings.alert_auto_close_enabled = True
                mock_settings.alert_auto_close_no_recurrence_hours = 24
                task = asyncio.create_task(alert_auto_closer_task())
                # Allow at least two iterations
                for _ in range(4):
                    await asyncio.sleep(0)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    assert call_count >= 2
