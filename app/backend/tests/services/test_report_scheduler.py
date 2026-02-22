"""Tests for report_scheduler background service — feature 31.4.

Coverage:
  calculate_next_run():
    - returns a UTC-aware datetime
    - returns a time after the given base
    - raises for an invalid cron expression

  _build_report_notification():
    - returns dict with expected keys
    - rule_title contains the schedule name

  _run_scheduler_cycle():
    - is a no-op when no schedules are due
    - calls _run_one_schedule for each due schedule
    - continues past errors in individual schedules

  _run_one_schedule():
    - generates a Report record in the DB
    - updates last_run_at and next_run_at after a successful run
    - marks the report as failed when generation raises
    - sends notification when notification_channel_id is set
    - skips notification when channel not found
    - skips notification when dispatcher is None

  report_scheduler_task():
    - calls _run_scheduler_cycle on each interval
    - stops cleanly on CancelledError
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.report_scheduler import (
    _build_report_notification,
    _run_scheduler_cycle,
    _run_one_schedule,
    calculate_next_run,
    _CHECK_INTERVAL_SECS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scheduled_report(
    *,
    id: str = "sr-001",
    name: str = "Weekly Executive",
    template_type: str = "executive_summary",
    schedule: str = "0 8 * * 1",
    params_json: dict | None = None,
    format: str = "json",
    enabled: bool = True,
    notification_channel_id: int | None = None,
    created_by: str = "analyst@mxtac.local",
) -> MagicMock:
    sr = MagicMock()
    sr.id = id
    sr.name = name
    sr.template_type = template_type
    sr.schedule = schedule
    sr.params_json = params_json or {"period_days": 7}
    sr.format = format
    sr.enabled = enabled
    sr.notification_channel_id = notification_channel_id
    sr.created_by = created_by
    return sr


def _make_channel(
    *,
    id: int = 1,
    name: str = "test-channel",
    channel_type: str = "slack",
    config_json: str = '{"webhook_url": "https://hooks.slack.com/test"}',
    enabled: bool = True,
) -> MagicMock:
    ch = MagicMock()
    ch.id = id
    ch.name = name
    ch.channel_type = channel_type
    ch.config_json = config_json
    ch.enabled = enabled
    ch.routing_rules = "[]"
    ch.min_severity = "low"
    return ch


# ---------------------------------------------------------------------------
# calculate_next_run()
# ---------------------------------------------------------------------------


def test_calculate_next_run_returns_utc_aware():
    """calculate_next_run() must return a UTC-aware datetime."""
    result = calculate_next_run("0 8 * * 1")
    assert result.tzinfo is not None


def test_calculate_next_run_is_after_base():
    """The next run time must be strictly after the given base time."""
    base = datetime(2025, 1, 6, 8, 0, 0, tzinfo=timezone.utc)  # Monday 08:00
    result = calculate_next_run("0 8 * * 1", after=base)
    assert result > base


def test_calculate_next_run_weekly_schedule():
    """Weekly Monday 08:00 UTC — next run after a Monday returns following Monday."""
    # Tuesday 2025-01-07 09:00 UTC
    base = datetime(2025, 1, 7, 9, 0, 0, tzinfo=timezone.utc)
    result = calculate_next_run("0 8 * * 1", after=base)
    # Next Monday is 2025-01-13
    assert result.weekday() == 0  # Monday
    assert result.hour == 8
    assert result.minute == 0


def test_calculate_next_run_daily_schedule():
    """Daily midnight schedule produces next run on following day."""
    base = datetime(2025, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = calculate_next_run("0 0 * * *", after=base)
    assert result.day == 2
    assert result.hour == 0
    assert result.minute == 0


def test_calculate_next_run_invalid_expression_raises():
    """An invalid cron expression must raise an exception."""
    import pytest  # noqa: PLC0415
    with pytest.raises(Exception):
        calculate_next_run("not a cron")


# ---------------------------------------------------------------------------
# _build_report_notification()
# ---------------------------------------------------------------------------


def test_build_report_notification_keys():
    """_build_report_notification() returns dict with required keys."""
    sr = _make_scheduled_report(name="My Report", template_type="detection_report")
    notif = _build_report_notification(sr, "rep-abc123")

    assert notif["report_id"] == "rep-abc123"
    assert notif["scheduled_report_id"] == sr.id
    assert "My Report" in notif["rule_title"]
    assert notif["report_template"] == "detection_report"
    assert isinstance(notif["technique_ids"], list)
    assert isinstance(notif["tactic_ids"], list)
    assert notif["level"] == "low"


def test_build_report_notification_title_contains_name():
    """rule_title must mention the schedule name."""
    sr = _make_scheduled_report(name="Compliance Weekly")
    notif = _build_report_notification(sr, "rep-xyz")
    assert "Compliance Weekly" in notif["rule_title"]


# ---------------------------------------------------------------------------
# _run_scheduler_cycle() — no due schedules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_cycle_no_due_schedules():
    """Cycle is a no-op when no schedules are due."""
    session_ctx = MagicMock()
    session_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    session_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("app.services.report_scheduler.AsyncSessionLocal", return_value=session_ctx):
        with patch(
            "app.repositories.scheduled_report_repo.ScheduledReportRepo.find_due",
            new=AsyncMock(return_value=[]),
        ):
            with patch("app.services.report_scheduler._run_one_schedule") as mock_run:
                await _run_scheduler_cycle(dispatcher=None)

    mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_run_cycle_calls_run_one_for_each_due():
    """Cycle calls _run_one_schedule for each due schedule."""
    sr1 = _make_scheduled_report(id="sr-1")
    sr2 = _make_scheduled_report(id="sr-2")

    session_ctx = MagicMock()
    session_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    session_ctx.__aexit__ = AsyncMock(return_value=False)

    called_ids: list[str] = []

    async def fake_run(sr, dispatcher):
        called_ids.append(sr.id)

    with patch("app.services.report_scheduler.AsyncSessionLocal", return_value=session_ctx):
        with patch(
            "app.repositories.scheduled_report_repo.ScheduledReportRepo.find_due",
            new=AsyncMock(return_value=[sr1, sr2]),
        ):
            with patch("app.services.report_scheduler._run_one_schedule", side_effect=fake_run):
                await _run_scheduler_cycle(dispatcher=None)

    assert sorted(called_ids) == ["sr-1", "sr-2"]


@pytest.mark.asyncio
async def test_run_cycle_continues_past_individual_error():
    """Cycle continues to remaining schedules even if one raises."""
    sr1 = _make_scheduled_report(id="sr-err")
    sr2 = _make_scheduled_report(id="sr-ok")

    session_ctx = MagicMock()
    session_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    session_ctx.__aexit__ = AsyncMock(return_value=False)

    ok_ids: list[str] = []

    async def fake_run(sr, dispatcher):
        if sr.id == "sr-err":
            raise RuntimeError("boom")
        ok_ids.append(sr.id)

    with patch("app.services.report_scheduler.AsyncSessionLocal", return_value=session_ctx):
        with patch(
            "app.repositories.scheduled_report_repo.ScheduledReportRepo.find_due",
            new=AsyncMock(return_value=[sr1, sr2]),
        ):
            with patch("app.services.report_scheduler._run_one_schedule", side_effect=fake_run):
                await _run_scheduler_cycle(dispatcher=None)  # must not raise

    assert ok_ids == ["sr-ok"]


# ---------------------------------------------------------------------------
# _run_one_schedule() — integration-style with mocked DB
# ---------------------------------------------------------------------------


def _make_session_ctx() -> tuple:
    """Return (ctx, session) mock pair."""
    session = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx, session


@pytest.mark.asyncio
async def test_run_one_schedule_happy_path():
    """Successful run creates a Report and updates run times."""
    sr = _make_scheduled_report()
    fake_content = {"template": "executive_summary", "kpis": {}}

    created_report_ids: list[str] = []
    updated_statuses: list[str] = []
    updated_run_times: list[dict] = []

    async def fake_create(session, *, id, template_type, format, params_json, created_by):
        created_report_ids.append(id)
        return MagicMock(id=id)

    async def fake_update_status(session, report_id, status, **kwargs):
        updated_statuses.append(status)
        return True

    async def fake_update_run_times(session, sr_id, *, last_run_at, next_run_at):
        updated_run_times.append({"last_run_at": last_run_at, "next_run_at": next_run_at})
        return True

    mock_engine = AsyncMock()
    mock_engine.generate = AsyncMock(return_value=fake_content)

    ctx, session = _make_session_ctx()

    with patch("app.services.report_scheduler.AsyncSessionLocal", return_value=ctx):
        with patch(
            "app.repositories.report_repo.ReportRepo.create",
            new=AsyncMock(side_effect=fake_create),
        ):
            with patch(
                "app.repositories.report_repo.ReportRepo.update_status",
                new=AsyncMock(side_effect=fake_update_status),
            ):
                with patch(
                    "app.repositories.scheduled_report_repo.ScheduledReportRepo.update_run_times",
                    new=AsyncMock(side_effect=fake_update_run_times),
                ):
                    with patch(
                        "app.services.report_scheduler.ReportEngine",
                        return_value=mock_engine,
                    ):
                        await _run_one_schedule(sr, dispatcher=None)

    assert len(created_report_ids) == 1
    assert "ready" in updated_statuses
    assert len(updated_run_times) == 1
    assert updated_run_times[0]["next_run_at"] is not None


@pytest.mark.asyncio
async def test_run_one_schedule_marks_failed_on_engine_error():
    """When ReportEngine raises, the report is marked as failed."""
    sr = _make_scheduled_report()
    failed_statuses: list[str] = []

    async def fake_update_status(session, report_id, status, **kwargs):
        failed_statuses.append(status)
        return True

    ctx, session = _make_session_ctx()
    err_ctx, _ = _make_session_ctx()

    def _make_ctx(*args, **kwargs):
        # Return the error context for update_status calls after the failure
        return ctx

    mock_engine = AsyncMock()
    mock_engine.generate = AsyncMock(side_effect=RuntimeError("DB error"))

    with patch("app.services.report_scheduler.AsyncSessionLocal", return_value=ctx):
        with patch(
            "app.repositories.report_repo.ReportRepo.create",
            new=AsyncMock(return_value=MagicMock()),
        ):
            with patch(
                "app.repositories.report_repo.ReportRepo.update_status",
                new=AsyncMock(side_effect=fake_update_status),
            ):
                with patch(
                    "app.repositories.scheduled_report_repo.ScheduledReportRepo.update_run_times",
                    new=AsyncMock(return_value=True),
                ):
                    with patch(
                        "app.services.report_scheduler.ReportEngine",
                        return_value=mock_engine,
                    ):
                        await _run_one_schedule(sr, dispatcher=None)  # must not raise

    assert "failed" in failed_statuses


@pytest.mark.asyncio
async def test_run_one_schedule_sends_notification_when_channel_set():
    """Notification is sent when notification_channel_id is configured."""
    channel = _make_channel()
    sr = _make_scheduled_report(notification_channel_id=channel.id)

    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    fake_content = {"template": "executive_summary"}

    ctx, _ = _make_session_ctx()

    mock_engine = AsyncMock()
    mock_engine.generate = AsyncMock(return_value=fake_content)

    with patch("app.services.report_scheduler.AsyncSessionLocal", return_value=ctx):
        with patch(
            "app.repositories.report_repo.ReportRepo.create",
            new=AsyncMock(return_value=MagicMock()),
        ):
            with patch(
                "app.repositories.report_repo.ReportRepo.update_status",
                new=AsyncMock(return_value=True),
            ):
                with patch(
                    "app.repositories.scheduled_report_repo.ScheduledReportRepo.update_run_times",
                    new=AsyncMock(return_value=True),
                ):
                    with patch(
                        "app.services.report_scheduler.ReportEngine",
                        return_value=mock_engine,
                    ):
                        with patch(
                            "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                            new=AsyncMock(return_value=channel),
                        ):
                            await _run_one_schedule(sr, dispatcher=dispatcher)

    dispatcher._dispatch_one.assert_awaited_once()
    call_channel, call_notif = dispatcher._dispatch_one.await_args.args
    assert call_channel is channel
    assert "report_id" in call_notif


@pytest.mark.asyncio
async def test_run_one_schedule_skips_notification_when_no_channel():
    """No notification is sent when notification_channel_id is None."""
    sr = _make_scheduled_report(notification_channel_id=None)
    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    fake_content = {"template": "executive_summary"}
    ctx, _ = _make_session_ctx()
    mock_engine = AsyncMock()
    mock_engine.generate = AsyncMock(return_value=fake_content)

    with patch("app.services.report_scheduler.AsyncSessionLocal", return_value=ctx):
        with patch("app.repositories.report_repo.ReportRepo.create", new=AsyncMock(return_value=MagicMock())):
            with patch("app.repositories.report_repo.ReportRepo.update_status", new=AsyncMock(return_value=True)):
                with patch("app.repositories.scheduled_report_repo.ScheduledReportRepo.update_run_times", new=AsyncMock(return_value=True)):
                    with patch("app.services.report_scheduler.ReportEngine", return_value=mock_engine):
                        await _run_one_schedule(sr, dispatcher=dispatcher)

    dispatcher._dispatch_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_one_schedule_skips_notification_when_dispatcher_none():
    """No notification is sent when dispatcher is None."""
    channel = _make_channel()
    sr = _make_scheduled_report(notification_channel_id=channel.id)

    fake_content = {"template": "executive_summary"}
    ctx, _ = _make_session_ctx()
    mock_engine = AsyncMock()
    mock_engine.generate = AsyncMock(return_value=fake_content)

    # If it tried to dispatch, it would fail since we pass None dispatcher
    with patch("app.services.report_scheduler.AsyncSessionLocal", return_value=ctx):
        with patch("app.repositories.report_repo.ReportRepo.create", new=AsyncMock(return_value=MagicMock())):
            with patch("app.repositories.report_repo.ReportRepo.update_status", new=AsyncMock(return_value=True)):
                with patch("app.repositories.scheduled_report_repo.ScheduledReportRepo.update_run_times", new=AsyncMock(return_value=True)):
                    with patch("app.services.report_scheduler.ReportEngine", return_value=mock_engine):
                        await _run_one_schedule(sr, dispatcher=None)  # must not raise


@pytest.mark.asyncio
async def test_run_one_schedule_skips_notification_when_channel_not_found():
    """No notification attempt when channel_id is set but channel does not exist in DB."""
    sr = _make_scheduled_report(notification_channel_id=999)
    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    fake_content = {"template": "executive_summary"}
    ctx, _ = _make_session_ctx()
    mock_engine = AsyncMock()
    mock_engine.generate = AsyncMock(return_value=fake_content)

    with patch("app.services.report_scheduler.AsyncSessionLocal", return_value=ctx):
        with patch("app.repositories.report_repo.ReportRepo.create", new=AsyncMock(return_value=MagicMock())):
            with patch("app.repositories.report_repo.ReportRepo.update_status", new=AsyncMock(return_value=True)):
                with patch("app.repositories.scheduled_report_repo.ScheduledReportRepo.update_run_times", new=AsyncMock(return_value=True)):
                    with patch("app.services.report_scheduler.ReportEngine", return_value=mock_engine):
                        with patch(
                            "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                            new=AsyncMock(return_value=None),
                        ):
                            await _run_one_schedule(sr, dispatcher=dispatcher)

    dispatcher._dispatch_one.assert_not_awaited()


# ---------------------------------------------------------------------------
# report_scheduler_task() outer loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scheduler_task_calls_cycle_on_interval():
    """report_scheduler_task() calls _run_scheduler_cycle on each interval."""
    from app.services.report_scheduler import report_scheduler_task

    cycles: list[int] = []

    async def fake_cycle(dispatcher):
        cycles.append(1)

    with patch("app.services.report_scheduler._run_scheduler_cycle", side_effect=fake_cycle):
        with patch("app.services.report_scheduler._CHECK_INTERVAL_SECS", 0):
            task = asyncio.create_task(report_scheduler_task(dispatcher=None))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    assert len(cycles) >= 1


@pytest.mark.asyncio
async def test_scheduler_task_stops_on_cancel():
    """report_scheduler_task() stops cleanly when cancelled."""
    from app.services.report_scheduler import report_scheduler_task

    with patch("app.services.report_scheduler._run_scheduler_cycle", new=AsyncMock()):
        with patch("app.services.report_scheduler._CHECK_INTERVAL_SECS", 0):
            task = asyncio.create_task(report_scheduler_task(dispatcher=None))
            await asyncio.sleep(0)
            task.cancel()
            # Should not raise anything except CancelledError which is swallowed
            try:
                await task
            except asyncio.CancelledError:
                pass
