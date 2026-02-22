"""Background task: scheduled report generation — feature 31.4.

Runs a check loop every 60 seconds.  On each tick it:
  1. Queries ScheduledReport rows where enabled=True AND next_run_at <= now().
  2. For each due schedule, generates the report via ReportEngine.
  3. If notification_channel_id is set, sends a notification via the
     NotificationDispatcher.
  4. Persists the new Report record and updates last_run_at / next_run_at.

Cron expressions are evaluated in UTC using the ``croniter`` library.
Each schedule's next_run_at is calculated from the time the report ran
(not the scheduled time), so the schedule stays stable even when the
process is briefly interrupted.

Error handling:
  - A failure in one schedule does not abort the remaining schedules.
  - Notification failures are logged and swallowed; the report record is
    still marked as ready.
  - A complete failure of the scheduler cycle is logged and the task
    continues to the next interval.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..models.base import new_uuid

if TYPE_CHECKING:
    from ..models.scheduled_report import ScheduledReport
    from .notification_dispatcher import NotificationDispatcher

logger = get_logger(__name__)

_CHECK_INTERVAL_SECS = 60  # run the check loop every minute


# ---------------------------------------------------------------------------
# Cron helpers
# ---------------------------------------------------------------------------


def calculate_next_run(cron_expression: str, after: datetime | None = None) -> datetime:
    """Return the next fire time for *cron_expression* (UTC) after *after*.

    *after* defaults to now (UTC).  The returned datetime is always UTC-aware.
    """
    from croniter import croniter  # noqa: PLC0415

    base = after or datetime.now(timezone.utc)
    # croniter works with naive datetimes internally; strip tzinfo, then re-add.
    base_naive = base.replace(tzinfo=None)
    it = croniter(cron_expression, base_naive)
    next_naive: datetime = it.get_next(datetime)
    return next_naive.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Notification helper
# ---------------------------------------------------------------------------


def _build_report_notification(sr: "ScheduledReport", report_id: str) -> dict[str, Any]:
    """Build an alert-like dict for report delivery via NotificationDispatcher."""
    return {
        "id": report_id,
        "rule_id": sr.id,
        "rule_title": f"Scheduled Report: {sr.name}",
        "level": "low",  # informational
        "technique_ids": [],
        "tactic_ids": [],
        "host": "mxtac-scheduler",
        "time": datetime.now(timezone.utc).isoformat(),
        "score": 0,
        "scheduled_report_id": sr.id,
        "scheduled_report_name": sr.name,
        "report_template": sr.template_type,
        "report_id": report_id,
    }


# ---------------------------------------------------------------------------
# Per-schedule execution
# ---------------------------------------------------------------------------


async def _run_one_schedule(
    sr: "ScheduledReport",
    dispatcher: "NotificationDispatcher | None",
) -> None:
    """Generate the report for a single schedule and update its run times.

    Opens its own DB session to stay independent of the outer session that
    loaded the schedule list.
    """
    from ..repositories.report_repo import ReportRepo
    from ..repositories.scheduled_report_repo import ScheduledReportRepo
    from ..services.report_engine import ReportEngine

    now = datetime.now(timezone.utc)

    # Compute the time window: look back ``period_days`` days (default 7)
    period_days = int(sr.params_json.get("period_days", 7))
    to_date = now
    from_date = now - timedelta(days=period_days)

    # Build params for ReportEngine (same format as on-demand generation)
    params: dict[str, Any] = {
        "from_date": from_date,
        "to_date": to_date,
    }
    # Forward any template-specific extras (e.g. framework for compliance_summary)
    for key, val in sr.params_json.items():
        if key != "period_days":
            params[key] = val

    report_id = new_uuid()

    # ── Generate the report ──────────────────────────────────────────────────
    async with AsyncSessionLocal() as session:
        try:
            # Persist a 'generating' record first
            await ReportRepo.create(
                session,
                id=report_id,
                template_type=sr.template_type,
                format=sr.format,
                params_json={
                    "from_date": from_date.isoformat(),
                    "to_date": to_date.isoformat(),
                    **{k: v for k, v in sr.params_json.items() if k != "period_days"},
                },
                created_by=sr.created_by,
            )
            await session.commit()

            # Generate content
            engine = ReportEngine(session)
            content = await engine.generate(sr.template_type, params)

            await ReportRepo.update_status(
                session, report_id, "ready", content_json=content
            )
            await session.commit()

            logger.info(
                "Scheduled report generated: id=%s schedule=%r template=%s",
                report_id,
                sr.name,
                sr.template_type,
            )

        except Exception as exc:
            await session.rollback()
            logger.exception(
                "Scheduled report generation failed: schedule=%r error=%s",
                sr.name,
                exc,
            )
            # Record failure — open a fresh session
            try:
                async with AsyncSessionLocal() as err_session:
                    await ReportRepo.update_status(
                        err_session, report_id, "failed", error=str(exc)
                    )
                    await err_session.commit()
            except Exception:
                pass
            # Still update run times below so we don't re-run immediately
        finally:
            # Calculate and persist updated run times regardless of success/failure
            try:
                next_run = calculate_next_run(sr.schedule, after=now)
            except Exception:
                next_run = None

            async with AsyncSessionLocal() as ts_session:
                await ScheduledReportRepo.update_run_times(
                    ts_session,
                    sr.id,
                    last_run_at=now,
                    next_run_at=next_run,
                )
                await ts_session.commit()

    # ── Send notification (optional) ─────────────────────────────────────────
    if sr.notification_channel_id is None or dispatcher is None:
        return

    try:
        from ..repositories.notification_channel_repo import NotificationChannelRepo

        async with AsyncSessionLocal() as nc_session:
            channel = await NotificationChannelRepo.get_by_id(
                nc_session, sr.notification_channel_id
            )

        if channel is None:
            logger.warning(
                "Scheduled report: notification_channel_id=%d not found for schedule=%r",
                sr.notification_channel_id,
                sr.name,
            )
            return

        if not channel.enabled:
            logger.debug(
                "Scheduled report: channel_id=%d is disabled — skipping notification",
                sr.notification_channel_id,
            )
            return

        notification = _build_report_notification(sr, report_id)
        await dispatcher._dispatch_one(channel, notification)
        logger.info(
            "Scheduled report notification sent: schedule=%r channel=%r",
            sr.name,
            channel.name,
        )

    except Exception:
        logger.exception(
            "Scheduled report notification failed: schedule=%r channel_id=%s",
            sr.name,
            sr.notification_channel_id,
        )


# ---------------------------------------------------------------------------
# Scheduler cycle
# ---------------------------------------------------------------------------


async def _run_scheduler_cycle(
    dispatcher: "NotificationDispatcher | None",
) -> None:
    """Check for due schedules and run each one."""
    from ..repositories.scheduled_report_repo import ScheduledReportRepo

    async with AsyncSessionLocal() as session:
        due = await ScheduledReportRepo.find_due(session)

    if not due:
        logger.debug("Report scheduler: no due schedules")
        return

    logger.info("Report scheduler: %d due schedule(s) found", len(due))

    for sr in due:
        try:
            await _run_one_schedule(sr, dispatcher)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "Report scheduler: unexpected error for schedule=%r", sr.name
            )


# ---------------------------------------------------------------------------
# Background task entry point
# ---------------------------------------------------------------------------


async def report_scheduler_task(
    dispatcher: "NotificationDispatcher | None" = None,
) -> None:
    """Periodically check for and execute due scheduled reports.

    Args:
        dispatcher: Shared :class:`NotificationDispatcher` instance.  When
            *None* notifications are skipped for all schedules.
    """
    logger.info(
        "Report scheduler task started (check_interval=%ds)", _CHECK_INTERVAL_SECS
    )

    while True:
        try:
            await asyncio.sleep(_CHECK_INTERVAL_SECS)
        except asyncio.CancelledError:
            break

        try:
            await _run_scheduler_cycle(dispatcher)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Report scheduler cycle failed — will retry next interval")
