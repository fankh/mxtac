"""Background task: auto-close inactive detections — feature 9.12.

Runs a check loop every 5 minutes.  On each tick it:
  1. Queries active detections where no detection with the same (rule_name, host)
     has been seen within the configured quiet window (default: 24 hours).
  2. Bulk-updates eligible detections to status='closed'.
  3. Logs each closure for audit purposes.

Configuration (via Settings):
  alert_auto_close_enabled           — enable/disable the task (default: True)
  alert_auto_close_no_recurrence_hours — quiet-window in hours (default: 24)

Error handling:
  - DB errors during the find phase abort the cycle; the task retries next interval.
  - DB errors during the close phase are logged; the task continues next interval.
  - CancelledError is propagated cleanly so the task can be cancelled on shutdown.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from ..core.config import settings
from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..repositories.detection_repo import DetectionRepo

logger = get_logger(__name__)

_CHECK_INTERVAL_SECS = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Core cycle
# ---------------------------------------------------------------------------


async def _run_auto_close_cycle(no_recurrence_hours: int) -> None:
    """Find and close detections whose (rule_name, host) cluster has gone quiet.

    Opens a single DB session to find eligible detections, then closes them in
    one bulk UPDATE.  A second session is used for the update so the find and
    write are independent — this avoids holding a long-lived transaction.
    """
    async with AsyncSessionLocal() as session:
        eligible = await DetectionRepo.find_stale_active_detections(
            session, no_recurrence_hours
        )

    if not eligible:
        logger.debug("Alert auto-closer: no eligible detections")
        return

    ids = [d.id for d in eligible]
    logger.info(
        "Alert auto-closer: %d detection(s) eligible for auto-close (window=%dh)",
        len(ids),
        no_recurrence_hours,
    )

    try:
        async with AsyncSessionLocal() as session:
            count = await DetectionRepo.auto_close_by_ids(session, ids)
            await session.commit()
        logger.info("Alert auto-closer: closed %d detection(s)", count)

        for d in eligible:
            logger.info(
                "Alert auto-closer: closed detection id=%s host=%s rule=%s",
                d.id,
                d.host,
                d.rule_name,
            )
    except Exception:
        logger.exception("Alert auto-closer: bulk close failed — will retry next cycle")


# ---------------------------------------------------------------------------
# Background task entry point
# ---------------------------------------------------------------------------


async def alert_auto_closer_task() -> None:
    """Periodically auto-close detections with no recurrence in N hours.

    Reads configuration from ``settings.alert_auto_close_no_recurrence_hours``.
    The task is a no-op (but still sleeps) when
    ``settings.alert_auto_close_enabled`` is False, allowing the setting to be
    toggled at runtime via an env-var reload without restarting the process.
    """
    no_recurrence_hours = settings.alert_auto_close_no_recurrence_hours
    logger.info(
        "Alert auto-closer task started (check_interval=%ds, window=%dh, enabled=%s)",
        _CHECK_INTERVAL_SECS,
        no_recurrence_hours,
        settings.alert_auto_close_enabled,
    )

    while True:
        try:
            await asyncio.sleep(_CHECK_INTERVAL_SECS)
        except asyncio.CancelledError:
            break

        if not settings.alert_auto_close_enabled:
            logger.debug("Alert auto-closer: disabled — skipping cycle")
            continue

        try:
            await _run_auto_close_cycle(no_recurrence_hours)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Alert auto-closer cycle failed — will retry next interval")
