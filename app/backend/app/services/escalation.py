"""Background task: escalate unacknowledged critical/high alerts — feature 27.7.

Runs every 5 minutes.  For each detection that:
  - has status="active"
  - has severity in ("critical", "high")
  - has been active for longer than escalation_timeout_minutes (default 30 min)

…an escalation notification is sent to the configured escalation_channel_id
and the detection ID is recorded in Valkey (key: ``escalated:{detection_id}``)
so that each detection is escalated at most once.

If ``escalation_channel_id`` is not configured (None) the task is a no-op.
Valkey failures are treated as fail-open: a temporarily unavailable Valkey may
cause a duplicate escalation, which is preferable to silently dropping one.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from ..core.config import settings
from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..core.valkey import get_valkey_client
from ..models.detection import Detection

if TYPE_CHECKING:
    from ..models.notification import NotificationChannel
    from .notification_dispatcher import NotificationDispatcher

logger = get_logger(__name__)

_CHECK_INTERVAL_SECS = 300  # 5 minutes
_ESCALATION_SEVERITIES = {"critical", "high"}
_VALKEY_KEY_PREFIX = "escalated:"


# ---------------------------------------------------------------------------
# Alert dict builder
# ---------------------------------------------------------------------------


def _build_escalation_alert(detection: Detection, minutes_active: int) -> dict[str, Any]:
    """Build an alert-like dict for the escalation notification.

    Mirrors the enriched-alert schema expected by NotificationDispatcher
    channel senders, with an extra ``escalation_message`` field.
    """
    return {
        "id": detection.id,
        "rule_id": detection.rule_name or detection.id,
        "rule_title": detection.name,
        "level": detection.severity,
        "technique_ids": [detection.technique_id] if detection.technique_id else [],
        "tactic_ids": [detection.tactic] if detection.tactic else [],
        "host": detection.host,
        "time": detection.created_at.isoformat(),
        "score": detection.score,
        "escalated": True,
        "escalation_message": (
            f"ESCALATED \u2014 unacknowledged for {minutes_active} minutes"
        ),
    }


# ---------------------------------------------------------------------------
# Valkey helpers
# ---------------------------------------------------------------------------


async def _is_already_escalated(detection_id: str) -> bool:
    """Return True if this detection has already been escalated (Valkey SET NX check).

    Fails open (returns False) on Valkey error so that unavailability does not
    permanently suppress escalations.
    """
    try:
        client = await get_valkey_client()
        result = await client.get(f"{_VALKEY_KEY_PREFIX}{detection_id}")
        return result is not None
    except Exception:
        logger.debug(
            "Valkey unavailable — assuming detection %s not yet escalated", detection_id
        )
        return False  # fail-open


async def _mark_escalated(detection_id: str) -> None:
    """Record that *detection_id* has been escalated using SET NX (one-time flag).

    No TTL is set: the key persists until the detection is resolved and the DB
    record is eventually pruned by the retention task.  Failures are logged at
    DEBUG level and swallowed (non-fatal).
    """
    try:
        client = await get_valkey_client()
        await client.set(f"{_VALKEY_KEY_PREFIX}{detection_id}", "1", nx=True)
    except Exception:
        logger.debug(
            "Valkey unavailable — could not mark detection %s as escalated", detection_id
        )


# ---------------------------------------------------------------------------
# Core escalation cycle
# ---------------------------------------------------------------------------


async def _run_escalation_cycle(dispatcher: NotificationDispatcher) -> None:
    """Query overdue active detections and dispatch escalation notifications.

    Called by :func:`escalation_task` on every check interval.
    """
    from ..repositories.notification_channel_repo import NotificationChannelRepo

    timeout = timedelta(minutes=settings.escalation_timeout_minutes)
    cutoff = datetime.now(timezone.utc) - timeout

    async with AsyncSessionLocal() as session:
        # Fetch escalation channel — bail early if missing or disabled
        channel = await NotificationChannelRepo.get_by_id(
            session, settings.escalation_channel_id  # type: ignore[arg-type]
        )
        if channel is None:
            logger.warning(
                "Escalation task: channel_id=%d not found in DB — skipping cycle",
                settings.escalation_channel_id,
            )
            return

        if not channel.enabled:
            logger.debug(
                "Escalation task: channel_id=%d is disabled — skipping cycle",
                settings.escalation_channel_id,
            )
            return

        # Query overdue active critical/high detections
        result = await session.execute(
            select(Detection).where(
                Detection.status == "active",
                Detection.severity.in_(_ESCALATION_SEVERITIES),
                Detection.created_at <= cutoff,
            )
        )
        detections = list(result.scalars().all())

    if not detections:
        logger.debug("Escalation task: no overdue detections found")
        return

    now = datetime.now(timezone.utc)
    escalated_count = 0

    for detection in detections:
        if await _is_already_escalated(detection.id):
            continue

        # Compute time since detection was created (active duration)
        created_at = detection.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        minutes_active = max(1, int((now - created_at).total_seconds() / 60))

        alert = _build_escalation_alert(detection, minutes_active)

        try:
            await dispatcher._dispatch_one(channel, alert)
            await _mark_escalated(detection.id)
            escalated_count += 1
            logger.info(
                "Escalated detection id=%s severity=%s host=%s age=%dm",
                detection.id,
                detection.severity,
                detection.host,
                minutes_active,
            )
        except Exception:
            logger.exception(
                "Escalation send failed for detection id=%s channel_id=%d",
                detection.id,
                channel.id,
            )

    if escalated_count:
        logger.info("Escalation task: escalated %d detection(s)", escalated_count)


# ---------------------------------------------------------------------------
# Background task entry point
# ---------------------------------------------------------------------------


async def escalation_task(dispatcher: NotificationDispatcher | None = None) -> None:
    """Periodically escalate unacknowledged critical/high detections.

    Args:
        dispatcher: Shared :class:`NotificationDispatcher` instance.  When
            *None* (e.g. if the dispatcher failed to start) a private instance
            is created and closed on task exit.
    """
    from .notification_dispatcher import NotificationDispatcher as _Dispatcher

    own_dispatcher = dispatcher is None
    if own_dispatcher:
        dispatcher = _Dispatcher()

    logger.info(
        "Escalation task started (interval=%ds timeout_min=%d channel_id=%s)",
        _CHECK_INTERVAL_SECS,
        settings.escalation_timeout_minutes,
        settings.escalation_channel_id,
    )

    try:
        while True:
            try:
                await asyncio.sleep(_CHECK_INTERVAL_SECS)
            except asyncio.CancelledError:
                break

            if settings.escalation_channel_id is None:
                logger.debug(
                    "Escalation task: escalation_channel_id not configured — skipping"
                )
                continue

            try:
                await _run_escalation_cycle(dispatcher)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Escalation task iteration failed")
    finally:
        if own_dispatcher:
            try:
                await dispatcher.close()
            except Exception:
                pass
