"""Background task: data retention cleanup — feature 38.4.

Runs daily at 02:00 UTC. Hard-deletes PostgreSQL records that exceed the
configured retention periods:

  - Detections older than ``retention_alerts_days``
  - Resolved/closed incidents with ``closed_at`` older than
    ``retention_incidents_days``
  - IOCs whose ``expires_at`` is older than ``retention_iocs_days``

OpenSearch ILM policies (feature 38.2) handle event/alert index cleanup
independently; this task only touches the PostgreSQL/SQLite tables.

Cleanup counts are written to the audit log and reported to Prometheus via
``mxtac_retention_deleted_total{type}``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import delete, func, select

from ..core.config import settings
from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..core import metrics
from ..models.detection import Detection
from ..models.incident import Incident
from ..models.ioc import IOC
from .audit import get_audit_logger

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = get_logger(__name__)


async def _delete_old_detections(session: AsyncSession, cutoff: datetime) -> int:
    """Hard-delete detections created before *cutoff*. Returns deleted row count."""
    result = await session.execute(
        delete(Detection).where(Detection.created_at < cutoff)
    )
    await session.flush()
    return result.rowcount


async def _delete_old_incidents(session: AsyncSession, cutoff: datetime) -> int:
    """Hard-delete resolved/closed incidents with ``closed_at`` before *cutoff*.

    Only incidents in terminal states (resolved, closed) are eligible so that
    active investigations are never removed during cleanup.
    """
    result = await session.execute(
        delete(Incident).where(
            Incident.status.in_(("resolved", "closed")),
            Incident.closed_at.is_not(None),
            Incident.closed_at < cutoff,
        )
    )
    await session.flush()
    return result.rowcount


async def _delete_old_iocs(session: AsyncSession, cutoff: datetime) -> int:
    """Hard-delete IOCs whose ``expires_at`` timestamp is before *cutoff*.

    Only IOCs with an explicit expiry date are deleted; IOCs without
    ``expires_at`` are retained indefinitely by this task.
    """
    result = await session.execute(
        delete(IOC).where(
            IOC.expires_at.is_not(None),
            IOC.expires_at < cutoff,
        )
    )
    await session.flush()
    return result.rowcount


async def data_retention_task() -> None:
    """Daily data retention cleanup — fires at 02:00 UTC.

    Sleeps until the next 02:00 UTC window, then deletes records from
    PostgreSQL that exceed the configured retention periods.  Runs
    indefinitely until cancelled on shutdown.
    """
    logger.info(
        "Data retention task started "
        "(alerts_days=%d incidents_days=%d iocs_days=%d)",
        settings.retention_alerts_days,
        settings.retention_incidents_days,
        settings.retention_iocs_days,
    )

    while True:
        # Sleep until the next 02:00 UTC.
        now = datetime.now(timezone.utc)
        next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        sleep_secs = (next_run - now).total_seconds()

        try:
            await asyncio.sleep(sleep_secs)
        except asyncio.CancelledError:
            raise

        try:
            now = datetime.now(timezone.utc)
            alerts_cutoff = now - timedelta(days=settings.retention_alerts_days)
            incidents_cutoff = now - timedelta(days=settings.retention_incidents_days)
            iocs_cutoff = now - timedelta(days=settings.retention_iocs_days)

            async with AsyncSessionLocal() as session:
                n_detections = await _delete_old_detections(session, alerts_cutoff)
                n_incidents = await _delete_old_incidents(session, incidents_cutoff)
                n_iocs = await _delete_old_iocs(session, iocs_cutoff)
                await session.commit()

            # Prometheus counters — only increment for non-zero deletes
            if n_detections:
                metrics.retention_deleted.labels(type="detection").inc(n_detections)
            if n_incidents:
                metrics.retention_deleted.labels(type="incident").inc(n_incidents)
            if n_iocs:
                metrics.retention_deleted.labels(type="ioc").inc(n_iocs)

            total = n_detections + n_incidents + n_iocs

            if total:
                # Audit log — best-effort, no DB session (OpenSearch write only)
                try:
                    audit = get_audit_logger()
                    await audit.log(
                        actor="system",
                        action="retention_cleanup",
                        resource_type="data_retention",
                        details={
                            "detections_deleted": n_detections,
                            "incidents_deleted": n_incidents,
                            "iocs_deleted": n_iocs,
                            "total_deleted": total,
                            "retention_alerts_days": settings.retention_alerts_days,
                            "retention_incidents_days": settings.retention_incidents_days,
                            "retention_iocs_days": settings.retention_iocs_days,
                        },
                    )
                except Exception:
                    logger.debug("Retention audit log write failed (non-fatal)")

                logger.info(
                    "Data retention cleanup: detections=%d incidents=%d iocs=%d total=%d",
                    n_detections,
                    n_incidents,
                    n_iocs,
                    total,
                )
            else:
                logger.debug("Data retention: no records eligible for deletion this cycle")

        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "Data retention task iteration failed — will retry at next 02:00 UTC"
            )


async def get_retention_storage_stats(session: AsyncSession) -> dict:
    """Return current PostgreSQL row counts and deletion-eligible counts.

    Used by the ``GET /admin/retention`` endpoint to provide storage usage
    alongside the retention policy settings.
    """
    now = datetime.now(timezone.utc)
    alerts_cutoff = now - timedelta(days=settings.retention_alerts_days)
    incidents_cutoff = now - timedelta(days=settings.retention_incidents_days)
    iocs_cutoff = now - timedelta(days=settings.retention_iocs_days)

    # Total counts
    detections_total = (
        await session.scalar(select(func.count()).select_from(Detection))
    ) or 0
    incidents_total = (
        await session.scalar(select(func.count()).select_from(Incident))
    ) or 0
    iocs_total = (
        await session.scalar(select(func.count()).select_from(IOC))
    ) or 0

    # Eligible-for-deletion counts
    detections_eligible = (
        await session.scalar(
            select(func.count())
            .select_from(Detection)
            .where(Detection.created_at < alerts_cutoff)
        )
    ) or 0
    incidents_eligible = (
        await session.scalar(
            select(func.count())
            .select_from(Incident)
            .where(
                Incident.status.in_(("resolved", "closed")),
                Incident.closed_at.is_not(None),
                Incident.closed_at < incidents_cutoff,
            )
        )
    ) or 0
    iocs_eligible = (
        await session.scalar(
            select(func.count())
            .select_from(IOC)
            .where(
                IOC.expires_at.is_not(None),
                IOC.expires_at < iocs_cutoff,
            )
        )
    ) or 0

    return {
        "detections_total": detections_total,
        "incidents_total": incidents_total,
        "iocs_total": iocs_total,
        "detections_eligible_for_deletion": detections_eligible,
        "incidents_eligible_for_deletion": incidents_eligible,
        "iocs_eligible_for_deletion": iocs_eligible,
    }
