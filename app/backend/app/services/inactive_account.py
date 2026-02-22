"""Background task: inactive account lock — feature 1.7.

Runs daily at 03:00 UTC. Locks any active user account whose ``last_login_at``
timestamp is older than ``account_inactivity_days`` days (default: 90).

Locking sets ``is_active=False`` and records ``inactive_locked_at`` so that
administrators can distinguish inactivity-locked accounts from manually
disabled ones.  An audit log entry is written for each run that locks accounts.

Administrators can re-activate locked accounts via ``PATCH /api/v1/users/{id}``
(set ``is_active=True``).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from ..core.config import settings
from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..models.user import User
from .audit import get_audit_logger

logger = get_logger(__name__)


async def inactive_account_lock_task() -> None:
    """Daily inactive account lock — fires at 03:00 UTC.

    Sleeps until the next 03:00 UTC window, then locks all active users whose
    ``last_login_at`` is older than ``account_inactivity_days`` days.  Runs
    indefinitely until cancelled on shutdown.
    """
    if settings.account_inactivity_days <= 0:
        logger.info(
            "Inactive account lock task disabled (account_inactivity_days=%d)",
            settings.account_inactivity_days,
        )
        return

    logger.info(
        "Inactive account lock task started (inactivity_days=%d)",
        settings.account_inactivity_days,
    )

    while True:
        # Sleep until the next 03:00 UTC.
        now = datetime.now(timezone.utc)
        next_run = now.replace(hour=3, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        sleep_secs = (next_run - now).total_seconds()

        try:
            await asyncio.sleep(sleep_secs)
        except asyncio.CancelledError:
            raise

        try:
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(days=settings.account_inactivity_days)

            async with AsyncSessionLocal() as session:
                # Collect emails before the update for audit logging.
                result = await session.execute(
                    select(User.email).where(
                        User.is_active == True,  # noqa: E712
                        User.last_login_at.is_not(None),
                        User.last_login_at < cutoff,
                    )
                )
                locked_emails = list(result.scalars().all())

                if locked_emails:
                    await session.execute(
                        update(User)
                        .where(
                            User.is_active == True,  # noqa: E712
                            User.last_login_at.is_not(None),
                            User.last_login_at < cutoff,
                        )
                        .values(is_active=False, inactive_locked_at=now)
                        .execution_options(synchronize_session="fetch")
                    )

                await session.commit()

            if locked_emails:
                try:
                    audit = get_audit_logger()
                    await audit.log(
                        actor="system",
                        action="inactive_account_lock",
                        resource_type="user",
                        details={
                            "locked_count": len(locked_emails),
                            "locked_emails": locked_emails,
                            "inactivity_days": settings.account_inactivity_days,
                            "cutoff": cutoff.isoformat(),
                        },
                    )
                except Exception:
                    logger.debug("Inactive account lock audit log write failed (non-fatal)")

                logger.info(
                    "Inactive account lock: locked %d account(s) inactive for >%d days",
                    len(locked_emails),
                    settings.account_inactivity_days,
                )
            else:
                logger.debug(
                    "Inactive account lock: no accounts eligible for locking this cycle"
                )

        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "Inactive account lock task iteration failed — will retry at next 03:00 UTC"
            )
