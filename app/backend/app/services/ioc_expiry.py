"""Background task: expire old and stale IOCs — feature 29.8.

Two expiry modes run each hour:

  1. expires_at expiry  — deactivate IOCs where expires_at < now()
     Uses IOCRepo.expire_old() which was already implemented for the repo layer.

  2. Stale-hit expiry   — deactivate active IOCs with no hit in > N days
     Uses IOCRepo.expire_stale(days=ioc_no_hit_expiry_days).
     Controlled by the IOC_NO_HIT_EXPIRY_DAYS setting (default 90).
     Set to 0 to disable this mode.

Both counts are summed and reported to the mxtac_iocs_expired_total counter.
"""

from __future__ import annotations

import asyncio

from ..core.config import settings
from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..core import metrics
from ..repositories.ioc_repo import IOCRepo

logger = get_logger(__name__)

_CHECK_INTERVAL_SECS = 3600  # run every hour


async def ioc_expiry_task() -> None:
    """Periodically expire time-limited and stale IOCs.

    Runs indefinitely until the task is cancelled (on shutdown).
    """
    logger.info(
        "IOC expiry task started (interval=%ds no_hit_expiry_days=%d)",
        _CHECK_INTERVAL_SECS,
        settings.ioc_no_hit_expiry_days,
    )
    while True:
        try:
            await asyncio.sleep(_CHECK_INTERVAL_SECS)
            async with AsyncSessionLocal() as session:
                # 1. Expire IOCs whose expires_at timestamp has passed.
                expired_count = await IOCRepo.expire_old(session)

                # 2. Expire IOCs with no hits in the configured window.
                stale_count = await IOCRepo.expire_stale(
                    session, days=settings.ioc_no_hit_expiry_days
                )

                await session.commit()

            total = expired_count + stale_count
            if total:
                metrics.iocs_expired.inc(total)
                logger.info(
                    "IOC expiry: deactivated %d IOC(s) "
                    "(expires_at=%d stale_hit=%d)",
                    total,
                    expired_count,
                    stale_count,
                )
            else:
                logger.debug("IOC expiry: no IOCs to deactivate this cycle")

        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("IOC expiry task iteration failed")
