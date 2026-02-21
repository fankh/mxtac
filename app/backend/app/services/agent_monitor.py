"""Background task: auto-degrade agents that stop sending heartbeats.

Degradation rules:
  - No heartbeat for >= 2 min  → degraded  (from online)
  - No heartbeat for >= 10 min → offline   (from online or degraded)

The monitor runs every 60 seconds and updates agent statuses in-place.
It is started as an asyncio.create_task in main.py on_startup.
"""

from __future__ import annotations

import asyncio

from ..core.database import AsyncSessionLocal
from ..core.logging import get_logger
from ..repositories.agent_repo import AgentRepo

logger = get_logger(__name__)

_CHECK_INTERVAL_SECS = 60  # run every minute


async def agent_status_monitor() -> None:
    """Periodically check all agents and degrade stale ones.

    Runs indefinitely until the task is cancelled (on shutdown).
    """
    logger.info("Agent status monitor started (interval=%ds)", _CHECK_INTERVAL_SECS)
    while True:
        try:
            await asyncio.sleep(_CHECK_INTERVAL_SECS)
            async with AsyncSessionLocal() as session:
                degraded, offline = await AgentRepo.degrade_stale_agents(session)
                await session.commit()
            if degraded or offline:
                logger.info(
                    "Agent monitor: newly degraded=%d newly offline=%d",
                    degraded,
                    offline,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Agent status monitor iteration failed")
