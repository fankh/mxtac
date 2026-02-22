"""Sigma evaluation consumer — reads normalized events, evaluates Sigma rules, publishes alerts."""

from __future__ import annotations

from typing import Any

from ..core.logging import get_logger
from ..engine.sigma_engine import SigmaEngine
from ..pipeline.queue import MessageQueue, Topic
from ..repositories.rule_repo import RuleRepo
from ..services.normalizers.ocsf import OCSFEvent

logger = get_logger(__name__)


async def sigma_consumer(
    queue: MessageQueue,
    engine: SigmaEngine,
    session_factory: Any = None,
) -> None:
    """Subscribe to mxtac.normalized and evaluate each event against loaded Sigma rules.

    When *session_factory* is provided (an async_sessionmaker or equivalent),
    each rule match atomically increments the rule's ``hit_count`` and
    ``last_hit_at`` columns in the database (feature 8.20).  DB failures are
    swallowed so that a database outage never stalls the evaluation pipeline.
    """

    async def _handle(event_dict: dict) -> None:
        try:
            event = OCSFEvent(**event_dict)
            async for alert in engine.evaluate(event):
                alert_dict = {
                    "id": alert.id,
                    "rule_id": alert.rule_id,
                    "rule_title": alert.rule_title,
                    "level": alert.level,
                    "severity_id": alert.severity_id,
                    "technique_ids": alert.technique_ids,
                    "tactic_ids": alert.tactic_ids,
                    "host": alert.host,
                    "time": alert.time.isoformat(),
                    "event_snapshot": alert.event_snapshot,
                }
                await queue.publish(Topic.ALERTS, alert_dict)
                logger.debug("Sigma match rule_id=%s host=%s", alert.rule_id, alert.host)

                # Feature 8.20 — persist hit to DB
                if session_factory is not None:
                    try:
                        async with session_factory() as session:
                            await RuleRepo.increment_hit(session, alert.rule_id)
                            await session.commit()
                    except Exception:
                        logger.debug(
                            "Rule hit_count update failed rule_id=%s", alert.rule_id
                        )
        except Exception:
            logger.exception("Sigma consumer error")

    await queue.subscribe(Topic.NORMALIZED, "sigma-eval", _handle)
    logger.info("Sigma consumer subscribed to %s", Topic.NORMALIZED)
