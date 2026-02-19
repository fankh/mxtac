"""Sigma evaluation consumer — reads normalized events, evaluates Sigma rules, publishes alerts."""

from __future__ import annotations

from ..core.logging import get_logger
from ..engine.sigma_engine import SigmaEngine
from ..pipeline.queue import MessageQueue, Topic
from ..services.normalizers.ocsf import OCSFEvent

logger = get_logger(__name__)


async def sigma_consumer(queue: MessageQueue, engine: SigmaEngine) -> None:
    """Subscribe to mxtac.normalized and evaluate each event against loaded Sigma rules."""

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
        except Exception:
            logger.exception("Sigma consumer error")

    await queue.subscribe(Topic.NORMALIZED, "sigma-eval", _handle)
    logger.info("Sigma consumer subscribed to %s", Topic.NORMALIZED)
