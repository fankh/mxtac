"""Dead Letter Queue consumer — Feature 5.8: Dead letter queue — failed events.

Subscribes to ``mxtac.dlq`` and processes events that could not be
normalized or validated by the ingestion pipeline.  Each rejected event
arrives with the fields published by NormalizerPipeline._send_to_dlq():

  source      — originating normalizer ("wazuh" / "zeek" / "suricata")
  raw         — original raw event dict as received from the source topic
  error       — string representation of the exception that caused the failure
  error_type  — classification: "schema_validation" | "normalization_error"
  failed_at   — ISO 8601 UTC timestamp of when the failure occurred

This consumer is intentionally read-only.  It does not retry or re-route
failed events.  Its purpose is to provide operational visibility into
pipeline failures so that operators can diagnose normalizer issues and
malformed event sources.

For each DLQ message the consumer:
  1. Logs the failure at WARNING level with full structured context.
  2. Increments mxtac_dlq_events_total{source, error_type} for Prometheus.
"""

from __future__ import annotations

from typing import Any

from ..core.logging import get_logger
from ..core.metrics import dlq_events_total
from ..pipeline.queue import MessageQueue, Topic

logger = get_logger(__name__)


async def dlq_consumer(queue: MessageQueue) -> None:
    """Subscribe to ``mxtac.dlq`` and process all failed events.

    Must be called once during application startup after the queue has been
    started.  Registers a background consumer task; returns immediately.
    """

    async def _handle(message: dict[str, Any]) -> None:
        source = message.get("source", "unknown")
        error_type = message.get("error_type", "unknown")
        error = message.get("error", "")
        failed_at = message.get("failed_at", "")

        logger.warning(
            "DLQ event received source=%s error_type=%s failed_at=%s error=%s",
            source,
            error_type,
            failed_at,
            error,
        )

        dlq_events_total.labels(source=source, error_type=error_type).inc()

    await queue.subscribe(Topic.DLQ, "dlq-consumer", _handle)
    logger.info("DLQ consumer subscribed to %s", Topic.DLQ)
