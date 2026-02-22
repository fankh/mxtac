"""Normalizer pipeline — subscribes to raw topics and publishes normalized OCSF events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from ...core.logging import get_logger
from ...pipeline.queue import MessageQueue, Topic
from .wazuh import WazuhNormalizer
from .zeek import ZeekNormalizer
from .suricata import SuricataNormalizer

logger = get_logger(__name__)


class NormalizerPipeline:
    """Consumes raw events from all source topics, normalizes to OCSF, publishes to mxtac.normalized."""

    def __init__(self, queue: MessageQueue) -> None:
        self._queue = queue
        self._wazuh = WazuhNormalizer()
        self._zeek = ZeekNormalizer()
        self._suricata = SuricataNormalizer()

    async def start(self) -> None:
        """Subscribe to all raw topics."""
        await self._queue.subscribe(Topic.RAW_WAZUH, "normalizer", self._handle_wazuh)
        await self._queue.subscribe(Topic.RAW_ZEEK, "normalizer", self._handle_zeek)
        await self._queue.subscribe(Topic.RAW_SURICATA, "normalizer", self._handle_suricata)
        logger.info("NormalizerPipeline subscribed to raw topics")

    async def _send_to_dlq(
        self,
        source: str,
        raw: dict[str, Any],
        exc: Exception,
        error_type: str,
    ) -> None:
        """Publish a rejected event to the Dead Letter Queue."""
        dlq_message: dict[str, Any] = {
            "source": source,
            "raw": raw,
            "error": str(exc),
            "error_type": error_type,
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }
        await self._queue.publish(Topic.DLQ, dlq_message)
        logger.warning(
            "Event rejected to DLQ source=%s error_type=%s error=%s",
            source,
            error_type,
            exc,
        )

    async def _handle_wazuh(self, raw: dict[str, Any]) -> None:
        try:
            event = self._wazuh.normalize(raw)
            await self._queue.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        except ValidationError as exc:
            logger.warning("Wazuh schema validation error: %s", exc)
            await self._send_to_dlq("wazuh", raw, exc, "schema_validation")
        except Exception as exc:
            logger.exception("Wazuh normalization error")
            await self._send_to_dlq("wazuh", raw, exc, "normalization_error")

    async def _handle_zeek(self, raw: dict[str, Any]) -> None:
        try:
            event = self._zeek.normalize(raw)
            await self._queue.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        except ValidationError as exc:
            logger.warning("Zeek schema validation error: %s", exc)
            await self._send_to_dlq("zeek", raw, exc, "schema_validation")
        except Exception as exc:
            logger.exception("Zeek normalization error")
            await self._send_to_dlq("zeek", raw, exc, "normalization_error")

    async def _handle_suricata(self, raw: dict[str, Any]) -> None:
        try:
            event = self._suricata.normalize(raw)
            await self._queue.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        except ValidationError as exc:
            logger.warning("Suricata schema validation error: %s", exc)
            await self._send_to_dlq("suricata", raw, exc, "schema_validation")
        except Exception as exc:
            logger.exception("Suricata normalization error")
            await self._send_to_dlq("suricata", raw, exc, "normalization_error")
