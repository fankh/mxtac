"""Normalizer pipeline — subscribes to raw topics and publishes normalized OCSF events."""

from __future__ import annotations

from typing import Any

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

    async def _handle_wazuh(self, raw: dict[str, Any]) -> None:
        try:
            event = self._wazuh.normalize(raw)
            await self._queue.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        except Exception:
            logger.exception("Wazuh normalization error")

    async def _handle_zeek(self, raw: dict[str, Any]) -> None:
        try:
            event = self._zeek.normalize(raw)
            await self._queue.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        except Exception:
            logger.exception("Zeek normalization error")

    async def _handle_suricata(self, raw: dict[str, Any]) -> None:
        try:
            event = self._suricata.normalize(raw)
            await self._queue.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        except Exception:
            logger.exception("Suricata normalization error")
