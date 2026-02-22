"""Normalizer pipeline — subscribes to raw topics and publishes normalized OCSF events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from ...core.logging import get_logger
from ...pipeline.queue import MessageQueue, Topic
from .field_mapping import FieldMappingConfig
from .wazuh import WazuhNormalizer
from .zeek import ZeekNormalizer
from .suricata import SuricataNormalizer

if TYPE_CHECKING:
    from ..auto_discovery import AssetDiscovery

logger = get_logger(__name__)

# Internal metadata key injected by BaseConnector (Feature 7.15)
_FIELD_MAPPING_KEY = "_mxtac_field_mapping"


def _extract_field_mapping(raw: dict[str, Any]) -> tuple[dict[str, Any], FieldMappingConfig]:
    """Strip the internal ``_mxtac_field_mapping`` key from *raw* and parse it.

    Returns a ``(clean_raw, field_mapping_config)`` pair.  The normaliser always
    receives a clean raw dict (no internal metadata keys), while the pipeline
    retains the parsed config to apply overrides after normalisation.
    """
    mapping_data = raw.get(_FIELD_MAPPING_KEY)
    if mapping_data is None:
        return raw, FieldMappingConfig()
    # Build clean copy without the internal key so normaliser & raw storage are clean
    clean = {k: v for k, v in raw.items() if k != _FIELD_MAPPING_KEY}
    return clean, FieldMappingConfig.from_config(mapping_data)


class NormalizerPipeline:
    """Consumes raw events from all source topics, normalizes to OCSF, publishes to mxtac.normalized."""

    def __init__(
        self,
        queue: MessageQueue,
        discovery: AssetDiscovery | None = None,
    ) -> None:
        self._queue = queue
        self._wazuh = WazuhNormalizer()
        self._zeek = ZeekNormalizer()
        self._suricata = SuricataNormalizer()
        # Feature 30.5: optional asset auto-discovery hook
        self._discovery = discovery

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
        # Feature 7.15: strip internal field mapping key before passing to normaliser
        clean_raw, field_mapping = _extract_field_mapping(raw)
        try:
            event = self._wazuh.normalize(clean_raw)
            event = field_mapping.apply(event, clean_raw)
            # Feature 30.5: auto-discover asset from Wazuh agent info
            if self._discovery is not None:
                await self._discovery.process_event(event, "wazuh")
            await self._queue.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        except ValidationError as exc:
            logger.warning("Wazuh schema validation error: %s", exc)
            await self._send_to_dlq("wazuh", clean_raw, exc, "schema_validation")
        except Exception as exc:
            logger.exception("Wazuh normalization error")
            await self._send_to_dlq("wazuh", clean_raw, exc, "normalization_error")

    async def _handle_zeek(self, raw: dict[str, Any]) -> None:
        # Feature 7.15: strip internal field mapping key before passing to normaliser
        clean_raw, field_mapping = _extract_field_mapping(raw)
        try:
            event = self._zeek.normalize(clean_raw)
            event = field_mapping.apply(event, clean_raw)
            # Feature 30.5: auto-discover assets from Zeek src/dst IPs
            if self._discovery is not None:
                await self._discovery.process_event(event, "zeek")
            await self._queue.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        except ValidationError as exc:
            logger.warning("Zeek schema validation error: %s", exc)
            await self._send_to_dlq("zeek", clean_raw, exc, "schema_validation")
        except Exception as exc:
            logger.exception("Zeek normalization error")
            await self._send_to_dlq("zeek", clean_raw, exc, "normalization_error")

    async def _handle_suricata(self, raw: dict[str, Any]) -> None:
        # Feature 7.15: strip internal field mapping key before passing to normaliser
        clean_raw, field_mapping = _extract_field_mapping(raw)
        try:
            event = self._suricata.normalize(clean_raw)
            event = field_mapping.apply(event, clean_raw)
            # Feature 30.5: auto-discover assets from Suricata src/dst IPs
            if self._discovery is not None:
                await self._discovery.process_event(event, "suricata")
            await self._queue.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        except ValidationError as exc:
            logger.warning("Suricata schema validation error: %s", exc)
            await self._send_to_dlq("suricata", clean_raw, exc, "schema_validation")
        except Exception as exc:
            logger.exception("Suricata normalization error")
            await self._send_to_dlq("suricata", clean_raw, exc, "normalization_error")
