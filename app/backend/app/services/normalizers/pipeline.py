"""Normalizer pipeline — subscribes to raw topics and publishes normalized OCSF events."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from ...core.logging import get_logger
from ...models.base import new_uuid
from ...pipeline.queue import MessageQueue, Topic
from .field_mapping import FieldMappingConfig
from .ocsf import EVENT_ID_KEY, OCSFEvent
from .suricata import SuricataNormalizer
from .syslog import SyslogNormalizer
from .wazuh import WazuhNormalizer
from .webhook import WebhookNormalizer
from .zeek import ZeekNormalizer

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

    def __init__(self, queue: MessageQueue) -> None:
        self._queue = queue
        self._wazuh = WazuhNormalizer()
        self._zeek = ZeekNormalizer()
        self._suricata = SuricataNormalizer()
        self._syslog = SyslogNormalizer()
        self._webhook = WebhookNormalizer()

    async def start(self) -> None:
        """Subscribe to all raw topics."""
        await self._queue.subscribe(Topic.RAW_WAZUH, "normalizer", self._handle_wazuh)
        await self._queue.subscribe(Topic.RAW_ZEEK, "normalizer", self._handle_zeek)
        await self._queue.subscribe(Topic.RAW_SURICATA, "normalizer", self._handle_suricata)
        await self._queue.subscribe(Topic.RAW_SYSLOG, "normalizer", self._handle_syslog)
        await self._queue.subscribe(Topic.RAW_WEBHOOK, "normalizer", self._handle_webhook)
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
            "failed_at": datetime.now(UTC).isoformat(),
        }
        await self._queue.publish(Topic.DLQ, dlq_message)
        logger.warning(
            "Event rejected to DLQ source=%s error_type=%s error=%s",
            source,
            error_type,
            exc,
        )

    async def _publish_normalized(self, event: OCSFEvent) -> None:
        """Publish *event* on ``mxtac.normalized`` together with a new event ID.

        The ID is assigned here, before the event is stored, so that the
        persister and the Sigma consumer (which read the same message
        independently) agree on it and a detection can name its event.
        """
        message = event.model_dump(mode="json")
        message[EVENT_ID_KEY] = new_uuid()
        await self._queue.publish(Topic.NORMALIZED, message)

    async def _handle_wazuh(self, raw: dict[str, Any]) -> None:
        # Feature 7.15: strip internal field mapping key before passing to normaliser
        clean_raw, field_mapping = _extract_field_mapping(raw)
        try:
            event = self._wazuh.normalize(clean_raw)
            event = field_mapping.apply(event, clean_raw)
            await self._publish_normalized(event)
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
            await self._publish_normalized(event)
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
            await self._publish_normalized(event)
        except ValidationError as exc:
            logger.warning("Suricata schema validation error: %s", exc)
            await self._send_to_dlq("suricata", clean_raw, exc, "schema_validation")
        except Exception as exc:
            logger.exception("Suricata normalization error")
            await self._send_to_dlq("suricata", clean_raw, exc, "normalization_error")

    async def _handle_syslog(self, raw: dict[str, Any]) -> None:
        # Feature 7.15: strip internal field mapping key before passing to normaliser
        clean_raw, field_mapping = _extract_field_mapping(raw)
        try:
            event = self._syslog.normalize(clean_raw)
            event = field_mapping.apply(event, clean_raw)
            await self._publish_normalized(event)
        except ValidationError as exc:
            logger.warning("Syslog schema validation error: %s", exc)
            await self._send_to_dlq("syslog", clean_raw, exc, "schema_validation")
        except Exception as exc:
            logger.exception("Syslog normalization error")
            await self._send_to_dlq("syslog", clean_raw, exc, "normalization_error")

    async def _handle_webhook(self, raw: dict[str, Any]) -> None:
        # Feature 7.15: strip internal field mapping key before passing to normaliser
        clean_raw, field_mapping = _extract_field_mapping(raw)
        try:
            event = self._webhook.normalize(clean_raw)
            event = field_mapping.apply(event, clean_raw)
            await self._publish_normalized(event)
        except ValidationError as exc:
            logger.warning("Webhook schema validation error: %s", exc)
            await self._send_to_dlq("webhook", clean_raw, exc, "schema_validation")
        except Exception as exc:
            logger.exception("Webhook normalization error")
            await self._send_to_dlq("webhook", clean_raw, exc, "normalization_error")
