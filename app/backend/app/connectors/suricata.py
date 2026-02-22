"""
Suricata connector — tails the EVE JSON log file.

Required config.extra keys:
  eve_file:    str       — path to eve.json (e.g. "/var/log/suricata/eve.json")

Optional config.extra keys:
  event_types: list[str] — allowlist of event_type values to ingest.
                           Default: ["alert", "dns", "http", "tls"].
                           Only events whose ``event_type`` field matches one
                           of the listed values are yielded; all others are
                           silently dropped.  An empty list blocks all events.

Feature 6.16: Filter by event_type — alert, dns, http, tls.
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncGenerator

from ..core.logging import get_logger
from ..pipeline.queue import Topic
from .base import BaseConnector, ConnectorConfig

logger = get_logger(__name__)


class SuricataConnector(BaseConnector):
    """Tails Suricata EVE JSON log file and publishes events to mxtac.raw.suricata."""

    def __init__(self, config: ConnectorConfig, queue) -> None:
        super().__init__(config, queue)
        self._file_position: int = 0

    @property
    def topic(self) -> str:
        return Topic.RAW_SURICATA

    async def _connect(self) -> None:
        eve_file = self.config.extra.get("eve_file", "/var/log/suricata/eve.json")
        if not os.path.isfile(eve_file):
            raise ConnectionError(f"Suricata EVE file not found: {eve_file}")
        # Start at end of file to only get new events
        self._file_position = os.path.getsize(eve_file)
        logger.info("SuricataConnector connected eve_file=%s", eve_file)

    # Feature 6.16: default allowlist of Suricata event_type values to ingest.
    DEFAULT_EVENT_TYPES: tuple[str, ...] = ("alert", "dns", "http", "tls")

    async def _fetch_events(self) -> AsyncGenerator[dict[str, Any], None]:
        eve_file = self.config.extra.get("eve_file", "/var/log/suricata/eve.json")
        # Feature 6.16: resolve the event_type allowlist once per call.
        event_types: list[str] = self.config.extra.get(
            "event_types", list(self.DEFAULT_EVENT_TYPES)
        )
        allowed: frozenset[str] = frozenset(event_types)

        if not os.path.isfile(eve_file):
            return

        with open(eve_file, "r", errors="replace") as f:
            f.seek(self._file_position)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    # Feature 6.16: drop events whose event_type is not allowed.
                    if event.get("event_type") not in allowed:
                        continue
                    yield event
                except json.JSONDecodeError:
                    continue
            self._file_position = f.tell()
