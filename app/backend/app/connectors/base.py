"""Abstract base class for all MxTac data source connectors."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from ..core.logging import get_logger
from ..pipeline.queue import MessageQueue, Topic

logger = get_logger(__name__)


class ConnectorStatus(str, Enum):
    INACTIVE    = "inactive"
    CONNECTING  = "connecting"
    ACTIVE      = "active"
    ERROR       = "error"
    PAUSED      = "paused"


@dataclass
class ConnectorConfig:
    """Generic connector configuration. Subclasses extend this."""
    name: str
    connector_type: str
    enabled: bool = True
    poll_interval_seconds: int = 60
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectorHealth:
    status: ConnectorStatus
    last_event_at: datetime | None = None
    events_total: int = 0
    errors_total: int = 0
    error_message: str | None = None


class BaseConnector(ABC):
    """
    Abstract connector. Each source (Wazuh, Zeek, Suricata, …) subclasses this.

    Lifecycle:
        start()  → _connect() → poll loop → _fetch_events() → publish
        stop()   → cancel poll task
    """

    def __init__(
        self,
        config: ConnectorConfig,
        queue: MessageQueue,
        *,
        status_callback: Callable[[str, str | None], Awaitable[None]] | None = None,
    ) -> None:
        self.config  = config
        self.queue   = queue
        self.health  = ConnectorHealth(status=ConnectorStatus.INACTIVE)
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self._status_callback = status_callback

    # ── Abstract interface ───────────────────────────────────────────────────

    @abstractmethod
    async def _connect(self) -> None:
        """Establish connection to the data source."""
        ...

    @abstractmethod
    async def _fetch_events(self) -> AsyncGenerator[dict[str, Any], None]:
        """Yield raw events from the source. Called every poll interval."""
        ...

    @property
    @abstractmethod
    def topic(self) -> str:
        """Kafka/queue topic to publish raw events to."""
        ...

    # ── DB status helper (Feature 6.6) ────────────────────────────────────────

    async def _update_db_status(
        self,
        status: str,
        error_message: str | None = None,
    ) -> None:
        """Persist connector status to the database via the injected callback.

        Errors in the callback are swallowed so they never interrupt the poll loop.
        """
        if self._status_callback is None:
            return
        try:
            await self._status_callback(status, error_message)
        except Exception as exc:
            logger.warning(
                "Connector status_callback failed name=%s err=%s",
                self.config.name,
                exc,
            )

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        logger.info("Connector starting name=%s type=%s", self.config.name, self.config.connector_type)
        self.health.status = ConnectorStatus.CONNECTING
        try:
            await self._connect()
            self.health.status = ConnectorStatus.ACTIVE
            # Feature 6.6: persist active status to DB after successful connect
            await self._update_db_status(ConnectorStatus.ACTIVE.value)
        except Exception as exc:
            self.health.status = ConnectorStatus.ERROR
            self.health.error_message = str(exc)
            logger.error("Connector connect failed name=%s err=%s", self.config.name, exc)
            # Feature 6.6: persist error status and message to DB
            await self._update_db_status(ConnectorStatus.ERROR.value, str(exc))
            return

        self._task = asyncio.create_task(self._poll_loop(), name=f"connector-{self.config.name}")
        logger.info("Connector active name=%s", self.config.name)

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self.health.status = ConnectorStatus.INACTIVE
        # Feature 6.6: persist inactive status to DB on stop
        await self._update_db_status(ConnectorStatus.INACTIVE.value)
        logger.info("Connector stopped name=%s", self.config.name)

    async def pause(self) -> None:
        self.health.status = ConnectorStatus.PAUSED
        # Feature 6.6: persist paused status to DB
        await self._update_db_status(ConnectorStatus.PAUSED.value)
        self._stop_event.set()

    # ── Poll loop ────────────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                async for event in self._fetch_events():
                    await self.queue.publish(self.topic, event)
                    self.health.events_total += 1
                    self.health.last_event_at = datetime.now(timezone.utc)
                # Feature 6.6: persist active status to DB after a successful cycle
                await self._update_db_status(ConnectorStatus.ACTIVE.value)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.health.errors_total += 1
                self.health.error_message = str(exc)
                logger.error(
                    "Connector fetch error name=%s err=%s", self.config.name, exc
                )
                # Feature 6.6: persist error status and message to DB
                await self._update_db_status(ConnectorStatus.ERROR.value, str(exc))

            try:
                await asyncio.wait_for(
                    asyncio.shield(self._stop_event.wait()),
                    timeout=self.config.poll_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass  # Normal — just continue polling

    def get_health(self) -> dict[str, Any]:
        return {
            "name":          self.config.name,
            "type":          self.config.connector_type,
            "status":        self.health.status.value,
            "last_event_at": self.health.last_event_at.isoformat() if self.health.last_event_at else None,
            "events_total":  self.health.events_total,
            "errors_total":  self.health.errors_total,
            "error_message": self.health.error_message,
        }
