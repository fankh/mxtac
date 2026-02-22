"""
Message queue abstraction — supports Kafka (production) and Valkey Streams (development).
Topic naming convention: mxtac.{stage}.{source}
  - mxtac.raw.wazuh       — raw Wazuh JSON alerts
  - mxtac.raw.zeek        — raw Zeek log lines
  - mxtac.raw.suricata    — raw Suricata EVE JSON
  - mxtac.raw.syslog      — raw generic syslog messages (UDP 514)
  - mxtac.raw.webhook     — raw generic webhook events (any JSON source)
  - mxtac.normalized      — OCSF-normalized events
  - mxtac.alerts          — matched Sigma alerts
  - mxtac.enriched        — enriched alerts
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Any, AsyncGenerator, Callable

from ..core.config import settings
from ..core.logging import get_logger

logger = get_logger(__name__)


# ── Topic constants ──────────────────────────────────────────────────────────

class Topic:
    RAW_WAZUH       = "mxtac.raw.wazuh"
    RAW_ZEEK        = "mxtac.raw.zeek"
    RAW_SURICATA    = "mxtac.raw.suricata"
    RAW_PROWLER     = "mxtac.raw.prowler"
    RAW_OPENCTI     = "mxtac.raw.opencti"
    RAW_SYSLOG      = "mxtac.raw.syslog"
    RAW_WEBHOOK     = "mxtac.raw.webhook"
    NORMALIZED      = "mxtac.normalized"
    ALERTS          = "mxtac.alerts"
    ENRICHED        = "mxtac.enriched"
    DLQ             = "mxtac.dlq"


# ── Abstract base ────────────────────────────────────────────────────────────

class MessageQueue(ABC):
    @abstractmethod
    async def publish(self, topic: str, message: dict[str, Any]) -> None: ...

    @abstractmethod
    async def subscribe(
        self,
        topic: str,
        group: str,
        handler: Callable[[dict[str, Any]], Any],
    ) -> None: ...

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def drain(self, timeout: float = 30.0) -> None: ...


# ── In-process queue (single-process dev / testing) ─────────────────────────

class InMemoryQueue(MessageQueue):
    """Asyncio-based in-memory queue. No persistence, single process only.

    Args:
        maxsize: Maximum number of messages per topic queue.  0 (default) means
                 unbounded — identical to previous behaviour.  A positive value
                 enables back-pressure: publish() blocks when the queue is full,
                 naturally slowing down the ingest producer until a consumer
                 drains enough messages to free space (Feature 5.9).
    """

    def __init__(self, maxsize: int = 0) -> None:
        self._maxsize = maxsize
        self._queues: dict[str, asyncio.Queue] = defaultdict(
            lambda: asyncio.Queue(maxsize=self._maxsize)
        )
        self._tasks: list[asyncio.Task] = []
        self._backpressure_events: int = 0

    @property
    def backpressure_count(self) -> int:
        """Number of times publish() encountered a full queue and had to block."""
        return self._backpressure_events

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        q = self._queues[topic]
        try:
            q.put_nowait(message)
        except asyncio.QueueFull:
            self._backpressure_events += 1
            logger.warning(
                "InMemoryQueue back-pressure: topic=%s queue full (size=%d maxsize=%d)"
                " — blocking publisher to slow ingest",
                topic,
                q.qsize(),
                self._maxsize,
            )
            await q.put(message)  # block until a consumer frees space
        logger.debug("InMemoryQueue publish topic=%s size=%d", topic, q.qsize())

    async def subscribe(
        self,
        topic: str,
        group: str,
        handler: Callable[[dict[str, Any]], Any],
    ) -> None:
        async def _consume() -> None:
            q = self._queues[topic]
            while True:
                msg = await q.get()
                try:
                    await handler(msg)
                except Exception:
                    logger.exception("InMemoryQueue handler error topic=%s group=%s", topic, group)
                finally:
                    q.task_done()

        task = asyncio.create_task(_consume(), name=f"consumer-{topic}-{group}")
        self._tasks.append(task)
        logger.info("InMemoryQueue subscribed topic=%s group=%s", topic, group)

    async def start(self) -> None:
        logger.info("InMemoryQueue started")

    async def drain(self, timeout: float = 30.0) -> None:
        """Wait for all queued messages to be processed before returning.

        Joins every per-topic asyncio.Queue so that stop() does not cancel
        consumer tasks while messages are still in-flight.  A configurable
        *timeout* prevents the process from hanging indefinitely when a
        consumer is slow or stalled.
        """
        joins = [q.join() for q in self._queues.values()]
        if not joins:
            logger.info("InMemoryQueue drain: no queues — nothing to drain")
            return
        try:
            await asyncio.wait_for(asyncio.gather(*joins), timeout=timeout)
            logger.info("InMemoryQueue drained successfully")
        except asyncio.TimeoutError:
            remaining = sum(q.qsize() for q in self._queues.values())
            logger.warning(
                "InMemoryQueue drain timed out after %.1fs — %d message(s) may be unprocessed",
                timeout,
                remaining,
            )

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("InMemoryQueue stopped")


# ── Redis Streams queue ───────────────────────────────────────────────────────

class RedisStreamQueue(MessageQueue):
    """Valkey Streams-based queue (Redis Streams-compatible). Requires valkey >= 6.0."""

    def __init__(self, valkey_url: str) -> None:
        import valkey.asyncio as aioredis  # type: ignore[import-untyped]
        self._redis = aioredis.from_url(valkey_url, decode_responses=True)
        self._tasks: list[asyncio.Task] = []

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        payload = {"data": json.dumps(message)}
        await self._redis.xadd(topic, payload, maxlen=10_000, approximate=True)

    async def subscribe(
        self,
        topic: str,
        group: str,
        handler: Callable[[dict[str, Any]], Any],
    ) -> None:
        # Create consumer group if it doesn't exist
        try:
            await self._redis.xgroup_create(topic, group, id="0", mkstream=True)
        except Exception:
            pass  # Group already exists

        consumer_name = f"{group}-worker"

        async def _consume() -> None:
            while True:
                try:
                    entries = await self._redis.xreadgroup(
                        group, consumer_name,
                        {topic: ">"}, count=10, block=1000,
                    )
                    for _stream, messages in (entries or []):
                        for msg_id, fields in messages:
                            msg = json.loads(fields["data"])
                            try:
                                await handler(msg)
                                await self._redis.xack(topic, group, msg_id)
                            except Exception:
                                logger.exception("RedisStreamQueue handler error")
                except asyncio.CancelledError:
                    break
                except Exception:
                    logger.exception("RedisStreamQueue consume error, retrying in 1s")
                    await asyncio.sleep(1)

        task = asyncio.create_task(_consume(), name=f"redis-consumer-{topic}-{group}")
        self._tasks.append(task)

    async def start(self) -> None:
        logger.info("RedisStreamQueue started url=%s", settings.valkey_url)

    async def drain(self, timeout: float = 30.0) -> None:
        """No-op: Redis Streams are persistent.

        Messages written to the stream survive process exit and will be
        re-delivered by the consumer group on the next startup.  There is
        no in-process buffer to drain.
        """
        logger.info(
            "RedisStreamQueue drain: messages persist in the stream — no in-process buffer to drain"
        )

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._redis.aclose()


# ── Kafka queue ───────────────────────────────────────────────────────────────

class KafkaQueue(MessageQueue):
    """Kafka-based queue using aiokafka. Requires aiokafka >= 0.10."""

    def __init__(self, bootstrap_servers: str) -> None:
        self._bootstrap = bootstrap_servers
        self._producer = None
        self._tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        from aiokafka import AIOKafkaProducer  # type: ignore[import-untyped]
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self._bootstrap,
            value_serializer=lambda v: json.dumps(v).encode(),
        )
        await self._producer.start()
        logger.info("KafkaQueue started bootstrap=%s", self._bootstrap)

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        if self._producer is None:
            raise RuntimeError("KafkaQueue not started")
        await self._producer.send_and_wait(topic, message)

    async def subscribe(
        self,
        topic: str,
        group: str,
        handler: Callable[[dict[str, Any]], Any],
    ) -> None:
        from aiokafka import AIOKafkaConsumer  # type: ignore[import-untyped]

        async def _consume() -> None:
            consumer = AIOKafkaConsumer(
                topic,
                bootstrap_servers=self._bootstrap,
                group_id=group,
                value_deserializer=lambda v: json.loads(v.decode()),
                auto_offset_reset="earliest",
            )
            await consumer.start()
            try:
                async for msg in consumer:
                    try:
                        await handler(msg.value)
                    except Exception:
                        logger.exception("KafkaQueue handler error topic=%s", topic)
            finally:
                await consumer.stop()

        task = asyncio.create_task(_consume(), name=f"kafka-consumer-{topic}-{group}")
        self._tasks.append(task)

    async def drain(self, timeout: float = 30.0) -> None:
        """Flush the Kafka producer so all published messages are sent before exit.

        Consumer messages persist in Kafka partitions and will not be lost.
        The producer flush ensures that any buffered-but-not-yet-sent records
        are committed to the broker before the process exits.
        """
        if self._producer is None:
            return
        try:
            await asyncio.wait_for(self._producer.flush(), timeout=timeout)
            logger.info("KafkaQueue producer flushed successfully")
        except asyncio.TimeoutError:
            logger.warning("KafkaQueue drain flush timed out after %.1fs", timeout)
        except Exception:
            logger.exception("KafkaQueue drain flush failed")

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._producer:
            await self._producer.stop()


# ── Factory ───────────────────────────────────────────────────────────────────

def create_queue() -> MessageQueue:
    """Instantiate the right queue backend based on settings."""
    backend = getattr(settings, "queue_backend", "memory")
    if backend == "kafka":
        return KafkaQueue(getattr(settings, "kafka_bootstrap_servers", "localhost:9092"))
    if backend == "redis":
        return RedisStreamQueue(settings.valkey_url)
    return InMemoryQueue()


# ── Singleton ─────────────────────────────────────────────────────────────────
_queue: MessageQueue | None = None


def get_queue() -> MessageQueue:
    global _queue
    if _queue is None:
        _queue = create_queue()
    return _queue
