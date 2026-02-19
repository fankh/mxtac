"""
Message queue abstraction — supports Kafka (production) and Redis Streams (development).
Topic naming convention: mxtac.{stage}.{source}
  - mxtac.raw.wazuh       — raw Wazuh JSON alerts
  - mxtac.raw.zeek        — raw Zeek log lines
  - mxtac.raw.suricata    — raw Suricata EVE JSON
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
    NORMALIZED      = "mxtac.normalized"
    ALERTS          = "mxtac.alerts"
    ENRICHED        = "mxtac.enriched"


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


# ── In-process queue (single-process dev / testing) ─────────────────────────

class InMemoryQueue(MessageQueue):
    """Asyncio-based in-memory queue. No persistence, single process only."""

    def __init__(self) -> None:
        self._queues: dict[str, asyncio.Queue] = defaultdict(asyncio.Queue)
        self._tasks: list[asyncio.Task] = []

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        await self._queues[topic].put(message)
        logger.debug("InMemoryQueue publish topic=%s size=%d", topic, self._queues[topic].qsize())

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

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("InMemoryQueue stopped")


# ── Redis Streams queue ───────────────────────────────────────────────────────

class RedisStreamQueue(MessageQueue):
    """Redis Streams-based queue. Requires redis-py[hiredis] >= 5.0."""

    def __init__(self, redis_url: str) -> None:
        import redis.asyncio as aioredis  # type: ignore[import-untyped]
        self._redis = aioredis.from_url(redis_url, decode_responses=True)
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
        logger.info("RedisStreamQueue started url=%s", settings.redis_url)

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
        return RedisStreamQueue(settings.redis_url)
    return InMemoryQueue()


# ── Singleton ─────────────────────────────────────────────────────────────────
_queue: MessageQueue | None = None


def get_queue() -> MessageQueue:
    global _queue
    if _queue is None:
        _queue = create_queue()
    return _queue
