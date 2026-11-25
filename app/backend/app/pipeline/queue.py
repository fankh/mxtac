"""
Message queue abstraction — in-process asyncio queues (default) or Valkey Streams.
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
import contextlib
import json
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from ..core.config import settings
from ..core.logging import get_logger

logger = get_logger(__name__)


# ── Topic constants ──────────────────────────────────────────────────────────

class Topic:
    RAW_WAZUH           = "mxtac.raw.wazuh"
    RAW_ZEEK            = "mxtac.raw.zeek"
    RAW_SURICATA        = "mxtac.raw.suricata"
    RAW_SYSLOG          = "mxtac.raw.syslog"
    RAW_WEBHOOK         = "mxtac.raw.webhook"
    NORMALIZED          = "mxtac.normalized"
    ALERTS              = "mxtac.alerts"
    ENRICHED            = "mxtac.enriched"
    DLQ                 = "mxtac.dlq"


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

    Every consumer group that subscribes to a topic receives every message
    published to it (like consumer groups of a Valkey stream); subscribers
    that share a group name share the work.  Messages published before the
    first subscription are buffered and delivered to the first group.

    Args:
        maxsize: Maximum number of messages per topic queue.  0 (default) means
                 unbounded — identical to previous behaviour.  A positive value
                 enables back-pressure: publish() blocks when the queue is full,
                 naturally slowing down the ingest producer until a consumer
                 drains enough messages to free space (Feature 5.9).
    """

    def __init__(self, maxsize: int = 0) -> None:
        self._maxsize = maxsize
        # topic → queue of the topic's first consumer group; it also buffers
        # messages published before anyone subscribed.
        self._queues: dict[str, asyncio.Queue[dict[str, Any]]] = defaultdict(
            lambda: asyncio.Queue(maxsize=self._maxsize)
        )
        # topic → group → queue.  The first group uses self._queues[topic].
        self._group_queues: dict[str, dict[str, asyncio.Queue[dict[str, Any]]]] = {}
        self._tasks: list[asyncio.Task[None]] = []
        self._backpressure_events: int = 0

    @property
    def backpressure_count(self) -> int:
        """Number of times publish() encountered a full queue and had to block."""
        return self._backpressure_events

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        group_queues = self._group_queues.get(topic)
        targets = list(group_queues.values()) if group_queues else [self._queues[topic]]
        for q in targets:
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
        group_queues = self._group_queues.setdefault(topic, {})
        if group not in group_queues:
            group_queues[group] = (
                asyncio.Queue(maxsize=self._maxsize) if group_queues else self._queues[topic]
            )
        q = group_queues[group]

        async def _consume() -> None:
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

        A handler may publish to another topic (raw → normalized → alerts …),
        so the queues are joined repeatedly until a full pass finds all of
        them idle.
        """
        if not self._all_queues():
            logger.info("InMemoryQueue drain: no queues — nothing to drain")
            return

        async def _join_until_idle() -> None:
            while True:
                # _unfinished_tasks: messages put but not yet marked task_done().
                # asyncio.Queue has no public counter that includes messages a
                # consumer is still handling, and typeshed omits the attribute.
                busy = [
                    q
                    for q in self._all_queues()
                    if q._unfinished_tasks  # type: ignore[attr-defined]
                ]
                if not busy:
                    return
                await asyncio.gather(*(q.join() for q in busy))

        try:
            await asyncio.wait_for(_join_until_idle(), timeout=timeout)
            logger.info("InMemoryQueue drained successfully")
        except TimeoutError:
            remaining = sum(q.qsize() for q in self._all_queues())
            logger.warning(
                "InMemoryQueue drain timed out after %.1fs — %d message(s) may be unprocessed",
                timeout,
                remaining,
            )

    def _all_queues(self) -> list[asyncio.Queue[dict[str, Any]]]:
        """Every queue of every topic and consumer group, without duplicates."""
        queues = {id(q): q for q in self._queues.values()}
        for group_queues in self._group_queues.values():
            queues.update((id(q), q) for q in group_queues.values())
        return list(queues.values())

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("InMemoryQueue stopped")


# ── Redis Streams queue ───────────────────────────────────────────────────────

class RedisStreamQueue(MessageQueue):
    """Valkey Streams-based queue (Redis Streams-compatible). Requires valkey >= 6.0."""

    def __init__(self, valkey_url: str) -> None:
        import valkey.asyncio as aioredis
        self._redis = aioredis.from_url(valkey_url, decode_responses=True)
        self._tasks: list[asyncio.Task[None]] = []

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        payload = {"data": json.dumps(message)}
        await self._redis.xadd(topic, payload, maxlen=10_000, approximate=True)

    async def subscribe(
        self,
        topic: str,
        group: str,
        handler: Callable[[dict[str, Any]], Any],
    ) -> None:
        # Create the consumer group; an error means it already exists.
        with contextlib.suppress(Exception):
            await self._redis.xgroup_create(topic, group, id="0", mkstream=True)

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


# ── Factory ───────────────────────────────────────────────────────────────────

def create_queue() -> MessageQueue:
    """Instantiate the right queue backend based on settings."""
    backend = getattr(settings, "queue_backend", "memory")
    if backend == "redis":
        return RedisStreamQueue(settings.valkey_url)
    if backend == "memory":
        return InMemoryQueue()
    raise ValueError(f"Unsupported QUEUE_BACKEND {backend!r}: use 'memory' or 'redis'")


# ── Singleton ─────────────────────────────────────────────────────────────────
_queue: MessageQueue | None = None


def get_queue() -> MessageQueue:
    global _queue
    if _queue is None:
        _queue = create_queue()
    return _queue
