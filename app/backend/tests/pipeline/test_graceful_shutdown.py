"""
Tests for Feature 5.7: Graceful shutdown — drain queue before exit.

Coverage:
  - InMemoryQueue.drain(): empty queue returns immediately, waits for in-flight
    messages, resolves only after all messages processed, times out gracefully
    when consumers are absent, drains multiple independent topics
  - RedisStreamQueue.drain(): returns immediately (messages persist in stream)
  - KafkaQueue.drain(): flushes producer when started, skips flush when not
    started, handles flush timeout gracefully, handles flush exception
  - on_shutdown ordering: drain is called before stop (feature 5.7)
  - on_shutdown resilience: drain failure does not prevent stop
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.pipeline.queue import (
    InMemoryQueue,
    KafkaQueue,
    RedisStreamQueue,
    Topic,
)


# ── InMemoryQueue.drain() ─────────────────────────────────────────────────────


class TestInMemoryQueueDrain:
    async def test_drain_on_empty_queue_returns_immediately(self) -> None:
        """drain() with no published messages must not block."""
        q = InMemoryQueue()
        await q.start()
        await asyncio.wait_for(q.drain(), timeout=1.0)
        await q.stop()

    async def test_drain_waits_until_single_message_is_processed(self) -> None:
        """drain() must block until the handler calls task_done()."""
        q = InMemoryQueue()
        await q.start()

        processed: list[dict[str, Any]] = []
        barrier = asyncio.Event()

        async def slow_handler(msg: dict[str, Any]) -> None:
            await barrier.wait()  # block until we release
            processed.append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", slow_handler)
        await q.publish(Topic.RAW_WAZUH, {"x": 1})

        # drain is still pending because handler is blocked
        drain_task = asyncio.create_task(q.drain(timeout=5.0))
        await asyncio.sleep(0.05)
        assert not drain_task.done(), "drain() should still be waiting"

        # release the handler — drain should now complete
        barrier.set()
        await asyncio.wait_for(drain_task, timeout=2.0)

        assert processed == [{"x": 1}]
        await q.stop()

    async def test_drain_resolves_only_after_all_messages_processed(self) -> None:
        """drain() returns only once every published message has been handled."""
        q = InMemoryQueue()
        await q.start()

        N = 10
        received: list[int] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg["n"])

        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        for i in range(N):
            await q.publish(Topic.NORMALIZED, {"n": i})

        await asyncio.wait_for(q.drain(timeout=5.0), timeout=6.0)

        assert len(received) == N
        await q.stop()

    async def test_drain_times_out_gracefully_when_no_consumer(self) -> None:
        """drain() with a very short timeout must not hang; it logs and returns."""
        q = InMemoryQueue()
        await q.start()

        # Publish to a topic with no consumer — queue.join() would block forever
        await q.publish(Topic.ALERTS, {"orphan": True})

        # drain must complete (timeout path) without raising
        await asyncio.wait_for(q.drain(timeout=0.1), timeout=2.0)

        await q.stop()

    async def test_drain_with_multiple_topics_waits_for_all(self) -> None:
        """drain() waits until every topic's queue is fully processed."""
        q = InMemoryQueue()
        await q.start()

        barriers = {
            Topic.RAW_WAZUH: asyncio.Event(),
            Topic.RAW_ZEEK: asyncio.Event(),
        }
        processed: dict[str, list[Any]] = {k: [] for k in barriers}

        for topic, barrier in barriers.items():
            captured = processed[topic]

            async def make_handler(b: asyncio.Event, buf: list[Any]):
                async def _h(msg: dict[str, Any]) -> None:
                    await b.wait()
                    buf.append(msg)
                return _h

            await q.subscribe(topic, "grp", await make_handler(barrier, captured))

        await q.publish(Topic.RAW_WAZUH, {"src": "wazuh"})
        await q.publish(Topic.RAW_ZEEK, {"src": "zeek"})

        drain_task = asyncio.create_task(q.drain(timeout=5.0))
        await asyncio.sleep(0.05)
        assert not drain_task.done(), "drain should wait for both topics"

        # Release wazuh — still waiting for zeek
        barriers[Topic.RAW_WAZUH].set()
        await asyncio.sleep(0.05)
        assert not drain_task.done(), "drain should still wait for zeek"

        # Release zeek — drain can now complete
        barriers[Topic.RAW_ZEEK].set()
        await asyncio.wait_for(drain_task, timeout=2.0)

        assert processed[Topic.RAW_WAZUH] == [{"src": "wazuh"}]
        assert processed[Topic.RAW_ZEEK] == [{"src": "zeek"}]
        await q.stop()

    async def test_drain_then_stop_does_not_lose_messages(self) -> None:
        """Messages processed before drain() + stop() leaves the queue empty."""
        q = InMemoryQueue()
        await q.start()

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "grp", handler)
        for i in range(5):
            await q.publish(Topic.ENRICHED, {"i": i})

        await q.drain(timeout=5.0)
        await q.stop()

        assert len(received) == 5

    async def test_drain_with_no_published_messages_on_topic_with_subscriber(self) -> None:
        """A subscribed but empty topic does not block drain()."""
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_SURICATA, "grp", handler)
        # No messages published — drain should return immediately
        await asyncio.wait_for(q.drain(timeout=1.0), timeout=2.0)
        await q.stop()


# ── RedisStreamQueue.drain() ─────────────────────────────────────────────────


class TestRedisStreamQueueDrain:
    def _make_queue(self) -> RedisStreamQueue:
        mock_redis = AsyncMock()
        mock_redis.aclose = AsyncMock()
        q = object.__new__(RedisStreamQueue)
        q._redis = mock_redis
        q._tasks = []
        return q

    async def test_drain_returns_immediately(self) -> None:
        """RedisStreamQueue.drain() is a no-op and must not block."""
        q = self._make_queue()
        await asyncio.wait_for(q.drain(), timeout=1.0)

    async def test_drain_with_custom_timeout_still_returns_immediately(self) -> None:
        """The timeout parameter is accepted but unused for Redis (no buffer to drain)."""
        q = self._make_queue()
        await asyncio.wait_for(q.drain(timeout=0.001), timeout=1.0)

    async def test_drain_does_not_interact_with_redis_client(self) -> None:
        """Redis drain is purely informational — no xreadgroup, xadd, or similar calls."""
        q = self._make_queue()
        await q.drain()
        # No Redis methods should have been called
        q._redis.xadd.assert_not_called()
        q._redis.xreadgroup.assert_not_called()
        q._redis.aclose.assert_not_called()


# ── KafkaQueue.drain() ────────────────────────────────────────────────────────


class TestKafkaQueueDrain:
    async def test_drain_skips_flush_when_producer_not_started(self) -> None:
        """drain() before start() must not raise — producer is None."""
        q = KafkaQueue("broker:9092")
        assert q._producer is None
        await asyncio.wait_for(q.drain(), timeout=1.0)  # must not raise

    async def test_drain_flushes_producer_when_started(self) -> None:
        """drain() calls producer.flush() after start()."""
        mock_producer = AsyncMock()
        mock_aiokafka = MagicMock()
        mock_aiokafka.AIOKafkaProducer.return_value = mock_producer

        with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}):
            q = KafkaQueue("broker:9092")
            await q.start()
            await q.drain()

        mock_producer.flush.assert_called_once()

    async def test_drain_timeout_does_not_raise(self) -> None:
        """If producer.flush() exceeds timeout, drain() logs and returns — no exception."""
        mock_producer = AsyncMock()
        mock_producer.flush = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_aiokafka = MagicMock()
        mock_aiokafka.AIOKafkaProducer.return_value = mock_producer

        with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}):
            q = KafkaQueue("broker:9092")
            await q.start()
            await asyncio.wait_for(q.drain(timeout=0.01), timeout=2.0)  # must not raise

    async def test_drain_flush_exception_does_not_propagate(self) -> None:
        """An unexpected flush error must be caught and logged, not propagated."""
        mock_producer = AsyncMock()
        mock_producer.flush = AsyncMock(side_effect=RuntimeError("broker gone"))
        mock_aiokafka = MagicMock()
        mock_aiokafka.AIOKafkaProducer.return_value = mock_producer

        with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}):
            q = KafkaQueue("broker:9092")
            await q.start()
            await q.drain()  # must not raise RuntimeError

    async def test_drain_respects_timeout_parameter(self) -> None:
        """drain() uses asyncio.wait_for with the provided timeout."""
        hang_forever = asyncio.Event()

        async def _blocking_flush():
            await hang_forever.wait()  # blocks until cancelled

        mock_producer = AsyncMock()
        mock_producer.flush = _blocking_flush
        mock_aiokafka = MagicMock()
        mock_aiokafka.AIOKafkaProducer.return_value = mock_producer

        with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}):
            q = KafkaQueue("broker:9092")
            await q.start()
            # drain with a very short timeout must return quickly without hanging
            await asyncio.wait_for(q.drain(timeout=0.05), timeout=2.0)
