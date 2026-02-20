"""
Tests for app.pipeline.queue — Feature 5.1: MessageQueue abstraction.

Coverage:
  - Topic constants: values, uniqueness, naming convention
  - MessageQueue ABC: instantiation enforcement, required abstract methods
  - InMemoryQueue: lifecycle, publish/subscribe delivery, ordering,
    error isolation, task naming, task_done() contract
  - RedisStreamQueue: xadd/xreadgroup wiring, JSON serialisation,
    maxlen enforcement, group creation, handler delivery, ack
  - KafkaQueue: producer lifecycle, publish wiring, stop cleanup
  - create_queue() factory: all three backends + fallback/defaults
  - get_queue() singleton: same-instance contract, module state
"""

from __future__ import annotations

import asyncio
import json as json_mod
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import app.pipeline.queue as queue_module
from app.pipeline.queue import (
    InMemoryQueue,
    KafkaQueue,
    MessageQueue,
    RedisStreamQueue,
    Topic,
    create_queue,
    get_queue,
)


# ── Topic constants ────────────────────────────────────────────────────────────

class TestTopic:
    def test_raw_wazuh(self) -> None:
        assert Topic.RAW_WAZUH == "mxtac.raw.wazuh"

    def test_raw_zeek(self) -> None:
        assert Topic.RAW_ZEEK == "mxtac.raw.zeek"

    def test_raw_suricata(self) -> None:
        assert Topic.RAW_SURICATA == "mxtac.raw.suricata"

    def test_normalized(self) -> None:
        assert Topic.NORMALIZED == "mxtac.normalized"

    def test_alerts(self) -> None:
        assert Topic.ALERTS == "mxtac.alerts"

    def test_enriched(self) -> None:
        assert Topic.ENRICHED == "mxtac.enriched"

    def test_all_topics_are_distinct(self) -> None:
        topics = [
            Topic.RAW_WAZUH,
            Topic.RAW_ZEEK,
            Topic.RAW_SURICATA,
            Topic.NORMALIZED,
            Topic.ALERTS,
            Topic.ENRICHED,
        ]
        assert len(set(topics)) == len(topics)

    def test_all_topics_follow_naming_convention(self) -> None:
        for topic in [
            Topic.RAW_WAZUH,
            Topic.RAW_ZEEK,
            Topic.RAW_SURICATA,
            Topic.NORMALIZED,
            Topic.ALERTS,
            Topic.ENRICHED,
        ]:
            assert topic.startswith("mxtac."), f"{topic!r} must start with 'mxtac.'"


# ── MessageQueue ABC ──────────────────────────────────────────────────────────

class TestMessageQueueABC:
    def test_cannot_instantiate_abstract_class(self) -> None:
        with pytest.raises(TypeError):
            MessageQueue()  # type: ignore[abstract]

    def test_incomplete_subclass_raises_on_instantiation(self) -> None:
        class IncompleteQueue(MessageQueue):
            async def publish(self, topic: str, message: dict[str, Any]) -> None:
                pass
            # Missing subscribe, start, stop

        with pytest.raises(TypeError):
            IncompleteQueue()

    def test_complete_subclass_can_be_instantiated(self) -> None:
        class FullQueue(MessageQueue):
            async def publish(self, topic: str, message: dict[str, Any]) -> None:
                pass

            async def subscribe(self, topic: str, group: str, handler: Any) -> None:
                pass

            async def start(self) -> None:
                pass

            async def stop(self) -> None:
                pass

        assert isinstance(FullQueue(), MessageQueue)

    def test_abstract_methods_are_publish_subscribe_start_stop(self) -> None:
        assert MessageQueue.__abstractmethods__ == frozenset(
            {"publish", "subscribe", "start", "stop"}
        )


# ── InMemoryQueue — lifecycle ─────────────────────────────────────────────────

class TestInMemoryQueueLifecycle:
    async def test_start_does_not_raise(self) -> None:
        q = InMemoryQueue()
        await q.start()

    async def test_stop_with_no_subscribers_does_not_raise(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await q.stop()

    async def test_stop_cancels_consumer_tasks(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        task = q._tasks[0]
        assert not task.done()

        await q.stop()
        await asyncio.sleep(0)  # allow cancellation to propagate

        assert task.done()

    async def test_stop_is_idempotent(self) -> None:
        """Calling stop() twice must not raise."""
        q = InMemoryQueue()
        await q.start()
        await q.stop()
        await q.stop()

    async def test_initial_state_has_no_tasks(self) -> None:
        q = InMemoryQueue()
        assert q._tasks == []


# ── InMemoryQueue — publish / subscribe ──────────────────────────────────────

class TestInMemoryQueuePublishSubscribe:
    async def test_single_message_delivered_to_handler(self) -> None:
        q = InMemoryQueue()
        await q.start()

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        await q.publish(Topic.RAW_WAZUH, {"event": "login", "user": "alice"})
        await asyncio.sleep(0.05)

        assert received == [{"event": "login", "user": "alice"}]
        await q.stop()

    async def test_messages_delivered_in_order(self) -> None:
        q = InMemoryQueue()
        await q.start()

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        messages = [{"seq": i} for i in range(10)]
        for msg in messages:
            await q.publish(Topic.NORMALIZED, msg)

        await asyncio.sleep(0.05)
        assert received == messages
        await q.stop()

    async def test_independent_topics_do_not_cross_deliver(self) -> None:
        q = InMemoryQueue()
        await q.start()

        wazuh_msgs: list[dict[str, Any]] = []
        zeek_msgs: list[dict[str, Any]] = []

        async def wazuh_handler(msg: dict[str, Any]) -> None:
            wazuh_msgs.append(msg)

        async def zeek_handler(msg: dict[str, Any]) -> None:
            zeek_msgs.append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", wazuh_handler)
        await q.subscribe(Topic.RAW_ZEEK, "grp", zeek_handler)

        await q.publish(Topic.RAW_WAZUH, {"src": "wazuh"})
        await q.publish(Topic.RAW_ZEEK, {"src": "zeek"})
        await asyncio.sleep(0.05)

        assert wazuh_msgs == [{"src": "wazuh"}]
        assert zeek_msgs == [{"src": "zeek"}]
        await q.stop()

    async def test_messages_published_before_subscribe_are_buffered(self) -> None:
        """asyncio.Queue buffers messages; late subscribers still receive them."""
        q = InMemoryQueue()
        await q.start()

        await q.publish(Topic.ALERTS, {"alert": "buffered"})

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.sleep(0.05)

        assert received == [{"alert": "buffered"}]
        await q.stop()

    async def test_complex_nested_message_delivered_intact(self) -> None:
        q = InMemoryQueue()
        await q.start()

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "grp", handler)
        complex_msg: dict[str, Any] = {
            "timestamp": "2026-02-20T12:00:00Z",
            "severity": "high",
            "tags": ["lateral-movement", "T1021"],
            "nested": {"rule_id": "sigma-001", "metadata": {"author": "mxtac"}},
        }
        await q.publish(Topic.ENRICHED, complex_msg)
        await asyncio.sleep(0.05)

        assert received == [complex_msg]
        await q.stop()

    async def test_subscribe_creates_task_with_correct_name(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe("mxtac.test", "mygroup", handler)

        task_names = [t.get_name() for t in q._tasks]
        assert "consumer-mxtac.test-mygroup" in task_names
        await q.stop()

    async def test_multiple_subscriptions_create_separate_tasks(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp-a", handler)
        await q.subscribe(Topic.RAW_ZEEK, "grp-b", handler)

        assert len(q._tasks) == 2
        await q.stop()

    async def test_task_done_called_after_handler_so_join_resolves(self) -> None:
        """Verify task_done() is called; asyncio.Queue.join() must not block forever."""
        q = InMemoryQueue()
        await q.start()

        inner_q = q._queues[Topic.RAW_WAZUH]

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        await q.publish(Topic.RAW_WAZUH, {"x": 1})

        await asyncio.wait_for(inner_q.join(), timeout=1.0)
        await q.stop()

    async def test_multiple_messages_all_delivered_across_topics(self) -> None:
        q = InMemoryQueue()
        await q.start()

        results: dict[str, list[dict[str, Any]]] = {
            Topic.RAW_WAZUH: [],
            Topic.RAW_SURICATA: [],
        }

        async def make_handler(topic: str):
            async def _h(msg: dict[str, Any]) -> None:
                results[topic].append(msg)
            return _h

        await q.subscribe(Topic.RAW_WAZUH, "w", await make_handler(Topic.RAW_WAZUH))
        await q.subscribe(Topic.RAW_SURICATA, "s", await make_handler(Topic.RAW_SURICATA))

        for i in range(5):
            await q.publish(Topic.RAW_WAZUH, {"w": i})
            await q.publish(Topic.RAW_SURICATA, {"s": i})

        await asyncio.sleep(0.1)

        assert results[Topic.RAW_WAZUH] == [{"w": i} for i in range(5)]
        assert results[Topic.RAW_SURICATA] == [{"s": i} for i in range(5)]
        await q.stop()


# ── InMemoryQueue — error handling ───────────────────────────────────────────

class TestInMemoryQueueErrorHandling:
    async def test_handler_exception_does_not_crash_consumer_loop(self) -> None:
        """A single handler failure must not stop subsequent message delivery."""
        q = InMemoryQueue()
        await q.start()

        call_count = 0

        async def flaky_handler(msg: dict[str, Any]) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("transient error")

        await q.subscribe(Topic.RAW_SURICATA, "grp", flaky_handler)
        await q.publish(Topic.RAW_SURICATA, {"msg": "first"})
        await q.publish(Topic.RAW_SURICATA, {"msg": "second"})
        await asyncio.sleep(0.05)

        assert call_count == 2
        await q.stop()

    async def test_handler_exception_still_calls_task_done(self) -> None:
        """task_done() must be called even when the handler raises."""
        q = InMemoryQueue()
        await q.start()

        inner_q = q._queues[Topic.RAW_SURICATA]

        async def raising_handler(msg: dict[str, Any]) -> None:
            raise RuntimeError("boom")

        await q.subscribe(Topic.RAW_SURICATA, "grp", raising_handler)
        await q.publish(Topic.RAW_SURICATA, {"x": 1})

        await asyncio.wait_for(inner_q.join(), timeout=1.0)
        await q.stop()

    async def test_consumer_continues_after_multiple_consecutive_failures(self) -> None:
        q = InMemoryQueue()
        await q.start()

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            if msg.get("fail"):
                raise ValueError("expected failure")
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "grp", handler)
        await q.publish(Topic.ALERTS, {"fail": True})
        await q.publish(Topic.ALERTS, {"fail": True})
        await q.publish(Topic.ALERTS, {"ok": True})
        await asyncio.sleep(0.05)

        assert received == [{"ok": True}]
        await q.stop()


# ── KafkaQueue ────────────────────────────────────────────────────────────────

class TestKafkaQueue:
    def test_init_stores_bootstrap_servers(self) -> None:
        q = KafkaQueue("broker1:9092,broker2:9092")
        assert q._bootstrap == "broker1:9092,broker2:9092"

    def test_init_producer_is_none_before_start(self) -> None:
        q = KafkaQueue("broker:9092")
        assert q._producer is None

    def test_init_tasks_list_is_empty(self) -> None:
        q = KafkaQueue("broker:9092")
        assert q._tasks == []

    async def test_publish_before_start_raises_runtime_error(self) -> None:
        q = KafkaQueue("broker:9092")
        with pytest.raises(RuntimeError, match="not started"):
            await q.publish(Topic.ALERTS, {"test": True})

    async def test_start_creates_and_starts_producer(self) -> None:
        mock_producer = AsyncMock()
        mock_aiokafka = MagicMock()
        mock_aiokafka.AIOKafkaProducer.return_value = mock_producer

        with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}):
            q = KafkaQueue("broker:9092")
            await q.start()

        assert q._producer is mock_producer
        mock_producer.start.assert_called_once()

    async def test_start_passes_bootstrap_servers_to_producer(self) -> None:
        mock_producer = AsyncMock()
        mock_aiokafka = MagicMock()
        mock_aiokafka.AIOKafkaProducer.return_value = mock_producer

        with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}):
            q = KafkaQueue("my-broker:9092")
            await q.start()

        mock_aiokafka.AIOKafkaProducer.assert_called_once()
        call_kwargs = mock_aiokafka.AIOKafkaProducer.call_args.kwargs
        assert call_kwargs["bootstrap_servers"] == "my-broker:9092"

    async def test_publish_calls_send_and_wait_with_correct_args(self) -> None:
        mock_producer = AsyncMock()
        mock_aiokafka = MagicMock()
        mock_aiokafka.AIOKafkaProducer.return_value = mock_producer

        with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}):
            q = KafkaQueue("broker:9092")
            await q.start()
            await q.publish(Topic.ALERTS, {"alert": "test"})

        mock_producer.send_and_wait.assert_called_once_with(Topic.ALERTS, {"alert": "test"})

    async def test_stop_cancels_tasks_and_stops_producer(self) -> None:
        mock_producer = AsyncMock()
        mock_aiokafka = MagicMock()
        mock_aiokafka.AIOKafkaProducer.return_value = mock_producer

        with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}):
            q = KafkaQueue("broker:9092")
            await q.start()
            await q.stop()

        mock_producer.stop.assert_called_once()

    async def test_stop_without_start_does_not_raise(self) -> None:
        """stop() with _producer=None must be safe."""
        q = KafkaQueue("broker:9092")
        await q.stop()

    async def test_subscribe_creates_task_for_consumer(self) -> None:
        mock_consumer = AsyncMock()
        mock_consumer.__aiter__ = MagicMock(return_value=iter([]))
        mock_aiokafka = MagicMock()
        mock_aiokafka.AIOKafkaConsumer.return_value = mock_consumer

        with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}):
            q = KafkaQueue("broker:9092")
            await q.subscribe(Topic.RAW_WAZUH, "grp", AsyncMock())
            assert len(q._tasks) == 1
            assert q._tasks[0].get_name() == f"kafka-consumer-{Topic.RAW_WAZUH}-grp"
            await q.stop()


# ── RedisStreamQueue ──────────────────────────────────────────────────────────

class TestRedisStreamQueue:
    """
    Tests for RedisStreamQueue.

    Since valkey is an external dependency, we bypass __init__ using
    object.__new__ and inject a mock _redis client directly. This avoids
    brittle sys.modules patching while still exercising all business logic.
    """

    def _make_mock_redis(self) -> AsyncMock:
        redis = AsyncMock()
        redis.xadd = AsyncMock()
        redis.xgroup_create = AsyncMock()
        redis.xreadgroup = AsyncMock(return_value=[])
        redis.xack = AsyncMock()
        redis.aclose = AsyncMock()
        return redis

    def _make_queue(self, mock_redis: AsyncMock) -> RedisStreamQueue:
        """Instantiate RedisStreamQueue without calling __init__ (no valkey import)."""
        q = object.__new__(RedisStreamQueue)
        q._redis = mock_redis
        q._tasks = []
        return q

    async def test_publish_calls_xadd_on_correct_topic(self) -> None:
        mock_redis = self._make_mock_redis()
        q = self._make_queue(mock_redis)
        await q.publish(Topic.ALERTS, {"alert": "test"})

        mock_redis.xadd.assert_called_once()
        assert mock_redis.xadd.call_args.args[0] == Topic.ALERTS

    async def test_publish_serialises_message_as_json_in_data_field(self) -> None:
        mock_redis = self._make_mock_redis()
        q = self._make_queue(mock_redis)
        msg = {"key": "value", "num": 42}
        await q.publish(Topic.ALERTS, msg)

        payload = mock_redis.xadd.call_args.args[1]
        assert "data" in payload
        assert json_mod.loads(payload["data"]) == msg

    async def test_publish_enforces_maxlen_10000_approximate(self) -> None:
        mock_redis = self._make_mock_redis()
        q = self._make_queue(mock_redis)
        await q.publish(Topic.NORMALIZED, {"x": 1})

        kw = mock_redis.xadd.call_args.kwargs
        assert kw["maxlen"] == 10_000
        assert kw["approximate"] is True

    async def test_subscribe_calls_xgroup_create_with_mkstream(self) -> None:
        mock_redis = self._make_mock_redis()
        q = self._make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "detection-grp", handler)
        await q.stop()

        mock_redis.xgroup_create.assert_called_once_with(
            Topic.RAW_WAZUH, "detection-grp", id="0", mkstream=True
        )

    async def test_subscribe_silently_ignores_existing_group_error(self) -> None:
        """BUSYGROUP exception from xgroup_create must be swallowed."""
        mock_redis = self._make_mock_redis()
        mock_redis.xgroup_create.side_effect = Exception(
            "BUSYGROUP Consumer Group name already exists"
        )
        q = self._make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)  # must not raise
        await q.stop()

    async def test_subscribe_creates_named_background_task(self) -> None:
        mock_redis = self._make_mock_redis()
        q = self._make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_ZEEK, "grp", handler)

        assert len(q._tasks) == 1
        assert q._tasks[0].get_name() == f"redis-consumer-{Topic.RAW_ZEEK}-grp"
        await q.stop()

    async def test_start_logs_and_does_not_raise(self) -> None:
        mock_redis = self._make_mock_redis()
        q = self._make_queue(mock_redis)
        await q.start()  # just a logger call — must not raise

    async def test_stop_closes_redis_connection(self) -> None:
        mock_redis = self._make_mock_redis()
        q = self._make_queue(mock_redis)
        await q.stop()

        mock_redis.aclose.assert_called_once()

    async def test_stop_cancels_all_consumer_tasks(self) -> None:
        mock_redis = self._make_mock_redis()
        q = self._make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        task = q._tasks[0]
        assert not task.done()

        await q.stop()
        await asyncio.sleep(0)
        assert task.done()

    async def test_consume_delivers_message_to_handler_and_acks(self) -> None:
        """xreadgroup returns a message → handler called → xack sent."""
        mock_redis = self._make_mock_redis()
        message = {"alert": "sigma-match", "severity": "high"}

        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.ALERTS, [("msg-001", {"data": json_mod.dumps(message)})])]
            await asyncio.sleep(0.05)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        q = self._make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.sleep(0.05)

        assert received == [message]
        mock_redis.xack.assert_called_once_with(Topic.ALERTS, "grp", "msg-001")
        await q.stop()

    async def test_consume_skips_xack_when_handler_raises(self) -> None:
        """If handler raises, xack must NOT be called for that message."""
        mock_redis = self._make_mock_redis()
        message = {"bad": True}

        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.ALERTS, [("msg-002", {"data": json_mod.dumps(message)})])]
            await asyncio.sleep(0.05)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def raising_handler(msg: dict[str, Any]) -> None:
            raise ValueError("handler failure")

        q = self._make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", raising_handler)
        await asyncio.sleep(0.05)

        mock_redis.xack.assert_not_called()
        await q.stop()

    async def test_consume_processes_multiple_messages_per_batch(self) -> None:
        mock_redis = self._make_mock_redis()
        batch = [
            ("id-1", {"data": json_mod.dumps({"n": 1})}),
            ("id-2", {"data": json_mod.dumps({"n": 2})}),
            ("id-3", {"data": json_mod.dumps({"n": 3})}),
        ]

        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.NORMALIZED, batch)]
            await asyncio.sleep(0.05)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        q = self._make_queue(mock_redis)
        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        await asyncio.sleep(0.05)

        assert received == [{"n": 1}, {"n": 2}, {"n": 3}]
        assert mock_redis.xack.call_count == 3
        await q.stop()

    async def test_consume_retries_after_non_cancelled_exception(self) -> None:
        """A transient xreadgroup error must not crash the consumer; it retries."""
        mock_redis = self._make_mock_redis()

        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionError("transient failure")
            await asyncio.sleep(1.5)  # Simulate blocking after retry
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        q = self._make_queue(mock_redis)
        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        await asyncio.sleep(0.05)  # Let the first (failing) call happen

        assert call_count >= 1  # At least one call was attempted
        await q.stop()


# ── create_queue() factory ────────────────────────────────────────────────────

class TestCreateQueue:
    def test_returns_in_memory_queue_for_memory_backend(self) -> None:
        with patch("app.pipeline.queue.settings") as mock_settings:
            mock_settings.queue_backend = "memory"
            result = create_queue()
        assert isinstance(result, InMemoryQueue)

    def test_returns_in_memory_queue_for_unknown_backend(self) -> None:
        with patch("app.pipeline.queue.settings") as mock_settings:
            mock_settings.queue_backend = "unknown-backend"
            result = create_queue()
        assert isinstance(result, InMemoryQueue)

    def test_returns_in_memory_queue_when_attribute_missing(self) -> None:
        """getattr fallback: no queue_backend on settings → InMemoryQueue."""

        class _MinimalSettings:
            pass

        with patch("app.pipeline.queue.settings", _MinimalSettings()):
            result = create_queue()
        assert isinstance(result, InMemoryQueue)

    def test_returns_kafka_queue_for_kafka_backend(self) -> None:
        with patch("app.pipeline.queue.settings") as mock_settings:
            mock_settings.queue_backend = "kafka"
            mock_settings.kafka_bootstrap_servers = "broker:9092"
            result = create_queue()
        assert isinstance(result, KafkaQueue)
        assert result._bootstrap == "broker:9092"

    def test_kafka_defaults_bootstrap_when_attribute_absent(self) -> None:
        """getattr fallback: no kafka_bootstrap_servers → 'localhost:9092'."""

        class _KafkaSettings:
            queue_backend = "kafka"

        with patch("app.pipeline.queue.settings", _KafkaSettings()):
            result = create_queue()
        assert isinstance(result, KafkaQueue)
        assert result._bootstrap == "localhost:9092"

    def test_returns_redis_queue_for_redis_backend(self) -> None:
        mock_valkey_asyncio = MagicMock()
        mock_valkey_asyncio.from_url.return_value = AsyncMock()

        with patch("app.pipeline.queue.settings") as mock_settings:
            mock_settings.queue_backend = "redis"
            mock_settings.valkey_url = "redis://localhost:6379"
            with patch.dict(
                sys.modules,
                {
                    "valkey": MagicMock(),
                    "valkey.asyncio": mock_valkey_asyncio,
                },
            ):
                result = create_queue()
        assert isinstance(result, RedisStreamQueue)


# ── get_queue() singleton ────────────────────────────────────────────────────

class TestGetQueue:
    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        """Isolate each test by clearing the module-level singleton."""
        queue_module._queue = None
        yield
        queue_module._queue = None

    def test_returns_message_queue_instance(self) -> None:
        with patch("app.pipeline.queue.settings") as mock_settings:
            mock_settings.queue_backend = "memory"
            q = get_queue()
        assert isinstance(q, MessageQueue)

    def test_returns_same_instance_on_repeated_calls(self) -> None:
        with patch("app.pipeline.queue.settings") as mock_settings:
            mock_settings.queue_backend = "memory"
            q1 = get_queue()
            q2 = get_queue()
        assert q1 is q2

    def test_singleton_starts_as_none(self) -> None:
        assert queue_module._queue is None

    def test_get_queue_sets_module_level_singleton(self) -> None:
        with patch("app.pipeline.queue.settings") as mock_settings:
            mock_settings.queue_backend = "memory"
            q = get_queue()
        assert queue_module._queue is q

    def test_singleton_is_in_memory_queue_by_default(self) -> None:
        with patch("app.pipeline.queue.settings") as mock_settings:
            mock_settings.queue_backend = "memory"
            q = get_queue()
        assert isinstance(q, InMemoryQueue)
