"""
Comprehensive tests for KafkaQueue — Feature 5.4: Kafka/Redpanda enterprise queue.

Coverage:
  - Initialisation: bootstrap stored, producer None before start, empty task list,
    isinstance of MessageQueue
  - Lifecycle: start creates/starts producer, start passes bootstrap_servers and
    value_serializer, stop calls producer.stop(), stop without start is safe,
    stop cancels single/multiple consumer tasks, stop without subscribe is safe
  - Publish: RuntimeError before start, send_and_wait wiring, topic and message
    pass-through, multiple publishes, all six topic constants, edge case payloads
    (empty dict, unicode, deeply nested)
  - Value serializer: lambda v: json.dumps(v).encode() — extracts and verifies
    encoding to bytes, handles edge cases
  - Value deserializer: lambda v: json.loads(v.decode()) — extracts and verifies
    decoding back to dict, handles edge cases
  - Serializer/deserializer round-trip: output of serializer is valid input to
    deserializer
  - Subscribe: task created with correct name (kafka-consumer-{topic}-{group}),
    appended to _tasks, consumer receives bootstrap_servers / group_id /
    auto_offset_reset="earliest" / value_deserializer, consumer.start() called
    before iteration, multiple subscriptions on different topics/groups
  - Consumer delivery: handler called with msg.value, handler called for each
    message in order, consumer.stop() called in finally on normal exit, consumer.stop()
    called in finally on CancelledError, handler exception isolated (loop continues)
  - Consumer error handling: single handler exception caught, all messages
    still attempted, multiple consecutive failures all isolated
  - Integration: full start → subscribe → stop lifecycle, serializer/deserializer
    end-to-end round-trip, consumer delivers message to handler, independent
    handlers on multiple topics
"""

from __future__ import annotations

import asyncio
import json as json_mod
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.pipeline.queue import KafkaQueue, MessageQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def make_kafka_message(value: Any) -> MagicMock:
    """Return a mock Kafka ConsumerRecord with a .value attribute."""
    msg = MagicMock()
    msg.value = value
    return msg


def make_mock_producer() -> AsyncMock:
    """Return an AsyncMock that mimics AIOKafkaProducer."""
    producer = AsyncMock()
    producer.start = AsyncMock()
    producer.stop = AsyncMock()
    producer.send_and_wait = AsyncMock()
    return producer


def make_mock_consumer(messages: list[Any] | None = None) -> MagicMock:
    """
    Return a MagicMock that mimics AIOKafkaConsumer.

    The consumer async-iterates over `messages` then stops.
    consumer.start and consumer.stop are AsyncMocks.
    """
    consumer = MagicMock()
    consumer.start = AsyncMock()
    consumer.stop = AsyncMock()
    _messages = list(messages) if messages is not None else []

    async def _aiter() -> Any:
        for msg in _messages:
            yield msg

    consumer.__aiter__ = lambda: _aiter()
    return consumer


def make_blocking_consumer() -> tuple[MagicMock, asyncio.Event]:
    """
    Return a consumer whose iteration blocks until the returned Event is set.

    Use to keep the consumer task alive so it can be cancelled via q.stop().
    """
    consumer = MagicMock()
    consumer.start = AsyncMock()
    consumer.stop = AsyncMock()
    unblock = asyncio.Event()

    async def _blocking_aiter() -> Any:
        await unblock.wait()
        return
        yield  # make it an async generator

    consumer.__aiter__ = lambda: _blocking_aiter()
    return consumer, unblock


def make_mock_aiokafka(
    messages: list[Any] | None = None,
) -> tuple[MagicMock, AsyncMock, MagicMock]:
    """
    Return (mock_aiokafka_module, mock_producer, mock_consumer).

    Suitable for use with patch.dict(sys.modules, {"aiokafka": mock_aiokafka}).
    """
    producer = make_mock_producer()
    consumer = make_mock_consumer(messages)
    aiokafka = MagicMock()
    aiokafka.AIOKafkaProducer.return_value = producer
    aiokafka.AIOKafkaConsumer.return_value = consumer
    return aiokafka, producer, consumer


# ── Initialisation ─────────────────────────────────────────────────────────────


class TestKafkaQueueInit:
    def test_is_instance_of_message_queue(self) -> None:
        q = KafkaQueue("broker:9092")
        assert isinstance(q, MessageQueue)

    def test_stores_bootstrap_servers(self) -> None:
        q = KafkaQueue("broker1:9092,broker2:9092")
        assert q._bootstrap == "broker1:9092,broker2:9092"

    def test_producer_is_none_before_start(self) -> None:
        q = KafkaQueue("broker:9092")
        assert q._producer is None

    def test_tasks_list_starts_empty(self) -> None:
        q = KafkaQueue("broker:9092")
        assert q._tasks == []

    def test_tasks_list_is_a_list(self) -> None:
        q = KafkaQueue("broker:9092")
        assert isinstance(q._tasks, list)


# ── Lifecycle ─────────────────────────────────────────────────────────────────


class TestKafkaQueueLifecycle:
    async def test_start_creates_producer(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        assert q._producer is producer

    async def test_start_calls_producer_start(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        producer.start.assert_called_once()

    async def test_start_passes_bootstrap_servers_to_producer(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("my-broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        call_kwargs = aiokafka.AIOKafkaProducer.call_args.kwargs
        assert call_kwargs["bootstrap_servers"] == "my-broker:9092"

    async def test_start_passes_value_serializer_kwarg(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        call_kwargs = aiokafka.AIOKafkaProducer.call_args.kwargs
        assert "value_serializer" in call_kwargs

    async def test_stop_without_start_does_not_raise(self) -> None:
        q = KafkaQueue("broker:9092")
        await q.stop()  # _producer is None — must not raise

    async def test_stop_calls_producer_stop(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        await q.stop()
        producer.stop.assert_called_once()

    async def test_stop_does_not_call_producer_stop_if_not_started(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        # Do NOT call start — _producer stays None
        await q.stop()
        producer.stop.assert_not_called()

    async def test_stop_without_subscribe_does_not_raise(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        await q.stop()  # no tasks — must not raise

    async def test_stop_cancels_single_consumer_task(self) -> None:
        consumer, _ = make_blocking_consumer()
        aiokafka = MagicMock()
        aiokafka.AIOKafkaConsumer.return_value = consumer

        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_WAZUH, "grp", handler)

        task = q._tasks[0]
        assert not task.done()

        await q.stop()
        await asyncio.sleep(0)
        assert task.done()

    async def test_stop_cancels_multiple_consumer_tasks(self) -> None:
        q = KafkaQueue("broker:9092")
        aiokafka = MagicMock()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        for topic in [Topic.RAW_WAZUH, Topic.RAW_ZEEK, Topic.NORMALIZED]:
            consumer, _ = make_blocking_consumer()
            aiokafka.AIOKafkaConsumer.return_value = consumer
            with patch.dict(sys.modules, {"aiokafka": aiokafka}):
                await q.subscribe(topic, "grp", handler)

        assert len(q._tasks) == 3
        tasks = list(q._tasks)

        await q.stop()
        await asyncio.sleep(0)
        assert all(t.done() for t in tasks)

    async def test_stop_called_twice_does_not_raise(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        await q.stop()
        await q.stop()  # second stop — _producer already stopped but must not raise


# ── Publish ───────────────────────────────────────────────────────────────────


class TestKafkaQueuePublish:
    async def test_publish_before_start_raises_runtime_error(self) -> None:
        q = KafkaQueue("broker:9092")
        with pytest.raises(RuntimeError, match="not started"):
            await q.publish(Topic.ALERTS, {"test": True})

    async def test_runtime_error_message_mentions_not_started(self) -> None:
        q = KafkaQueue("broker:9092")
        with pytest.raises(RuntimeError, match="not started"):
            await q.publish(Topic.NORMALIZED, {})

    async def test_publish_calls_send_and_wait(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        await q.publish(Topic.ALERTS, {"alert": "test"})
        producer.send_and_wait.assert_called_once()

    async def test_publish_passes_topic_as_first_positional_arg(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        await q.publish(Topic.ALERTS, {"x": 1})
        assert producer.send_and_wait.call_args.args[0] == Topic.ALERTS

    async def test_publish_passes_message_as_second_positional_arg(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        msg = {"key": "value", "num": 42}
        await q.publish(Topic.ALERTS, msg)
        assert producer.send_and_wait.call_args.args[1] == msg

    async def test_multiple_publishes_each_call_send_and_wait(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        for i in range(5):
            await q.publish(Topic.ALERTS, {"i": i})
        assert producer.send_and_wait.call_count == 5

    async def test_publish_with_empty_dict(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        await q.publish(Topic.ENRICHED, {})
        assert producer.send_and_wait.call_args.args[1] == {}

    async def test_publish_with_unicode_values(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        msg = {"msg": "ñoño 日本語 Ωmega"}
        await q.publish(Topic.RAW_WAZUH, msg)
        assert producer.send_and_wait.call_args.args[1] == msg

    async def test_publish_with_deeply_nested_payload(self) -> None:
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        msg: dict[str, Any] = {
            "a": {"b": {"c": {"d": [1, 2, 3]}}},
            "tags": ["T1021", "T1078"],
        }
        await q.publish(Topic.ENRICHED, msg)
        assert producer.send_and_wait.call_args.args[1] == msg

    async def test_publish_all_six_topics(self) -> None:
        topics = [
            Topic.RAW_WAZUH,
            Topic.RAW_ZEEK,
            Topic.RAW_SURICATA,
            Topic.NORMALIZED,
            Topic.ALERTS,
            Topic.ENRICHED,
        ]
        for topic in topics:
            aiokafka, producer, _ = make_mock_aiokafka()
            q = KafkaQueue("broker:9092")
            with patch.dict(sys.modules, {"aiokafka": aiokafka}):
                await q.start()
            await q.publish(topic, {"src": topic})
            assert producer.send_and_wait.call_args.args[0] == topic

    async def test_publish_preserves_message_identity(self) -> None:
        """send_and_wait receives the exact same dict object, not a copy."""
        aiokafka, producer, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        msg = {"ref": "check-identity"}
        await q.publish(Topic.NORMALIZED, msg)
        assert producer.send_and_wait.call_args.args[1] is msg


# ── Value serializer / deserializer ───────────────────────────────────────────


class TestKafkaQueueSerializers:
    async def _get_producer_serializer(self) -> Any:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
        return aiokafka.AIOKafkaProducer.call_args.kwargs["value_serializer"]

    async def _get_consumer_deserializer(self) -> Any:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.NORMALIZED, "grp", handler)
            await asyncio.sleep(0)
            await q.stop()
        return aiokafka.AIOKafkaConsumer.call_args.kwargs["value_deserializer"]

    async def test_value_serializer_returns_bytes(self) -> None:
        serializer = await self._get_producer_serializer()
        result = serializer({"k": "v"})
        assert isinstance(result, bytes)

    async def test_value_serializer_encodes_dict_to_json(self) -> None:
        serializer = await self._get_producer_serializer()
        payload = {"alert": "T1021", "severity": 3}
        result = serializer(payload)
        assert json_mod.loads(result) == payload

    async def test_value_serializer_handles_empty_dict(self) -> None:
        serializer = await self._get_producer_serializer()
        result = serializer({})
        assert json_mod.loads(result) == {}

    async def test_value_serializer_handles_nested_payload(self) -> None:
        serializer = await self._get_producer_serializer()
        payload: dict[str, Any] = {"a": {"b": [1, 2, 3]}, "tags": ["T1021"]}
        assert json_mod.loads(serializer(payload)) == payload

    async def test_value_serializer_handles_unicode(self) -> None:
        serializer = await self._get_producer_serializer()
        payload = {"msg": "ñoño 日本語"}
        assert json_mod.loads(serializer(payload)) == payload

    async def test_value_deserializer_returns_dict(self) -> None:
        deserializer = await self._get_consumer_deserializer()
        raw = json_mod.dumps({"k": "v"}).encode()
        result = deserializer(raw)
        assert isinstance(result, dict)

    async def test_value_deserializer_decodes_json_bytes_to_dict(self) -> None:
        deserializer = await self._get_consumer_deserializer()
        payload = {"event_type": "NetworkActivity", "severity": 5}
        raw = json_mod.dumps(payload).encode()
        assert deserializer(raw) == payload

    async def test_value_deserializer_handles_empty_object(self) -> None:
        deserializer = await self._get_consumer_deserializer()
        assert deserializer(b"{}") == {}

    async def test_value_deserializer_handles_nested_payload(self) -> None:
        deserializer = await self._get_consumer_deserializer()
        payload: dict[str, Any] = {"attacks": [{"technique_id": "T1021"}]}
        raw = json_mod.dumps(payload).encode()
        assert deserializer(raw) == payload

    async def test_serializer_deserializer_roundtrip(self) -> None:
        """Output of value_serializer is valid input to value_deserializer."""
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
            await q.subscribe(Topic.NORMALIZED, "grp", handler)
            await asyncio.sleep(0)
            await q.stop()

        serializer = aiokafka.AIOKafkaProducer.call_args.kwargs["value_serializer"]
        deserializer = aiokafka.AIOKafkaConsumer.call_args.kwargs["value_deserializer"]
        original: dict[str, Any] = {
            "event_type": "NetworkActivity",
            "severity": 5,
            "nested": {"key": "value"},
            "list": [1, 2, 3],
        }
        assert deserializer(serializer(original)) == original


# ── Subscribe ─────────────────────────────────────────────────────────────────


class TestKafkaQueueSubscribe:
    async def test_subscribe_creates_exactly_one_task(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        assert len(q._tasks) == 1
        await q.stop()

    async def test_subscribe_task_is_asyncio_task(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "grp", handler)
        assert isinstance(q._tasks[0], asyncio.Task)
        await q.stop()

    async def test_subscribe_task_name_format(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_WAZUH, "detection-grp", handler)
        expected = f"kafka-consumer-{Topic.RAW_WAZUH}-detection-grp"
        assert q._tasks[0].get_name() == expected
        await q.stop()

    async def test_subscribe_task_name_includes_topic(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.NORMALIZED, "grp", handler)
        assert Topic.NORMALIZED in q._tasks[0].get_name()
        await q.stop()

    async def test_subscribe_task_name_includes_group(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ENRICHED, "sigma-consumers", handler)
        assert "sigma-consumers" in q._tasks[0].get_name()
        await q.stop()

    async def test_subscribe_passes_topic_to_consumer(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_SURICATA, "grp", handler)
            await asyncio.sleep(0)  # let task run and create consumer
            await q.stop()

        assert Topic.RAW_SURICATA in aiokafka.AIOKafkaConsumer.call_args.args

    async def test_subscribe_passes_bootstrap_servers_to_consumer(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("custom-broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.NORMALIZED, "grp", handler)
            await asyncio.sleep(0)
            await q.stop()

        kw = aiokafka.AIOKafkaConsumer.call_args.kwargs
        assert kw["bootstrap_servers"] == "custom-broker:9092"

    async def test_subscribe_passes_group_id_to_consumer(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.NORMALIZED, "my-consumer-group", handler)
            await asyncio.sleep(0)
            await q.stop()

        kw = aiokafka.AIOKafkaConsumer.call_args.kwargs
        assert kw["group_id"] == "my-consumer-group"

    async def test_subscribe_passes_auto_offset_reset_earliest(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0)
            await q.stop()

        kw = aiokafka.AIOKafkaConsumer.call_args.kwargs
        assert kw["auto_offset_reset"] == "earliest"

    async def test_subscribe_passes_value_deserializer_kwarg(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0)
            await q.stop()

        assert "value_deserializer" in aiokafka.AIOKafkaConsumer.call_args.kwargs

    async def test_multiple_subscribes_create_multiple_tasks(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_WAZUH, "grp-a", handler)
            await q.subscribe(Topic.RAW_ZEEK, "grp-b", handler)
            await q.subscribe(Topic.NORMALIZED, "grp-c", handler)

        assert len(q._tasks) == 3
        await q.stop()

    async def test_multiple_subscribes_have_unique_task_names(self) -> None:
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_WAZUH, "grp-a", handler)
            await q.subscribe(Topic.RAW_ZEEK, "grp-b", handler)

        names = {t.get_name() for t in q._tasks}
        assert len(names) == 2
        await q.stop()

    async def test_all_six_topics_can_be_subscribed(self) -> None:
        topics = [
            Topic.RAW_WAZUH,
            Topic.RAW_ZEEK,
            Topic.RAW_SURICATA,
            Topic.NORMALIZED,
            Topic.ALERTS,
            Topic.ENRICHED,
        ]
        for topic in topics:
            aiokafka, _, _ = make_mock_aiokafka()
            q = KafkaQueue("broker:9092")

            async def handler(msg: dict[str, Any]) -> None:
                pass

            with patch.dict(sys.modules, {"aiokafka": aiokafka}):
                await q.subscribe(topic, "grp", handler)

            assert len(q._tasks) == 1
            assert q._tasks[0].get_name() == f"kafka-consumer-{topic}-grp"
            await q.stop()


# ── Consumer delivery ─────────────────────────────────────────────────────────


class TestKafkaQueueConsumerDelivery:
    async def test_consumer_start_called_before_iteration(self) -> None:
        """consumer.start() must be awaited before async for begins."""
        aiokafka, _, consumer = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")
        call_order: list[str] = []

        original_start = consumer.start.side_effect

        async def track_start() -> None:
            call_order.append("start")

        consumer.start.side_effect = track_start

        async def handler(msg: dict[str, Any]) -> None:
            call_order.append("handler")

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0.05)
            await q.stop()

        assert "start" in call_order
        if "handler" in call_order:
            assert call_order.index("start") < call_order.index("handler")

    async def test_consumer_stop_called_after_empty_consumer(self) -> None:
        """consumer.stop() must be called in finally even when no messages."""
        aiokafka, _, consumer = make_mock_aiokafka(messages=[])
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0.05)

        consumer.stop.assert_called_once()
        await q.stop()

    async def test_handler_called_with_msg_value(self) -> None:
        payload = {"event_type": "NetworkActivity", "severity": 5}
        messages = [make_kafka_message(payload)]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        received: list[Any] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0.05)

        assert len(received) == 1
        assert received[0] is payload
        await q.stop()

    async def test_handler_called_for_each_message(self) -> None:
        payloads = [{"id": i} for i in range(5)]
        messages = [make_kafka_message(p) for p in payloads]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        received: list[Any] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.NORMALIZED, "grp", handler)
            await asyncio.sleep(0.05)

        assert len(received) == 5
        assert received == payloads
        await q.stop()

    async def test_handler_receives_messages_in_order(self) -> None:
        payloads = [{"seq": i} for i in range(10)]
        messages = [make_kafka_message(p) for p in payloads]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        received: list[int] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg["seq"])

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ENRICHED, "grp", handler)
            await asyncio.sleep(0.05)

        assert received == list(range(10))
        await q.stop()

    async def test_handler_receives_exact_value_not_wrapper(self) -> None:
        """Handler receives msg.value directly — no extra wrapping."""
        inner = {"source": "zeek", "proto": "tcp"}
        messages = [make_kafka_message(inner)]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        received: list[Any] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_ZEEK, "grp", handler)
            await asyncio.sleep(0.05)

        assert len(received) == 1
        assert received[0] == inner
        await q.stop()

    async def test_consumer_stop_called_on_task_cancellation(self) -> None:
        """consumer.stop() must be called in finally even on CancelledError."""
        consumer, _ = make_blocking_consumer()
        aiokafka = MagicMock()
        aiokafka.AIOKafkaConsumer.return_value = consumer

        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0)  # let task start and reach blocking wait

        await q.stop()
        await asyncio.sleep(0)

        consumer.stop.assert_called_once()

    async def test_single_message_no_extra_handler_calls(self) -> None:
        payload = {"only": "message"}
        messages = [make_kafka_message(payload)]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        call_count = 0

        async def handler(msg: dict[str, Any]) -> None:
            nonlocal call_count
            call_count += 1

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_SURICATA, "grp", handler)
            await asyncio.sleep(0.05)

        assert call_count == 1
        await q.stop()


# ── Consumer error handling ───────────────────────────────────────────────────


class TestKafkaQueueConsumerErrors:
    async def test_handler_exception_isolated_loop_continues(self) -> None:
        """Exception in handler is caught; remaining messages are still processed."""
        payloads = [{"n": 0}, {"n": 1}, {"n": 2}]
        messages = [make_kafka_message(p) for p in payloads]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        received: list[int] = []

        async def handler(msg: dict[str, Any]) -> None:
            if msg["n"] == 1:
                raise ValueError("forced failure on message 1")
            received.append(msg["n"])

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0.05)

        assert received == [0, 2]
        await q.stop()

    async def test_all_messages_attempted_when_handler_always_fails(self) -> None:
        """Every message is passed to the handler even if all raise exceptions."""
        payloads = [{"n": i} for i in range(5)]
        messages = [make_kafka_message(p) for p in payloads]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        attempted: list[int] = []

        async def handler(msg: dict[str, Any]) -> None:
            attempted.append(msg["n"])
            raise RuntimeError("always fail")

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0.05)

        assert attempted == list(range(5))
        await q.stop()

    async def test_first_message_failure_does_not_prevent_second_delivery(self) -> None:
        payloads = [{"ok": False}, {"ok": True}]
        messages = [make_kafka_message(p) for p in payloads]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        received: list[Any] = []

        async def handler(msg: dict[str, Any]) -> None:
            if not msg["ok"]:
                raise ValueError("bad message")
            received.append(msg)

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
            await asyncio.sleep(0.05)

        assert received == [{"ok": True}]
        await q.stop()

    async def test_consumer_stop_called_after_handler_exceptions(self) -> None:
        """consumer.stop() is called in finally even when all handlers raise."""
        payloads = [{"n": i} for i in range(3)]
        messages = [make_kafka_message(p) for p in payloads]
        aiokafka, _, consumer = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            raise RuntimeError("always fail")

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.NORMALIZED, "grp", handler)
            await asyncio.sleep(0.05)

        consumer.stop.assert_called_once()
        await q.stop()

    async def test_handler_exception_type_does_not_matter(self) -> None:
        """Any Exception subclass from the handler is caught and isolated."""
        exception_types = [ValueError, RuntimeError, KeyError, TypeError, OSError]
        for exc_type in exception_types:
            payloads = [{"raise": True}, {"raise": False}]
            messages = [make_kafka_message(p) for p in payloads]
            aiokafka, _, _ = make_mock_aiokafka(messages=messages)
            q = KafkaQueue("broker:9092")
            received: list[Any] = []

            async def handler(msg: dict[str, Any], _exc=exc_type) -> None:
                if msg["raise"]:
                    raise _exc("test")
                received.append(msg)

            with patch.dict(sys.modules, {"aiokafka": aiokafka}):
                await q.subscribe(Topic.ALERTS, "grp", handler)
                await asyncio.sleep(0.05)

            assert received == [{"raise": False}]
            await q.stop()


# ── Integration ───────────────────────────────────────────────────────────────


class TestKafkaQueueIntegration:
    async def test_start_subscribe_stop_full_lifecycle(self) -> None:
        """Full lifecycle: start → subscribe → stop without errors."""
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
            await q.subscribe(Topic.NORMALIZED, "grp", handler)
        await q.stop()

    async def test_serializer_deserializer_roundtrip_integration(self) -> None:
        """Serialize → wire → deserialize yields the original dict."""
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
            await q.subscribe(Topic.ENRICHED, "grp", handler)
            await asyncio.sleep(0)
            await q.stop()

        serializer = aiokafka.AIOKafkaProducer.call_args.kwargs["value_serializer"]
        deserializer = aiokafka.AIOKafkaConsumer.call_args.kwargs["value_deserializer"]
        original: dict[str, Any] = {
            "event_type": "NetworkActivity",
            "severity": 5,
            "attacks": [{"technique_id": "T1021", "tactic": "lateral-movement"}],
        }
        wire = serializer(original)
        assert isinstance(wire, bytes)
        assert deserializer(wire) == original

    async def test_consumer_delivers_message_to_handler_end_to_end(self) -> None:
        """Message flows from consumer → msg.value → handler."""
        expected = {"event": "alert", "src_ip": "192.168.1.100"}
        messages = [make_kafka_message(expected)]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        received: list[Any] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ALERTS, "sigma-consumer", handler)
            await asyncio.sleep(0.05)

        assert received == [expected]
        await q.stop()

    async def test_multiple_topics_deliver_to_independent_handlers(self) -> None:
        """Two subscriptions on different topics deliver to separate handlers."""
        wazuh_payload = {"src": "wazuh", "rule": "1001"}
        zeek_payload = {"src": "zeek", "proto": "tcp"}

        wazuh_msg = make_kafka_message(wazuh_payload)
        zeek_msg = make_kafka_message(zeek_payload)

        consumer_wazuh = make_mock_consumer(messages=[wazuh_msg])
        consumer_zeek = make_mock_consumer(messages=[zeek_msg])

        aiokafka = MagicMock()
        aiokafka.AIOKafkaConsumer.side_effect = [consumer_wazuh, consumer_zeek]

        q = KafkaQueue("broker:9092")
        received_wazuh: list[Any] = []
        received_zeek: list[Any] = []

        async def wazuh_handler(msg: dict[str, Any]) -> None:
            received_wazuh.append(msg)

        async def zeek_handler(msg: dict[str, Any]) -> None:
            received_zeek.append(msg)

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.RAW_WAZUH, "wazuh-grp", wazuh_handler)
            await q.subscribe(Topic.RAW_ZEEK, "zeek-grp", zeek_handler)
            await asyncio.sleep(0.05)

        assert received_wazuh == [wazuh_payload]
        assert received_zeek == [zeek_payload]
        await q.stop()

    async def test_multiple_messages_across_single_subscription(self) -> None:
        """A batch of messages is fully delivered through a single subscription."""
        payloads = [{"alert_id": i, "severity": i % 5} for i in range(8)]
        messages = [make_kafka_message(p) for p in payloads]
        aiokafka, _, _ = make_mock_aiokafka(messages=messages)
        q = KafkaQueue("broker:9092")
        received: list[Any] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.subscribe(Topic.ENRICHED, "alert-manager", handler)
            await asyncio.sleep(0.05)

        assert received == payloads
        await q.stop()

    async def test_publish_and_consumer_use_compatible_params(self) -> None:
        """
        Producer is created with bootstrap_servers; consumer also gets
        bootstrap_servers — both from the same KafkaQueue._bootstrap.
        """
        aiokafka, _, _ = make_mock_aiokafka()
        q = KafkaQueue("shared-broker:9092")

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch.dict(sys.modules, {"aiokafka": aiokafka}):
            await q.start()
            await q.subscribe(Topic.NORMALIZED, "grp", handler)
            await asyncio.sleep(0)
            await q.stop()

        producer_bs = aiokafka.AIOKafkaProducer.call_args.kwargs["bootstrap_servers"]
        consumer_bs = aiokafka.AIOKafkaConsumer.call_args.kwargs["bootstrap_servers"]
        assert producer_bs == consumer_bs == "shared-broker:9092"
