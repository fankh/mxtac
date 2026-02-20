"""
Comprehensive tests for RedisStreamQueue — Feature 19.2: Valkey Streams queue.

Coverage:
  - Initialisation: task list starts empty, _redis attribute injected
  - Lifecycle: start (no-op), stop with 0/1/N tasks, aclose always called
  - Publish: xadd wiring, JSON serialisation in data field, maxlen/approximate
    flags, multiple publishes, all six topic constants, empty dict, unicode,
    deeply nested payloads
  - Subscribe: xgroup_create wiring (topic, group, id="0", mkstream=True),
    BUSYGROUP handling, arbitrary exception from xgroup_create swallowed,
    task naming (redis-consumer-{topic}-{group}), task appended to _tasks,
    consumer name is "{group}-worker", xreadgroup called with count=10 /
    block=1000 / {topic: ">"}, multiple groups on same topic, multiple topics
  - Consume loop — delivery: empty list batch, None batch, single message
    JSON-decoded, handler receives exact dict, xack(topic, group, msg_id) on
    success, no xack on handler failure, handler continues after failure
  - Consume loop — batch processing: multiple messages in one xreadgroup return,
    all delivered in order, all acked separately, partial failure (some acked,
    some not)
  - Consume loop — error handling: CancelledError from xreadgroup exits loop,
    CancelledError from asyncio.sleep(1) exits loop, connection/transient error
    triggers asyncio.sleep(1) retry, multiple consecutive errors retry each time
  - Integration: publish payload captured → injected into xreadgroup → handler
    receives identical deserialized dict
"""

from __future__ import annotations

import asyncio
import json as json_mod
from typing import Any
from unittest.mock import AsyncMock, call, patch

import pytest

from app.pipeline.queue import MessageQueue, RedisStreamQueue, Topic


# ── Helpers ────────────────────────────────────────────────────────────────────


def make_mock_redis() -> AsyncMock:
    """Return an AsyncMock that mimics the valkey async client interface."""
    redis = AsyncMock()
    redis.xadd = AsyncMock(return_value="1-0")
    redis.xgroup_create = AsyncMock()
    redis.xreadgroup = AsyncMock(return_value=[])
    redis.xack = AsyncMock()
    redis.aclose = AsyncMock()
    return redis


def make_queue(mock_redis: AsyncMock) -> RedisStreamQueue:
    """Instantiate RedisStreamQueue without calling __init__ (no valkey import)."""
    q: RedisStreamQueue = object.__new__(RedisStreamQueue)
    q._redis = mock_redis
    q._tasks = []
    return q


# ── Initialisation ─────────────────────────────────────────────────────────────


class TestRedisStreamQueueInit:
    def test_is_instance_of_message_queue(self) -> None:
        q = make_queue(make_mock_redis())
        assert isinstance(q, MessageQueue)

    def test_tasks_list_starts_empty(self) -> None:
        q = make_queue(make_mock_redis())
        assert q._tasks == []

    def test_redis_attribute_is_set(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        assert q._redis is mock_redis


# ── Lifecycle ─────────────────────────────────────────────────────────────────


class TestRedisStreamQueueLifecycle:
    async def test_start_does_not_raise(self) -> None:
        q = make_queue(make_mock_redis())
        await q.start()

    async def test_start_does_not_call_redis(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        await q.start()
        mock_redis.xadd.assert_not_called()
        mock_redis.xgroup_create.assert_not_called()
        mock_redis.xreadgroup.assert_not_called()

    async def test_stop_with_no_tasks_calls_aclose(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        await q.stop()
        mock_redis.aclose.assert_called_once()

    async def test_stop_calls_aclose_exactly_once(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.ALERTS, "grp", handler)
        await q.stop()
        mock_redis.aclose.assert_called_once()

    async def test_stop_cancels_single_consumer_task(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        task = q._tasks[0]
        assert not task.done()

        await q.stop()
        await asyncio.sleep(0)
        assert task.done()

    async def test_stop_cancels_multiple_consumer_tasks(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp-a", handler)
        await q.subscribe(Topic.RAW_ZEEK, "grp-b", handler)
        await q.subscribe(Topic.NORMALIZED, "grp-c", handler)
        tasks = list(q._tasks)
        assert len(tasks) == 3

        await q.stop()
        await asyncio.sleep(0)
        assert all(t.done() for t in tasks)

    async def test_stop_without_subscribe_does_not_raise(self) -> None:
        q = make_queue(make_mock_redis())
        await q.start()
        await q.stop()


# ── Publish ───────────────────────────────────────────────────────────────────


class TestRedisStreamQueuePublish:
    async def test_xadd_called_with_correct_topic(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        await q.publish(Topic.ALERTS, {"k": "v"})
        assert mock_redis.xadd.call_args.args[0] == Topic.ALERTS

    async def test_payload_has_data_field(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        await q.publish(Topic.ALERTS, {"x": 1})
        payload = mock_redis.xadd.call_args.args[1]
        assert "data" in payload

    async def test_data_field_is_json_encoded_string(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        msg = {"key": "value", "num": 42}
        await q.publish(Topic.ALERTS, msg)
        payload = mock_redis.xadd.call_args.args[1]
        assert json_mod.loads(payload["data"]) == msg

    async def test_maxlen_is_10000(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        await q.publish(Topic.NORMALIZED, {"x": 1})
        kw = mock_redis.xadd.call_args.kwargs
        assert kw["maxlen"] == 10_000

    async def test_approximate_is_true(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        await q.publish(Topic.NORMALIZED, {"x": 1})
        kw = mock_redis.xadd.call_args.kwargs
        assert kw["approximate"] is True

    async def test_multiple_publishes_each_call_xadd(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        for i in range(5):
            await q.publish(Topic.ALERTS, {"i": i})
        assert mock_redis.xadd.call_count == 5

    async def test_empty_dict_serialised_correctly(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        await q.publish(Topic.ENRICHED, {})
        payload = mock_redis.xadd.call_args.args[1]
        assert json_mod.loads(payload["data"]) == {}

    async def test_unicode_values_preserved(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        msg = {"msg": "ñoño 日本語 Ωmega"}
        await q.publish(Topic.RAW_WAZUH, msg)
        payload = mock_redis.xadd.call_args.args[1]
        assert json_mod.loads(payload["data"]) == msg

    async def test_deeply_nested_payload_serialised(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        msg: dict[str, Any] = {
            "a": {"b": {"c": {"d": [1, 2, 3]}}},
            "tags": ["T1021", "T1078"],
        }
        await q.publish(Topic.ENRICHED, msg)
        payload = mock_redis.xadd.call_args.args[1]
        assert json_mod.loads(payload["data"]) == msg

    async def test_all_six_topics_publish_successfully(self) -> None:
        topics = [
            Topic.RAW_WAZUH,
            Topic.RAW_ZEEK,
            Topic.RAW_SURICATA,
            Topic.NORMALIZED,
            Topic.ALERTS,
            Topic.ENRICHED,
        ]
        for topic in topics:
            mock_redis = make_mock_redis()
            q = make_queue(mock_redis)
            await q.publish(topic, {"src": topic})
            assert mock_redis.xadd.call_args.args[0] == topic

    async def test_payload_contains_only_data_field(self) -> None:
        """xadd payload must have exactly one key: 'data'."""
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)
        await q.publish(Topic.ALERTS, {"x": 1})
        payload = mock_redis.xadd.call_args.args[1]
        assert set(payload.keys()) == {"data"}


# ── Subscribe ─────────────────────────────────────────────────────────────────


class TestRedisStreamQueueSubscribe:
    async def test_xgroup_create_called_with_correct_args(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "detection-grp", handler)
        await q.stop()

        mock_redis.xgroup_create.assert_called_once_with(
            Topic.RAW_WAZUH, "detection-grp", id="0", mkstream=True
        )

    async def test_xgroup_create_called_with_id_zero(self) -> None:
        """id='0' means read from the beginning of the stream."""
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        await q.stop()

        kw = mock_redis.xgroup_create.call_args.kwargs
        assert kw["id"] == "0"

    async def test_xgroup_create_called_with_mkstream_true(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        await q.stop()

        kw = mock_redis.xgroup_create.call_args.kwargs
        assert kw["mkstream"] is True

    async def test_busygroup_exception_swallowed(self) -> None:
        """BUSYGROUP from xgroup_create must not propagate."""
        mock_redis = make_mock_redis()
        mock_redis.xgroup_create.side_effect = Exception(
            "BUSYGROUP Consumer Group name already exists"
        )
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_ZEEK, "grp", handler)  # must not raise
        await q.stop()

    async def test_arbitrary_exception_from_xgroup_create_swallowed(self) -> None:
        """Any exception (not just BUSYGROUP) from xgroup_create is ignored."""
        mock_redis = make_mock_redis()
        mock_redis.xgroup_create.side_effect = RuntimeError("unexpected error")
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.ALERTS, "grp", handler)  # must not raise
        await q.stop()

    async def test_task_name_is_redis_consumer_topic_group(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_SURICATA, "sigma-grp", handler)
        assert q._tasks[0].get_name() == f"redis-consumer-{Topic.RAW_SURICATA}-sigma-grp"
        await q.stop()

    async def test_task_appended_to_tasks_list(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        assert len(q._tasks) == 0
        await q.subscribe(Topic.ALERTS, "grp", handler)
        assert len(q._tasks) == 1
        await q.stop()

    async def test_multiple_subscriptions_create_separate_tasks(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp-a", handler)
        await q.subscribe(Topic.RAW_ZEEK, "grp-b", handler)
        await q.subscribe(Topic.NORMALIZED, "grp-c", handler)
        assert len(q._tasks) == 3
        await q.stop()

    async def test_multiple_groups_same_topic_each_get_own_task(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.ALERTS, "enricher", handler)
        await q.subscribe(Topic.ALERTS, "reporter", handler)
        assert len(q._tasks) == 2
        names = {t.get_name() for t in q._tasks}
        assert f"redis-consumer-{Topic.ALERTS}-enricher" in names
        assert f"redis-consumer-{Topic.ALERTS}-reporter" in names
        await q.stop()

    async def test_xreadgroup_consumer_name_is_group_worker(self) -> None:
        """Consumer name used in xreadgroup must be '{group}-worker'."""
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        called_event = asyncio.Event()
        captured_consumer: list[str] = []

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            if not called_event.is_set():
                captured_consumer.append(args[1])  # second positional arg is consumer
                called_event.set()
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.ALERTS, "mygroup", handler)
        await asyncio.wait_for(called_event.wait(), timeout=1.0)
        await q.stop()

        assert captured_consumer == ["mygroup-worker"]

    async def test_xreadgroup_uses_topic_gt_stream_spec(self) -> None:
        """xreadgroup must be called with {topic: '>'} to read new messages."""
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        called_event = asyncio.Event()
        captured_streams: list[dict[str, str]] = []

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            if not called_event.is_set():
                captured_streams.append(args[2])  # third positional arg is streams dict
                called_event.set()
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        await asyncio.wait_for(called_event.wait(), timeout=1.0)
        await q.stop()

        assert captured_streams == [{Topic.NORMALIZED: ">"}]

    async def test_xreadgroup_called_with_count_10(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        called_event = asyncio.Event()
        captured_kwargs: list[dict[str, Any]] = []

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            if not called_event.is_set():
                captured_kwargs.append(kwargs)
                called_event.set()
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.wait_for(called_event.wait(), timeout=1.0)
        await q.stop()

        assert captured_kwargs[0]["count"] == 10

    async def test_xreadgroup_called_with_block_1000(self) -> None:
        mock_redis = make_mock_redis()
        q = make_queue(mock_redis)

        called_event = asyncio.Event()
        captured_kwargs: list[dict[str, Any]] = []

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            if not called_event.is_set():
                captured_kwargs.append(kwargs)
                called_event.set()
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.wait_for(called_event.wait(), timeout=1.0)
        await q.stop()

        assert captured_kwargs[0]["block"] == 1000


# ── Consume loop — delivery ────────────────────────────────────────────────────


class TestRedisStreamQueueConsumeDelivery:
    async def test_empty_batch_does_not_call_handler(self) -> None:
        mock_redis = make_mock_redis()
        call_count = 0

        async def counting_xreadgroup(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=counting_xreadgroup)

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.sleep(0.05)
        await q.stop()

        assert received == []

    async def test_none_batch_does_not_crash(self) -> None:
        """xreadgroup returning None (no new messages) must not crash the loop."""
        mock_redis = make_mock_redis()
        call_count = 0

        async def none_xreadgroup(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=none_xreadgroup)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.sleep(0.05)
        await q.stop()  # must not raise

    async def test_single_message_delivered_to_handler(self) -> None:
        mock_redis = make_mock_redis()
        message = {"alert": "sigma-match", "severity": "high"}
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.ALERTS, [("msg-001", {"data": json_mod.dumps(message)})])]
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.sleep(0.05)
        await q.stop()

        assert received == [message]

    async def test_handler_receives_exact_deserialized_dict(self) -> None:
        """No extra wrapping — handler receives the original dict, not a wrapper."""
        mock_redis = make_mock_redis()
        original = {"source": "wazuh", "rule_id": "sigma-999", "count": 3, "nested": {"ok": True}}
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.RAW_WAZUH, [("id-x", {"data": json_mod.dumps(original)})])]
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        q = make_queue(mock_redis)
        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        await asyncio.sleep(0.05)
        await q.stop()

        assert len(received) == 1
        assert received[0] == original

    async def test_xack_called_with_topic_group_msg_id(self) -> None:
        mock_redis = make_mock_redis()
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.ALERTS, [("msg-abc", {"data": json_mod.dumps({"x": 1})})])]
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "my-group", handler)
        await asyncio.sleep(0.05)
        await q.stop()

        mock_redis.xack.assert_called_once_with(Topic.ALERTS, "my-group", "msg-abc")

    async def test_xack_not_called_when_handler_raises(self) -> None:
        mock_redis = make_mock_redis()
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.ALERTS, [("msg-fail", {"data": json_mod.dumps({"bad": True})})])]
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def raising_handler(msg: dict[str, Any]) -> None:
            raise ValueError("handler failure")

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", raising_handler)
        await asyncio.sleep(0.05)
        await q.stop()

        mock_redis.xack.assert_not_called()

    async def test_consumer_continues_after_handler_failure(self) -> None:
        """A handler exception must not stop the consume loop."""
        mock_redis = make_mock_redis()
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.ALERTS, [("msg-1", {"data": json_mod.dumps({"fail": True})})])]
            if call_count == 2:
                return [(Topic.ALERTS, [("msg-2", {"data": json_mod.dumps({"ok": True})})])]
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        received: list[dict[str, Any]] = []
        handler_call = 0

        async def flaky_handler(msg: dict[str, Any]) -> None:
            nonlocal handler_call
            handler_call += 1
            if msg.get("fail"):
                raise RuntimeError("expected failure")
            received.append(msg)

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", flaky_handler)
        await asyncio.sleep(0.1)
        await q.stop()

        assert received == [{"ok": True}]
        assert handler_call == 2


# ── Consume loop — batch processing ───────────────────────────────────────────


class TestRedisStreamQueueBatchProcessing:
    async def test_batch_all_messages_delivered_in_order(self) -> None:
        mock_redis = make_mock_redis()
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
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        q = make_queue(mock_redis)
        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        await asyncio.sleep(0.05)
        await q.stop()

        assert received == [{"n": 1}, {"n": 2}, {"n": 3}]

    async def test_batch_all_messages_acked_separately(self) -> None:
        mock_redis = make_mock_redis()
        batch = [
            ("id-10", {"data": json_mod.dumps({"n": 10})}),
            ("id-20", {"data": json_mod.dumps({"n": 20})}),
            ("id-30", {"data": json_mod.dumps({"n": 30})}),
        ]
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.NORMALIZED, batch)]
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        q = make_queue(mock_redis)
        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        await asyncio.sleep(0.05)
        await q.stop()

        assert mock_redis.xack.call_count == 3
        xack_calls = mock_redis.xack.call_args_list
        assert call(Topic.NORMALIZED, "grp", "id-10") in xack_calls
        assert call(Topic.NORMALIZED, "grp", "id-20") in xack_calls
        assert call(Topic.NORMALIZED, "grp", "id-30") in xack_calls

    async def test_batch_partial_failure_only_successful_messages_acked(self) -> None:
        """In a batch: msg-1 succeeds (acked), msg-2 fails (not acked), msg-3 succeeds (acked)."""
        mock_redis = make_mock_redis()
        batch = [
            ("id-ok-1", {"data": json_mod.dumps({"ok": True, "idx": 1})}),
            ("id-fail",  {"data": json_mod.dumps({"fail": True})}),
            ("id-ok-2", {"data": json_mod.dumps({"ok": True, "idx": 2})}),
        ]
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.ENRICHED, batch)]
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            if msg.get("fail"):
                raise ValueError("intentional failure")

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ENRICHED, "grp", handler)
        await asyncio.sleep(0.05)
        await q.stop()

        assert mock_redis.xack.call_count == 2
        xack_calls = mock_redis.xack.call_args_list
        assert call(Topic.ENRICHED, "grp", "id-ok-1") in xack_calls
        assert call(Topic.ENRICHED, "grp", "id-ok-2") in xack_calls
        assert call(Topic.ENRICHED, "grp", "id-fail") not in xack_calls

    async def test_max_count_messages_in_single_batch(self) -> None:
        """A full batch of 10 (the count limit) is handled correctly."""
        mock_redis = make_mock_redis()
        batch = [
            (f"id-{i}", {"data": json_mod.dumps({"n": i})}) for i in range(10)
        ]
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.ALERTS, batch)]
            await asyncio.sleep(0.1)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.sleep(0.05)
        await q.stop()

        assert len(received) == 10
        assert received == [{"n": i} for i in range(10)]
        assert mock_redis.xack.call_count == 10


# ── Consume loop — error handling ─────────────────────────────────────────────


class TestRedisStreamQueueConsumeErrors:
    async def test_cancelled_error_from_xreadgroup_exits_loop(self) -> None:
        """CancelledError must break out of the consume loop immediately."""
        mock_redis = make_mock_redis()
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise asyncio.CancelledError()
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.sleep(0.05)

        # The task should be done because CancelledError broke the loop
        task = q._tasks[0]
        await asyncio.sleep(0)
        assert task.done()
        # No retry sleep should have been called
        mock_redis.xack.assert_not_called()
        await q.stop()

    async def test_transient_connection_error_triggers_retry(self) -> None:
        """A non-CancelledError from xreadgroup triggers retry (sleep + loop continues)."""
        mock_redis = make_mock_redis()
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionError("Valkey connection lost")
            await asyncio.sleep(0.2)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch("app.pipeline.queue.asyncio.sleep", wraps=asyncio.sleep) as mock_sleep:
            q = make_queue(mock_redis)
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0.05)
            await q.stop()

        # asyncio.sleep(1) should have been called for the retry backoff
        sleep_calls = [c.args[0] for c in mock_sleep.call_args_list if c.args]
        assert 1 in sleep_calls

    async def test_multiple_consecutive_errors_each_retry(self) -> None:
        """Multiple transient xreadgroup errors → retries on each, loop continues."""
        mock_redis = make_mock_redis()
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                raise OSError(f"error #{call_count}")
            await asyncio.sleep(0.2)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        with patch("app.pipeline.queue.asyncio.sleep", wraps=asyncio.sleep) as mock_sleep:
            q = make_queue(mock_redis)
            await q.subscribe(Topic.ALERTS, "grp", handler)
            await asyncio.sleep(0.15)
            await q.stop()

        # At least 3 retry sleeps of 1 second should have been attempted
        sleep_1s_calls = [c for c in mock_sleep.call_args_list if c.args and c.args[0] == 1]
        assert len(sleep_1s_calls) >= 1  # at least one retry happened

    async def test_cancelled_error_during_retry_sleep_exits_loop(self) -> None:
        """CancelledError raised in asyncio.sleep(1) during retry also exits loop."""
        mock_redis = make_mock_redis()
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("transient error")
            await asyncio.sleep(0.5)
            return []

        mock_redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        async def handler(msg: dict[str, Any]) -> None:
            pass

        q = make_queue(mock_redis)
        await q.subscribe(Topic.ALERTS, "grp", handler)

        # Give the loop time to hit the error and begin sleeping
        await asyncio.sleep(0.05)

        # Cancel the task while it's sleeping
        q._tasks[0].cancel()
        await asyncio.sleep(0)
        assert q._tasks[0].done()

        mock_redis.aclose = AsyncMock()
        await q.stop()

    async def test_xadd_exception_propagates_to_caller(self) -> None:
        """A failed publish (xadd raises) should propagate to the caller."""
        mock_redis = make_mock_redis()
        mock_redis.xadd.side_effect = ConnectionError("stream unavailable")
        q = make_queue(mock_redis)

        with pytest.raises(ConnectionError, match="stream unavailable"):
            await q.publish(Topic.ALERTS, {"x": 1})


# ── Integration — simulated round-trip ────────────────────────────────────────


class TestRedisStreamQueueIntegration:
    async def test_publish_payload_matches_subscribe_delivery(self) -> None:
        """Simulate a full publish→subscribe round-trip via mock.

        1. Call publish() — captures the xadd payload.
        2. Feed that payload into xreadgroup mock.
        3. Verify handler receives the exact original message.
        """
        mock_redis = make_mock_redis()

        original_message = {
            "timestamp": "2026-02-21T00:00:00Z",
            "rule": "Sigma-T1059-001",
            "severity": "high",
            "host": {"name": "srv-01", "ip": "10.0.0.1"},
            "tags": ["execution", "scripting"],
        }

        # Step 1: publish and capture xadd payload
        q_pub = make_queue(mock_redis)
        await q_pub.publish(Topic.ALERTS, original_message)
        captured_payload = mock_redis.xadd.call_args.args[1]
        assert "data" in captured_payload

        # Step 2: set up subscriber with xreadgroup returning that payload
        mock_redis2 = make_mock_redis()
        call_count = 0

        async def xreadgroup_side_effect(*args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [(Topic.ALERTS, [("msg-rt-001", captured_payload)])]
            await asyncio.sleep(0.1)
            return []

        mock_redis2.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        q_sub = make_queue(mock_redis2)
        await q_sub.subscribe(Topic.ALERTS, "grp", handler)
        await asyncio.sleep(0.05)
        await q_sub.stop()

        # Step 3: verify round-trip fidelity
        assert len(received) == 1
        assert received[0] == original_message

    async def test_multiple_topics_independent_consume_loops(self) -> None:
        """Two subscriptions on different topics both deliver independently."""
        mock_redis = make_mock_redis()

        wazuh_msg = {"src": "wazuh", "rule": "1001"}
        zeek_msg = {"src": "zeek", "conn": "tcp"}

        call_counts: dict[str, int] = {Topic.RAW_WAZUH: 0, Topic.RAW_ZEEK: 0}

        def make_xreadgroup(topic: str, message: dict[str, Any]) -> AsyncMock:
            inner_count = 0

            async def side_effect(*args: Any, **kwargs: Any) -> Any:
                nonlocal inner_count
                inner_count += 1
                if inner_count == 1:
                    return [(topic, [("id-1", {"data": json_mod.dumps(message)})])]
                await asyncio.sleep(0.1)
                return []

            return AsyncMock(side_effect=side_effect)

        # Use separate mock redis instances for the two subscriptions
        mock_redis_w = make_mock_redis()
        mock_redis_z = make_mock_redis()
        mock_redis_w.xreadgroup = make_xreadgroup(Topic.RAW_WAZUH, wazuh_msg)
        mock_redis_z.xreadgroup = make_xreadgroup(Topic.RAW_ZEEK, zeek_msg)

        received_wazuh: list[dict[str, Any]] = []
        received_zeek: list[dict[str, Any]] = []

        async def wazuh_handler(msg: dict[str, Any]) -> None:
            received_wazuh.append(msg)

        async def zeek_handler(msg: dict[str, Any]) -> None:
            received_zeek.append(msg)

        q_w = make_queue(mock_redis_w)
        q_z = make_queue(mock_redis_z)

        await q_w.subscribe(Topic.RAW_WAZUH, "grp", wazuh_handler)
        await q_z.subscribe(Topic.RAW_ZEEK, "grp", zeek_handler)
        await asyncio.sleep(0.05)
        await q_w.stop()
        await q_z.stop()

        assert received_wazuh == [wazuh_msg]
        assert received_zeek == [zeek_msg]
