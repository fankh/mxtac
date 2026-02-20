"""
Tests for InMemoryQueue — Feature 5.2: asyncio in-process queue (dev/test).

Coverage:
  - Initialisation: initial state, isinstance, defaultdict lazy creation
  - Lifecycle: start/stop idempotency, task cancellation, stop without start
  - Publish: lazy queue creation, empty dict, size tracking, post-stop publish,
    concurrent publishes, per-topic isolation of underlying queues
  - Subscribe: task creation, naming, competing consumers (same topic splits
    messages), multiple groups, cross-topic independence
  - Delivery: single message, empty payload, complex nested payload, identity
    preservation (no copy/serialisation), 50-message bulk delivery
  - FIFO ordering: strict sequence with fast handler, ordering preserved with
    slow handler
  - Topic isolation: no cross-delivery, unsubscribed topic noise ignored,
    all six Topic constants deliver independently
  - Pre-subscription buffering: messages queued before subscribe are delivered,
    many buffered messages, mixed buffered + new messages ordered correctly
  - Error handling: handler exception does not stop consumer, task_done()
    called even on exception, consecutive failures, varied exception types,
    task_done() contract (join resolves) across N messages with failures
  - CancelledError edge cases: handler raising CancelledError ends task,
    finally-block still calls task_done() so join() resolves, stop() via
    cancel raises CancelledError at q.get() marking task as cancelled
  - Concurrency: 100 concurrent publishes all delivered, concurrent publishes
    to multiple topics
  - task_done() contract: join resolves for single message, join resolves for
    many messages processed by a slow handler
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.pipeline.queue import InMemoryQueue, MessageQueue, Topic


# ── Initialisation ─────────────────────────────────────────────────────────────


class TestInMemoryQueueInit:
    def test_is_instance_of_message_queue(self) -> None:
        assert isinstance(InMemoryQueue(), MessageQueue)

    def test_tasks_list_starts_empty(self) -> None:
        assert InMemoryQueue()._tasks == []

    def test_queues_dict_starts_with_no_entries(self) -> None:
        assert len(InMemoryQueue()._queues) == 0

    def test_queues_defaultdict_creates_asyncio_queue_on_access(self) -> None:
        q = InMemoryQueue()
        inner = q._queues["brand.new.topic"]
        assert isinstance(inner, asyncio.Queue)
        assert inner.qsize() == 0

    def test_two_instances_are_independent(self) -> None:
        q1, q2 = InMemoryQueue(), InMemoryQueue()
        assert q1._queues is not q2._queues
        assert q1._tasks is not q2._tasks


# ── Lifecycle ──────────────────────────────────────────────────────────────────


class TestInMemoryQueueLifecycle:
    async def test_start_does_not_raise(self) -> None:
        q = InMemoryQueue()
        await q.start()

    async def test_start_called_multiple_times_does_not_raise(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await q.start()

    async def test_stop_with_no_tasks_does_not_raise(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await q.stop()

    async def test_stop_called_twice_is_safe(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await q.stop()
        await q.stop()

    async def test_stop_without_start_does_not_raise(self) -> None:
        """A freshly created queue that was never started can be stopped."""
        q = InMemoryQueue()
        await q.stop()

    async def test_stop_cancels_all_consumer_tasks(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "g1", handler)
        await q.subscribe(Topic.RAW_ZEEK, "g2", handler)

        tasks = list(q._tasks)
        assert all(not t.done() for t in tasks)

        await q.stop()
        await asyncio.sleep(0)

        assert all(t.done() for t in tasks)

    async def test_tasks_list_preserved_after_stop(self) -> None:
        """Tasks remain in _tasks after stop — they are done, not removed."""
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.ALERTS, "grp", handler)
        await q.stop()
        assert len(q._tasks) == 1


# ── Publish ────────────────────────────────────────────────────────────────────


class TestInMemoryQueuePublish:
    async def test_publish_increases_inner_queue_size(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await q.publish(Topic.RAW_WAZUH, {"event": "test"})
        assert q._queues[Topic.RAW_WAZUH].qsize() == 1
        await q.stop()

    async def test_publish_multiple_messages_size_tracks_correctly(self) -> None:
        q = InMemoryQueue()
        await q.start()
        for i in range(7):
            await q.publish(Topic.NORMALIZED, {"n": i})
        assert q._queues[Topic.NORMALIZED].qsize() == 7
        await q.stop()

    async def test_publish_with_empty_dict_succeeds(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await q.publish(Topic.ALERTS, {})
        assert q._queues[Topic.ALERTS].qsize() == 1
        await q.stop()

    async def test_publish_creates_queue_lazily_for_new_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()
        assert Topic.ENRICHED not in q._queues
        await q.publish(Topic.ENRICHED, {"x": 1})
        assert Topic.ENRICHED in q._queues
        await q.stop()

    async def test_publish_to_different_topics_uses_separate_queues(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await q.publish(Topic.RAW_WAZUH, {"a": 1})
        await q.publish(Topic.RAW_ZEEK, {"b": 1})
        await q.publish(Topic.RAW_ZEEK, {"b": 2})
        assert q._queues[Topic.RAW_WAZUH].qsize() == 1
        assert q._queues[Topic.RAW_ZEEK].qsize() == 2
        await q.stop()

    async def test_concurrent_publishes_all_enqueued(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await asyncio.gather(
            *[q.publish(Topic.RAW_SURICATA, {"n": i}) for i in range(30)]
        )
        assert q._queues[Topic.RAW_SURICATA].qsize() == 30
        await q.stop()

    async def test_publish_after_stop_does_not_raise(self) -> None:
        """The underlying asyncio.Queue still accepts items after stop()."""
        q = InMemoryQueue()
        await q.start()
        await q.stop()
        await q.publish(Topic.ALERTS, {"late": True})
        assert q._queues[Topic.ALERTS].qsize() == 1


# ── Subscribe ──────────────────────────────────────────────────────────────────


class TestInMemoryQueueSubscribe:
    async def test_subscribe_appends_task_to_tasks_list(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        assert len(q._tasks) == 1
        await q.stop()

    async def test_subscribe_task_is_running_immediately(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        assert not q._tasks[0].done()
        await q.stop()

    async def test_subscribe_task_name_format(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "detection", handler)
        assert q._tasks[0].get_name() == "consumer-mxtac.raw.wazuh-detection"
        await q.stop()

    async def test_subscribe_task_name_uses_topic_and_group(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.NORMALIZED, "normalizer-grp", handler)
        assert q._tasks[0].get_name() == "consumer-mxtac.normalized-normalizer-grp"
        await q.stop()

    async def test_multiple_groups_same_topic_create_separate_tasks(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "group-a", handler)
        await q.subscribe(Topic.RAW_WAZUH, "group-b", handler)
        assert len(q._tasks) == 2
        names = {t.get_name() for t in q._tasks}
        assert "consumer-mxtac.raw.wazuh-group-a" in names
        assert "consumer-mxtac.raw.wazuh-group-b" in names
        await q.stop()

    async def test_subscribe_across_different_topics(self) -> None:
        q = InMemoryQueue()
        await q.start()

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        await q.subscribe(Topic.RAW_ZEEK, "grp", handler)
        await q.subscribe(Topic.RAW_SURICATA, "grp", handler)
        assert len(q._tasks) == 3
        await q.stop()

    async def test_competing_consumers_on_same_topic_split_messages(self) -> None:
        """Two consumers on the same topic compete — each message goes to one."""
        q = InMemoryQueue()
        await q.start()

        received_a: list[dict[str, Any]] = []
        received_b: list[dict[str, Any]] = []

        async def handler_a(msg: dict[str, Any]) -> None:
            received_a.append(msg)

        async def handler_b(msg: dict[str, Any]) -> None:
            received_b.append(msg)

        await q.subscribe(Topic.NORMALIZED, "group-a", handler_a)
        await q.subscribe(Topic.NORMALIZED, "group-b", handler_b)

        for i in range(10):
            await q.publish(Topic.NORMALIZED, {"n": i})

        await asyncio.sleep(0.1)

        # Every message is delivered exactly once across both consumers
        assert len(received_a) + len(received_b) == 10
        assert len(received_a) > 0
        assert len(received_b) > 0
        await q.stop()


# ── Message delivery ───────────────────────────────────────────────────────────


class TestInMemoryQueueDelivery:
    async def test_single_message_delivered_to_handler(self) -> None:
        q = InMemoryQueue()
        await q.start()
        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        await q.publish(Topic.RAW_WAZUH, {"event": "login"})
        await asyncio.sleep(0.05)

        assert received == [{"event": "login"}]
        await q.stop()

    async def test_empty_dict_delivered_intact(self) -> None:
        q = InMemoryQueue()
        await q.start()
        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "grp", handler)
        await q.publish(Topic.ALERTS, {})
        await asyncio.sleep(0.05)

        assert received == [{}]
        await q.stop()

    async def test_complex_nested_payload_delivered_intact(self) -> None:
        q = InMemoryQueue()
        await q.start()
        received: list[dict[str, Any]] = []

        original: dict[str, Any] = {
            "timestamp": "2026-02-20T00:00:00Z",
            "severity": 8,
            "tags": ["T1059", "T1003"],
            "meta": {"rule": "sigma-001", "scores": [9.5, 7.2]},
            "nested": {"a": {"b": {"c": True}}},
        }

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "grp", handler)
        await q.publish(Topic.ENRICHED, original)
        await asyncio.sleep(0.05)

        assert received[0] == original
        await q.stop()

    async def test_handler_receives_exact_same_object_no_copy(self) -> None:
        """InMemoryQueue passes the dict reference — no serialisation occurs."""
        q = InMemoryQueue()
        await q.start()
        received_ids: list[int] = []
        msg: dict[str, Any] = {"ref": "identity-check"}

        async def handler(m: dict[str, Any]) -> None:
            received_ids.append(id(m))

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        await q.publish(Topic.RAW_WAZUH, msg)
        await asyncio.sleep(0.05)

        assert received_ids == [id(msg)]
        await q.stop()

    async def test_all_50_messages_delivered(self) -> None:
        q = InMemoryQueue()
        await q.start()
        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.RAW_SURICATA, "grp", handler)
        for i in range(50):
            await q.publish(Topic.RAW_SURICATA, {"i": i})
        await asyncio.sleep(0.2)

        assert len(received) == 50
        await q.stop()


# ── FIFO ordering ──────────────────────────────────────────────────────────────


class TestInMemoryQueueOrdering:
    async def test_messages_delivered_in_fifo_order(self) -> None:
        q = InMemoryQueue()
        await q.start()
        received: list[int] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg["seq"])

        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        for i in range(20):
            await q.publish(Topic.NORMALIZED, {"seq": i})
        await asyncio.sleep(0.1)

        assert received == list(range(20))
        await q.stop()

    async def test_ordering_preserved_with_slow_handler(self) -> None:
        """A handler that sleeps between messages must still receive them in order."""
        q = InMemoryQueue()
        await q.start()
        received: list[int] = []

        async def slow_handler(msg: dict[str, Any]) -> None:
            await asyncio.sleep(0.005)
            received.append(msg["seq"])

        await q.subscribe(Topic.RAW_WAZUH, "grp", slow_handler)
        for i in range(5):
            await q.publish(Topic.RAW_WAZUH, {"seq": i})
        await asyncio.sleep(0.5)

        assert received == list(range(5))
        await q.stop()


# ── Topic isolation ────────────────────────────────────────────────────────────


class TestInMemoryQueueTopicIsolation:
    async def test_messages_not_delivered_to_wrong_topic_subscriber(self) -> None:
        q = InMemoryQueue()
        await q.start()
        wazuh: list[dict[str, Any]] = []
        zeek: list[dict[str, Any]] = []

        async def wazuh_handler(msg: dict[str, Any]) -> None:
            wazuh.append(msg)

        async def zeek_handler(msg: dict[str, Any]) -> None:
            zeek.append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", wazuh_handler)
        await q.subscribe(Topic.RAW_ZEEK, "grp", zeek_handler)
        await q.publish(Topic.RAW_WAZUH, {"src": "wazuh"})
        await q.publish(Topic.RAW_ZEEK, {"src": "zeek"})
        await asyncio.sleep(0.05)

        assert wazuh == [{"src": "wazuh"}]
        assert zeek == [{"src": "zeek"}]
        await q.stop()

    async def test_unsubscribed_topic_noise_does_not_affect_subscribed_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()
        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "grp", handler)
        await q.publish(Topic.ENRICHED, {"noise": True})  # no subscriber
        await q.publish(Topic.ALERTS, {"signal": True})
        await asyncio.sleep(0.05)

        assert received == [{"signal": True}]
        await q.stop()

    async def test_all_six_topics_deliver_independently(self) -> None:
        q = InMemoryQueue()
        await q.start()
        results: dict[str, list[dict[str, Any]]] = {}
        all_topics = [
            Topic.RAW_WAZUH,
            Topic.RAW_ZEEK,
            Topic.RAW_SURICATA,
            Topic.NORMALIZED,
            Topic.ALERTS,
            Topic.ENRICHED,
        ]
        for topic in all_topics:
            results[topic] = []
            captured = results[topic]

            async def _make_handler(buf: list[dict[str, Any]]) -> Any:
                async def _h(msg: dict[str, Any]) -> None:
                    buf.append(msg)
                return _h

            await q.subscribe(topic, "grp", await _make_handler(captured))

        for topic in all_topics:
            await q.publish(topic, {"topic": topic})

        await asyncio.sleep(0.1)

        for topic in all_topics:
            assert results[topic] == [{"topic": topic}], f"topic {topic} delivery failed"
        await q.stop()


# ── Pre-subscription buffering ─────────────────────────────────────────────────


class TestInMemoryQueueBuffering:
    async def test_message_published_before_subscribe_is_delivered(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await q.publish(Topic.RAW_WAZUH, {"buffered": True})
        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        await asyncio.sleep(0.05)

        assert received == [{"buffered": True}]
        await q.stop()

    async def test_many_messages_buffered_before_subscribe_all_delivered(self) -> None:
        q = InMemoryQueue()
        await q.start()
        N = 20
        for i in range(N):
            await q.publish(Topic.NORMALIZED, {"i": i})

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        await asyncio.sleep(0.2)

        assert len(received) == N
        assert [m["i"] for m in received] == list(range(N))
        await q.stop()

    async def test_buffered_then_live_messages_ordered_correctly(self) -> None:
        """Messages published before and after subscribe arrive in global order."""
        q = InMemoryQueue()
        await q.start()
        await q.publish(Topic.ALERTS, {"seq": 0})
        await q.publish(Topic.ALERTS, {"seq": 1})
        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "grp", handler)
        await q.publish(Topic.ALERTS, {"seq": 2})
        await asyncio.sleep(0.05)

        assert [m["seq"] for m in received] == [0, 1, 2]
        await q.stop()


# ── Error handling ─────────────────────────────────────────────────────────────


class TestInMemoryQueueErrorHandling:
    async def test_handler_exception_does_not_stop_consumer(self) -> None:
        """A single handler failure must not prevent subsequent message delivery."""
        q = InMemoryQueue()
        await q.start()
        call_count = 0

        async def flaky(msg: dict[str, Any]) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("first call fails")

        await q.subscribe(Topic.RAW_SURICATA, "grp", flaky)
        await q.publish(Topic.RAW_SURICATA, {"n": 1})
        await q.publish(Topic.RAW_SURICATA, {"n": 2})
        await asyncio.sleep(0.05)

        assert call_count == 2
        await q.stop()

    async def test_task_done_called_even_when_handler_raises(self) -> None:
        """finally block guarantees task_done(); join() must resolve."""
        q = InMemoryQueue()
        await q.start()
        inner_q = q._queues[Topic.ALERTS]

        async def bad_handler(msg: dict[str, Any]) -> None:
            raise RuntimeError("always fails")

        await q.subscribe(Topic.ALERTS, "grp", bad_handler)
        await q.publish(Topic.ALERTS, {"x": 1})

        await asyncio.wait_for(inner_q.join(), timeout=1.0)
        await q.stop()

    async def test_consecutive_handler_failures_consumer_stays_alive(self) -> None:
        q = InMemoryQueue()
        await q.start()
        good: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            if msg.get("bad"):
                raise ValueError("bad message")
            good.append(msg)

        await q.subscribe(Topic.ENRICHED, "grp", handler)
        for _ in range(3):
            await q.publish(Topic.ENRICHED, {"bad": True})
        await q.publish(Topic.ENRICHED, {"ok": True})
        await asyncio.sleep(0.05)

        assert good == [{"ok": True}]
        await q.stop()

    async def test_varied_exception_types_all_caught_consumer_continues(self) -> None:
        """ValueError, TypeError, KeyError, RuntimeError must all be swallowed."""
        q = InMemoryQueue()
        await q.start()
        exc_sequence = [ValueError("v"), TypeError("t"), KeyError("k"), RuntimeError("r")]
        call_count = 0
        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            nonlocal call_count
            if call_count < len(exc_sequence):
                exc = exc_sequence[call_count]
                call_count += 1
                raise exc
            received.append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        for _ in range(len(exc_sequence)):
            await q.publish(Topic.RAW_WAZUH, {"noise": True})
        await q.publish(Topic.RAW_WAZUH, {"final": True})
        await asyncio.sleep(0.1)

        assert received == [{"final": True}]
        await q.stop()

    async def test_join_resolves_for_n_messages_with_intermittent_failures(self) -> None:
        """task_done() is called for every message; join() resolves for all N."""
        q = InMemoryQueue()
        await q.start()
        N = 12
        inner_q = q._queues[Topic.NORMALIZED]
        fail_on = {1, 4, 9}
        call_count = 0

        async def handler(msg: dict[str, Any]) -> None:
            nonlocal call_count
            call_count += 1
            if call_count in fail_on:
                raise ValueError("deliberate failure")

        await q.subscribe(Topic.NORMALIZED, "grp", handler)
        for i in range(N):
            await q.publish(Topic.NORMALIZED, {"i": i})

        await asyncio.wait_for(inner_q.join(), timeout=2.0)
        assert call_count == N
        await q.stop()


# ── CancelledError edge cases ─────────────────────────────────────────────────


class TestInMemoryQueueCancelledError:
    async def test_cancelled_error_from_handler_ends_consumer_task(self) -> None:
        """CancelledError is BaseException, not Exception — propagates and ends task."""
        q = InMemoryQueue()
        await q.start()

        async def cancelling_handler(msg: dict[str, Any]) -> None:
            raise asyncio.CancelledError()

        await q.subscribe(Topic.ALERTS, "grp", cancelling_handler)
        await q.publish(Topic.ALERTS, {"trigger": True})
        await asyncio.sleep(0.05)

        assert q._tasks[0].done()
        await q.stop()

    async def test_cancelled_error_finally_still_calls_task_done(self) -> None:
        """finally block guarantees task_done() even when CancelledError propagates."""
        q = InMemoryQueue()
        await q.start()
        inner_q = q._queues[Topic.ALERTS]

        async def cancelling_handler(msg: dict[str, Any]) -> None:
            raise asyncio.CancelledError()

        await q.subscribe(Topic.ALERTS, "grp", cancelling_handler)
        await q.publish(Topic.ALERTS, {"trigger": True})

        # join() must resolve because task_done() is called in finally
        await asyncio.wait_for(inner_q.join(), timeout=1.0)
        await q.stop()

    async def test_stop_cancel_marks_idle_consumer_as_cancelled(self) -> None:
        """stop() cancels a task blocked on q.get(); task.cancelled() is True."""
        q = InMemoryQueue()
        await q.start()

        async def idle_handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", idle_handler)
        task = q._tasks[0]

        await q.stop()
        await asyncio.sleep(0)

        assert task.done()
        assert task.cancelled()


# ── Concurrency ────────────────────────────────────────────────────────────────


class TestInMemoryQueueConcurrency:
    async def test_100_concurrent_publishes_all_delivered(self) -> None:
        q = InMemoryQueue()
        await q.start()
        N = 100
        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.RAW_SURICATA, "grp", handler)
        await asyncio.gather(*[q.publish(Topic.RAW_SURICATA, {"n": i}) for i in range(N)])
        await asyncio.sleep(0.3)

        assert len(received) == N
        await q.stop()

    async def test_concurrent_publishes_to_multiple_topics(self) -> None:
        q = InMemoryQueue()
        await q.start()
        N = 25
        results: dict[str, list[dict[str, Any]]] = {
            Topic.RAW_WAZUH: [],
            Topic.RAW_ZEEK: [],
        }

        async def wazuh_h(msg: dict[str, Any]) -> None:
            results[Topic.RAW_WAZUH].append(msg)

        async def zeek_h(msg: dict[str, Any]) -> None:
            results[Topic.RAW_ZEEK].append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", wazuh_h)
        await q.subscribe(Topic.RAW_ZEEK, "grp", zeek_h)
        await asyncio.gather(
            *[q.publish(Topic.RAW_WAZUH, {"w": i}) for i in range(N)],
            *[q.publish(Topic.RAW_ZEEK, {"z": i}) for i in range(N)],
        )
        await asyncio.sleep(0.2)

        assert len(results[Topic.RAW_WAZUH]) == N
        assert len(results[Topic.RAW_ZEEK]) == N
        await q.stop()


# ── task_done() contract ───────────────────────────────────────────────────────


class TestInMemoryQueueTaskDoneContract:
    async def test_join_resolves_after_single_message(self) -> None:
        q = InMemoryQueue()
        await q.start()
        inner_q = q._queues[Topic.RAW_WAZUH]

        async def handler(msg: dict[str, Any]) -> None:
            pass

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        await q.publish(Topic.RAW_WAZUH, {"x": 1})
        await asyncio.wait_for(inner_q.join(), timeout=1.0)
        await q.stop()

    async def test_join_resolves_after_many_messages_with_slow_handler(self) -> None:
        q = InMemoryQueue()
        await q.start()
        inner_q = q._queues[Topic.NORMALIZED]

        async def slow_handler(msg: dict[str, Any]) -> None:
            await asyncio.sleep(0.002)

        await q.subscribe(Topic.NORMALIZED, "grp", slow_handler)
        for i in range(15):
            await q.publish(Topic.NORMALIZED, {"i": i})

        await asyncio.wait_for(inner_q.join(), timeout=5.0)
        await q.stop()
