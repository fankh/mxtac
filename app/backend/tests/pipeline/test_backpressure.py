"""
Tests for InMemoryQueue back-pressure — Feature 5.9.

When the internal asyncio.Queue is bounded (maxsize > 0), publish() blocks
rather than growing memory unboundedly.  This naturally slows down the ingest
producer so that consumers have time to drain messages — "queue full → slow
ingest".

Coverage:
  - Initialisation: maxsize default (0 = unbounded), maxsize stored, counter
    and property start at 0, two instances are independent
  - Bounded queue creation: per-topic asyncio.Queue respects maxsize,
    full() becomes True when at capacity, put_nowait() raises QueueFull
  - Back-pressure counter: increments when publish() hits a full queue,
    does NOT increment for a non-full queue, accumulates across multiple hits,
    counts per-publisher-call not per-message
  - Back-pressure logging: WARNING emitted when queue is full on publish(),
    message contains expected keywords (topic, "back-pressure")
  - Blocking / ingest slowdown: publish() on a full queue blocks the caller
    until a consumer dequeues at least one message, back-pressure resolves
    automatically when space is freed, producer unblocks exactly once per freed
    slot
  - Topic independence: back-pressure on one topic does not affect another
  - Unbounded queue (maxsize=0): counter never increments, put_nowait always
    succeeds, behaviour identical to the original InMemoryQueue()
  - Backward compatibility: InMemoryQueue() (no args) behaves exactly as
    before — messages always enqueued, counter stays 0
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from app.pipeline.queue import InMemoryQueue, Topic


# ── Initialisation ─────────────────────────────────────────────────────────────


class TestInMemoryQueueBackpressureInit:
    def test_default_maxsize_is_zero(self) -> None:
        q = InMemoryQueue()
        assert q._maxsize == 0

    def test_maxsize_stored_correctly(self) -> None:
        q = InMemoryQueue(maxsize=100)
        assert q._maxsize == 100

    def test_maxsize_one_stored(self) -> None:
        q = InMemoryQueue(maxsize=1)
        assert q._maxsize == 1

    def test_backpressure_events_starts_at_zero(self) -> None:
        q = InMemoryQueue(maxsize=10)
        assert q._backpressure_events == 0

    def test_backpressure_count_property_starts_at_zero(self) -> None:
        q = InMemoryQueue(maxsize=5)
        assert q.backpressure_count == 0

    def test_two_instances_have_independent_counters(self) -> None:
        q1 = InMemoryQueue(maxsize=2)
        q2 = InMemoryQueue(maxsize=2)
        q1._backpressure_events += 5
        assert q2._backpressure_events == 0

    def test_bounded_queue_has_correct_maxsize_attribute(self) -> None:
        q = InMemoryQueue(maxsize=7)
        inner = q._queues[Topic.RAW_WAZUH]
        assert inner.maxsize == 7

    def test_unbounded_queue_maxsize_is_zero(self) -> None:
        q = InMemoryQueue()
        inner = q._queues[Topic.RAW_WAZUH]
        assert inner.maxsize == 0


# ── Bounded queue creation ─────────────────────────────────────────────────────


class TestBoundedQueueCreation:
    def test_inner_queue_maxsize_matches_constructor_arg(self) -> None:
        q = InMemoryQueue(maxsize=3)
        inner = q._queues["mxtac.test.topic"]
        assert inner.maxsize == 3

    async def test_queue_is_not_full_when_empty(self) -> None:
        q = InMemoryQueue(maxsize=2)
        await q.start()
        assert not q._queues[Topic.RAW_WAZUH].full()
        await q.stop()

    async def test_queue_becomes_full_at_maxsize(self) -> None:
        q = InMemoryQueue(maxsize=2)
        await q.start()
        await q.publish(Topic.RAW_WAZUH, {"n": 0})
        await q.publish(Topic.RAW_WAZUH, {"n": 1})
        assert q._queues[Topic.RAW_WAZUH].full()
        await q.stop()

    async def test_put_nowait_raises_queue_full_when_at_maxsize(self) -> None:
        q = InMemoryQueue(maxsize=1)
        await q.start()
        await q.publish(Topic.RAW_WAZUH, {"n": 0})  # fills the queue
        inner = q._queues[Topic.RAW_WAZUH]
        with pytest.raises(asyncio.QueueFull):
            inner.put_nowait({"n": 1})
        await q.stop()

    async def test_different_topics_have_independent_bounded_queues(self) -> None:
        q = InMemoryQueue(maxsize=1)
        await q.start()
        # Fill one topic
        await q.publish(Topic.RAW_WAZUH, {"n": 0})
        assert q._queues[Topic.RAW_WAZUH].full()
        # The other topic is still empty
        assert not q._queues[Topic.RAW_ZEEK].full()
        await q.stop()


# ── Back-pressure counter ──────────────────────────────────────────────────────


class TestBackpressureCounter:
    async def test_counter_does_not_increment_when_queue_is_not_full(self) -> None:
        q = InMemoryQueue(maxsize=10)
        await q.start()

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        await q.publish(Topic.RAW_WAZUH, {"n": 1})
        await asyncio.sleep(0.05)

        assert q.backpressure_count == 0
        await q.stop()

    async def test_counter_increments_when_queue_is_full(self) -> None:
        q = InMemoryQueue(maxsize=1)
        await q.start()

        # Fill the queue with one message (no consumer to drain it)
        await q.publish(Topic.RAW_WAZUH, {"n": 0})

        # Now publish a second message — this will block; start it as a task
        # and free space immediately so the counter has been incremented
        freed = asyncio.Event()

        async def _free_after_block() -> None:
            # Let the publish task block first
            await asyncio.sleep(0)
            item = await q._queues[Topic.RAW_WAZUH].get()
            q._queues[Topic.RAW_WAZUH].task_done()
            freed.set()

        free_task = asyncio.create_task(_free_after_block())
        await q.publish(Topic.RAW_WAZUH, {"n": 1})  # blocks briefly
        await freed.wait()

        assert q.backpressure_count == 1
        await q.stop()

    async def test_counter_does_not_increment_for_unbounded_queue(self) -> None:
        q = InMemoryQueue()  # maxsize=0 → unbounded
        await q.start()

        for i in range(50):
            await q.publish(Topic.RAW_WAZUH, {"n": i})

        assert q.backpressure_count == 0
        await q.stop()

    async def test_counter_accumulates_across_multiple_back_pressure_events(self) -> None:
        """Each time publish() hits a full queue, the counter must increment by 1."""
        N = 3
        q = InMemoryQueue(maxsize=1)
        await q.start()

        for i in range(N):
            # Fill the queue
            await q.publish(Topic.RAW_WAZUH, {"n": i * 2})
            assert q._queues[Topic.RAW_WAZUH].full()

            # Launch a task that frees space so the blocked publish can complete
            freed = asyncio.Event()

            async def _free(ev: asyncio.Event = freed) -> None:
                await asyncio.sleep(0)
                await q._queues[Topic.RAW_WAZUH].get()
                q._queues[Topic.RAW_WAZUH].task_done()
                # Also drain the newly published one
                await q._queues[Topic.RAW_WAZUH].get()
                q._queues[Topic.RAW_WAZUH].task_done()
                ev.set()

            free_task = asyncio.create_task(_free())
            await q.publish(Topic.RAW_WAZUH, {"n": i * 2 + 1})  # triggers back-pressure
            await freed.wait()

        assert q.backpressure_count == N
        await q.stop()

    async def test_backpressure_count_property_matches_internal_counter(self) -> None:
        q = InMemoryQueue(maxsize=1)
        assert q.backpressure_count == q._backpressure_events

        await q.start()
        # Fill and trigger once
        await q.publish(Topic.ALERTS, {"n": 0})

        freed = asyncio.Event()

        async def _free() -> None:
            await asyncio.sleep(0)
            await q._queues[Topic.ALERTS].get()
            q._queues[Topic.ALERTS].task_done()
            freed.set()

        asyncio.create_task(_free())
        await q.publish(Topic.ALERTS, {"n": 1})
        await freed.wait()

        assert q.backpressure_count == q._backpressure_events == 1
        await q.stop()


# ── Back-pressure logging ──────────────────────────────────────────────────────


class TestBackpressureLogging:
    async def test_warning_logged_when_queue_full_on_publish(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        q = InMemoryQueue(maxsize=1)
        await q.start()

        # Fill the queue
        await q.publish(Topic.RAW_WAZUH, {"n": 0})

        freed = asyncio.Event()

        async def _free() -> None:
            await asyncio.sleep(0)
            await q._queues[Topic.RAW_WAZUH].get()
            q._queues[Topic.RAW_WAZUH].task_done()
            freed.set()

        with caplog.at_level(logging.WARNING, logger="app.pipeline.queue"):
            asyncio.create_task(_free())
            await q.publish(Topic.RAW_WAZUH, {"n": 1})

        await freed.wait()
        await q.stop()

        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("back-pressure" in m for m in warning_messages), (
            f"Expected a back-pressure WARNING log; got: {warning_messages}"
        )

    async def test_warning_log_includes_topic_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        q = InMemoryQueue(maxsize=1)
        await q.start()
        await q.publish(Topic.RAW_ZEEK, {"n": 0})

        freed = asyncio.Event()

        async def _free() -> None:
            await asyncio.sleep(0)
            await q._queues[Topic.RAW_ZEEK].get()
            q._queues[Topic.RAW_ZEEK].task_done()
            freed.set()

        with caplog.at_level(logging.WARNING, logger="app.pipeline.queue"):
            asyncio.create_task(_free())
            await q.publish(Topic.RAW_ZEEK, {"n": 1})

        await freed.wait()
        await q.stop()

        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any(Topic.RAW_ZEEK in m for m in warning_messages), (
            f"Expected topic name {Topic.RAW_ZEEK!r} in WARNING log; got: {warning_messages}"
        )

    async def test_no_warning_logged_for_unbounded_queue(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        q = InMemoryQueue()  # unbounded
        await q.start()

        with caplog.at_level(logging.WARNING, logger="app.pipeline.queue"):
            for i in range(20):
                await q.publish(Topic.RAW_WAZUH, {"n": i})

        await q.stop()

        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        bp_warnings = [m for m in warning_messages if "back-pressure" in m]
        assert bp_warnings == [], f"Unexpected back-pressure warnings: {bp_warnings}"

    async def test_no_warning_when_queue_has_space(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        q = InMemoryQueue(maxsize=5)
        await q.start()

        # Only fill 3 of 5 slots — no back-pressure expected
        with caplog.at_level(logging.WARNING, logger="app.pipeline.queue"):
            for i in range(3):
                await q.publish(Topic.NORMALIZED, {"n": i})

        await q.stop()

        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        bp_warnings = [m for m in warning_messages if "back-pressure" in m]
        assert bp_warnings == [], f"Unexpected back-pressure warnings: {bp_warnings}"


# ── Blocking / ingest slowdown ────────────────────────────────────────────────


class TestBackpressureBlocking:
    async def test_publish_blocks_when_queue_is_full(self) -> None:
        """publish() on a full bounded queue must block the caller."""
        q = InMemoryQueue(maxsize=1)
        await q.start()

        # Fill the queue
        await q.publish(Topic.RAW_WAZUH, {"seq": 0})
        assert q._queues[Topic.RAW_WAZUH].full()

        publish_done = asyncio.Event()

        async def _blocked_publish() -> None:
            await q.publish(Topic.RAW_WAZUH, {"seq": 1})
            publish_done.set()

        task = asyncio.create_task(_blocked_publish())
        await asyncio.sleep(0)  # yield so task reaches await q.put()

        assert not publish_done.is_set(), (
            "publish() should be blocking while queue is full"
        )

        # Free one slot
        await q._queues[Topic.RAW_WAZUH].get()
        q._queues[Topic.RAW_WAZUH].task_done()

        # Blocked publish should now complete
        await asyncio.wait_for(publish_done.wait(), timeout=1.0)
        assert publish_done.is_set()

        await q.stop()

    async def test_producer_unblocks_exactly_when_consumer_frees_space(self) -> None:
        """Producer must remain blocked until a consumer calls get()."""
        q = InMemoryQueue(maxsize=2)
        await q.start()

        # Fill to maxsize
        await q.publish(Topic.NORMALIZED, {"n": 0})
        await q.publish(Topic.NORMALIZED, {"n": 1})

        sequence: list[str] = []

        async def _slow_producer() -> None:
            sequence.append("producer_start")
            await q.publish(Topic.NORMALIZED, {"n": 2})  # blocks here
            sequence.append("producer_done")

        async def _consumer() -> None:
            await asyncio.sleep(0.02)  # brief delay so producer gets to wait
            sequence.append("consumer_get")
            await q._queues[Topic.NORMALIZED].get()
            q._queues[Topic.NORMALIZED].task_done()

        await asyncio.gather(
            asyncio.create_task(_slow_producer()),
            asyncio.create_task(_consumer()),
        )

        # consumer_get must precede producer_done
        assert "consumer_get" in sequence
        assert "producer_done" in sequence
        assert sequence.index("consumer_get") < sequence.index("producer_done"), (
            f"Expected consumer_get before producer_done; got: {sequence}"
        )

        await q.stop()

    async def test_multiple_producers_all_unblock_as_consumer_drains(self) -> None:
        """Several blocked publishers must each unblock as space becomes available."""
        maxsize = 2
        q = InMemoryQueue(maxsize=maxsize)
        await q.start()

        # Fill queue to capacity
        await q.publish(Topic.ALERTS, {"n": 0})
        await q.publish(Topic.ALERTS, {"n": 1})

        # Launch 3 more producers, all of which will block
        N_blocked = 3
        done_flags: list[asyncio.Event] = [asyncio.Event() for _ in range(N_blocked)]

        async def _producer(idx: int) -> None:
            await q.publish(Topic.ALERTS, {"n": idx + maxsize})
            done_flags[idx].set()

        tasks = [asyncio.create_task(_producer(i)) for i in range(N_blocked)]
        await asyncio.sleep(0)  # let all producers reach their blocked put()

        assert not any(f.is_set() for f in done_flags), (
            "All producers should be blocked with a full queue"
        )

        # Drain the queue one slot at a time — each drain should unblock one producer
        inner = q._queues[Topic.ALERTS]
        for _ in range(N_blocked):
            await inner.get()
            inner.task_done()
            await asyncio.sleep(0)  # let one blocked producer run

        await asyncio.gather(*tasks)
        assert all(f.is_set() for f in done_flags)

        await q.stop()

    async def test_backpressure_does_not_lose_messages(self) -> None:
        """All messages published under back-pressure must eventually be delivered."""
        maxsize = 3
        q = InMemoryQueue(maxsize=maxsize)
        await q.start()

        received: list[int] = []

        async def handler(msg: dict[str, Any]) -> None:
            await asyncio.sleep(0.001)  # slow consumer
            received.append(msg["n"])

        await q.subscribe(Topic.RAW_SURICATA, "grp", handler)

        N = 20
        for i in range(N):
            await q.publish(Topic.RAW_SURICATA, {"n": i})

        # Wait until all messages are consumed
        await asyncio.wait_for(
            q._queues[Topic.RAW_SURICATA].join(), timeout=10.0
        )
        await q.stop()

        assert len(received) == N, (
            f"Expected {N} messages; got {len(received)} under back-pressure"
        )
        assert sorted(received) == list(range(N))


# ── Topic independence ─────────────────────────────────────────────────────────


class TestBackpressureTopicIndependence:
    async def test_full_topic_does_not_block_other_topic_publish(self) -> None:
        """Back-pressure on one topic must not affect publishing to another."""
        q = InMemoryQueue(maxsize=1)
        await q.start()

        # Fill RAW_WAZUH to capacity
        await q.publish(Topic.RAW_WAZUH, {"n": 0})
        assert q._queues[Topic.RAW_WAZUH].full()

        # Publishing to a DIFFERENT topic must succeed immediately (no block)
        publish_done = asyncio.Event()

        async def _publish_other() -> None:
            await q.publish(Topic.RAW_ZEEK, {"n": 0})
            publish_done.set()

        task = asyncio.create_task(_publish_other())
        await asyncio.sleep(0)  # yield to let task run

        assert publish_done.is_set(), (
            "Publish to an uncongested topic must not block due to another topic being full"
        )

        await q.stop()

    async def test_backpressure_counter_only_counts_affected_topic(self) -> None:
        q = InMemoryQueue(maxsize=1)
        await q.start()

        # Fill RAW_WAZUH
        await q.publish(Topic.RAW_WAZUH, {"n": 0})

        freed = asyncio.Event()

        async def _free() -> None:
            await asyncio.sleep(0)
            await q._queues[Topic.RAW_WAZUH].get()
            q._queues[Topic.RAW_WAZUH].task_done()
            freed.set()

        asyncio.create_task(_free())
        await q.publish(Topic.RAW_WAZUH, {"n": 1})  # triggers back-pressure
        await freed.wait()

        # Publish freely to another topic
        for i in range(5):
            await q.publish(Topic.RAW_ZEEK, {"n": i})
            await q._queues[Topic.RAW_ZEEK].get()
            q._queues[Topic.RAW_ZEEK].task_done()

        # Counter should be exactly 1 (only RAW_WAZUH triggered back-pressure)
        assert q.backpressure_count == 1

        await q.stop()


# ── Unbounded queue (backward compatibility) ───────────────────────────────────


class TestUnboundedQueueBackwardsCompat:
    async def test_default_queue_never_triggers_backpressure(self) -> None:
        q = InMemoryQueue()
        await q.start()

        for i in range(100):
            await q.publish(Topic.RAW_WAZUH, {"n": i})

        assert q.backpressure_count == 0
        assert q._queues[Topic.RAW_WAZUH].qsize() == 100
        await q.stop()

    async def test_default_queue_inner_maxsize_is_zero(self) -> None:
        q = InMemoryQueue()
        inner = q._queues[Topic.NORMALIZED]
        assert inner.maxsize == 0

    async def test_default_queue_never_full(self) -> None:
        q = InMemoryQueue()
        await q.start()

        for i in range(200):
            await q.publish(Topic.ENRICHED, {"n": i})

        assert not q._queues[Topic.ENRICHED].full()
        await q.stop()

    async def test_explicit_maxsize_zero_is_same_as_default(self) -> None:
        q = InMemoryQueue(maxsize=0)
        await q.start()

        for i in range(50):
            await q.publish(Topic.ALERTS, {"n": i})

        assert q.backpressure_count == 0
        assert q._queues[Topic.ALERTS].qsize() == 50
        await q.stop()

    async def test_existing_message_delivery_unaffected_by_default(self) -> None:
        """Verify normal unbounded publish/subscribe still works after the change."""
        q = InMemoryQueue()
        await q.start()

        received: list[dict[str, Any]] = []

        async def handler(msg: dict[str, Any]) -> None:
            received.append(msg)

        await q.subscribe(Topic.RAW_WAZUH, "grp", handler)
        for i in range(10):
            await q.publish(Topic.RAW_WAZUH, {"n": i})

        await asyncio.sleep(0.1)
        assert len(received) == 10
        assert received == [{"n": i} for i in range(10)]
        await q.stop()
