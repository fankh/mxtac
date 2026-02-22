"""Tests for Feature 5.8 — Dead letter queue — failed events.

Coverage:
  Subscription wiring:
  - dlq_consumer() subscribes to Topic.DLQ
  - dlq_consumer() uses consumer group "dlq-consumer"
  - dlq_consumer() registers a callable handler

  Handler — well-formed DLQ message:
  - source field extracted from message
  - error_type field extracted from message
  - error field extracted from message
  - failed_at field extracted from message
  - mxtac_dlq_events_total metric incremented with correct source label
  - mxtac_dlq_events_total metric incremented with correct error_type label

  Handler — missing/unknown fields:
  - Missing source → defaults to "unknown" (no KeyError)
  - Missing error_type → defaults to "unknown"
  - Missing error → defaults to ""
  - Missing failed_at → defaults to ""
  - Completely empty message dict handled without raising

  Metrics:
  - schema_validation error_type increments correct metric label
  - normalization_error error_type increments correct metric label
  - Multiple messages → metric counter accumulates correctly
  - Different source labels are tracked independently

  Integration (real InMemoryQueue end-to-end):
  - DLQ message published to Topic.DLQ is received by the consumer
  - Consumer processes multiple DLQ messages in sequence
  - DLQ consumer does not publish anything back to any topic
  - NormalizerPipeline → DLQ consumer end-to-end: failed wazuh event counted
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.dlq_consumer import dlq_consumer


# ── Helper fixtures ───────────────────────────────────────────────────────────


def _make_dlq_message(
    source: str = "wazuh",
    error_type: str = "schema_validation",
    error: str = "field required",
    failed_at: str = "2026-02-22T10:00:00+00:00",
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "source": source,
        "error_type": error_type,
        "error": error,
        "failed_at": failed_at,
        "raw": raw or {"original": "event"},
    }


# ── Subscription wiring ────────────────────────────────────────────────────────


class TestDLQConsumerSubscription:
    async def test_subscribes_to_dlq_topic(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()

        await dlq_consumer(q)

        q.subscribe.assert_awaited_once()
        assert q.subscribe.call_args.args[0] == Topic.DLQ

    async def test_uses_dlq_consumer_group(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()

        await dlq_consumer(q)

        assert q.subscribe.call_args.args[1] == "dlq-consumer"

    async def test_registers_callable_handler(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()

        await dlq_consumer(q)

        handler = q.subscribe.call_args.args[2]
        assert callable(handler)


# ── Handler — well-formed DLQ message ─────────────────────────────────────────


class TestDLQHandlerWellFormed:
    """Handler correctly processes messages with all expected fields."""

    async def _invoke_handler(self, message: dict[str, Any]) -> None:
        """Extract and invoke the registered handler directly."""
        q = MagicMock()
        q.subscribe = AsyncMock()
        await dlq_consumer(q)
        handler = q.subscribe.call_args.args[2]
        await handler(message)

    async def test_source_field_logged_without_error(self) -> None:
        """Handler must not raise when source field is present."""
        msg = _make_dlq_message(source="wazuh")
        await self._invoke_handler(msg)  # must not raise

    async def test_error_type_field_handled(self) -> None:
        msg = _make_dlq_message(error_type="schema_validation")
        await self._invoke_handler(msg)  # must not raise

    async def test_error_field_handled(self) -> None:
        msg = _make_dlq_message(error="field 'class_uid' is required")
        await self._invoke_handler(msg)  # must not raise

    async def test_failed_at_field_handled(self) -> None:
        msg = _make_dlq_message(failed_at="2026-02-22T12:34:56+00:00")
        await self._invoke_handler(msg)  # must not raise

    async def test_metric_incremented_on_handle(self) -> None:
        from app.core.metrics import dlq_events_total

        before = (
            dlq_events_total.labels(source="wazuh", error_type="schema_validation")
            ._value.get()
        )
        await self._invoke_handler(
            _make_dlq_message(source="wazuh", error_type="schema_validation")
        )
        after = (
            dlq_events_total.labels(source="wazuh", error_type="schema_validation")
            ._value.get()
        )
        assert after == before + 1

    async def test_metric_source_label_matches_message(self) -> None:
        from app.core.metrics import dlq_events_total

        before_zeek = (
            dlq_events_total.labels(source="zeek", error_type="normalization_error")
            ._value.get()
        )
        await self._invoke_handler(
            _make_dlq_message(source="zeek", error_type="normalization_error")
        )
        after_zeek = (
            dlq_events_total.labels(source="zeek", error_type="normalization_error")
            ._value.get()
        )
        assert after_zeek == before_zeek + 1

    async def test_metric_error_type_schema_validation_label(self) -> None:
        from app.core.metrics import dlq_events_total

        before = (
            dlq_events_total.labels(source="suricata", error_type="schema_validation")
            ._value.get()
        )
        await self._invoke_handler(
            _make_dlq_message(source="suricata", error_type="schema_validation")
        )
        after = (
            dlq_events_total.labels(source="suricata", error_type="schema_validation")
            ._value.get()
        )
        assert after == before + 1

    async def test_metric_error_type_normalization_error_label(self) -> None:
        from app.core.metrics import dlq_events_total

        before = (
            dlq_events_total.labels(source="wazuh", error_type="normalization_error")
            ._value.get()
        )
        await self._invoke_handler(
            _make_dlq_message(source="wazuh", error_type="normalization_error")
        )
        after = (
            dlq_events_total.labels(source="wazuh", error_type="normalization_error")
            ._value.get()
        )
        assert after == before + 1


# ── Handler — missing/unknown fields ──────────────────────────────────────────


class TestDLQHandlerMissingFields:
    """Handler must be robust to incomplete DLQ messages."""

    async def _invoke_handler(self, message: dict[str, Any]) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        await dlq_consumer(q)
        handler = q.subscribe.call_args.args[2]
        await handler(message)

    async def test_missing_source_does_not_raise(self) -> None:
        msg = {"error_type": "schema_validation", "error": "bad", "failed_at": "2026-02-22T00:00:00+00:00"}
        await self._invoke_handler(msg)  # must not raise

    async def test_missing_source_defaults_to_unknown(self) -> None:
        from app.core.metrics import dlq_events_total

        msg = {"error_type": "schema_validation", "error": "bad", "failed_at": "ts"}
        before = dlq_events_total.labels(source="unknown", error_type="schema_validation")._value.get()
        await self._invoke_handler(msg)
        after = dlq_events_total.labels(source="unknown", error_type="schema_validation")._value.get()
        assert after == before + 1

    async def test_missing_error_type_does_not_raise(self) -> None:
        msg = {"source": "wazuh", "error": "bad", "failed_at": "ts"}
        await self._invoke_handler(msg)  # must not raise

    async def test_missing_error_type_defaults_to_unknown(self) -> None:
        from app.core.metrics import dlq_events_total

        msg = {"source": "wazuh", "error": "bad", "failed_at": "ts"}
        before = dlq_events_total.labels(source="wazuh", error_type="unknown")._value.get()
        await self._invoke_handler(msg)
        after = dlq_events_total.labels(source="wazuh", error_type="unknown")._value.get()
        assert after == before + 1

    async def test_missing_error_does_not_raise(self) -> None:
        msg = {"source": "zeek", "error_type": "normalization_error", "failed_at": "ts"}
        await self._invoke_handler(msg)  # must not raise

    async def test_missing_failed_at_does_not_raise(self) -> None:
        msg = {"source": "zeek", "error_type": "normalization_error", "error": "oops"}
        await self._invoke_handler(msg)  # must not raise

    async def test_completely_empty_message_does_not_raise(self) -> None:
        await self._invoke_handler({})  # must not raise

    async def test_empty_message_increments_unknown_metric(self) -> None:
        from app.core.metrics import dlq_events_total

        before = dlq_events_total.labels(source="unknown", error_type="unknown")._value.get()
        await self._invoke_handler({})
        after = dlq_events_total.labels(source="unknown", error_type="unknown")._value.get()
        assert after == before + 1


# ── Metrics accumulation ───────────────────────────────────────────────────────


class TestDLQMetricsAccumulation:
    async def _invoke_handler(self, message: dict[str, Any]) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        await dlq_consumer(q)
        handler = q.subscribe.call_args.args[2]
        await handler(message)

    async def test_multiple_messages_accumulate_count(self) -> None:
        from app.core.metrics import dlq_events_total

        before = dlq_events_total.labels(source="wazuh", error_type="schema_validation")._value.get()

        for _ in range(5):
            await self._invoke_handler(
                _make_dlq_message(source="wazuh", error_type="schema_validation")
            )

        after = dlq_events_total.labels(source="wazuh", error_type="schema_validation")._value.get()
        assert after == before + 5

    async def test_different_sources_tracked_independently(self) -> None:
        from app.core.metrics import dlq_events_total

        before_wazuh = dlq_events_total.labels(source="wazuh", error_type="normalization_error")._value.get()
        before_zeek = dlq_events_total.labels(source="zeek", error_type="normalization_error")._value.get()

        await self._invoke_handler(_make_dlq_message(source="wazuh", error_type="normalization_error"))
        await self._invoke_handler(_make_dlq_message(source="zeek", error_type="normalization_error"))
        await self._invoke_handler(_make_dlq_message(source="wazuh", error_type="normalization_error"))

        after_wazuh = dlq_events_total.labels(source="wazuh", error_type="normalization_error")._value.get()
        after_zeek = dlq_events_total.labels(source="zeek", error_type="normalization_error")._value.get()

        assert after_wazuh == before_wazuh + 2
        assert after_zeek == before_zeek + 1

    async def test_different_error_types_tracked_independently(self) -> None:
        from app.core.metrics import dlq_events_total

        before_val = dlq_events_total.labels(source="suricata", error_type="schema_validation")._value.get()
        before_norm = dlq_events_total.labels(source="suricata", error_type="normalization_error")._value.get()

        await self._invoke_handler(_make_dlq_message(source="suricata", error_type="schema_validation"))
        await self._invoke_handler(_make_dlq_message(source="suricata", error_type="normalization_error"))

        after_val = dlq_events_total.labels(source="suricata", error_type="schema_validation")._value.get()
        after_norm = dlq_events_total.labels(source="suricata", error_type="normalization_error")._value.get()

        assert after_val == before_val + 1
        assert after_norm == before_norm + 1


# ── Integration: InMemoryQueue end-to-end ────────────────────────────────────


class TestDLQConsumerIntegration:
    """Full integration tests with a real InMemoryQueue."""

    async def test_dlq_message_published_is_received_by_consumer(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await dlq_consumer(q)

        received: list[dict] = []

        # Subscribe a secondary consumer to intercept calls (via metrics)
        # We verify indirectly via metric increment
        from app.core.metrics import dlq_events_total
        before = dlq_events_total.labels(source="wazuh", error_type="schema_validation")._value.get()

        await q.publish(Topic.DLQ, _make_dlq_message(source="wazuh", error_type="schema_validation"))
        await asyncio.sleep(0.1)

        after = dlq_events_total.labels(source="wazuh", error_type="schema_validation")._value.get()
        assert after == before + 1

        await q.stop()

    async def test_multiple_dlq_messages_all_processed(self) -> None:
        q = InMemoryQueue()
        await q.start()
        await dlq_consumer(q)

        from app.core.metrics import dlq_events_total
        before_wazuh = dlq_events_total.labels(source="wazuh", error_type="schema_validation")._value.get()
        before_zeek = dlq_events_total.labels(source="zeek", error_type="normalization_error")._value.get()
        before_suricata = dlq_events_total.labels(source="suricata", error_type="schema_validation")._value.get()

        await q.publish(Topic.DLQ, _make_dlq_message(source="wazuh", error_type="schema_validation"))
        await q.publish(Topic.DLQ, _make_dlq_message(source="zeek", error_type="normalization_error"))
        await q.publish(Topic.DLQ, _make_dlq_message(source="suricata", error_type="schema_validation"))
        await asyncio.sleep(0.15)

        after_wazuh = dlq_events_total.labels(source="wazuh", error_type="schema_validation")._value.get()
        after_zeek = dlq_events_total.labels(source="zeek", error_type="normalization_error")._value.get()
        after_suricata = dlq_events_total.labels(source="suricata", error_type="schema_validation")._value.get()

        assert after_wazuh == before_wazuh + 1
        assert after_zeek == before_zeek + 1
        assert after_suricata == before_suricata + 1

        await q.stop()

    async def test_consumer_does_not_publish_to_other_topics(self) -> None:
        """DLQ consumer must be read-only — no republishing anywhere."""
        q = InMemoryQueue()
        await q.start()
        await dlq_consumer(q)

        normalized_received: list[dict] = []
        alerts_received: list[dict] = []

        await q.subscribe(Topic.NORMALIZED, "test", normalized_received.append)
        await q.subscribe(Topic.ALERTS, "test", alerts_received.append)

        await q.publish(Topic.DLQ, _make_dlq_message())
        await asyncio.sleep(0.1)

        assert normalized_received == []
        assert alerts_received == []

        await q.stop()

    async def test_normalizer_pipeline_failure_reaches_dlq_consumer(self) -> None:
        """End-to-end: normalizer rejects an event → DLQ consumer increments metric."""
        from unittest.mock import MagicMock
        from app.services.normalizers.pipeline import NormalizerPipeline
        from pydantic import ValidationError
        from pydantic import BaseModel

        # Construct a real ValidationError
        class _Stub(BaseModel):
            required_field: int

        try:
            _Stub()  # type: ignore[call-arg]
        except ValidationError as exc:
            validation_exc = exc

        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()
        await dlq_consumer(q)

        from app.core.metrics import dlq_events_total
        before = dlq_events_total.labels(source="wazuh", error_type="schema_validation")._value.get()

        # Force normalizer to fail with a schema validation error
        pipeline._wazuh.normalize = MagicMock(side_effect=validation_exc)  # type: ignore[method-assign]

        await q.publish(Topic.RAW_WAZUH, {
            "id": "test-001",
            "timestamp": "2026-02-22T10:00:00Z",
            "agent": {"id": "001", "name": "host", "ip": "10.0.0.1"},
            "rule": {"id": "100", "level": 5, "description": "test", "groups": ["test"]},
        })
        await asyncio.sleep(0.2)

        after = dlq_events_total.labels(source="wazuh", error_type="schema_validation")._value.get()
        assert after == before + 1

        await q.stop()
