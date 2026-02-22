"""Tests for Feature 7.14: Schema validation — reject malformed events to DLQ.

Coverage:
  - Topic.DLQ constant exists
  - ValidationError from Pydantic → publishes to DLQ with error_type="schema_validation"
  - Non-ValidationError exceptions → publishes to DLQ with error_type="normalization_error"
  - Malformed events are NOT published to Topic.NORMALIZED
  - DLQ message has required fields: source, raw, error, error_type, failed_at
  - DLQ message "source" is correct per handler (wazuh / zeek / suricata)
  - DLQ message "raw" contains the original raw event
  - DLQ message "failed_at" is an ISO 8601 timestamp
  - Valid events still publish to NORMALIZED (no regression)
  - Integration: malformed event → DLQ, valid event → NORMALIZED (same source)
  - Integration: DLQ subscriber receives rejected events from all three sources
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.normalizers.pipeline import NormalizerPipeline


# ── Test fixtures ──────────────────────────────────────────────────────────────


def _wazuh_raw() -> dict[str, Any]:
    return {
        "id": "wazuh-001",
        "timestamp": "2026-02-22T10:00:00.000+0000",
        "agent": {"id": "001", "name": "win-host", "ip": "10.0.0.10"},
        "rule": {
            "id": "100200",
            "level": 10,
            "description": "Suspicious PowerShell execution",
            "groups": ["windows", "powershell"],
        },
        "data": {
            "win": {
                "eventdata": {
                    "commandLine": "powershell.exe -enc SGVsbG8=",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                }
            }
        },
    }


def _zeek_raw() -> dict[str, Any]:
    return {
        "_log_type": "conn",
        "ts": 1740218400.0,
        "uid": "CzeekConn001",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 55001,
        "id.resp_h": "203.0.113.1",
        "id.resp_p": 80,
        "proto": "tcp",
        "service": "http",
        "conn_state": "SF",
        "orig_bytes": 1024,
        "resp_bytes": 2048,
    }


def _suricata_raw() -> dict[str, Any]:
    return {
        "timestamp": "2026-02-22T10:30:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.200",
        "src_port": 4444,
        "dest_ip": "10.0.0.5",
        "dest_port": 443,
        "proto": "TCP",
        "flow_id": 1234567890,
        "alert": {
            "action": "allowed",
            "signature_id": 2030358,
            "signature": "ET MALWARE CobaltStrike Beacon Activity",
            "category": "Trojan",
            "severity": 1,
            "metadata": {"mitre_technique_id": ["T1071.001"]},
        },
    }


def _make_validation_error() -> ValidationError:
    """Construct a real Pydantic ValidationError for testing."""
    from pydantic import BaseModel

    class _Stub(BaseModel):
        required_field: int

    try:
        _Stub()  # type: ignore[call-arg]
    except ValidationError as exc:
        return exc
    raise AssertionError("Expected ValidationError")  # pragma: no cover


# ── Topic.DLQ constant ─────────────────────────────────────────────────────────


class TestDLQTopicConstant:
    def test_dlq_topic_exists(self) -> None:
        assert hasattr(Topic, "DLQ")

    def test_dlq_topic_value(self) -> None:
        assert Topic.DLQ == "mxtac.dlq"

    def test_dlq_topic_is_string(self) -> None:
        assert isinstance(Topic.DLQ, str)

    def test_dlq_topic_differs_from_normalized(self) -> None:
        assert Topic.DLQ != Topic.NORMALIZED

    def test_dlq_topic_differs_from_alerts(self) -> None:
        assert Topic.DLQ != Topic.ALERTS


# ── DLQ routing on ValidationError ────────────────────────────────────────────


class TestValidationErrorRoutedToDLQ:
    """When a normalizer raises Pydantic ValidationError, the event goes to DLQ."""

    async def test_wazuh_validation_error_publishes_to_dlq(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)
        exc = _make_validation_error()

        with patch.object(pipeline._wazuh, "normalize", side_effect=exc):
            await pipeline._handle_wazuh(_wazuh_raw())

        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ

    async def test_zeek_validation_error_publishes_to_dlq(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)
        exc = _make_validation_error()

        with patch.object(pipeline._zeek, "normalize", side_effect=exc):
            await pipeline._handle_zeek(_zeek_raw())

        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ

    async def test_suricata_validation_error_publishes_to_dlq(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)
        exc = _make_validation_error()

        with patch.object(pipeline._suricata, "normalize", side_effect=exc):
            await pipeline._handle_suricata(_suricata_raw())

        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ

    async def test_wazuh_validation_error_does_not_publish_to_normalized(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)
        exc = _make_validation_error()

        with patch.object(pipeline._wazuh, "normalize", side_effect=exc):
            await pipeline._handle_wazuh(_wazuh_raw())

        published_topics = [call.args[0] for call in q.publish.call_args_list]
        assert Topic.NORMALIZED not in published_topics

    async def test_zeek_validation_error_does_not_publish_to_normalized(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)
        exc = _make_validation_error()

        with patch.object(pipeline._zeek, "normalize", side_effect=exc):
            await pipeline._handle_zeek(_zeek_raw())

        published_topics = [call.args[0] for call in q.publish.call_args_list]
        assert Topic.NORMALIZED not in published_topics

    async def test_suricata_validation_error_does_not_publish_to_normalized(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)
        exc = _make_validation_error()

        with patch.object(pipeline._suricata, "normalize", side_effect=exc):
            await pipeline._handle_suricata(_suricata_raw())

        published_topics = [call.args[0] for call in q.publish.call_args_list]
        assert Topic.NORMALIZED not in published_topics


# ── DLQ routing on generic normalization errors ────────────────────────────────


class TestNormalizationErrorRoutedToDLQ:
    """Non-ValidationError exceptions also route to DLQ."""

    async def test_wazuh_runtime_error_publishes_to_dlq(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(pipeline._wazuh, "normalize", side_effect=RuntimeError("boom")):
            await pipeline._handle_wazuh({})

        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ

    async def test_zeek_key_error_publishes_to_dlq(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(pipeline._zeek, "normalize", side_effect=KeyError("ts")):
            await pipeline._handle_zeek({})

        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ

    async def test_suricata_value_error_publishes_to_dlq(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(pipeline._suricata, "normalize", side_effect=ValueError("bad")):
            await pipeline._handle_suricata({})

        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ


# ── DLQ message structure ──────────────────────────────────────────────────────


class TestDLQMessageStructure:
    """DLQ messages must have: source, raw, error, error_type, failed_at."""

    _REQUIRED_DLQ_FIELDS = {"source", "raw", "error", "error_type", "failed_at"}

    async def _get_dlq_message(
        self,
        handler: str,
        raw: dict[str, Any],
        exc: Exception,
        normalizer_attr: str,
    ) -> dict[str, Any]:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)
        with patch.object(getattr(pipeline, normalizer_attr), "normalize", side_effect=exc):
            await getattr(pipeline, handler)(raw)
        return q.publish.call_args.args[1]

    async def test_wazuh_dlq_message_has_all_required_fields(self) -> None:
        msg = await self._get_dlq_message(
            "_handle_wazuh", _wazuh_raw(), RuntimeError("fail"), "_wazuh"
        )
        for field in self._REQUIRED_DLQ_FIELDS:
            assert field in msg, f"DLQ message missing field: {field}"

    async def test_zeek_dlq_message_has_all_required_fields(self) -> None:
        msg = await self._get_dlq_message(
            "_handle_zeek", _zeek_raw(), RuntimeError("fail"), "_zeek"
        )
        for field in self._REQUIRED_DLQ_FIELDS:
            assert field in msg, f"DLQ message missing field: {field}"

    async def test_suricata_dlq_message_has_all_required_fields(self) -> None:
        msg = await self._get_dlq_message(
            "_handle_suricata", _suricata_raw(), RuntimeError("fail"), "_suricata"
        )
        for field in self._REQUIRED_DLQ_FIELDS:
            assert field in msg, f"DLQ message missing field: {field}"

    async def test_wazuh_dlq_source_is_wazuh(self) -> None:
        msg = await self._get_dlq_message(
            "_handle_wazuh", _wazuh_raw(), RuntimeError("fail"), "_wazuh"
        )
        assert msg["source"] == "wazuh"

    async def test_zeek_dlq_source_is_zeek(self) -> None:
        msg = await self._get_dlq_message(
            "_handle_zeek", _zeek_raw(), RuntimeError("fail"), "_zeek"
        )
        assert msg["source"] == "zeek"

    async def test_suricata_dlq_source_is_suricata(self) -> None:
        msg = await self._get_dlq_message(
            "_handle_suricata", _suricata_raw(), RuntimeError("fail"), "_suricata"
        )
        assert msg["source"] == "suricata"

    async def test_dlq_message_raw_contains_original_event(self) -> None:
        raw = _wazuh_raw()
        msg = await self._get_dlq_message(
            "_handle_wazuh", raw, RuntimeError("fail"), "_wazuh"
        )
        assert msg["raw"] == raw

    async def test_dlq_message_error_is_string(self) -> None:
        msg = await self._get_dlq_message(
            "_handle_wazuh", _wazuh_raw(), RuntimeError("boom"), "_wazuh"
        )
        assert isinstance(msg["error"], str)

    async def test_dlq_message_error_contains_exception_message(self) -> None:
        msg = await self._get_dlq_message(
            "_handle_wazuh", _wazuh_raw(), RuntimeError("specific-error-text"), "_wazuh"
        )
        assert "specific-error-text" in msg["error"]

    async def test_dlq_message_error_type_validation_error(self) -> None:
        exc = _make_validation_error()
        msg = await self._get_dlq_message(
            "_handle_wazuh", _wazuh_raw(), exc, "_wazuh"
        )
        assert msg["error_type"] == "schema_validation"

    async def test_dlq_message_error_type_normalization_error(self) -> None:
        msg = await self._get_dlq_message(
            "_handle_wazuh", _wazuh_raw(), RuntimeError("parse fail"), "_wazuh"
        )
        assert msg["error_type"] == "normalization_error"

    async def test_dlq_message_failed_at_is_iso8601(self) -> None:
        from datetime import datetime

        msg = await self._get_dlq_message(
            "_handle_wazuh", _wazuh_raw(), RuntimeError("fail"), "_wazuh"
        )
        # Should parse as a valid ISO 8601 datetime
        dt = datetime.fromisoformat(msg["failed_at"])
        assert dt is not None

    async def test_dlq_message_failed_at_is_utc(self) -> None:
        from datetime import timezone

        msg = await self._get_dlq_message(
            "_handle_wazuh", _wazuh_raw(), RuntimeError("fail"), "_wazuh"
        )
        from datetime import datetime

        dt = datetime.fromisoformat(msg["failed_at"])
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0  # type: ignore[union-attr]


# ── Valid events are unaffected (regression) ──────────────────────────────────


class TestValidEventsUnaffected:
    """Valid events must still reach NORMALIZED; no regression from DLQ feature."""

    async def test_valid_wazuh_event_still_publishes_to_normalized(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_wazuh(_wazuh_raw())

        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.NORMALIZED

    async def test_valid_zeek_event_still_publishes_to_normalized(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_zeek(_zeek_raw())

        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.NORMALIZED

    async def test_valid_suricata_event_still_publishes_to_normalized(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_suricata(_suricata_raw())

        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.NORMALIZED

    async def test_valid_event_does_not_publish_to_dlq(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_wazuh(_wazuh_raw())

        published_topics = [call.args[0] for call in q.publish.call_args_list]
        assert Topic.DLQ not in published_topics


# ── Integration: InMemoryQueue end-to-end ─────────────────────────────────────


class TestDLQIntegration:
    """Full pipeline integration: verify DLQ receives rejected events.

    Note: patch.object context managers exit before async consumers run.
    Use direct attribute assignment (MagicMock) so the mock persists when
    the background consumer task processes the queued message.
    """

    async def test_malformed_wazuh_event_goes_to_dlq(self) -> None:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        dlq_received: list[dict] = []
        await q.subscribe(Topic.DLQ, "test-dlq", dlq_received.append)

        exc = _make_validation_error()
        pipeline._wazuh.normalize = MagicMock(side_effect=exc)  # type: ignore[method-assign]

        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await asyncio.sleep(0.15)

        assert len(dlq_received) == 1
        assert dlq_received[0]["source"] == "wazuh"
        assert dlq_received[0]["error_type"] == "schema_validation"

        await q.stop()

    async def test_malformed_event_does_not_appear_on_normalized(self) -> None:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        normalized_received: list[dict] = []
        await q.subscribe(Topic.NORMALIZED, "test-norm", normalized_received.append)

        exc = _make_validation_error()
        pipeline._zeek.normalize = MagicMock(side_effect=exc)  # type: ignore[method-assign]

        await q.publish(Topic.RAW_ZEEK, _zeek_raw())
        await asyncio.sleep(0.15)

        assert len(normalized_received) == 0

        await q.stop()

    async def test_good_event_after_bad_still_reaches_normalized(self) -> None:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        normalized_received: list[dict] = []
        dlq_received: list[dict] = []
        await q.subscribe(Topic.NORMALIZED, "test-norm", normalized_received.append)
        await q.subscribe(Topic.DLQ, "test-dlq", dlq_received.append)

        exc = _make_validation_error()

        # First: bad event — permanent mock so it's active when consumer runs
        original_normalize = pipeline._suricata.normalize
        pipeline._suricata.normalize = MagicMock(side_effect=exc)  # type: ignore[method-assign]
        await q.publish(Topic.RAW_SURICATA, _suricata_raw())
        await asyncio.sleep(0.1)

        # Restore normalizer for valid event
        pipeline._suricata.normalize = original_normalize  # type: ignore[method-assign]
        await q.publish(Topic.RAW_SURICATA, _suricata_raw())
        await asyncio.sleep(0.15)

        assert len(normalized_received) == 1
        assert normalized_received[0]["metadata_product"] == "Suricata"
        assert len(dlq_received) == 1
        assert dlq_received[0]["source"] == "suricata"

        await q.stop()

    async def test_dlq_receives_events_from_all_three_sources(self) -> None:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        dlq_received: list[dict] = []
        await q.subscribe(Topic.DLQ, "test-dlq", dlq_received.append)

        exc = _make_validation_error()
        pipeline._wazuh.normalize = MagicMock(side_effect=exc)   # type: ignore[method-assign]
        pipeline._zeek.normalize = MagicMock(side_effect=exc)    # type: ignore[method-assign]
        pipeline._suricata.normalize = MagicMock(side_effect=exc)  # type: ignore[method-assign]

        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await q.publish(Topic.RAW_ZEEK, _zeek_raw())
        await q.publish(Topic.RAW_SURICATA, _suricata_raw())
        await asyncio.sleep(0.3)

        assert len(dlq_received) == 3
        sources = {msg["source"] for msg in dlq_received}
        assert sources == {"wazuh", "zeek", "suricata"}

        await q.stop()

    async def test_normalization_error_also_goes_to_dlq(self) -> None:
        """Non-ValidationError (e.g. parsing failure) also routes to DLQ."""
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        dlq_received: list[dict] = []
        await q.subscribe(Topic.DLQ, "test-dlq", dlq_received.append)

        pipeline._wazuh.normalize = MagicMock(side_effect=RuntimeError("parse fail"))  # type: ignore[method-assign]

        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await asyncio.sleep(0.15)

        assert len(dlq_received) == 1
        assert dlq_received[0]["error_type"] == "normalization_error"

        await q.stop()
