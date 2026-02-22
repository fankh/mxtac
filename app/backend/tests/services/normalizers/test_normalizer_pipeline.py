"""Tests for NormalizerPipeline — Feature 7.13 / 35.2: subscribe + route + publish.

Coverage:
  - Construction: WazuhNormalizer, ZeekNormalizer, SuricataNormalizer, ProwlerNormalizer,
    VelociraptorNormalizer instantiated
  - start(): subscribes to RAW_WAZUH, RAW_ZEEK, RAW_SURICATA, RAW_PROWLER,
    RAW_VELOCIRAPTOR with group "normalizer"
  - _handle_wazuh(): routes to WazuhNormalizer, publishes to NORMALIZED
  - _handle_zeek(): routes to ZeekNormalizer, publishes to NORMALIZED
  - _handle_suricata(): routes to SuricataNormalizer, publishes to NORMALIZED
  - _handle_prowler(): routes to ProwlerNormalizer, publishes to NORMALIZED
  - _handle_velociraptor(): routes to VelociraptorNormalizer, publishes to NORMALIZED
  - Error isolation: normalizer exception is caught, does NOT propagate to queue
  - Published payload is a dict (model_dump result) with required OCSF fields
  - Metadata product correctly set per source (Wazuh, Zeek, Suricata, Velociraptor)
  - Integration: InMemoryQueue end-to-end — raw event in → OCSF dict on NORMALIZED
  - Multiple raw events from different sources all land on same NORMALIZED topic
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.normalizers.pipeline import NormalizerPipeline


# ── Minimal raw-event fixtures ─────────────────────────────────────────────────


def _wazuh_raw() -> dict[str, Any]:
    """Minimal Wazuh alert event that produces a valid OCSFEvent."""
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
    """Minimal Zeek conn log event that produces a valid OCSFEvent."""
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
    """Minimal Suricata alert event that produces a valid OCSFEvent."""
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


def _velociraptor_raw() -> dict[str, Any]:
    """Minimal Velociraptor Linux.Sys.Pslist artifact that produces a valid OCSFEvent."""
    return {
        "_artifact_name": "Linux.Sys.Pslist",
        "_source": "velociraptor",
        "Pid": 1234,
        "PPid": 1,
        "Name": "bash",
        "Exe": "/bin/bash",
        "Cmdline": "/bin/bash -c id",
        "Username": "root",
    }


# ── Construction ───────────────────────────────────────────────────────────────


class TestNormalizerPipelineConstruction:
    def test_accepts_message_queue(self) -> None:
        q = InMemoryQueue()
        pipeline = NormalizerPipeline(q)
        assert pipeline._queue is q

    def test_wazuh_normalizer_created(self) -> None:
        from app.services.normalizers.wazuh import WazuhNormalizer

        pipeline = NormalizerPipeline(InMemoryQueue())
        assert isinstance(pipeline._wazuh, WazuhNormalizer)

    def test_zeek_normalizer_created(self) -> None:
        from app.services.normalizers.zeek import ZeekNormalizer

        pipeline = NormalizerPipeline(InMemoryQueue())
        assert isinstance(pipeline._zeek, ZeekNormalizer)

    def test_suricata_normalizer_created(self) -> None:
        from app.services.normalizers.suricata import SuricataNormalizer

        pipeline = NormalizerPipeline(InMemoryQueue())
        assert isinstance(pipeline._suricata, SuricataNormalizer)

    def test_prowler_normalizer_created(self) -> None:
        from app.services.normalizers.prowler import ProwlerNormalizer

        pipeline = NormalizerPipeline(InMemoryQueue())
        assert isinstance(pipeline._prowler, ProwlerNormalizer)

    def test_velociraptor_normalizer_created(self) -> None:
        from app.services.normalizers.velociraptor import VelociraptorNormalizer

        pipeline = NormalizerPipeline(InMemoryQueue())
        assert isinstance(pipeline._velociraptor, VelociraptorNormalizer)


# ── start() — subscription wiring ─────────────────────────────────────────────


class TestNormalizerPipelineStart:
    async def test_start_subscribes_to_raw_wazuh(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        topics_subscribed = [call.args[0] for call in q.subscribe.call_args_list]
        assert Topic.RAW_WAZUH in topics_subscribed

    async def test_start_subscribes_to_raw_zeek(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        topics_subscribed = [call.args[0] for call in q.subscribe.call_args_list]
        assert Topic.RAW_ZEEK in topics_subscribed

    async def test_start_subscribes_to_raw_suricata(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        topics_subscribed = [call.args[0] for call in q.subscribe.call_args_list]
        assert Topic.RAW_SURICATA in topics_subscribed

    async def test_start_subscribes_to_raw_prowler(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        topics_subscribed = [call.args[0] for call in q.subscribe.call_args_list]
        assert Topic.RAW_PROWLER in topics_subscribed

    async def test_start_subscribes_to_raw_velociraptor(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        topics_subscribed = [call.args[0] for call in q.subscribe.call_args_list]
        assert Topic.RAW_VELOCIRAPTOR in topics_subscribed

    async def test_start_makes_five_subscriptions(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        assert q.subscribe.call_count == 5

    async def test_start_uses_normalizer_consumer_group(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        groups = [call.args[1] for call in q.subscribe.call_args_list]
        assert all(g == "normalizer" for g in groups), f"Expected all groups to be 'normalizer', got {groups}"

    async def test_start_registers_callable_handlers(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        handlers = [call.args[2] for call in q.subscribe.call_args_list]
        assert all(callable(h) for h in handlers)


# ── _handle_wazuh() — route + publish ─────────────────────────────────────────


class TestHandleWazuh:
    async def test_handle_wazuh_publishes_to_normalized_topic(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_wazuh(_wazuh_raw())

        q.publish.assert_awaited_once()
        topic_published = q.publish.call_args.args[0]
        assert topic_published == Topic.NORMALIZED

    async def test_handle_wazuh_publishes_dict(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_wazuh(_wazuh_raw())

        payload = q.publish.call_args.args[1]
        assert isinstance(payload, dict)

    async def test_handle_wazuh_payload_has_class_uid(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_wazuh(_wazuh_raw())

        payload = q.publish.call_args.args[1]
        assert "class_uid" in payload

    async def test_handle_wazuh_payload_metadata_product_is_wazuh(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_wazuh(_wazuh_raw())

        payload = q.publish.call_args.args[1]
        assert payload["metadata_product"] == "Wazuh"

    async def test_handle_wazuh_exception_does_not_propagate(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        bad_event: dict[str, Any] = {}  # malformed — normalizer may raise
        # Must not raise; exceptions should be swallowed
        with patch.object(pipeline._wazuh, "normalize", side_effect=ValueError("bad")):
            await pipeline._handle_wazuh(bad_event)  # should not raise

    async def test_handle_wazuh_no_normalized_publish_on_exception(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(pipeline._wazuh, "normalize", side_effect=RuntimeError("fail")):
            await pipeline._handle_wazuh({})

        # Must publish to DLQ, never to NORMALIZED
        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ


# ── _handle_zeek() — route + publish ──────────────────────────────────────────


class TestHandleZeek:
    async def test_handle_zeek_publishes_to_normalized_topic(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_zeek(_zeek_raw())

        q.publish.assert_awaited_once()
        topic_published = q.publish.call_args.args[0]
        assert topic_published == Topic.NORMALIZED

    async def test_handle_zeek_publishes_dict(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_zeek(_zeek_raw())

        payload = q.publish.call_args.args[1]
        assert isinstance(payload, dict)

    async def test_handle_zeek_payload_has_class_uid(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_zeek(_zeek_raw())

        payload = q.publish.call_args.args[1]
        assert "class_uid" in payload

    async def test_handle_zeek_payload_metadata_product_is_zeek(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_zeek(_zeek_raw())

        payload = q.publish.call_args.args[1]
        assert payload["metadata_product"] == "Zeek"

    async def test_handle_zeek_exception_does_not_propagate(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(pipeline._zeek, "normalize", side_effect=ValueError("bad zeek")):
            await pipeline._handle_zeek({})  # should not raise

    async def test_handle_zeek_no_normalized_publish_on_exception(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(pipeline._zeek, "normalize", side_effect=RuntimeError("fail")):
            await pipeline._handle_zeek({})

        # Must publish to DLQ, never to NORMALIZED
        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ


# ── _handle_suricata() — route + publish ───────────────────────────────────────


class TestHandleSuricata:
    async def test_handle_suricata_publishes_to_normalized_topic(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_suricata(_suricata_raw())

        q.publish.assert_awaited_once()
        topic_published = q.publish.call_args.args[0]
        assert topic_published == Topic.NORMALIZED

    async def test_handle_suricata_publishes_dict(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_suricata(_suricata_raw())

        payload = q.publish.call_args.args[1]
        assert isinstance(payload, dict)

    async def test_handle_suricata_payload_has_class_uid(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_suricata(_suricata_raw())

        payload = q.publish.call_args.args[1]
        assert "class_uid" in payload

    async def test_handle_suricata_payload_metadata_product_is_suricata(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_suricata(_suricata_raw())

        payload = q.publish.call_args.args[1]
        assert payload["metadata_product"] == "Suricata"

    async def test_handle_suricata_exception_does_not_propagate(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(pipeline._suricata, "normalize", side_effect=ValueError("bad")):
            await pipeline._handle_suricata({})  # should not raise

    async def test_handle_suricata_no_normalized_publish_on_exception(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(pipeline._suricata, "normalize", side_effect=RuntimeError("fail")):
            await pipeline._handle_suricata({})

        # Must publish to DLQ, never to NORMALIZED
        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ


# ── _handle_velociraptor() — route + publish ───────────────────────────────────


class TestHandleVelociraptor:
    async def test_handle_velociraptor_publishes_to_normalized_topic(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_velociraptor(_velociraptor_raw())

        q.publish.assert_awaited_once()
        topic_published = q.publish.call_args.args[0]
        assert topic_published == Topic.NORMALIZED

    async def test_handle_velociraptor_publishes_dict(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_velociraptor(_velociraptor_raw())

        payload = q.publish.call_args.args[1]
        assert isinstance(payload, dict)

    async def test_handle_velociraptor_payload_has_class_uid(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_velociraptor(_velociraptor_raw())

        payload = q.publish.call_args.args[1]
        assert "class_uid" in payload

    async def test_handle_velociraptor_payload_metadata_product_is_velociraptor(
        self,
    ) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        await pipeline._handle_velociraptor(_velociraptor_raw())

        payload = q.publish.call_args.args[1]
        assert payload["metadata_product"] == "Velociraptor"

    async def test_handle_velociraptor_exception_does_not_propagate(self) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(
            pipeline._velociraptor, "normalize", side_effect=ValueError("bad velociraptor")
        ):
            await pipeline._handle_velociraptor({})  # should not raise

    async def test_handle_velociraptor_no_normalized_publish_on_exception(
        self,
    ) -> None:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)

        with patch.object(
            pipeline._velociraptor, "normalize", side_effect=RuntimeError("fail")
        ):
            await pipeline._handle_velociraptor({})

        # Must publish to DLQ, never to NORMALIZED
        q.publish.assert_awaited_once()
        assert q.publish.call_args.args[0] == Topic.DLQ


# ── OCSF field validation ──────────────────────────────────────────────────────


class TestOCSFPayloadFields:
    """Published payload must be a proper OCSF dict with mandatory fields."""

    _REQUIRED_FIELDS = {
        "class_uid",
        "class_name",
        "category_uid",
        "time",
        "severity_id",
        "metadata_product",
    }

    async def _get_payload(self, handler_name: str, raw: dict) -> dict:
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)
        handler = getattr(pipeline, handler_name)
        await handler(raw)
        return q.publish.call_args.args[1]

    async def test_wazuh_payload_has_all_required_ocsf_fields(self) -> None:
        payload = await self._get_payload("_handle_wazuh", _wazuh_raw())
        for field in self._REQUIRED_FIELDS:
            assert field in payload, f"Missing OCSF field: {field}"

    async def test_zeek_payload_has_all_required_ocsf_fields(self) -> None:
        payload = await self._get_payload("_handle_zeek", _zeek_raw())
        for field in self._REQUIRED_FIELDS:
            assert field in payload, f"Missing OCSF field: {field}"

    async def test_suricata_payload_has_all_required_ocsf_fields(self) -> None:
        payload = await self._get_payload("_handle_suricata", _suricata_raw())
        for field in self._REQUIRED_FIELDS:
            assert field in payload, f"Missing OCSF field: {field}"

    async def test_wazuh_payload_time_is_string(self) -> None:
        """model_dump(mode='json') serializes datetime → str."""
        payload = await self._get_payload("_handle_wazuh", _wazuh_raw())
        assert isinstance(payload["time"], str)

    async def test_suricata_alert_payload_class_uid_is_security_finding(self) -> None:
        from app.services.normalizers.ocsf import OCSFClass

        payload = await self._get_payload("_handle_suricata", _suricata_raw())
        assert payload["class_uid"] == OCSFClass.SECURITY_FINDING

    async def test_suricata_payload_severity_id_is_int(self) -> None:
        payload = await self._get_payload("_handle_suricata", _suricata_raw())
        assert isinstance(payload["severity_id"], int)

    async def test_velociraptor_payload_has_all_required_ocsf_fields(self) -> None:
        payload = await self._get_payload("_handle_velociraptor", _velociraptor_raw())
        for field in self._REQUIRED_FIELDS:
            assert field in payload, f"Missing OCSF field: {field}"

    async def test_velociraptor_payload_metadata_product_is_velociraptor(self) -> None:
        payload = await self._get_payload("_handle_velociraptor", _velociraptor_raw())
        assert payload["metadata_product"] == "Velociraptor"


# ── Integration: InMemoryQueue end-to-end ─────────────────────────────────────


class TestNormalizerPipelineIntegration:
    """Full pipeline integration using real InMemoryQueue and real normalizers."""

    async def test_wazuh_raw_event_lands_on_normalized_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []
        await q.subscribe(Topic.NORMALIZED, "test-collector", received.append)

        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await asyncio.sleep(0.15)

        assert len(received) == 1
        assert received[0]["metadata_product"] == "Wazuh"

        await q.stop()

    async def test_zeek_raw_event_lands_on_normalized_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []
        await q.subscribe(Topic.NORMALIZED, "test-collector", received.append)

        await q.publish(Topic.RAW_ZEEK, _zeek_raw())
        await asyncio.sleep(0.15)

        assert len(received) == 1
        assert received[0]["metadata_product"] == "Zeek"

        await q.stop()

    async def test_suricata_raw_event_lands_on_normalized_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []
        await q.subscribe(Topic.NORMALIZED, "test-collector", received.append)

        await q.publish(Topic.RAW_SURICATA, _suricata_raw())
        await asyncio.sleep(0.15)

        assert len(received) == 1
        assert received[0]["metadata_product"] == "Suricata"

        await q.stop()

    async def test_velociraptor_raw_event_lands_on_normalized_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []
        await q.subscribe(Topic.NORMALIZED, "test-collector", received.append)

        await q.publish(Topic.RAW_VELOCIRAPTOR, _velociraptor_raw())
        await asyncio.sleep(0.15)

        assert len(received) == 1
        assert received[0]["metadata_product"] == "Velociraptor"

        await q.stop()

    async def test_events_from_all_sources_all_land_on_normalized(self) -> None:
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []
        await q.subscribe(Topic.NORMALIZED, "test-collector", received.append)

        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await q.publish(Topic.RAW_ZEEK, _zeek_raw())
        await q.publish(Topic.RAW_SURICATA, _suricata_raw())
        await q.publish(Topic.RAW_VELOCIRAPTOR, _velociraptor_raw())
        await asyncio.sleep(0.30)

        assert len(received) == 4
        products = {e["metadata_product"] for e in received}
        assert products == {"Wazuh", "Zeek", "Suricata", "Velociraptor"}

        await q.stop()

    async def test_normalized_payload_is_valid_ocsf_dict(self) -> None:
        """Published payload can be used to reconstruct an OCSFEvent."""
        from app.services.normalizers.ocsf import OCSFEvent

        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []
        await q.subscribe(Topic.NORMALIZED, "test-collector", received.append)

        await q.publish(Topic.RAW_SURICATA, _suricata_raw())
        await asyncio.sleep(0.15)

        assert len(received) == 1
        # Reconstruct OCSFEvent from published dict — should not raise
        event = OCSFEvent(**received[0])
        assert event.metadata_product == "Suricata"

        await q.stop()

    async def test_normalizer_error_does_not_block_subsequent_events(self) -> None:
        """A bad event must not prevent the next good event from being processed."""
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []
        await q.subscribe(Topic.NORMALIZED, "test-collector", received.append)

        # Publish a malformed Suricata event (missing alert dict) followed by valid one
        bad = {"event_type": "alert", "timestamp": "not-a-date", "alert": {}}
        good = _suricata_raw()

        await q.publish(Topic.RAW_SURICATA, bad)
        await q.publish(Topic.RAW_SURICATA, good)
        await asyncio.sleep(0.25)

        # The good event must still be received
        assert any(e.get("metadata_product") == "Suricata" for e in received)

        await q.stop()
