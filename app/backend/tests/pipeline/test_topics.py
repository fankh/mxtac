"""
Tests for Feature 5.5 — Topics: `mxtac.raw.*`, `normalized`, `alerts`, `enriched`.

Coverage:
  - Topic constant semantics: raw-topic naming pattern, processing-topic naming,
    stage ordering, namespace, count invariants
  - NormalizerPipeline routing: subscribes to all three raw topics; each source's
    events appear on Topic.NORMALIZED; normalization errors swallowed without publish
  - SigmaConsumer routing: subscribes to Topic.NORMALIZED; Sigma matches published
    to Topic.ALERTS with all required fields; non-matches produce no ALERTS message;
    invalid event dicts do not publish
  - AlertManager routing: process() publishes enriched alerts to Topic.ENRICHED;
    duplicates are dropped; score is within [0, 10]; Valkey failure → fail-open;
    does not publish to any other topic
  - WebSocketBroadcaster routing: subscribes to Topic.ENRICHED; calls broadcast_alert
    for each message; errors do not crash the consumer loop
  - End-to-end integration: raw → NORMALIZED → ALERTS → ENRICHED via InMemoryQueue
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.engine.sigma_engine import SigmaAlert, SigmaEngine
from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_manager import AlertManager
from app.services.normalizers.ocsf import Endpoint, OCSFCategory, OCSFClass, OCSFEvent
from app.services.normalizers.pipeline import NormalizerPipeline
from app.services.sigma_consumer import sigma_consumer
from app.services.ws_broadcaster import websocket_broadcaster


# ── Async generator helper ─────────────────────────────────────────────────────

async def _agen(items: list) -> AsyncGenerator:
    """Yield items as an async generator — used to mock SigmaEngine.evaluate()."""
    for item in items:
        yield item


# ── Test data helpers ──────────────────────────────────────────────────────────

def _wazuh_raw(**overrides: Any) -> dict[str, Any]:
    """Minimal valid Wazuh alert dict."""
    raw: dict[str, Any] = {
        "timestamp": "2026-02-20T10:00:00.000Z",
        "id": "1708331400.12345",
        "rule": {
            "id": "100234",
            "description": "Test Wazuh Rule",
            "level": 12,
            "mitre": {"id": ["T1059"], "tactic": ["execution"]},
        },
        "agent": {"id": "001", "name": "WIN-DC01", "ip": "192.168.1.10"},
        "data": {},
    }
    raw.update(overrides)
    return raw


def _zeek_raw(**overrides: Any) -> dict[str, Any]:
    """Minimal valid Zeek conn.log dict."""
    raw: dict[str, Any] = {
        "ts": 1708331400.123,
        "_path": "conn",
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 54321,
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 443,
        "proto": "tcp",
    }
    raw.update(overrides)
    return raw


def _suricata_raw(**overrides: Any) -> dict[str, Any]:
    """Minimal valid Suricata EVE JSON alert dict."""
    raw: dict[str, Any] = {
        "timestamp": "2026-02-20T10:00:00.123456+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.200",
        "src_port": 4444,
        "dest_ip": "10.0.0.5",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "signature_id": 2030358,
            "signature": "ET MALWARE Test Signature",
            "category": "Malware",
            "severity": 1,
        },
    }
    raw.update(overrides)
    return raw


def _ocsf_event(**overrides: Any) -> OCSFEvent:
    """Minimal valid OCSFEvent."""
    return OCSFEvent(
        class_uid=OCSFClass.SECURITY_FINDING,
        class_name="Security Finding",
        category_uid=OCSFCategory.FINDINGS,
        time=datetime.now(timezone.utc),
        severity_id=3,
        metadata_product="Wazuh",
        dst_endpoint=Endpoint(hostname="WIN-DC01", ip="192.168.1.10"),
        **overrides,
    )


def _alert_dict(**overrides: Any) -> dict[str, Any]:
    """Minimal alert dict as published to Topic.ALERTS."""
    d: dict[str, Any] = {
        "id": "test-alert-id",
        "rule_id": "rule-001",
        "rule_title": "Test Rule",
        "level": "high",
        "severity_id": 4,
        "technique_ids": ["T1059"],
        "tactic_ids": ["TA0002"],
        "host": "WIN-DC01",
        "time": datetime.now(timezone.utc).isoformat(),
        "event_snapshot": {},
    }
    d.update(overrides)
    return d


def _make_alert_manager(queue: InMemoryQueue) -> AlertManager:
    """Build an AlertManager with a mocked Valkey client (no real Redis needed)."""
    with patch("app.services.alert_manager.aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = AsyncMock()
        mgr = AlertManager(queue)
    # Replace the real Valkey client with a fresh mock; default: not a duplicate
    mgr._valkey = AsyncMock()
    mgr._valkey.set = AsyncMock(return_value=True)  # True → key newly set → not dup
    return mgr


# ── Topic constant semantics ───────────────────────────────────────────────────

class TestTopicSemantics:
    """Naming patterns and categorical semantics of all six topic constants."""

    RAW_TOPICS = [Topic.RAW_WAZUH, Topic.RAW_ZEEK, Topic.RAW_SURICATA]
    PROCESSING_TOPICS = [Topic.NORMALIZED, Topic.ALERTS, Topic.ENRICHED]
    ALL_TOPICS = RAW_TOPICS + PROCESSING_TOPICS

    def test_raw_topics_all_start_with_mxtac_raw(self) -> None:
        for topic in self.RAW_TOPICS:
            assert topic.startswith("mxtac.raw."), (
                f"{topic!r} must start with 'mxtac.raw.'"
            )

    def test_processing_topics_do_not_have_raw_prefix(self) -> None:
        for topic in self.PROCESSING_TOPICS:
            assert not topic.startswith("mxtac.raw."), (
                f"{topic!r} must not be a raw topic"
            )

    def test_raw_topic_sources_are_distinct(self) -> None:
        sources = [t.split(".")[-1] for t in self.RAW_TOPICS]
        assert len(set(sources)) == len(sources), "Each raw topic must have a unique source suffix"

    def test_raw_topics_cover_wazuh_zeek_suricata(self) -> None:
        sources = {t.split(".")[-1] for t in self.RAW_TOPICS}
        assert sources == {"wazuh", "zeek", "suricata"}

    def test_processing_topics_contain_stage_names(self) -> None:
        assert "normalized" in Topic.NORMALIZED
        assert "alerts" in Topic.ALERTS
        assert "enriched" in Topic.ENRICHED

    def test_all_topics_use_mxtac_namespace(self) -> None:
        for topic in self.ALL_TOPICS:
            assert topic.startswith("mxtac."), f"{topic!r} must use 'mxtac.' namespace"

    def test_exactly_six_topics_defined(self) -> None:
        assert len(self.ALL_TOPICS) == 6

    def test_three_raw_and_three_processing_topics(self) -> None:
        assert len(self.RAW_TOPICS) == 3
        assert len(self.PROCESSING_TOPICS) == 3

    def test_all_topics_are_distinct(self) -> None:
        assert len(set(self.ALL_TOPICS)) == len(self.ALL_TOPICS)

    def test_normalized_comes_before_alerts_alphabetically_in_pipeline(self) -> None:
        """NORMALIZED → ALERTS → ENRICHED is the pipeline order; verify topic values reflect it."""
        # Topics are not required to sort alphabetically, but their string values
        # must contain the stage name so the pipeline can be reasoned about.
        stage_order = ["normalized", "alerts", "enriched"]
        for stage, topic in zip(stage_order, self.PROCESSING_TOPICS):
            assert stage in topic, f"Stage '{stage}' not found in topic '{topic}'"


# ── NormalizerPipeline topic routing ──────────────────────────────────────────

class TestNormalizerPipelineTopics:
    """NormalizerPipeline subscribes to all raw topics and publishes to NORMALIZED."""

    async def test_start_subscribes_to_raw_wazuh(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        task_names = [t.get_name() for t in q._tasks]
        assert any(Topic.RAW_WAZUH in name for name in task_names)
        await q.stop()

    async def test_start_subscribes_to_raw_zeek(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        task_names = [t.get_name() for t in q._tasks]
        assert any(Topic.RAW_ZEEK in name for name in task_names)
        await q.stop()

    async def test_start_subscribes_to_raw_suricata(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        task_names = [t.get_name() for t in q._tasks]
        assert any(Topic.RAW_SURICATA in name for name in task_names)
        await q.stop()

    async def test_start_creates_exactly_three_subscriptions(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        assert len(q._tasks) == 3
        await q.stop()

    async def test_wazuh_raw_event_published_to_normalized(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "test", capture)
        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0]["metadata_product"] == "Wazuh"
        await q.stop()

    async def test_zeek_raw_event_published_to_normalized(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "test", capture)
        await q.publish(Topic.RAW_ZEEK, _zeek_raw())
        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0]["metadata_product"] == "Zeek"
        await q.stop()

    async def test_suricata_raw_event_published_to_normalized(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "test", capture)
        await q.publish(Topic.RAW_SURICATA, _suricata_raw())
        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0]["metadata_product"] == "Suricata"
        await q.stop()

    async def test_wazuh_event_not_published_to_alerts_topic(self) -> None:
        """NormalizerPipeline must not route events to ALERTS directly."""
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        alerts: list[dict] = []

        async def capture_alerts(msg: dict) -> None:
            alerts.append(msg)

        await q.subscribe(Topic.ALERTS, "test", capture_alerts)
        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await asyncio.sleep(0.1)

        assert len(alerts) == 0
        await q.stop()

    async def test_normalization_error_does_not_publish_to_normalized(self) -> None:
        """When normalization raises, nothing is published to NORMALIZED."""
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        pipeline._wazuh.normalize = MagicMock(side_effect=ValueError("bad event"))
        await pipeline.start()

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "test", capture)
        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await asyncio.sleep(0.1)

        assert len(received) == 0
        await q.stop()

    async def test_multiple_wazuh_events_all_reach_normalized(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "test", capture)

        for _ in range(5):
            await q.publish(Topic.RAW_WAZUH, _wazuh_raw())

        await asyncio.sleep(0.2)
        assert len(received) == 5
        await q.stop()

    async def test_three_sources_all_converge_on_normalized(self) -> None:
        """Wazuh, Zeek, and Suricata events must all appear on NORMALIZED."""
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "test", capture)

        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await q.publish(Topic.RAW_ZEEK, _zeek_raw())
        await q.publish(Topic.RAW_SURICATA, _suricata_raw())

        await asyncio.sleep(0.2)
        assert len(received) == 3
        products = {msg["metadata_product"] for msg in received}
        assert products == {"Wazuh", "Zeek", "Suricata"}
        await q.stop()

    async def test_normalized_event_contains_required_ocsf_fields(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "test", capture)
        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await asyncio.sleep(0.1)

        assert len(received) == 1
        event = received[0]
        for field in ("class_uid", "class_name", "category_uid", "severity_id",
                      "metadata_product", "time"):
            assert field in event, f"OCSFEvent field '{field}' missing from normalized message"
        await q.stop()

    async def test_zeek_normalization_error_does_not_affect_wazuh_handler(self) -> None:
        """A failing Zeek normalizer must not prevent Wazuh events from being normalized."""
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        pipeline._zeek.normalize = MagicMock(side_effect=ValueError("zeek failure"))
        await pipeline.start()

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.NORMALIZED, "test", capture)

        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await q.publish(Topic.RAW_ZEEK, _zeek_raw())  # Will fail
        await asyncio.sleep(0.1)

        # Only the Wazuh event should have been normalized
        assert len(received) == 1
        assert received[0]["metadata_product"] == "Wazuh"
        await q.stop()


# ── SigmaConsumer topic routing ────────────────────────────────────────────────

class TestSigmaConsumerTopics:
    """sigma_consumer() subscribes to NORMALIZED and routes matches to ALERTS."""

    async def test_subscribes_to_normalized_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen([]))
        await sigma_consumer(q, engine)

        task_names = [t.get_name() for t in q._tasks]
        assert any(Topic.NORMALIZED in name for name in task_names)
        await q.stop()

    async def test_matching_event_published_to_alerts_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        alert = SigmaAlert(
            id="alert-001",
            rule_id="rule-001",
            rule_title="Test Rule",
            level="high",
            severity_id=4,
            technique_ids=["T1059"],
            tactic_ids=["TA0002"],
            host="WIN-DC01",
            time=datetime.now(timezone.utc),
            event_snapshot={},
        )
        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen([alert]))
        await sigma_consumer(q, engine)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "test", capture)
        await q.publish(Topic.NORMALIZED, _ocsf_event().model_dump(mode="json"))
        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0]["rule_id"] == "rule-001"
        assert received[0]["level"] == "high"
        await q.stop()

    async def test_non_matching_event_does_not_publish_to_alerts(self) -> None:
        q = InMemoryQueue()
        await q.start()

        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen([]))
        await sigma_consumer(q, engine)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "test", capture)
        await q.publish(Topic.NORMALIZED, _ocsf_event().model_dump(mode="json"))
        await asyncio.sleep(0.1)

        assert len(received) == 0
        await q.stop()

    async def test_alert_dict_contains_all_required_fields(self) -> None:
        q = InMemoryQueue()
        await q.start()

        alert = SigmaAlert(
            id="chk-id",
            rule_id="rule-chk",
            rule_title="Field Check",
            level="medium",
            severity_id=3,
            technique_ids=["T1055"],
            tactic_ids=["TA0005"],
            host="linux-srv",
            time=datetime.now(timezone.utc),
            event_snapshot={"key": "val"},
        )
        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen([alert]))
        await sigma_consumer(q, engine)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "test", capture)
        await q.publish(Topic.NORMALIZED, _ocsf_event().model_dump(mode="json"))
        await asyncio.sleep(0.1)

        assert len(received) == 1
        alert_msg = received[0]
        required = ("id", "rule_id", "rule_title", "level", "severity_id",
                    "technique_ids", "tactic_ids", "host", "time", "event_snapshot")
        for field in required:
            assert field in alert_msg, f"Required field '{field}' missing from ALERTS message"
        await q.stop()

    async def test_multiple_rule_matches_publish_multiple_alerts(self) -> None:
        q = InMemoryQueue()
        await q.start()

        alerts = [
            SigmaAlert(rule_id="rule-A", host="host1", time=datetime.now(timezone.utc)),
            SigmaAlert(rule_id="rule-B", host="host1", time=datetime.now(timezone.utc)),
        ]
        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen(alerts))
        await sigma_consumer(q, engine)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "test", capture)
        await q.publish(Topic.NORMALIZED, _ocsf_event().model_dump(mode="json"))
        await asyncio.sleep(0.1)

        assert len(received) == 2
        rule_ids = {r["rule_id"] for r in received}
        assert rule_ids == {"rule-A", "rule-B"}
        await q.stop()

    async def test_invalid_event_dict_does_not_publish_to_alerts(self) -> None:
        """If OCSFEvent(**event_dict) raises (missing required fields), no ALERTS published."""
        q = InMemoryQueue()
        await q.start()

        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen([]))
        await sigma_consumer(q, engine)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "test", capture)
        # Publish a structurally invalid event that cannot be deserialized as OCSFEvent
        await q.publish(Topic.NORMALIZED, {"invalid": "payload"})
        await asyncio.sleep(0.1)

        assert len(received) == 0
        await q.stop()

    async def test_alert_time_field_is_iso_format_string(self) -> None:
        ts = datetime(2026, 2, 20, 10, 0, 0, tzinfo=timezone.utc)
        alert = SigmaAlert(rule_id="r1", host="host1", time=ts)

        q = InMemoryQueue()
        await q.start()

        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen([alert]))
        await sigma_consumer(q, engine)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ALERTS, "test", capture)
        await q.publish(Topic.NORMALIZED, _ocsf_event().model_dump(mode="json"))
        await asyncio.sleep(0.1)

        assert len(received) == 1
        time_val = received[0]["time"]
        assert isinstance(time_val, str), "'time' must be a string in the ALERTS message"
        parsed = datetime.fromisoformat(time_val)
        assert parsed == ts
        await q.stop()

    async def test_sigma_consumer_does_not_subscribe_to_raw_topics(self) -> None:
        q = InMemoryQueue()
        await q.start()

        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen([]))
        await sigma_consumer(q, engine)

        task_names = [t.get_name() for t in q._tasks]
        assert not any(Topic.RAW_WAZUH in name for name in task_names)
        assert not any(Topic.RAW_ZEEK in name for name in task_names)
        assert not any(Topic.RAW_SURICATA in name for name in task_names)
        await q.stop()


# ── AlertManager topic routing ─────────────────────────────────────────────────

class TestAlertManagerTopics:
    """AlertManager.process() publishes enriched alerts to Topic.ENRICHED."""

    async def test_process_publishes_to_enriched_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "test", capture)
        await mgr.process(_alert_dict())
        await asyncio.sleep(0.05)

        assert len(received) == 1
        await q.stop()

    async def test_enriched_alert_has_score_field(self) -> None:
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "test", capture)
        await mgr.process(_alert_dict())
        await asyncio.sleep(0.05)

        assert "score" in received[0]
        await q.stop()

    async def test_enriched_alert_has_asset_criticality(self) -> None:
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "test", capture)
        await mgr.process(_alert_dict(host="dc01.corp"))
        await asyncio.sleep(0.05)

        assert "asset_criticality" in received[0]
        await q.stop()

    async def test_duplicate_alert_not_published_to_enriched(self) -> None:
        """When _is_duplicate returns True the alert must not reach ENRICHED."""
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)
        # First set returns True (new key), second returns None (key exists → duplicate)
        mgr._valkey.set = AsyncMock(side_effect=[True, None])

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "test", capture)

        alert = _alert_dict()
        await mgr.process(alert)
        await mgr.process(alert)
        await asyncio.sleep(0.1)

        assert len(received) == 1, "Duplicate alert must be dropped"
        await q.stop()

    async def test_process_does_not_publish_to_alerts_or_normalized(self) -> None:
        """AlertManager must only write to ENRICHED, never to upstream topics."""
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)

        alerts_received: list[dict] = []
        normalized_received: list[dict] = []

        async def cap_alerts(msg: dict) -> None:
            alerts_received.append(msg)

        async def cap_normalized(msg: dict) -> None:
            normalized_received.append(msg)

        await q.subscribe(Topic.ALERTS, "test", cap_alerts)
        await q.subscribe(Topic.NORMALIZED, "test", cap_normalized)
        await mgr.process(_alert_dict())
        await asyncio.sleep(0.05)

        assert len(alerts_received) == 0
        assert len(normalized_received) == 0
        await q.stop()

    async def test_score_is_within_0_to_10(self) -> None:
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "test", capture)

        # Distinct rule_ids ensure each call produces a unique dedup key
        for severity_id in range(1, 6):
            mgr._valkey.set = AsyncMock(return_value=True)
            await mgr.process(_alert_dict(rule_id=f"rule-{severity_id}", severity_id=severity_id))

        await asyncio.sleep(0.2)
        assert len(received) == 5
        for msg in received:
            score = msg["score"]
            assert 0.0 <= score <= 10.0, f"Score {score} is outside [0, 10]"
        await q.stop()

    async def test_valkey_failure_allows_alert_through(self) -> None:
        """If Valkey is unreachable the manager must fail-open and still publish to ENRICHED."""
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)
        mgr._valkey.set = AsyncMock(side_effect=ConnectionError("Valkey unavailable"))

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "test", capture)
        await mgr.process(_alert_dict())
        await asyncio.sleep(0.05)

        assert len(received) == 1, "Alert must pass through when Valkey is unreachable"
        await q.stop()

    async def test_enriched_alert_contains_original_alert_fields(self) -> None:
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "test", capture)
        await mgr.process(_alert_dict(rule_id="sentinel-rule", host="dc01.corp"))
        await asyncio.sleep(0.05)

        assert len(received) == 1
        enriched = received[0]
        assert enriched["rule_id"] == "sentinel-rule"
        assert enriched["host"] == "dc01.corp"
        await q.stop()

    async def test_dc_host_has_highest_asset_criticality(self) -> None:
        """Domain controller prefix ('dc') must produce the highest criticality score."""
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)

        received: list[dict] = []

        async def capture(msg: dict) -> None:
            received.append(msg)

        await q.subscribe(Topic.ENRICHED, "test", capture)

        mgr._valkey.set = AsyncMock(return_value=True)
        await mgr.process(_alert_dict(rule_id="dc-rule", host="dc01"))
        mgr._valkey.set = AsyncMock(return_value=True)
        await mgr.process(_alert_dict(rule_id="win-rule", host="win-workstation"))

        await asyncio.sleep(0.1)
        assert len(received) == 2

        dc_msg = next(m for m in received if m["host"] == "dc01")
        win_msg = next(m for m in received if m["host"] == "win-workstation")
        assert dc_msg["asset_criticality"] > win_msg["asset_criticality"]
        await q.stop()


# ── WebSocketBroadcaster topic routing ────────────────────────────────────────

class TestWebSocketBroadcasterTopics:
    """websocket_broadcaster() subscribes to ENRICHED and calls broadcast_alert."""

    async def test_subscribes_to_enriched_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        with patch(
            "app.api.v1.endpoints.websocket.broadcast_alert",
            new_callable=AsyncMock,
        ):
            await websocket_broadcaster(q)

        task_names = [t.get_name() for t in q._tasks]
        assert any(Topic.ENRICHED in name for name in task_names)
        await q.stop()

    async def test_creates_exactly_one_subscription(self) -> None:
        q = InMemoryQueue()
        await q.start()

        with patch(
            "app.api.v1.endpoints.websocket.broadcast_alert",
            new_callable=AsyncMock,
        ):
            await websocket_broadcaster(q)

        assert len(q._tasks) == 1
        await q.stop()

    async def test_broadcast_alert_called_for_enriched_message(self) -> None:
        q = InMemoryQueue()
        await q.start()

        with patch(
            "app.api.v1.endpoints.websocket.broadcast_alert",
            new_callable=AsyncMock,
        ) as mock_broadcast:
            await websocket_broadcaster(q)

            enriched = _alert_dict(score=7.5, asset_criticality=0.8)
            await q.publish(Topic.ENRICHED, enriched)
            await asyncio.sleep(0.1)

            mock_broadcast.assert_called_once_with(enriched)

        await q.stop()

    async def test_broadcast_called_for_each_of_multiple_enriched_messages(self) -> None:
        q = InMemoryQueue()
        await q.start()

        with patch(
            "app.api.v1.endpoints.websocket.broadcast_alert",
            new_callable=AsyncMock,
        ) as mock_broadcast:
            await websocket_broadcaster(q)

            for i in range(3):
                await q.publish(Topic.ENRICHED, _alert_dict(id=f"alert-{i}"))

            await asyncio.sleep(0.2)
            assert mock_broadcast.call_count == 3

        await q.stop()

    async def test_broadcast_error_does_not_crash_consumer(self) -> None:
        """If broadcast_alert raises, the broadcaster must continue handling future messages."""
        q = InMemoryQueue()
        await q.start()

        call_count = 0

        async def failing_broadcast(alert: dict) -> None:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("WebSocket connection lost")

        with patch(
            "app.api.v1.endpoints.websocket.broadcast_alert",
            failing_broadcast,
        ):
            await websocket_broadcaster(q)

            await q.publish(Topic.ENRICHED, _alert_dict(id="a1"))
            await q.publish(Topic.ENRICHED, _alert_dict(id="a2"))
            await asyncio.sleep(0.2)

        assert call_count == 2, "Both messages must be attempted despite first failure"
        await q.stop()

    async def test_does_not_subscribe_to_alerts_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        with patch(
            "app.api.v1.endpoints.websocket.broadcast_alert",
            new_callable=AsyncMock,
        ):
            await websocket_broadcaster(q)

        task_names = [t.get_name() for t in q._tasks]
        assert not any(Topic.ALERTS in name for name in task_names)
        await q.stop()

    async def test_does_not_subscribe_to_normalized_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        with patch(
            "app.api.v1.endpoints.websocket.broadcast_alert",
            new_callable=AsyncMock,
        ):
            await websocket_broadcaster(q)

        task_names = [t.get_name() for t in q._tasks]
        assert not any(Topic.NORMALIZED in name for name in task_names)
        await q.stop()


# ── End-to-end topic flow integration ─────────────────────────────────────────

class TestTopicFlowIntegration:
    """
    End-to-end: raw event flows through RAW → NORMALIZED → ALERTS → ENRICHED.
    Uses real InMemoryQueue + real NormalizerPipeline + mocked SigmaEngine + mocked Valkey.
    """

    async def test_wazuh_raw_reaches_normalized(self) -> None:
        q = InMemoryQueue()
        await q.start()
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        normalized: list[dict] = []

        async def capture(msg: dict) -> None:
            normalized.append(msg)

        await q.subscribe(Topic.NORMALIZED, "integration", capture)
        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await asyncio.sleep(0.1)

        assert len(normalized) == 1
        assert normalized[0]["metadata_product"] == "Wazuh"
        await q.stop()

    async def test_normalized_event_reaches_alerts_on_sigma_match(self) -> None:
        q = InMemoryQueue()
        await q.start()

        fired = SigmaAlert(
            rule_id="integration-rule",
            rule_title="Integration Test",
            host="WIN-DC01",
            time=datetime.now(timezone.utc),
        )
        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen([fired]))
        await sigma_consumer(q, engine)

        alerts: list[dict] = []

        async def capture(msg: dict) -> None:
            alerts.append(msg)

        await q.subscribe(Topic.ALERTS, "integration", capture)
        await q.publish(Topic.NORMALIZED, _ocsf_event().model_dump(mode="json"))
        await asyncio.sleep(0.1)

        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "integration-rule"
        await q.stop()

    async def test_alert_reaches_enriched_via_alert_manager(self) -> None:
        q = InMemoryQueue()
        await q.start()
        mgr = _make_alert_manager(q)

        async def alert_consumer(msg: dict) -> None:
            await mgr.process(msg)

        await q.subscribe(Topic.ALERTS, "alert-mgr", alert_consumer)

        enriched: list[dict] = []

        async def capture(msg: dict) -> None:
            enriched.append(msg)

        await q.subscribe(Topic.ENRICHED, "integration", capture)
        await q.publish(Topic.ALERTS, _alert_dict())
        await asyncio.sleep(0.1)

        assert len(enriched) == 1
        assert "score" in enriched[0]
        await q.stop()

    async def test_full_pipeline_raw_wazuh_to_enriched(self) -> None:
        """
        Full pipeline: RAW_WAZUH → NORMALIZED → ALERTS → ENRICHED.
        NormalizerPipeline + SigmaConsumer + AlertManager all running concurrently.
        """
        q = InMemoryQueue()
        await q.start()

        # Stage 1: normalizer
        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        # Stage 2: Sigma consumer — always fires one alert
        fired = SigmaAlert(
            rule_id="full-pipeline-rule",
            rule_title="Full Pipeline Test",
            host="WIN-DC01",
            level="high",
            severity_id=4,
            time=datetime.now(timezone.utc),
        )
        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=lambda e: _agen([fired]))
        await sigma_consumer(q, engine)

        # Stage 3: alert manager
        mgr = _make_alert_manager(q)

        async def alert_consumer(msg: dict) -> None:
            await mgr.process(msg)

        await q.subscribe(Topic.ALERTS, "alert-mgr", alert_consumer)

        # Capture enriched output
        enriched: list[dict] = []

        async def capture(msg: dict) -> None:
            enriched.append(msg)

        await q.subscribe(Topic.ENRICHED, "integration", capture)

        # Inject a single raw Wazuh event
        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())

        # Allow all async tasks to propagate through the full pipeline
        await asyncio.sleep(0.3)

        assert len(enriched) == 1
        result = enriched[0]
        assert "score" in result
        assert "asset_criticality" in result
        assert result["rule_id"] == "full-pipeline-rule"
        assert 0.0 <= result["score"] <= 10.0
        await q.stop()

    async def test_full_pipeline_three_sources_produce_three_enriched(self) -> None:
        """One event from each source should produce three separate enriched alerts."""
        q = InMemoryQueue()
        await q.start()

        pipeline = NormalizerPipeline(q)
        await pipeline.start()

        # Engine fires one alert per normalized event
        def _make_alert_gen(event: OCSFEvent) -> AsyncGenerator:
            return _agen([
                SigmaAlert(
                    rule_id="multi-source-rule",
                    host=event.dst_endpoint.hostname or "unknown",
                    time=datetime.now(timezone.utc),
                )
            ])

        engine = MagicMock(spec=SigmaEngine)
        engine.evaluate = MagicMock(side_effect=_make_alert_gen)
        await sigma_consumer(q, engine)

        mgr = _make_alert_manager(q)

        async def alert_consumer(msg: dict) -> None:
            mgr._valkey.set = AsyncMock(return_value=True)  # each is unique
            await mgr.process(msg)

        await q.subscribe(Topic.ALERTS, "alert-mgr", alert_consumer)

        enriched: list[dict] = []

        async def capture(msg: dict) -> None:
            enriched.append(msg)

        await q.subscribe(Topic.ENRICHED, "integration", capture)

        await q.publish(Topic.RAW_WAZUH, _wazuh_raw())
        await q.publish(Topic.RAW_ZEEK, _zeek_raw())
        await q.publish(Topic.RAW_SURICATA, _suricata_raw())

        await asyncio.sleep(0.5)
        assert len(enriched) == 3
        await q.stop()
