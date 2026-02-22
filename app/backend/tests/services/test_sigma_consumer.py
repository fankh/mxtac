"""Tests for Feature 8.19 — sigma_consumer: reads mxtac.normalized, publishes mxtac.alerts.
Feature 8.20 — DB hit_count update on rule match via session_factory.

Coverage:

  Subscription wiring:
  - sigma_consumer() subscribes to Topic.NORMALIZED
  - sigma_consumer() uses consumer group "sigma-eval"
  - sigma_consumer() registers a callable handler

  Handler — matching event:
  - Matching event dict → alert published to Topic.ALERTS
  - Published payload is a dict
  - Alert dict has key: id (UUID4-format string)
  - Alert dict has key: rule_id
  - Alert dict has key: rule_title
  - Alert dict has key: level
  - Alert dict has key: severity_id (int)
  - Alert dict has key: technique_ids (list)
  - Alert dict has key: tactic_ids (list)
  - Alert dict has key: host
  - Alert dict has key: time (ISO string, not datetime)
  - Alert dict has key: event_snapshot (dict)
  - Alert dict time value is a string (isoformat serialized)

  Handler — multiple matching rules:
  - Two matching rules → two publishes to Topic.ALERTS

  Handler — non-matching event:
  - Non-matching event → no publish to Topic.ALERTS

  Error isolation:
  - Invalid event_dict (cannot construct OCSFEvent) → no publish, no exception
  - Engine exception → no publish, no exception

  Integration (real InMemoryQueue + real SigmaEngine):
  - Normalized event matching a rule → alert on Topic.ALERTS
  - Normalized event not matching → no alert on Topic.ALERTS
  - Multiple events → multiple alerts
  - Error in one event does not block subsequent events

  DB hit tracking (Feature 8.20):
  - session_factory=None → RuleRepo.increment_hit not called
  - Matching event with session_factory → RuleRepo.increment_hit called once
  - increment_hit called with the correct rule_id
  - session.commit() called after increment_hit
  - Non-matching event → RuleRepo.increment_hit not called
  - Two matching rules → increment_hit called twice
  - Alert published even when session_factory() raises
  - Alert published even when increment_hit raises
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.engine.sigma_engine import SigmaEngine
from app.pipeline.queue import InMemoryQueue, Topic
from app.repositories.rule_repo import RuleRepo
from app.services.normalizers.ocsf import (
    Endpoint,
    OCSFCategory,
    OCSFClass,
    OCSFEvent,
    ProcessInfo,
)
from app.services.sigma_consumer import sigma_consumer


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Sigma rule YAML fixtures
# ---------------------------------------------------------------------------

_RULE_PS_ENCODED = """\
title: PowerShell Encoded Command
id: rule-ps-encoded-001
status: stable
level: high
description: Detects Base64-encoded PowerShell commands.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: powershell.exe
    cmd_line|contains: -enc
  condition: selection
tags:
  - attack.T1059.001
  - attack.TA0002
"""

_RULE_MIMIKATZ = """\
title: Mimikatz Credential Access
id: rule-mimikatz-001
status: stable
level: critical
description: Detects mimikatz credential dumping.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    cmd_line|contains: mimikatz
  condition: selection
tags:
  - attack.T1003.001
  - attack.TA0006
"""

_RULE_NO_MATCH = """\
title: Unreachable Rule
id: rule-no-match-001
status: experimental
level: low
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    name: this-process-does-not-exist.exe
  condition: selection
"""


# ---------------------------------------------------------------------------
# Event fixtures
# ---------------------------------------------------------------------------


def _process_ocsf_event(**overrides: Any) -> OCSFEvent:
    """Minimal OCSFEvent for a windows process-creation scenario."""
    kwargs: dict[str, Any] = dict(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        class_name="Process Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        time=datetime(2026, 2, 22, 12, 0, 0, tzinfo=timezone.utc),
        severity_id=1,
        metadata_product="windows",
        process=ProcessInfo(name="powershell.exe", cmd_line="powershell -enc abc123"),
        dst_endpoint=Endpoint(hostname="workstation-01", ip="10.0.0.1"),
    )
    kwargs.update(overrides)
    return OCSFEvent(**kwargs)  # type: ignore[arg-type]


def _event_dict(**overrides: Any) -> dict[str, Any]:
    """Return a normalized OCSFEvent serialized as dict (as NormalizerPipeline publishes)."""
    event = _process_ocsf_event(**overrides)
    return event.model_dump(mode="json")


def _engine_with_rule(yaml_text: str) -> SigmaEngine:
    engine = SigmaEngine()
    rule = engine.load_rule_yaml(yaml_text)
    assert rule is not None
    engine.add_rule(rule)
    return engine


# ---------------------------------------------------------------------------
# Helpers for extracting the captured handler from a mock queue
# ---------------------------------------------------------------------------


async def _get_handler(engine: SigmaEngine) -> tuple[MagicMock, Any]:
    """Call sigma_consumer with a mock queue and return (mock_queue, _handle)."""
    q = MagicMock()
    q.subscribe = AsyncMock()
    await sigma_consumer(q, engine)
    handler = q.subscribe.call_args.args[2]
    return q, handler


# ---------------------------------------------------------------------------
# Subscription wiring
# ---------------------------------------------------------------------------


class TestSubscriptionWiring:
    async def test_subscribes_to_normalized_topic(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        await sigma_consumer(q, SigmaEngine())
        topic = q.subscribe.call_args.args[0]
        assert topic == Topic.NORMALIZED

    async def test_uses_sigma_eval_consumer_group(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        await sigma_consumer(q, SigmaEngine())
        group = q.subscribe.call_args.args[1]
        assert group == "sigma-eval"

    async def test_registers_callable_handler(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        await sigma_consumer(q, SigmaEngine())
        handler = q.subscribe.call_args.args[2]
        assert callable(handler)

    async def test_subscribe_called_exactly_once(self) -> None:
        q = MagicMock()
        q.subscribe = AsyncMock()
        await sigma_consumer(q, SigmaEngine())
        assert q.subscribe.call_count == 1


# ---------------------------------------------------------------------------
# Handler — matching event
# ---------------------------------------------------------------------------


class TestHandlerMatchingEvent:
    async def test_matching_event_publishes_to_alerts_topic(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        q.publish.assert_awaited_once()
        topic = q.publish.call_args.args[0]
        assert topic == Topic.ALERTS

    async def test_published_payload_is_dict(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert isinstance(payload, dict)

    async def test_alert_dict_has_id(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "id" in payload

    async def test_alert_id_is_uuid4_format(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        alert_id = q.publish.call_args.args[1]["id"]
        assert _UUID4_RE.match(alert_id), f"id {alert_id!r} is not UUID4"

    async def test_alert_dict_has_rule_id(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "rule_id" in payload
        assert payload["rule_id"] == "rule-ps-encoded-001"

    async def test_alert_dict_has_rule_title(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "rule_title" in payload
        assert payload["rule_title"] == "PowerShell Encoded Command"

    async def test_alert_dict_has_level(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "level" in payload
        assert payload["level"] == "high"

    async def test_alert_dict_has_severity_id_as_int(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "severity_id" in payload
        assert isinstance(payload["severity_id"], int)
        assert payload["severity_id"] == 4  # high → 4

    async def test_alert_dict_has_technique_ids(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "technique_ids" in payload
        assert "T1059.001" in payload["technique_ids"]

    async def test_alert_dict_has_tactic_ids(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "tactic_ids" in payload
        assert "TA0002" in payload["tactic_ids"]

    async def test_alert_dict_has_host(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "host" in payload
        assert payload["host"] == "workstation-01"

    async def test_alert_dict_has_time(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "time" in payload

    async def test_alert_dict_time_is_string(self) -> None:
        """time must be serialized via isoformat(), not a raw datetime object."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert isinstance(payload["time"], str)

    async def test_alert_dict_time_is_iso_format(self) -> None:
        """time string must be parseable as a datetime (ISO 8601)."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        time_str = q.publish.call_args.args[1]["time"]
        # Should not raise
        parsed = datetime.fromisoformat(time_str)
        assert parsed.year == 2026

    async def test_alert_dict_has_event_snapshot(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        assert "event_snapshot" in payload
        assert isinstance(payload["event_snapshot"], dict)
        assert len(payload["event_snapshot"]) > 0

    async def test_alert_event_snapshot_has_all_required_keys(self) -> None:
        """Alert dict must include all nine documented fields."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        payload = q.publish.call_args.args[1]
        required_keys = {
            "id", "rule_id", "rule_title", "level", "severity_id",
            "technique_ids", "tactic_ids", "host", "time", "event_snapshot",
        }
        for key in required_keys:
            assert key in payload, f"Missing required key in alert dict: {key!r}"

    async def test_critical_rule_severity_id_is_5(self) -> None:
        engine = _engine_with_rule(_RULE_MIMIKATZ)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        event = _event_dict(
            process=ProcessInfo(name="cmd.exe", cmd_line="cmd /c mimikatz.exe").model_dump(),
        )
        await handler(event)

        payload = q.publish.call_args.args[1]
        assert payload["severity_id"] == 5
        assert payload["level"] == "critical"


# ---------------------------------------------------------------------------
# Handler — multiple matching rules
# ---------------------------------------------------------------------------


class TestHandlerMultipleRules:
    async def test_two_matching_rules_yield_two_publishes(self) -> None:
        engine = SigmaEngine()
        for yaml_text in (_RULE_PS_ENCODED, _RULE_MIMIKATZ):
            rule = engine.load_rule_yaml(yaml_text)
            assert rule is not None
            engine.add_rule(rule)

        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        # Event that matches both rules
        event = _event_dict(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell -enc mimikatz",
            ).model_dump(),
        )
        await handler(event)

        assert q.publish.await_count == 2
        topics = [call.args[0] for call in q.publish.call_args_list]
        assert all(t == Topic.ALERTS for t in topics)

    async def test_two_matching_rules_produce_distinct_alert_ids(self) -> None:
        engine = SigmaEngine()
        for yaml_text in (_RULE_PS_ENCODED, _RULE_MIMIKATZ):
            rule = engine.load_rule_yaml(yaml_text)
            assert rule is not None
            engine.add_rule(rule)

        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        event = _event_dict(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell -enc mimikatz",
            ).model_dump(),
        )
        await handler(event)

        ids = [call.args[1]["id"] for call in q.publish.call_args_list]
        assert len(set(ids)) == 2, "Each fired rule must produce a distinct alert id"


# ---------------------------------------------------------------------------
# Handler — non-matching event
# ---------------------------------------------------------------------------


class TestHandlerNonMatchingEvent:
    async def test_non_matching_event_does_not_publish(self) -> None:
        engine = _engine_with_rule(_RULE_NO_MATCH)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())  # powershell.exe, not the no-match process

        q.publish.assert_not_awaited()

    async def test_no_rules_loaded_does_not_publish(self) -> None:
        engine = SigmaEngine()  # no rules
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        q.publish.assert_not_awaited()


# ---------------------------------------------------------------------------
# Error isolation
# ---------------------------------------------------------------------------


class TestErrorIsolation:
    async def test_invalid_event_dict_does_not_raise(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        # Empty dict cannot reconstruct OCSFEvent — should be caught internally
        await handler({})  # must not raise

    async def test_invalid_event_dict_does_not_publish(self) -> None:
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler({})

        q.publish.assert_not_awaited()

    async def test_engine_exception_does_not_propagate(self) -> None:
        """If evaluate() raises, handler catches it and does not re-raise."""

        async def _bad_evaluate(event):  # type: ignore[override]
            raise RuntimeError("engine exploded")
            yield  # make it an async generator

        engine = MagicMock()
        engine.evaluate = _bad_evaluate

        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())  # must not raise

    async def test_engine_exception_does_not_publish(self) -> None:
        async def _bad_evaluate(event):  # type: ignore[override]
            raise RuntimeError("engine exploded")
            yield

        engine = MagicMock()
        engine.evaluate = _bad_evaluate

        q, handler = await _get_handler(engine)
        q.publish = AsyncMock()

        await handler(_event_dict())

        q.publish.assert_not_awaited()

    async def test_publish_exception_does_not_propagate(self) -> None:
        """If publish() raises, handler catches it and does not re-raise."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q, handler = await _get_handler(engine)
        q.publish = AsyncMock(side_effect=RuntimeError("publish failed"))

        await handler(_event_dict())  # must not raise


# ---------------------------------------------------------------------------
# Integration — real InMemoryQueue + real SigmaEngine
# ---------------------------------------------------------------------------


class TestSigmaConsumerIntegration:
    """End-to-end: normalized event dict in → alert dict on Topic.ALERTS."""

    async def test_matching_event_produces_alert_on_alerts_topic(self) -> None:
        q = InMemoryQueue()
        await q.start()

        engine = _engine_with_rule(_RULE_PS_ENCODED)
        await sigma_consumer(q, engine)

        received: list[dict] = []
        await q.subscribe(Topic.ALERTS, "test-sink", received.append)

        await q.publish(Topic.NORMALIZED, _event_dict())
        await asyncio.sleep(0.15)

        assert len(received) == 1
        assert received[0]["rule_id"] == "rule-ps-encoded-001"

        await q.stop()

    async def test_non_matching_event_produces_no_alert(self) -> None:
        q = InMemoryQueue()
        await q.start()

        engine = _engine_with_rule(_RULE_NO_MATCH)
        await sigma_consumer(q, engine)

        received: list[dict] = []
        await q.subscribe(Topic.ALERTS, "test-sink", received.append)

        await q.publish(Topic.NORMALIZED, _event_dict())
        await asyncio.sleep(0.15)

        assert len(received) == 0

        await q.stop()

    async def test_multiple_events_each_produce_alert(self) -> None:
        q = InMemoryQueue()
        await q.start()

        engine = _engine_with_rule(_RULE_PS_ENCODED)
        await sigma_consumer(q, engine)

        received: list[dict] = []
        await q.subscribe(Topic.ALERTS, "test-sink", received.append)

        for _ in range(3):
            await q.publish(Topic.NORMALIZED, _event_dict())
        await asyncio.sleep(0.25)

        assert len(received) == 3

        await q.stop()

    async def test_alert_ids_are_distinct_across_events(self) -> None:
        q = InMemoryQueue()
        await q.start()

        engine = _engine_with_rule(_RULE_PS_ENCODED)
        await sigma_consumer(q, engine)

        received: list[dict] = []
        await q.subscribe(Topic.ALERTS, "test-sink", received.append)

        for _ in range(3):
            await q.publish(Topic.NORMALIZED, _event_dict())
        await asyncio.sleep(0.25)

        ids = [r["id"] for r in received]
        assert len(set(ids)) == 3, "Each alert must have a distinct UUID4 id"

        await q.stop()

    async def test_error_in_one_event_does_not_block_subsequent(self) -> None:
        """An invalid event_dict must not prevent the next valid event from being processed."""
        q = InMemoryQueue()
        await q.start()

        engine = _engine_with_rule(_RULE_PS_ENCODED)
        await sigma_consumer(q, engine)

        received: list[dict] = []
        await q.subscribe(Topic.ALERTS, "test-sink", received.append)

        # Publish a malformed dict first, then a valid one
        await q.publish(Topic.NORMALIZED, {"invalid": "data"})
        await q.publish(Topic.NORMALIZED, _event_dict())
        await asyncio.sleep(0.25)

        assert len(received) == 1
        assert received[0]["rule_id"] == "rule-ps-encoded-001"

        await q.stop()

    async def test_integration_alert_dict_is_json_serializable(self) -> None:
        """All values in the published alert dict must be JSON-serializable types."""
        import json

        q = InMemoryQueue()
        await q.start()

        engine = _engine_with_rule(_RULE_PS_ENCODED)
        await sigma_consumer(q, engine)

        received: list[dict] = []
        await q.subscribe(Topic.ALERTS, "test-sink", received.append)

        await q.publish(Topic.NORMALIZED, _event_dict())
        await asyncio.sleep(0.15)

        assert len(received) == 1
        # Should not raise
        serialized = json.dumps(received[0])
        assert len(serialized) > 0

        await q.stop()

    async def test_integration_two_matching_rules_produce_two_alerts(self) -> None:
        q = InMemoryQueue()
        await q.start()

        engine = SigmaEngine()
        for yaml_text in (_RULE_PS_ENCODED, _RULE_MIMIKATZ):
            rule = engine.load_rule_yaml(yaml_text)
            assert rule is not None
            engine.add_rule(rule)

        await sigma_consumer(q, engine)

        received: list[dict] = []
        await q.subscribe(Topic.ALERTS, "test-sink", received.append)

        # Event matching both PS-encoded and mimikatz rules
        event = _process_ocsf_event(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell -enc mimikatz",
            )
        )
        await q.publish(Topic.NORMALIZED, event.model_dump(mode="json"))
        await asyncio.sleep(0.2)

        assert len(received) == 2
        rule_ids = {r["rule_id"] for r in received}
        assert rule_ids == {"rule-ps-encoded-001", "rule-mimikatz-001"}

        await q.stop()


# ---------------------------------------------------------------------------
# DB hit tracking (Feature 8.20)
# ---------------------------------------------------------------------------


def _make_session_factory():
    """Return (factory, session) for testing session_factory DB integration.

    The factory is a sync callable (like async_sessionmaker) that returns an
    object usable as ``async with session_factory() as session:``.
    """
    mock_session = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_factory = MagicMock(return_value=mock_session)
    return mock_factory, mock_session


async def _get_handler_with_db(engine: SigmaEngine, session_factory) -> tuple[MagicMock, Any]:
    """Call sigma_consumer with session_factory and return (mock_queue, handler)."""
    q = MagicMock()
    q.subscribe = AsyncMock()
    await sigma_consumer(q, engine, session_factory=session_factory)
    handler = q.subscribe.call_args.args[2]
    return q, handler


class TestHandlerHitCountDB:
    """Feature 8.20 — sigma_consumer increments hit_count in DB on rule match."""

    async def test_no_db_call_when_session_factory_is_none(self) -> None:
        """session_factory=None → RuleRepo.increment_hit must not be called."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        q = MagicMock()
        q.subscribe = AsyncMock()
        await sigma_consumer(q, engine, session_factory=None)
        handler = q.subscribe.call_args.args[2]
        q.publish = AsyncMock()

        with patch.object(RuleRepo, "increment_hit", new=AsyncMock()) as mock_inc:
            await handler(_event_dict())

        mock_inc.assert_not_awaited()

    async def test_increment_hit_called_on_match(self) -> None:
        """Matching event with session_factory → RuleRepo.increment_hit awaited once."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        mock_factory, mock_session = _make_session_factory()
        q, handler = await _get_handler_with_db(engine, mock_factory)
        q.publish = AsyncMock()

        with patch.object(RuleRepo, "increment_hit", new=AsyncMock()) as mock_inc:
            await handler(_event_dict())

        mock_inc.assert_awaited_once()

    async def test_increment_hit_called_with_correct_rule_id(self) -> None:
        """increment_hit is called with the matched rule's id."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        mock_factory, mock_session = _make_session_factory()
        q, handler = await _get_handler_with_db(engine, mock_factory)
        q.publish = AsyncMock()

        with patch.object(RuleRepo, "increment_hit", new=AsyncMock()) as mock_inc:
            await handler(_event_dict())

        _, call_rule_id = mock_inc.call_args.args
        assert call_rule_id == "rule-ps-encoded-001"

    async def test_session_commit_called_after_increment_hit(self) -> None:
        """session.commit() is awaited after a successful increment_hit."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        mock_factory, mock_session = _make_session_factory()
        q, handler = await _get_handler_with_db(engine, mock_factory)
        q.publish = AsyncMock()

        with patch.object(RuleRepo, "increment_hit", new=AsyncMock()):
            await handler(_event_dict())

        mock_session.commit.assert_awaited_once()

    async def test_no_db_call_on_non_matching_event(self) -> None:
        """Non-matching event → RuleRepo.increment_hit not called."""
        engine = _engine_with_rule(_RULE_NO_MATCH)
        mock_factory, mock_session = _make_session_factory()
        q, handler = await _get_handler_with_db(engine, mock_factory)
        q.publish = AsyncMock()

        with patch.object(RuleRepo, "increment_hit", new=AsyncMock()) as mock_inc:
            await handler(_event_dict())  # powershell.exe won't match _RULE_NO_MATCH

        mock_inc.assert_not_awaited()

    async def test_two_matching_rules_call_increment_hit_twice(self) -> None:
        """Two matching rules → increment_hit called once per matched rule."""
        engine = SigmaEngine()
        for yaml_text in (_RULE_PS_ENCODED, _RULE_MIMIKATZ):
            rule = engine.load_rule_yaml(yaml_text)
            assert rule is not None
            engine.add_rule(rule)

        mock_factory, mock_session = _make_session_factory()
        q, handler = await _get_handler_with_db(engine, mock_factory)
        q.publish = AsyncMock()

        event = _event_dict(
            process=ProcessInfo(
                name="powershell.exe",
                cmd_line="powershell -enc mimikatz",
            ).model_dump(),
        )
        with patch.object(RuleRepo, "increment_hit", new=AsyncMock()) as mock_inc:
            await handler(event)

        assert mock_inc.await_count == 2

    async def test_alert_published_when_session_factory_raises(self) -> None:
        """DB failure (session_factory() raises) does not suppress the alert publish."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        # factory itself raises — simulates connection pool exhaustion
        bad_factory = MagicMock(side_effect=Exception("DB down"))
        q, handler = await _get_handler_with_db(engine, bad_factory)
        q.publish = AsyncMock()

        await handler(_event_dict())  # must not raise

        q.publish.assert_awaited_once()

    async def test_alert_published_when_increment_hit_raises(self) -> None:
        """DB UPDATE failure does not suppress the alert publish."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        mock_factory, mock_session = _make_session_factory()
        q, handler = await _get_handler_with_db(engine, mock_factory)
        q.publish = AsyncMock()

        with patch.object(
            RuleRepo, "increment_hit", new=AsyncMock(side_effect=Exception("DB error"))
        ):
            await handler(_event_dict())  # must not raise

        q.publish.assert_awaited_once()

    async def test_handler_does_not_raise_when_session_factory_raises(self) -> None:
        """DB failure must never propagate out of the handler."""
        engine = _engine_with_rule(_RULE_PS_ENCODED)
        bad_factory = MagicMock(side_effect=RuntimeError("connection refused"))
        q, handler = await _get_handler_with_db(engine, bad_factory)
        q.publish = AsyncMock()

        await handler(_event_dict())  # must not raise
