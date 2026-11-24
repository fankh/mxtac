"""Source (connector) status and counters as the Sources page shows them.

Found while driving the real UI against the real backend:

  - POST /connectors with a name that exists answered 500 instead of 409.
  - A new connector stayed "connecting": its start task reported "active"
    through another session before the request had committed the row.
  - ``events_total`` and ``errors_total`` were counted in memory only, so the
    Sources page showed 0 events for every source.
  - A generic webhook source showed "Inactive" and "Never" after it had
    accepted events, and a disabled one still accepted events.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints import connectors as connectors_endpoint
from app.api.v1.endpoints.overview import _connector_to_integration_status
from app.connectors import syslog as syslog_module
from app.connectors.base import BaseConnector, ConnectorConfig
from app.connectors.registry import build_connector, start_connectors_from_db
from app.connectors.syslog import SyslogUDPConnector
from app.core.database import get_db
from app.main import app
from app.models.connector import Connector
from app.pipeline.queue import Topic, get_queue
from app.repositories.connector_repo import ConnectorRepo

CONNECTORS = "/api/v1/connectors"
INGEST = "/api/v1/ingest"
TOKEN = "a-long-webhook-token"
HEADERS = {"X-MxTac-Source": "hook", "X-MxTac-Token": TOKEN}


def _generic(name: str = "hook", **extra: Any) -> dict[str, Any]:
    return {"name": name, "connector_type": "generic", "config": {"webhook_token": TOKEN}, **extra}


@pytest.fixture
async def ingest_client(db_session) -> AsyncGenerator[AsyncClient, None]:
    queue = MagicMock()
    queue.publish = AsyncMock()

    async def _override_get_db() -> AsyncGenerator:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_queue] = lambda: queue
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ── POST /connectors ──────────────────────────────────────────────────────────


async def test_duplicate_name_is_409_with_a_readable_message(client, engineer_headers) -> None:
    first = await client.post(CONNECTORS, json=_generic(), headers=engineer_headers)
    assert first.status_code == 201

    second = await client.post(CONNECTORS, json=_generic(), headers=engineer_headers)

    assert second.status_code == 409
    assert "already exists" in second.json()["detail"]
    assert "hook" in second.json()["detail"]


async def test_enabled_generic_source_is_active_from_the_start(client, engineer_headers) -> None:
    resp = await client.post(CONNECTORS, json=_generic(), headers=engineer_headers)
    assert resp.json()["status"] == "active"

    health = await client.get(f"{CONNECTORS}/{resp.json()['id']}/health", headers=engineer_headers)
    assert health.json()["healthy"] is True


async def test_generic_source_status_follows_the_enabled_flag(client, engineer_headers) -> None:
    created = await client.post(CONNECTORS, json=_generic(enabled=False), headers=engineer_headers)
    assert created.json()["status"] == "inactive"
    url = f"{CONNECTORS}/{created.json()['id']}"

    enabled = await client.patch(url, json={"enabled": True}, headers=engineer_headers)
    assert enabled.json()["status"] == "active"

    disabled = await client.patch(url, json={"enabled": False}, headers=engineer_headers)
    assert disabled.json()["status"] == "inactive"


async def test_other_types_stay_inactive_without_a_runtime(client, engineer_headers) -> None:
    body = {"name": "sys", "connector_type": "syslog", "config": {"port": 5514}}
    resp = await client.post(CONNECTORS, json=body, headers=engineer_headers)
    assert resp.json()["status"] == "inactive"


async def test_new_connector_row_is_committed_before_its_start_task_runs(
    client, engineer_headers, db_session
) -> None:
    """The start task writes "active" in its own session, so it must see the row."""
    order: list[str] = []

    class _Fake:
        async def start(self) -> None:
            order.append("start")

    real_commit = db_session.commit

    async def _commit() -> None:
        order.append("commit")
        await real_commit()

    app.state.queue = MagicMock()
    with (
        patch.object(connectors_endpoint, "build_connector", return_value=_Fake()),
        patch.object(db_session, "commit", _commit),
    ):
        body = {"name": "sys", "connector_type": "syslog", "config": {"port": 5514}}
        resp = await client.post(CONNECTORS, json=body, headers=engineer_headers)
        await asyncio.sleep(0)

    assert resp.status_code == 201
    assert resp.json()["status"] == "connecting"
    assert order[:2] == ["commit", "start"]


# ── POST /ingest ──────────────────────────────────────────────────────────────


async def test_accepted_webhook_events_are_counted_on_the_source(ingest_client, db_session) -> None:
    conn = await ConnectorRepo.create(
        db_session, name="hook", connector_type="generic",
        config_json=json.dumps({"webhook_token": TOKEN}),
    )
    assert (conn.events_total, conn.last_seen_at, conn.status) == (0, None, "inactive")

    first = await ingest_client.post(INGEST, headers=HEADERS, json=[{"a": 1}, {"a": 2}, "not an object"])
    second = await ingest_client.post(INGEST, headers=HEADERS, json={"a": 3})
    assert (first.status_code, second.status_code) == (202, 202)

    await db_session.refresh(conn)
    assert conn.events_total == 3
    assert conn.status == "active"
    assert conn.last_seen_at is not None


async def test_request_without_accepted_events_changes_nothing(ingest_client, db_session) -> None:
    conn = await ConnectorRepo.create(
        db_session, name="hook", connector_type="generic",
        config_json=json.dumps({"webhook_token": TOKEN}),
    )

    resp = await ingest_client.post(INGEST, headers=HEADERS, json=["x", 1])
    assert resp.json() == {"accepted": 0, "rejected": 2}

    await db_session.refresh(conn)
    assert (conn.events_total, conn.last_seen_at) == (0, None)


async def test_disabled_webhook_source_is_refused(ingest_client, db_session) -> None:
    await ConnectorRepo.create(
        db_session, name="hook", connector_type="generic",
        config_json=json.dumps({"webhook_token": TOKEN}), enabled=False,
    )

    resp = await ingest_client.post(INGEST, headers=HEADERS, json={"a": 1})
    probe = await ingest_client.post(f"{INGEST}/test", headers=HEADERS)

    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"]
    assert probe.status_code == 403


async def test_wrong_token_is_checked_before_the_disabled_state(ingest_client, db_session) -> None:
    await ConnectorRepo.create(
        db_session, name="hook", connector_type="generic",
        config_json=json.dumps({"webhook_token": TOKEN}), enabled=False,
    )
    resp = await ingest_client.post(INGEST, headers={**HEADERS, "X-MxTac-Token": "wrong"}, json={})
    assert resp.status_code == 401


# ── Counters of running connectors ────────────────────────────────────────────


class _Dummy(BaseConnector):
    async def _connect(self) -> None:
        return None

    async def _fetch_events(self):
        for i in range(3):
            yield {"n": i}

    @property
    def topic(self) -> str:
        return Topic.RAW_SYSLOG


def _dummy() -> _Dummy:
    queue = MagicMock()
    queue.publish = AsyncMock()
    return _Dummy(ConnectorConfig(name="d", connector_type="syslog", poll_interval_seconds=3600), queue)


async def test_flush_sends_only_what_was_counted_since_the_last_flush() -> None:
    connector = _dummy()
    connector.counters_callback = AsyncMock()

    await connector._flush_counters()
    connector.counters_callback.assert_not_awaited()

    connector.health.events_total = 5
    connector.health.errors_total = 1
    await connector._flush_counters()
    connector.health.events_total = 7
    await connector._flush_counters()
    await connector._flush_counters()

    assert [c.args for c in connector.counters_callback.await_args_list] == [(5, 1), (2, 0)]


async def test_failed_flush_is_retried_with_the_next_one() -> None:
    connector = _dummy()
    connector.counters_callback = AsyncMock(side_effect=[RuntimeError("db down"), None])
    connector.health.events_total = 4

    await connector._flush_counters()
    connector.health.events_total = 6
    await connector._flush_counters()

    assert connector.counters_callback.await_args_list[-1].args == (6, 0)


async def test_poll_cycle_and_stop_persist_the_totals() -> None:
    connector = _dummy()
    connector.counters_callback = AsyncMock()

    await connector.start()
    await asyncio.sleep(0.05)
    assert connector.counters_callback.await_args_list[0].args == (3, 0)

    connector.health.events_total += 2
    await connector.stop()
    assert connector.counters_callback.await_args_list[-1].args == (2, 0)


async def test_syslog_connector_flushes_while_it_waits(monkeypatch) -> None:
    monkeypatch.setattr(syslog_module, "COUNTER_FLUSH_SECONDS", 0.01)
    connector = SyslogUDPConnector(ConnectorConfig(name="s", connector_type="syslog"), MagicMock())
    connector.counters_callback = AsyncMock()
    connector.health.events_total = 2

    task = asyncio.create_task(connector._poll_loop())
    await asyncio.sleep(0.1)
    connector._stop_event.set()
    await task

    connector.counters_callback.assert_awaited_once_with(2, 0)


@pytest.mark.parametrize("connector_type", ["wazuh", "zeek", "suricata", "syslog"])
def test_registry_gives_every_connector_a_counters_callback(connector_type: str) -> None:
    row = Connector(id="c-1", name="n", connector_type=connector_type, config_json="{}", enabled=True)
    connector = build_connector(row, MagicMock())
    assert connector is not None
    assert connector.counters_callback is not None


async def test_add_counters_adds_to_the_stored_totals(db_session) -> None:
    conn = await ConnectorRepo.create(db_session, name="n", connector_type="syslog", config_json="{}")

    await ConnectorRepo.add_counters(db_session, conn.id, errors=1)
    await db_session.refresh(conn)
    assert conn.last_seen_at is None

    await ConnectorRepo.add_counters(db_session, conn.id, events=4)
    await ConnectorRepo.add_counters(db_session, conn.id, events=6)
    await ConnectorRepo.add_counters(db_session, conn.id)

    await db_session.refresh(conn)
    assert (conn.events_total, conn.errors_total, conn.status) == (10, 1, "inactive")
    # New events move "last seen"; errors alone do not.
    assert conn.last_seen_at is not None


async def test_webhook_source_is_not_reported_as_skipped_at_startup(db_session, caplog) -> None:
    await ConnectorRepo.create(
        db_session, name="hook", connector_type="generic",
        config_json=json.dumps({"webhook_token": TOKEN}),
    )

    with caplog.at_level("WARNING"):
        started = await start_connectors_from_db(db_session, MagicMock())

    assert started == {}
    assert "Skipped" not in caplog.text


# ── Overview source card ──────────────────────────────────────────────────────


def test_disabled_source_is_labelled_disabled_on_the_overview() -> None:
    row = Connector(id="c-1", name="n", connector_type="syslog", enabled=False, status="inactive",
                    events_total=0, errors_total=0)
    assert _connector_to_integration_status(row).metric == "Disabled"
