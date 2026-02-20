"""Tests for WS /api/v1/ws/alerts — Feature 17.1

Coverage:
  - Happy path: WebSocket connection, "connected" handshake schema
  - Filter protocol: client sends filter → server acks with echoed data
  - Non-filter message: connection stays alive, subsequent filter still acks
  - Disconnect: manager.disconnect called on clean close
  - DistributedConnectionManager: connect/disconnect lifecycle (unit)
  - DistributedConnectionManager: send_to delivers JSON text (unit)
  - DistributedConnectionManager: send_to prunes dead connection on error (unit)
  - DistributedConnectionManager: local fanout to all connections (unit)
  - DistributedConnectionManager: fanout with no connections completes silently (unit)
  - DistributedConnectionManager: dead connection pruning during fanout (unit)
  - DistributedConnectionManager: Valkey error → graceful local fanout fallback (unit)
  - broadcast_alert: wraps payload with type='alert' and publishes via manager (unit)
  - _ping_loop: sends ping message with type and ts fields (unit)
  - _ping_loop: stops cleanly when send_to raises (unit)
  - _mock_replay: streams one alert message per detection (unit)
  - _mock_replay: all streamed messages have type='alert' (unit)
  - _mock_replay: alert data includes required fields (unit)
  - _mock_replay: stops cleanly when send_to raises (unit)
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest
from starlette.testclient import TestClient

import app.api.v1.endpoints.websocket as ws_module
from app.api.v1.endpoints.websocket import (
    DistributedConnectionManager,
    broadcast_alert,
    manager,
)
from app.main import app
from app.services.mock_data import DETECTIONS

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WS_URL = "/api/v1/ws/alerts"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_manager():
    """Reset the module-level manager singleton before and after every test."""
    manager._started = False
    manager._connections.clear()
    manager._subscriber_task = None
    manager._pub_client = None
    manager._sub_client = None
    yield
    manager._connections.clear()


@pytest.fixture
def ws_mocks():
    """Patch slow / external dependencies so TestClient-based tests don't block
    or attempt real Valkey connections."""
    with (
        patch.object(manager, "_ensure_subscriber", new=AsyncMock()),
        patch("app.api.v1.endpoints.websocket._ping_loop", new=AsyncMock()),
        patch("app.api.v1.endpoints.websocket._mock_replay", new=AsyncMock()),
    ):
        yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ws() -> AsyncMock:
    """Return a minimal async mock that mimics a FastAPI WebSocket."""
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    return ws


# ---------------------------------------------------------------------------
# Section 1 — WebSocket integration tests (Starlette TestClient)
# ---------------------------------------------------------------------------


def test_ws_handshake_type_is_connected(ws_mocks):
    """First message after connect must have type='connected'."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            data = ws.receive_json()
    assert data["type"] == "connected"


def test_ws_handshake_has_message_field(ws_mocks):
    """'connected' handshake must include a non-empty human-readable 'message'."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            data = ws.receive_json()
    assert "message" in data
    assert isinstance(data["message"], str)
    assert data["message"]


def test_ws_handshake_has_ts_field(ws_mocks):
    """'connected' handshake must include a 'ts' timestamp field."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            data = ws.receive_json()
    assert "ts" in data


def test_ws_handshake_ts_is_iso_format(ws_mocks):
    """'ts' field in the handshake must be a valid ISO 8601 datetime string."""
    from datetime import datetime

    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            data = ws.receive_json()
    datetime.fromisoformat(data["ts"])  # raises ValueError if malformed


def test_ws_filter_receives_ack(ws_mocks):
    """Sending a filter message must produce an ack response."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()  # consume "connected"
            ws.send_json({"type": "filter", "data": {"severity": "critical"}})
            ack = ws.receive_json()
    assert ack is not None


def test_ws_filter_ack_type(ws_mocks):
    """Filter ack must have type='ack'."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter", "data": {"severity": "high"}})
            ack = ws.receive_json()
    assert ack["type"] == "ack"


def test_ws_filter_ack_echoes_filter_data(ws_mocks):
    """Filter ack must echo back the exact filter data sent by the client."""
    filter_payload = {"severity": "critical", "tactic": "Execution"}
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter", "data": filter_payload})
            ack = ws.receive_json()
    assert ack["filter"] == filter_payload


def test_ws_non_filter_message_connection_stays_alive(ws_mocks):
    """An unrecognised message type must be silently ignored; subsequent filter acks."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()  # connected
            ws.send_json({"type": "unknown_command", "data": {}})
            ws.send_json({"type": "filter", "data": {"host": "dc-01"}})
            ack = ws.receive_json()
    assert ack["type"] == "ack"


def test_ws_disconnect_calls_manager_disconnect(ws_mocks):
    """Clean WebSocket close must trigger manager.disconnect exactly once."""
    with patch.object(manager, "disconnect") as mock_disconnect:
        with TestClient(app) as client:
            with client.websocket_connect(WS_URL) as ws:
                ws.receive_json()
    mock_disconnect.assert_called_once()


# ---------------------------------------------------------------------------
# Section 2 — DistributedConnectionManager unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dcm_connect_accepts_websocket():
    """connect() must call ws.accept() to complete the HTTP upgrade."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws)
    ws.accept.assert_awaited_once()


@pytest.mark.asyncio
async def test_dcm_connect_adds_to_connections():
    """connect() must register the WebSocket in _connections."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws)
    assert ws in m._connections


@pytest.mark.asyncio
async def test_dcm_disconnect_removes_from_connections():
    """disconnect() must remove the WebSocket from _connections."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws)
    m.disconnect(ws)
    assert ws not in m._connections


@pytest.mark.asyncio
async def test_dcm_disconnect_unknown_ws_does_not_raise():
    """disconnect() with a WebSocket that was never connected must not raise."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    m.disconnect(ws)  # should be a silent no-op


@pytest.mark.asyncio
async def test_dcm_send_to_sends_json_text():
    """send_to() must serialise the message dict to JSON and call ws.send_text."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    msg = {"type": "ping", "ts": "2026-02-20T00:00:00+00:00"}
    await m.send_to(ws, msg)
    ws.send_text.assert_awaited_once_with(json.dumps(msg))


@pytest.mark.asyncio
async def test_dcm_send_to_on_error_disconnects_ws():
    """send_to() must remove the WebSocket when ws.send_text raises."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    ws.send_text.side_effect = RuntimeError("connection reset")
    m._connections.add(ws)
    await m.send_to(ws, {"type": "ping"})
    assert ws not in m._connections


@pytest.mark.asyncio
async def test_dcm_fanout_local_sends_to_all_connections():
    """_fanout_local() must deliver the payload string to every local connection."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws_a, ws_b = _make_ws(), _make_ws()
    m._connections.update({ws_a, ws_b})

    payload = json.dumps({"type": "alert", "data": {"id": "t-001"}})
    await m._fanout_local(payload)

    ws_a.send_text.assert_awaited_once_with(payload)
    ws_b.send_text.assert_awaited_once_with(payload)


@pytest.mark.asyncio
async def test_dcm_fanout_local_empty_connections_no_error():
    """_fanout_local() with no connections must complete without error."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    assert not m._connections
    await m._fanout_local(json.dumps({"type": "ping"}))  # must not raise


@pytest.mark.asyncio
async def test_dcm_fanout_local_removes_dead_connections():
    """_fanout_local() must prune connections that raise during send."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    alive = _make_ws()
    dead = _make_ws()
    dead.send_text.side_effect = RuntimeError("broken pipe")
    m._connections.update({alive, dead})

    await m._fanout_local(json.dumps({"type": "ping"}))

    assert dead not in m._connections
    assert alive in m._connections


@pytest.mark.asyncio
async def test_dcm_broadcast_fallback_on_valkey_publish_error():
    """broadcast() must fall back to local fanout when Valkey publish fails."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    m._connections.add(ws)

    mock_pub = AsyncMock()
    mock_pub.publish.side_effect = ConnectionError("valkey down")

    with patch.object(m, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await m.broadcast({"type": "alert", "data": {"id": "t-001"}})

    # Local fanout must deliver the message even when Valkey is unavailable
    ws.send_text.assert_awaited_once()
    sent = json.loads(ws.send_text.call_args[0][0])
    assert sent["type"] == "alert"


# ---------------------------------------------------------------------------
# Section 3 — broadcast_alert unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_alert_type_is_alert():
    """broadcast_alert() must wrap the payload under type='alert'."""
    with patch.object(manager, "broadcast", new=AsyncMock()) as mock_bcast:
        await broadcast_alert({"id": "test-001"})
    assert mock_bcast.call_args[0][0]["type"] == "alert"


@pytest.mark.asyncio
async def test_broadcast_alert_data_passed_through():
    """broadcast_alert() must forward the original dict unchanged as 'data'."""
    alert = {"id": "test-002", "severity": "critical", "host": "srv-01"}
    with patch.object(manager, "broadcast", new=AsyncMock()) as mock_bcast:
        await broadcast_alert(alert)
    assert mock_bcast.call_args[0][0]["data"] == alert


# ---------------------------------------------------------------------------
# Section 4 — _ping_loop unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ping_loop_sends_ping_type():
    """_ping_loop() must send a message with type='ping'."""
    ws = _make_ws()
    captured: list[dict] = []

    async def capture_and_stop(w, msg):
        captured.append(msg)
        raise RuntimeError("stop")  # exit the while-loop via except Exception: break

    with (
        patch("asyncio.sleep", new=AsyncMock()),
        patch.object(manager, "send_to", side_effect=capture_and_stop),
    ):
        await ws_module._ping_loop(ws)

    assert captured[0]["type"] == "ping"


@pytest.mark.asyncio
async def test_ping_loop_sends_ts_field():
    """_ping_loop() message must include a valid ISO 8601 'ts' field."""
    from datetime import datetime

    ws = _make_ws()
    captured: list[dict] = []

    async def capture_and_stop(w, msg):
        captured.append(msg)
        raise RuntimeError("stop")

    with (
        patch("asyncio.sleep", new=AsyncMock()),
        patch.object(manager, "send_to", side_effect=capture_and_stop),
    ):
        await ws_module._ping_loop(ws)

    assert "ts" in captured[0]
    datetime.fromisoformat(captured[0]["ts"])  # raises ValueError if malformed


@pytest.mark.asyncio
async def test_ping_loop_stops_on_send_error():
    """_ping_loop() must exit the loop when send_to raises."""
    ws = _make_ws()
    call_count = 0

    async def fail_once(w, msg):
        nonlocal call_count
        call_count += 1
        raise RuntimeError("connection reset")

    with (
        patch("asyncio.sleep", new=AsyncMock()),
        patch.object(manager, "send_to", side_effect=fail_once),
    ):
        await ws_module._ping_loop(ws)

    assert call_count == 1  # loop must stop after the first failure


# ---------------------------------------------------------------------------
# Section 5 — _mock_replay unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mock_replay_sends_one_message_per_detection():
    """_mock_replay() must send exactly one alert for each entry in DETECTIONS."""
    ws = _make_ws()
    sent: list[dict] = []

    async def capture(w, msg):
        sent.append(msg)

    with (
        patch("asyncio.sleep", new=AsyncMock()),
        patch.object(manager, "send_to", side_effect=capture),
    ):
        await ws_module._mock_replay(ws)

    assert len(sent) == len(DETECTIONS)


@pytest.mark.asyncio
async def test_mock_replay_all_messages_are_alert_type():
    """Every message emitted by _mock_replay() must have type='alert'."""
    ws = _make_ws()
    sent: list[dict] = []

    async def capture(w, msg):
        sent.append(msg)

    with (
        patch("asyncio.sleep", new=AsyncMock()),
        patch.object(manager, "send_to", side_effect=capture),
    ):
        await ws_module._mock_replay(ws)

    assert all(m["type"] == "alert" for m in sent)


@pytest.mark.asyncio
async def test_mock_replay_alert_message_has_required_fields():
    """Each alert data dict must contain the fields consumed by the frontend."""
    ws = _make_ws()
    first: dict | None = None

    async def capture_first(w, msg):
        nonlocal first
        if first is None:
            first = msg

    with (
        patch("asyncio.sleep", new=AsyncMock()),
        patch.object(manager, "send_to", side_effect=capture_first),
    ):
        await ws_module._mock_replay(ws)

    assert first is not None
    required = {"id", "score", "severity", "technique_id", "name", "host", "status", "time"}
    assert required <= set(first["data"])


@pytest.mark.asyncio
async def test_mock_replay_stops_on_send_error():
    """_mock_replay() must exit after the first send_to failure."""
    ws = _make_ws()
    call_count = 0

    async def fail_once(w, msg):
        nonlocal call_count
        call_count += 1
        raise RuntimeError("broken pipe")

    with (
        patch("asyncio.sleep", new=AsyncMock()),
        patch.object(manager, "send_to", side_effect=fail_once),
    ):
        await ws_module._mock_replay(ws)

    assert call_count == 1  # loop must stop after the first failure


# ---------------------------------------------------------------------------
# Section 6 — _get_pub_client unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dcm_get_pub_client_creates_lazily():
    """_get_pub_client() must create the Valkey client on the first call."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    mock_client = AsyncMock()
    with patch.object(ws_module, "aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client
        client = await m._get_pub_client()
    mock_aioredis.from_url.assert_called_once()
    assert client is mock_client
    assert m._pub_client is mock_client


@pytest.mark.asyncio
async def test_dcm_get_pub_client_caches_client():
    """_get_pub_client() must return the same client instance on subsequent calls."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    mock_client = AsyncMock()
    with patch.object(ws_module, "aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client
        client1 = await m._get_pub_client()
        client2 = await m._get_pub_client()
    mock_aioredis.from_url.assert_called_once()  # created only once
    assert client1 is client2


@pytest.mark.asyncio
async def test_dcm_get_pub_client_uses_valkey_url():
    """_get_pub_client() must pass the configured Valkey URL to from_url."""
    url = "redis://custom-host:6380/1"
    m = DistributedConnectionManager(url)
    mock_client = AsyncMock()
    with patch.object(ws_module, "aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client
        await m._get_pub_client()
    mock_aioredis.from_url.assert_called_once_with(url, decode_responses=True)


# ---------------------------------------------------------------------------
# Section 7 — shutdown unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dcm_shutdown_no_op_when_nothing_started():
    """shutdown() with no task and no pub client must complete without error."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    await m.shutdown()  # must not raise


@pytest.mark.asyncio
async def test_dcm_shutdown_resets_started_flag():
    """shutdown() must set _started to False."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    m._started = True
    await m.shutdown()
    assert m._started is False


@pytest.mark.asyncio
async def test_dcm_shutdown_closes_pub_client():
    """shutdown() must call aclose() on an existing pub client and clear the reference."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    mock_client = AsyncMock()
    m._pub_client = mock_client
    await m.shutdown()
    mock_client.aclose.assert_awaited_once()
    assert m._pub_client is None


@pytest.mark.asyncio
async def test_dcm_shutdown_cancels_running_task():
    """shutdown() must cancel a live asyncio.Task and wait for it to finish."""
    m = DistributedConnectionManager("redis://localhost:6379/0")

    async def hang_forever():
        await asyncio.sleep(3600)

    task = asyncio.create_task(hang_forever())
    m._subscriber_task = task
    m._started = True

    await m.shutdown()

    assert task.cancelled()
    assert m._started is False


# ---------------------------------------------------------------------------
# Section 8 — _ensure_subscriber unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dcm_ensure_subscriber_sets_started_and_creates_task():
    """_ensure_subscriber() must set _started=True and assign _subscriber_task."""
    m = DistributedConnectionManager("redis://localhost:6379/0")

    async def fast_noop():
        pass  # completes immediately — no real Valkey calls

    with patch.object(m, "_subscriber_loop", return_value=fast_noop()):
        await m._ensure_subscriber()

    assert m._started is True
    assert m._subscriber_task is not None


@pytest.mark.asyncio
async def test_dcm_ensure_subscriber_idempotent_when_started():
    """_ensure_subscriber() with _started=True must return without creating a task."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    m._started = True  # pre-set to simulate already-running state

    with patch("asyncio.create_task") as mock_create:
        await m._ensure_subscriber()

    mock_create.assert_not_called()


# ---------------------------------------------------------------------------
# Section 9 — broadcast happy-path unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dcm_broadcast_publishes_to_correct_channel():
    """broadcast() must publish to the 'mxtac:alerts' channel when Valkey is healthy."""
    from app.api.v1.endpoints.websocket import _CHANNEL

    m = DistributedConnectionManager("redis://localhost:6379/0")
    mock_pub = AsyncMock()
    with patch.object(m, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await m.broadcast({"type": "alert", "data": {"id": "t-001"}})

    mock_pub.publish.assert_awaited_once()
    assert mock_pub.publish.call_args[0][0] == _CHANNEL


@pytest.mark.asyncio
async def test_dcm_broadcast_sends_json_encoded_payload():
    """broadcast() must JSON-encode the message dict before publishing."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    mock_pub = AsyncMock()
    msg = {"type": "alert", "data": {"id": "t-002", "severity": "high"}}

    with patch.object(m, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await m.broadcast(msg)

    raw_payload = mock_pub.publish.call_args[0][1]
    assert json.loads(raw_payload) == msg


@pytest.mark.asyncio
async def test_dcm_broadcast_success_does_not_call_local_fanout():
    """broadcast() must not invoke _fanout_local directly on a successful publish."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    m._connections.add(ws)
    mock_pub = AsyncMock()

    with patch.object(m, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await m.broadcast({"type": "alert", "data": {"id": "t-003"}})

    # Local fanout goes through Valkey subscriber, not directly — ws must not be called
    ws.send_text.assert_not_awaited()


# ---------------------------------------------------------------------------
# Section 10 — _subscriber_loop unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dcm_subscriber_loop_exits_cleanly_on_cancelled_error():
    """_subscriber_loop() must break out of the retry loop on CancelledError."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    mock_client = AsyncMock()
    mock_pubsub = AsyncMock()
    mock_client.pubsub.return_value = mock_pubsub
    mock_pubsub.subscribe.side_effect = asyncio.CancelledError()

    with patch.object(ws_module, "aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()  # must return, not re-raise

    # finally block must close the sub_client even on CancelledError
    mock_client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_dcm_subscriber_loop_retries_after_connection_error():
    """_subscriber_loop() must retry after a transient error, then stop on CancelledError."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    call_count = 0

    async def mock_subscribe(_channel):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("Valkey unavailable")
        raise asyncio.CancelledError()

    mock_client = AsyncMock()
    mock_pubsub = AsyncMock()
    mock_client.pubsub.return_value = mock_pubsub
    mock_pubsub.subscribe = mock_subscribe

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    assert call_count == 2  # failed once, then exited on CancelledError


@pytest.mark.asyncio
async def test_dcm_subscriber_loop_closes_sub_client_in_finally():
    """_subscriber_loop() must call aclose() on the sub_client after every iteration."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    call_count = 0

    async def mock_subscribe(_channel):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("first failure")
        raise asyncio.CancelledError()

    mock_client = AsyncMock()
    mock_pubsub = AsyncMock()
    mock_client.pubsub.return_value = mock_pubsub
    mock_pubsub.subscribe = mock_subscribe

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    # Two iterations → aclose() called twice
    assert mock_client.aclose.await_count == 2


@pytest.mark.asyncio
async def test_dcm_subscriber_loop_fanouts_messages_to_local_connections():
    """_subscriber_loop() must call _fanout_local() for 'message' type events only."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    alert_payload = json.dumps({"type": "alert", "data": {"id": "t-fan"}})

    async def fake_listen():
        yield {"type": "subscribe", "data": None}   # ignored — not 'message'
        yield {"type": "message", "data": alert_payload}
        raise asyncio.CancelledError()

    mock_client = AsyncMock()
    mock_pubsub = AsyncMock()
    mock_client.pubsub.return_value = mock_pubsub
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.listen = fake_listen

    fanout_calls: list[str] = []

    async def capture_fanout(payload: str) -> None:
        fanout_calls.append(payload)

    with patch.object(ws_module, "aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client
        with patch.object(m, "_fanout_local", side_effect=capture_fanout):
            await m._subscriber_loop()

    assert len(fanout_calls) == 1
    assert json.loads(fanout_calls[0])["type"] == "alert"


# ---------------------------------------------------------------------------
# Section 11 — Integration edge cases
# ---------------------------------------------------------------------------


def test_ws_malformed_json_handled_gracefully(ws_mocks):
    """Malformed JSON from the client must be handled; manager.disconnect still called."""
    with patch.object(manager, "disconnect") as mock_disconnect:
        with TestClient(app) as client:
            with client.websocket_connect(WS_URL) as ws:
                ws.receive_json()  # consume "connected"
                ws.send_text("{bad json {{{{")  # malformed — json.loads raises
    mock_disconnect.assert_called_once()


def test_ws_multiple_filter_messages_each_get_acked(ws_mocks):
    """Each filter message sent in sequence must receive its own independent ack."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()  # connected
            ws.send_json({"type": "filter", "data": {"severity": "high"}})
            ack1 = ws.receive_json()
            ws.send_json({"type": "filter", "data": {"tactic": "Discovery"}})
            ack2 = ws.receive_json()
    assert ack1["type"] == "ack"
    assert ack1["filter"] == {"severity": "high"}
    assert ack2["type"] == "ack"
    assert ack2["filter"] == {"tactic": "Discovery"}


def test_ws_filter_with_no_data_key_acks_none(ws_mocks):
    """A filter message missing the 'data' key must ack with filter=None."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter"})  # no 'data' key
            ack = ws.receive_json()
    assert ack["type"] == "ack"
    assert ack["filter"] is None
