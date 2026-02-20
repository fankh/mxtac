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
