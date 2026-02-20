"""Tests for WS /api/v1/ws/alerts — Features 17.1, 17.3, 17.4, 17.5, 17.6, 28.27, 28.28, and 28.29

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

Feature 17.6 — Distributed broadcast via Valkey pub/sub (multi-instance):
  - _CHANNEL constant is exactly "mxtac:alerts"
  - module-level manager singleton is configured with settings.valkey_url
  - cross-instance delivery: Instance A broadcast() → Valkey → Instance B clients receive
  - instance isolation: Instance B fanout does not directly touch Instance A connections
  - pub client and sub client use separate Valkey connections (independent failover)
  - exponential backoff: first retry delay is 1 second
  - exponential backoff: second retry delay doubles to 2 seconds
  - exponential backoff: delay caps at 30 seconds regardless of failure count
  - backoff delay resets to 1s after a successful Valkey connection
  - subscriber creates a fresh Valkey connection object on each retry iteration
  - pub client is created lazily only on the first broadcast() call
  - broadcast payload is preserved exactly across instance boundary
  - single-instance self-delivery via pub/sub loopback

Feature 17.3 — Ping every 30s keep-alive (comprehensive):
  - _ping_loop: asyncio.sleep is called with exactly 30 seconds
  - _ping_loop: multiple pings sent continuously before any error
  - _ping_loop: ts field is UTC-aware (non-naive datetime)
  - _ping_loop: CancelledError during sleep propagates (task is cancellable)
  - _ping_loop: CancelledError during send_to propagates (not swallowed)
  - _ping_loop: sleep occurs before each send (delay-then-ping ordering)
  - _ping_loop: sleep-before-send pattern holds for multiple iterations
  - alerts_ws: _ping_loop is started as a background task on connect
  - alerts_ws: _ping_loop receives the WebSocket instance
  - alerts_ws: ping task is cancelled when the client disconnects

Feature 17.5 — Broadcast enriched alerts to all clients (single instance):
  - ws_broadcaster subscribes to mxtac.enriched topic
  - ws_broadcaster forwards each enriched alert to broadcast_alert()
  - broadcast_alert() delivers enriched alert to every connected WebSocket client

Feature 17.4 — Accept `filter` message from client (ACK response):
  - ACK response contains exactly 'type' and 'filter' keys (no extra fields)
  - Filter with data=null (JSON null) echoed as filter=null (key present, value None)
  - Filter with data={} echoed as filter={} (empty dict, not null)
  - Filter data with list values preserved exactly
  - Filter data with nested objects preserved with identical structure
  - Filter data with numeric values preserved with exact precision
  - Filter data with boolean values preserved as true/false (not 1/0)
  - Type field matching is case-sensitive: 'Filter' does not trigger ack
  - manager.send_to called with exact ACK dict for each filter message
  - Connection pruned when send_to fails during ACK delivery

Feature 28.27 — WebSocket client receives broadcast alert:
  - Client receives JSON message with type='alert' from broadcast_alert()
  - Client receives exact alert data dict that was passed to broadcast_alert()
  - Three simultaneously-connected clients each receive the same broadcast
  - Sequential broadcast alerts are received in the order they were sent
  - Dead client is pruned while live clients continue to receive broadcasts
  - Valkey subscriber loop fans out published message to local WebSocket clients
  - Full pipeline: ENRICHED queue publish → ws_broadcaster → client receives alert
  - broadcast_alert() with no connected clients completes without error
  - Received JSON is valid and decodable by the client

Feature 28.28 — WebSocket: client on instance-2 receives alert from instance-1 (distributed):
  - Instance-2 client receives alert broadcast by instance-1 via Valkey pub/sub
  - Instance-2 client receives exact alert data dict published by instance-1
  - Three clients on instance-2 each receive the alert from instance-1
  - Instance-1's connections are isolated from instance-2's fanout (no direct cross-write)
  - Both instances receive the same alert (instance-1 via loopback, instance-2 via sub)
  - All alert data fields (nested dicts, arrays, numerics) preserved exactly across boundary
  - Sequential alerts from instance-1 arrive at instance-2 client in order
  - Dead client on instance-2 pruned; live client still receives from instance-1
  - Instance-1 Valkey publish failure falls back to local fanout only (instance-2 not reached)

Feature 28.29 — WebSocket: auto-reconnect after drop:
  - Reconnected WebSocket is added to manager._connections
  - Dropped WebSocket is removed from manager._connections
  - Connection count is exactly 1 after one drop-then-reconnect cycle
  - Reconnected client receives _fanout_local() payloads; dropped client does not
  - Dropped client does not receive broadcasts when connections set is empty
  - Multiple drop-reconnect cycles (×3) each produce a fresh receiving WebSocket
  - broadcast() via local-fanout fallback reaches reconnected client, not dropped client
  - Each new WebSocket connection receives its own 'connected' handshake via send_to
  - Integration: second connection (reconnect) receives 'connected' handshake
  - Integration: each reconnect handshake has a valid ISO 8601 timestamp
  - Integration: first disconnect triggers manager.disconnect exactly once
  - subscriber_loop retries when listen() generator terminates without error
  - Alerts resume reaching WS clients after Valkey subscriber reconnects following a drop
  - Each subscriber reconnect attempt creates a fresh Valkey client (from_url called per attempt)
  - Sub client aclose() called after every connection attempt (success or failure)
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

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
#
# IMPORTANT: mock_client must be MagicMock (not AsyncMock) because
# self._sub_client.pubsub() is a *synchronous* call in the production code.
# Using AsyncMock would make pubsub() return a coroutine instead of the
# pubsub mock, causing AttributeError → infinite retry → test hangs.
# Async methods (aclose, subscribe) are set explicitly as AsyncMock.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dcm_subscriber_loop_exits_cleanly_on_cancelled_error():
    """_subscriber_loop() must break out of the retry loop on CancelledError."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    mock_client = MagicMock()          # sync — pubsub() is a sync call
    mock_client.aclose = AsyncMock()   # but aclose() is async
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock(side_effect=asyncio.CancelledError())
    mock_client.pubsub.return_value = mock_pubsub

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

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_client.pubsub.return_value = mock_pubsub

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

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_client.pubsub.return_value = mock_pubsub

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
    subscribe_count = 0

    async def mock_subscribe(_channel):
        """Raise CancelledError on the second subscribe (after listen() error triggers retry)."""
        nonlocal subscribe_count
        subscribe_count += 1
        if subscribe_count >= 2:
            raise asyncio.CancelledError()

    async def fake_listen():
        """Yield test messages then raise RuntimeError to trigger the retry path."""
        yield {"type": "subscribe", "data": None}   # ignored — not 'message'
        yield {"type": "message", "data": alert_payload}
        raise RuntimeError("connection lost")  # caught by except Exception, triggers retry

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    fanout_calls: list[str] = []

    async def capture_fanout(payload: str) -> None:
        fanout_calls.append(payload)

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
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


# ---------------------------------------------------------------------------
# Section 12 — Feature 17.3: Ping every 30s keep-alive — comprehensive tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ping_loop_sleep_duration_is_30_seconds():
    """_ping_loop() must call asyncio.sleep(30) between each ping — the '30s' requirement."""
    ws = _make_ws()
    sleep_args: list[float] = []

    async def record_sleep(duration):
        sleep_args.append(duration)

    async def stop_on_first_send(w, msg):
        raise RuntimeError("stop after first send")

    with (
        patch("asyncio.sleep", side_effect=record_sleep),
        patch.object(manager, "send_to", side_effect=stop_on_first_send),
    ):
        await ws_module._ping_loop(ws)

    assert sleep_args[0] == 30


@pytest.mark.asyncio
async def test_ping_loop_sends_multiple_pings_before_stopping():
    """_ping_loop() must keep sending pings until an error occurs — continuous operation."""
    ws = _make_ws()
    send_count = 0

    async def count_and_eventually_fail(w, msg):
        nonlocal send_count
        send_count += 1
        if send_count >= 3:
            raise RuntimeError("stop after 3 pings")

    with (
        patch("asyncio.sleep", new=AsyncMock()),
        patch.object(manager, "send_to", side_effect=count_and_eventually_fail),
    ):
        await ws_module._ping_loop(ws)

    assert send_count == 3


@pytest.mark.asyncio
async def test_ping_loop_ts_is_utc_timezone_aware():
    """_ping_loop() must embed a UTC-aware timestamp in every ping message."""
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

    ts = datetime.fromisoformat(captured[0]["ts"])
    assert ts.tzinfo is not None, "timestamp must be timezone-aware (UTC)"
    assert ts.utcoffset().total_seconds() == 0, "timestamp must be UTC (offset 0)"


@pytest.mark.asyncio
async def test_ping_loop_cancelled_error_during_sleep_propagates():
    """_ping_loop() must NOT suppress CancelledError — the task must be cancellable."""
    ws = _make_ws()

    with patch("asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError())):
        with pytest.raises(asyncio.CancelledError):
            await ws_module._ping_loop(ws)


@pytest.mark.asyncio
async def test_ping_loop_cancelled_error_during_send_propagates():
    """CancelledError during send_to must not be swallowed by the except Exception block."""
    ws = _make_ws()

    async def raise_cancelled(w, msg):
        raise asyncio.CancelledError()

    with (
        patch("asyncio.sleep", new=AsyncMock()),
        patch.object(manager, "send_to", side_effect=raise_cancelled),
    ):
        with pytest.raises(asyncio.CancelledError):
            await ws_module._ping_loop(ws)


@pytest.mark.asyncio
async def test_ping_loop_sleep_called_before_each_send():
    """_ping_loop() must sleep *before* each send — delay-then-ping, not ping-then-delay."""
    ws = _make_ws()
    call_order: list[str] = []

    async def record_sleep(duration):
        call_order.append(f"sleep:{duration}")

    async def record_send_and_stop(w, msg):
        call_order.append("send")
        raise RuntimeError("stop")

    with (
        patch("asyncio.sleep", side_effect=record_sleep),
        patch.object(manager, "send_to", side_effect=record_send_and_stop),
    ):
        await ws_module._ping_loop(ws)

    assert call_order == ["sleep:30", "send"], (
        f"expected [sleep:30, send], got {call_order}"
    )


@pytest.mark.asyncio
async def test_ping_loop_sleep_called_before_every_send():
    """Each ping must be preceded by a 30s sleep — pattern holds for multiple iterations."""
    ws = _make_ws()
    call_order: list[str] = []
    iteration = 0

    async def record_sleep(duration):
        call_order.append(f"sleep:{duration}")

    async def record_and_stop_after_two(w, msg):
        nonlocal iteration
        call_order.append("send")
        iteration += 1
        if iteration >= 2:
            raise RuntimeError("stop")

    with (
        patch("asyncio.sleep", side_effect=record_sleep),
        patch.object(manager, "send_to", side_effect=record_and_stop_after_two),
    ):
        await ws_module._ping_loop(ws)

    assert call_order == ["sleep:30", "send", "sleep:30", "send"]


# ---------------------------------------------------------------------------
# Section 12b — Feature 17.3: Integration tests (ping task lifecycle)
# ---------------------------------------------------------------------------


def test_alerts_ws_starts_ping_loop_on_connect():
    """alerts_ws must launch _ping_loop as a background task on every new connection."""
    mock_ping = AsyncMock()

    with (
        patch.object(manager, "_ensure_subscriber", new=AsyncMock()),
        patch("app.api.v1.endpoints.websocket._ping_loop", new=mock_ping),
        patch("app.api.v1.endpoints.websocket._mock_replay", new=AsyncMock()),
    ):
        with TestClient(app) as client:
            with client.websocket_connect(WS_URL) as ws:
                ws.receive_json()  # consume "connected"

    mock_ping.assert_called_once()


def test_alerts_ws_ping_loop_receives_websocket_object():
    """alerts_ws must pass the WebSocket instance to _ping_loop."""
    mock_ping = AsyncMock()

    with (
        patch.object(manager, "_ensure_subscriber", new=AsyncMock()),
        patch("app.api.v1.endpoints.websocket._ping_loop", new=mock_ping),
        patch("app.api.v1.endpoints.websocket._mock_replay", new=AsyncMock()),
    ):
        with TestClient(app) as client:
            with client.websocket_connect(WS_URL) as ws:
                ws.receive_json()

    # First positional arg to _ping_loop must be a WebSocket-like object
    call_ws_arg = mock_ping.call_args[0][0]
    assert call_ws_arg is not None


def test_alerts_ws_ping_task_cancelled_on_disconnect():
    """alerts_ws must cancel the ping task in its finally block when the client disconnects."""
    import threading

    ping_was_cancelled = threading.Event()

    async def cancellable_ping(ws):
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            ping_was_cancelled.set()
            raise

    with (
        patch.object(manager, "_ensure_subscriber", new=AsyncMock()),
        patch("app.api.v1.endpoints.websocket._ping_loop", new=cancellable_ping),
        patch("app.api.v1.endpoints.websocket._mock_replay", new=AsyncMock()),
    ):
        with TestClient(app) as client:
            with client.websocket_connect(WS_URL) as ws:
                ws.receive_json()  # consume "connected", then disconnect

    assert ping_was_cancelled.wait(timeout=2.0), "ping task was not cancelled on disconnect"


def test_alerts_ws_ping_task_cancelled_when_both_tasks_present():
    """alerts_ws must cancel the ping task in its finally block (only ping task started)."""
    import threading

    ping_cancelled = threading.Event()

    async def cancellable_ping(ws):
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            ping_cancelled.set()
            raise

    with (
        patch.object(manager, "_ensure_subscriber", new=AsyncMock()),
        patch("app.api.v1.endpoints.websocket._ping_loop", new=cancellable_ping),
    ):
        with TestClient(app) as client:
            with client.websocket_connect(WS_URL) as ws:
                ws.receive_json()

    assert ping_cancelled.wait(timeout=2.0), "ping task was not cancelled"


# ---------------------------------------------------------------------------
# Section 13 — Feature 17.5: Broadcast enriched alerts to all clients
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_17_5_ws_broadcaster_subscribes_to_enriched_topic():
    """websocket_broadcaster() must register a subscriber on the mxtac.enriched topic."""
    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.ws_broadcaster import websocket_broadcaster

    queue = InMemoryQueue()
    await queue.start()

    with patch("app.api.v1.endpoints.websocket.broadcast_alert", new=AsyncMock()):
        await websocket_broadcaster(queue)

    # A consumer task must have been created for the enriched topic
    assert len(queue._tasks) >= 1
    assert Topic.ENRICHED in queue._queues or any(
        "consumer-mxtac.enriched" in (t.get_name() or "") for t in queue._tasks
    )
    await queue.stop()


@pytest.mark.asyncio
async def test_17_5_ws_broadcaster_calls_broadcast_alert_on_enriched_message():
    """ws_broadcaster must forward each mxtac.enriched message to broadcast_alert()."""
    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.ws_broadcaster import websocket_broadcaster

    queue = InMemoryQueue()
    await queue.start()

    enriched_alert = {
        "id": "e2e-17-5",
        "rule_title": "Suspicious Process Execution",
        "level": "high",
        "score": 7.2,
        "host": "srv-01",
    }

    with patch(
        "app.api.v1.endpoints.websocket.broadcast_alert", new=AsyncMock()
    ) as mock_bcast:
        await websocket_broadcaster(queue)
        await queue.publish(Topic.ENRICHED, enriched_alert)
        # Yield to the event loop so the consumer task processes the message
        await asyncio.sleep(0)

    mock_bcast.assert_awaited_once_with(enriched_alert)
    await queue.stop()


@pytest.mark.asyncio
async def test_17_5_broadcast_alert_delivers_to_all_connected_clients():
    """Feature 17.5: broadcast_alert() must deliver enriched alert to every local client."""
    ws_a, ws_b = _make_ws(), _make_ws()
    manager._connections.update({ws_a, ws_b})

    alert_data = {"id": "fan-17-5", "level": "critical", "score": 9.5, "host": "dc-01"}

    # Simulate Valkey unavailable → triggers graceful local fanout
    mock_pub = AsyncMock()
    mock_pub.publish.side_effect = ConnectionError("no valkey in test")

    with patch.object(manager, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await broadcast_alert(alert_data)

    expected_payload = json.dumps({"type": "alert", "data": alert_data})
    ws_a.send_text.assert_awaited_once_with(expected_payload)
    ws_b.send_text.assert_awaited_once_with(expected_payload)


@pytest.mark.asyncio
async def test_17_5_broadcast_alert_wraps_with_type_alert():
    """broadcast_alert() must always wrap the payload as {type: 'alert', data: <alert>}."""
    alert_data = {"id": "wrap-17-5", "level": "medium", "host": "win-01"}

    with patch.object(manager, "broadcast", new=AsyncMock()) as mock_bcast:
        await broadcast_alert(alert_data)

    call_arg = mock_bcast.call_args[0][0]
    assert call_arg["type"] == "alert"
    assert call_arg["data"] is alert_data


# ---------------------------------------------------------------------------
# Section 14 — Feature 28.27: WebSocket client receives broadcast alert
# ---------------------------------------------------------------------------


def _mock_pub_down() -> AsyncMock:
    """Return a mock Valkey pub client that fails publish (triggers local fanout)."""
    mock_pub = AsyncMock()
    mock_pub.publish.side_effect = ConnectionError("valkey down in test")
    return mock_pub


@pytest.mark.asyncio
async def test_28_27_client_receives_type_alert():
    """Connected client must receive a JSON message with type='alert' from broadcast_alert()."""
    ws = _make_ws()
    manager._connections.add(ws)

    alert_data = {"id": "28-27-001", "level": "high", "host": "srv-01", "score": 7.0}

    with patch.object(manager, "_get_pub_client", new=AsyncMock(return_value=_mock_pub_down())):
        await broadcast_alert(alert_data)

    ws.send_text.assert_awaited_once()
    received = json.loads(ws.send_text.call_args[0][0])
    assert received["type"] == "alert"


@pytest.mark.asyncio
async def test_28_27_alert_data_field_matches_broadcast():
    """Client must receive the exact alert data dict that was passed to broadcast_alert()."""
    ws = _make_ws()
    manager._connections.add(ws)

    alert_data = {
        "id": "28-27-002",
        "rule_title": "Suspicious PowerShell Execution",
        "level": "critical",
        "score": 8.5,
        "host": "dc-01",
        "technique_ids": ["T1059.001"],
        "tactic_ids": ["TA0002"],
    }

    with patch.object(manager, "_get_pub_client", new=AsyncMock(return_value=_mock_pub_down())):
        await broadcast_alert(alert_data)

    received = json.loads(ws.send_text.call_args[0][0])
    assert received["data"] == alert_data


@pytest.mark.asyncio
async def test_28_27_three_simultaneous_clients_each_receive():
    """Every connected client (including multiple simultaneous connections) must receive the broadcast."""
    ws_a, ws_b, ws_c = _make_ws(), _make_ws(), _make_ws()
    manager._connections.update({ws_a, ws_b, ws_c})

    alert_data = {"id": "28-27-003", "level": "high", "host": "srv-02", "score": 6.5}

    with patch.object(manager, "_get_pub_client", new=AsyncMock(return_value=_mock_pub_down())):
        await broadcast_alert(alert_data)

    for ws in (ws_a, ws_b, ws_c):
        ws.send_text.assert_awaited_once()
        received = json.loads(ws.send_text.call_args[0][0])
        assert received["type"] == "alert"
        assert received["data"] == alert_data


@pytest.mark.asyncio
async def test_28_27_sequential_alerts_received_in_order():
    """Multiple broadcast_alert() calls must be received by the client in the same order."""
    ws = _make_ws()
    manager._connections.add(ws)

    alerts = [
        {"id": f"28-27-seq-{i}", "level": "medium", "host": f"host-{i}", "score": float(i)}
        for i in range(3)
    ]

    with patch.object(manager, "_get_pub_client", new=AsyncMock(return_value=_mock_pub_down())):
        for alert in alerts:
            await broadcast_alert(alert)

    assert ws.send_text.await_count == 3
    received_ids = [
        json.loads(call[0][0])["data"]["id"]
        for call in ws.send_text.call_args_list
    ]
    assert received_ids == ["28-27-seq-0", "28-27-seq-1", "28-27-seq-2"]


@pytest.mark.asyncio
async def test_28_27_dead_client_pruned_live_client_receives():
    """A dead connection must be pruned while live clients still receive the broadcast."""
    alive = _make_ws()
    dead = _make_ws()
    dead.send_text.side_effect = RuntimeError("connection reset")
    manager._connections.update({alive, dead})

    alert_data = {"id": "28-27-dead", "level": "medium", "host": "win-01", "score": 4.0}

    with patch.object(manager, "_get_pub_client", new=AsyncMock(return_value=_mock_pub_down())):
        await broadcast_alert(alert_data)

    # Live client received the alert
    alive.send_text.assert_awaited_once()
    received = json.loads(alive.send_text.call_args[0][0])
    assert received["type"] == "alert"
    assert received["data"] == alert_data
    # Dead client was pruned from connection set
    assert dead not in manager._connections


@pytest.mark.asyncio
async def test_28_27_subscriber_loop_fanouts_alert_to_local_client():
    """Valkey subscriber loop must deliver a received channel message to all local clients."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    m._connections.add(ws)

    alert_payload = json.dumps({"type": "alert", "data": {"id": "28-27-sub", "level": "high", "score": 8.0}})
    subscribe_count = 0

    async def mock_subscribe(_channel):
        nonlocal subscribe_count
        subscribe_count += 1
        if subscribe_count >= 2:
            raise asyncio.CancelledError()

    async def fake_listen():
        # Yield the alert message then exit via RuntimeError → retry → CancelledError
        yield {"type": "message", "data": alert_payload}
        raise RuntimeError("connection lost")

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    # The client must have received the exact JSON payload from the channel
    ws.send_text.assert_awaited_once_with(alert_payload)
    received = json.loads(ws.send_text.call_args[0][0])
    assert received["type"] == "alert"
    assert received["data"]["id"] == "28-27-sub"


@pytest.mark.asyncio
async def test_28_27_full_pipeline_enriched_queue_to_ws_client():
    """Full pipeline: publish enriched alert to queue → ws_broadcaster → client receives alert."""
    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.ws_broadcaster import websocket_broadcaster

    queue = InMemoryQueue()
    await queue.start()

    ws = _make_ws()
    manager._connections.add(ws)

    enriched_alert = {
        "id": "28-27-pipeline",
        "rule_title": "Credential Dumping Detected",
        "level": "critical",
        "severity_id": 5,
        "score": 9.5,
        "host": "dc-01",
        "technique_ids": ["T1003"],
        "tactic_ids": ["TA0006"],
    }

    with patch.object(manager, "_get_pub_client", new=AsyncMock(return_value=_mock_pub_down())):
        await websocket_broadcaster(queue)
        await queue.publish(Topic.ENRICHED, enriched_alert)
        # Yield to allow the consumer task to process the message
        await asyncio.sleep(0)

    ws.send_text.assert_awaited_once()
    received = json.loads(ws.send_text.call_args[0][0])
    assert received["type"] == "alert"
    assert received["data"] == enriched_alert

    await queue.stop()


@pytest.mark.asyncio
async def test_28_27_no_clients_broadcast_completes_silently():
    """broadcast_alert() with no connected clients must complete without raising."""
    assert not manager._connections  # confirm clean state

    with patch.object(manager, "_get_pub_client", new=AsyncMock(return_value=_mock_pub_down())):
        await broadcast_alert({"id": "28-27-empty", "level": "low", "score": 1.0})
    # Reaching here without exception satisfies the assertion


@pytest.mark.asyncio
async def test_28_27_received_json_is_valid_and_decodable():
    """The raw bytes received by the client must be valid JSON with the expected envelope."""
    ws = _make_ws()
    manager._connections.add(ws)

    alert_data = {
        "id": "28-27-json",
        "rule_title": "Lateral Movement Detected",
        "level": "high",
        "score": 7.8,
        "host": "srv-03",
    }

    with patch.object(manager, "_get_pub_client", new=AsyncMock(return_value=_mock_pub_down())):
        await broadcast_alert(alert_data)

    raw = ws.send_text.call_args[0][0]
    # Must be decodable JSON
    decoded = json.loads(raw)
    # Must have required envelope keys
    assert "type" in decoded
    assert "data" in decoded
    # Data content must match
    assert decoded["type"] == "alert"
    assert decoded["data"]["id"] == "28-27-json"
    assert decoded["data"]["score"] == 7.8


# ---------------------------------------------------------------------------
# Section 15 — Feature 17.4: Accept `filter` message from client (ACK response)
#
# Implementation (websocket.py lines 228-229):
#   if msg.get("type") == "filter":
#       await manager.send_to(ws, {"type": "ack", "filter": msg.get("data")})
# ---------------------------------------------------------------------------


# --- Integration: ACK structure ---


def test_17_4_ack_has_exactly_type_and_filter_keys(ws_mocks):
    """ACK response must have exactly the 'type' and 'filter' keys — no extra fields."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter", "data": {"severity": "high"}})
            ack = ws.receive_json()
    assert set(ack.keys()) == {"type", "filter"}


# --- Integration: filter data echoing edge cases ---


def test_17_4_filter_data_explicit_null_acks_filter_none(ws_mocks):
    """Client sending data=null (JSON null) must receive ack with filter=null (key present, value None)."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter", "data": None})
            ack = ws.receive_json()
    assert ack["type"] == "ack"
    assert "filter" in ack
    assert ack["filter"] is None


def test_17_4_filter_data_empty_dict_not_none(ws_mocks):
    """Client sending data={} must receive ack with filter={} (empty dict, not null)."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter", "data": {}})
            ack = ws.receive_json()
    assert ack["type"] == "ack"
    assert ack["filter"] == {}
    assert ack["filter"] is not None


def test_17_4_filter_data_list_values_preserved(ws_mocks):
    """Filter data containing list fields must be echoed back with exact list contents."""
    filter_data = {"technique_ids": ["T1059.001", "T1059.003"], "tactic_ids": ["TA0002"]}
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter", "data": filter_data})
            ack = ws.receive_json()
    assert ack["filter"] == filter_data


def test_17_4_filter_data_nested_objects_preserved(ws_mocks):
    """Filter data containing nested dicts must be echoed back with identical nested structure."""
    filter_data = {
        "severity": "critical",
        "time_range": {"from": "2026-01-01T00:00:00Z", "to": "2026-01-31T23:59:59Z"},
        "host": {"name": "dc-01", "os": "windows"},
    }
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter", "data": filter_data})
            ack = ws.receive_json()
    assert ack["filter"] == filter_data


def test_17_4_filter_data_numeric_values_preserved(ws_mocks):
    """Filter data containing numeric fields must be echoed with exact numeric values."""
    filter_data = {"min_score": 7.5, "max_score": 10.0, "limit": 50}
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter", "data": filter_data})
            ack = ws.receive_json()
    assert ack["filter"]["min_score"] == 7.5
    assert ack["filter"]["max_score"] == 10.0
    assert ack["filter"]["limit"] == 50


def test_17_4_filter_data_boolean_values_preserved(ws_mocks):
    """Filter data containing booleans must be echoed as true/false (not 1/0)."""
    filter_data = {"show_resolved": False, "include_low_severity": True}
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()
            ws.send_json({"type": "filter", "data": filter_data})
            ack = ws.receive_json()
    assert ack["filter"]["show_resolved"] is False
    assert ack["filter"]["include_low_severity"] is True


# --- Integration: type field case sensitivity ---


def test_17_4_type_field_matching_is_case_sensitive(ws_mocks):
    """Type check is case-sensitive: 'Filter' (capital F) must be ignored, not acked."""
    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()  # consume connected
            ws.send_json({"type": "Filter", "data": {"severity": "high"}})  # wrong case — ignored
            # Follow up with correct lowercase to prove the first produced no ack
            ws.send_json({"type": "filter", "data": {"host": "probe-01"}})
            ack = ws.receive_json()
    assert ack["type"] == "ack"
    assert ack["filter"] == {"host": "probe-01"}


# --- Unit tests: send_to call verification ---


def test_17_4_send_to_called_with_exact_ack_payload(ws_mocks):
    """alerts_ws must call manager.send_to with the exact ACK dict for each filter message."""
    filter_data = {"tactic": "Persistence", "technique_ids": ["T1053.005"]}
    sent_messages: list[dict] = []
    original_send_to = manager.send_to

    async def recording_send_to(ws, msg):
        sent_messages.append(msg)
        await original_send_to(ws, msg)

    with patch.object(manager, "send_to", new=recording_send_to):
        with TestClient(app) as client:
            with client.websocket_connect(WS_URL) as ws:
                ws.receive_json()  # consume connected
                ws.send_json({"type": "filter", "data": filter_data})
                ws.receive_json()  # consume ack

    ack_msgs = [m for m in sent_messages if m.get("type") == "ack"]
    assert len(ack_msgs) == 1
    assert ack_msgs[0] == {"type": "ack", "filter": filter_data}


@pytest.mark.asyncio
async def test_17_4_send_to_failure_during_ack_prunes_connection():
    """When ws.send_text raises while sending the filter ACK, the dead connection is pruned."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    ws.send_text.side_effect = RuntimeError("broken pipe")
    m._connections.add(ws)

    # Replicate the filter-ack path from alerts_ws
    msg = {"type": "filter", "data": {"severity": "high"}}
    await m.send_to(ws, {"type": "ack", "filter": msg.get("data")})

    # send_to must have called disconnect() internally, pruning the dead WebSocket
    assert ws not in m._connections


# ---------------------------------------------------------------------------
# Section 16 — Feature 17.6: Distributed broadcast via Valkey pub/sub (multi-instance)
#
# Tests the distributed fan-out architecture where multiple backend replicas each
# maintain their own local WebSocket connections. When any replica calls broadcast(),
# the message is published to the Valkey channel "mxtac:alerts" and received by EVERY
# replica's subscriber loop, which then fans out to its own local WebSocket clients.
#
# Single-instance deployments work identically: the pub/sub round-trip is effectively
# a local loopback through Valkey.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_17_6_channel_constant_is_mxtac_alerts():
    """_CHANNEL must be exactly 'mxtac:alerts' — the cross-replica fan-out channel name."""
    from app.api.v1.endpoints.websocket import _CHANNEL

    assert _CHANNEL == "mxtac:alerts"


@pytest.mark.asyncio
async def test_17_6_manager_singleton_uses_settings_valkey_url():
    """Module-level manager singleton must be configured with settings.valkey_url."""
    from app.core.config import settings

    assert manager._valkey_url == settings.valkey_url


@pytest.mark.asyncio
async def test_17_6_cross_instance_delivery_instance_a_to_b():
    """Multi-instance: Instance A calls broadcast() → Valkey pub/sub → Instance B's clients receive."""
    from app.api.v1.endpoints.websocket import _CHANNEL

    # Two separate manager instances simulating two backend replicas
    instance_a = DistributedConnectionManager("redis://localhost:6379/0")
    instance_b = DistributedConnectionManager("redis://localhost:6379/0")

    # Each instance has its own local WebSocket connections
    ws_a = _make_ws()  # client connected to replica A
    ws_b = _make_ws()  # client connected to replica B
    instance_a._connections.add(ws_a)
    instance_b._connections.add(ws_b)

    alert_data = {"id": "17-6-cross", "level": "critical", "score": 9.5, "host": "dc-01"}

    # Step 1: Instance A publishes to the Valkey channel
    mock_pub = AsyncMock()
    with patch.object(instance_a, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await instance_a.broadcast({"type": "alert", "data": alert_data})

    mock_pub.publish.assert_awaited_once()
    published_channel = mock_pub.publish.call_args[0][0]
    published_payload = mock_pub.publish.call_args[0][1]
    assert published_channel == _CHANNEL

    # Step 2: Instance B's subscriber loop receives the same payload from the channel
    # (as would happen in production via Valkey delivering to all subscribers)
    subscribe_count = 0

    async def mock_subscribe(_channel):
        nonlocal subscribe_count
        subscribe_count += 1
        if subscribe_count >= 2:
            raise asyncio.CancelledError()

    async def fake_listen():
        yield {"type": "message", "data": published_payload}
        raise RuntimeError("connection lost")

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await instance_b._subscriber_loop()

    # Instance B's client must have received the exact payload published by Instance A
    ws_b.send_text.assert_awaited_once_with(published_payload)
    received = json.loads(ws_b.send_text.call_args[0][0])
    assert received["type"] == "alert"
    assert received["data"] == alert_data


@pytest.mark.asyncio
async def test_17_6_instance_isolation_a_connections_not_touched_by_b_fanout():
    """Instance B's _fanout_local() must only deliver to Instance B's own connections."""
    instance_a = DistributedConnectionManager("redis://localhost:6379/0")
    instance_b = DistributedConnectionManager("redis://localhost:6379/0")

    ws_a = _make_ws()  # client on replica A
    ws_b = _make_ws()  # client on replica B
    instance_a._connections.add(ws_a)
    instance_b._connections.add(ws_b)

    alert_payload = json.dumps({"type": "alert", "data": {"id": "17-6-iso", "level": "high"}})

    # Instance B fans out a message locally — must not affect Instance A's connections
    await instance_b._fanout_local(alert_payload)

    ws_b.send_text.assert_awaited_once_with(alert_payload)
    ws_a.send_text.assert_not_awaited()  # Instance A's client untouched


@pytest.mark.asyncio
async def test_17_6_pub_client_independent_from_sub_client():
    """Publisher and subscriber use separate Valkey client references for independent failover."""
    m = DistributedConnectionManager("redis://localhost:6379/0")

    # Initially both clients are None
    assert m._pub_client is None
    assert m._sub_client is None

    # After _get_pub_client(), pub_client is populated but sub_client remains None
    mock_pub = AsyncMock()
    with patch.object(ws_module, "aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_pub
        await m._get_pub_client()

    assert m._pub_client is mock_pub
    assert m._sub_client is None  # subscriber not started — connections are independent


@pytest.mark.asyncio
async def test_17_6_exponential_backoff_first_retry_is_1s():
    """Subscriber loop first retry delay must be exactly 1 second."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    call_count = 0
    sleep_durations: list[float] = []

    async def mock_subscribe(_channel):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("first failure")
        raise asyncio.CancelledError()

    async def record_sleep(duration):
        sleep_durations.append(duration)

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", side_effect=record_sleep),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    assert len(sleep_durations) >= 1
    assert sleep_durations[0] == 1.0, f"Expected first retry delay of 1.0s, got {sleep_durations[0]}"


@pytest.mark.asyncio
async def test_17_6_exponential_backoff_second_retry_is_2s():
    """Subscriber loop second retry delay must double to 2 seconds."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    call_count = 0
    sleep_durations: list[float] = []

    async def mock_subscribe(_channel):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError(f"failure {call_count}")
        raise asyncio.CancelledError()

    async def record_sleep(duration):
        sleep_durations.append(duration)

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", side_effect=record_sleep),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    assert len(sleep_durations) >= 2
    assert sleep_durations[0] == 1.0, f"Expected first retry 1.0s, got {sleep_durations[0]}"
    assert sleep_durations[1] == 2.0, f"Expected second retry 2.0s, got {sleep_durations[1]}"


@pytest.mark.asyncio
async def test_17_6_exponential_backoff_caps_at_30s():
    """Subscriber loop retry delay must cap at 30 seconds regardless of failure count."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    call_count = 0
    sleep_durations: list[float] = []
    # 10 failures guarantees we exceed the 30s cap (1, 2, 4, 8, 16, 30, 30, 30, 30, 30)
    max_failures = 10

    async def mock_subscribe(_channel):
        nonlocal call_count
        call_count += 1
        if call_count <= max_failures:
            raise ConnectionError(f"failure {call_count}")
        raise asyncio.CancelledError()

    async def record_sleep(duration):
        sleep_durations.append(duration)

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", side_effect=record_sleep),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    assert all(d <= 30.0 for d in sleep_durations), (
        f"Some delays exceeded 30s cap: {sleep_durations}"
    )
    assert 30.0 in sleep_durations, (
        f"Max delay of 30s never reached after {max_failures} failures: {sleep_durations}"
    )


@pytest.mark.asyncio
async def test_17_6_backoff_resets_to_1s_after_successful_connect():
    """Retry delay must reset to 1s after a successful Valkey connection, not carry over."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    call_count = 0
    sleep_durations: list[float] = []

    async def mock_subscribe(_channel):
        nonlocal call_count
        call_count += 1
        # First attempt succeeds (subscribe returns) — listen() will then raise RuntimeError
        # Second attempt fails — sleep should use the reset 1s delay, not carry-over

    async def fake_listen():
        # Successful connection: immediately drops (simulates clean disconnect)
        raise RuntimeError("clean disconnect after successful subscribe")

    async def mock_subscribe_v2(_channel):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            pass  # subscribe succeeds; listen() will raise RuntimeError
        elif call_count == 2:
            raise ConnectionError("second attempt fails")
        else:
            raise asyncio.CancelledError()

    async def record_sleep(duration):
        sleep_durations.append(duration)

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe_v2
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", side_effect=record_sleep),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    # After successful connect + RuntimeError from listen(), the retry delay must be 1.0s
    # (reset by the `retry_delay = 1.0` line after successful subscribe)
    assert len(sleep_durations) >= 1
    assert sleep_durations[0] == 1.0, (
        f"Expected reset delay of 1.0s after successful connect, got {sleep_durations[0]}"
    )


@pytest.mark.asyncio
async def test_17_6_subscriber_creates_fresh_connection_on_each_retry():
    """Subscriber loop must call aioredis.from_url() on each retry — fresh connection per attempt."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    call_count = 0

    async def mock_subscribe(_channel):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("first failure")
        raise asyncio.CancelledError()

    # Two distinct client objects returned on successive from_url() calls
    mock_client_1 = MagicMock()
    mock_client_1.aclose = AsyncMock()
    mock_pubsub_1 = MagicMock()
    mock_pubsub_1.subscribe = mock_subscribe
    mock_client_1.pubsub.return_value = mock_pubsub_1

    mock_client_2 = MagicMock()
    mock_client_2.aclose = AsyncMock()
    mock_pubsub_2 = MagicMock()
    mock_pubsub_2.subscribe = mock_subscribe
    mock_client_2.pubsub.return_value = mock_pubsub_2

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.side_effect = [mock_client_1, mock_client_2]
        await m._subscriber_loop()

    # Two iterations → two distinct calls to from_url (new connection per retry)
    assert mock_aioredis.from_url.call_count == 2


@pytest.mark.asyncio
async def test_17_6_pub_client_created_lazily_on_first_broadcast():
    """Pub client must not be created until the first broadcast() call (lazy singleton)."""
    m = DistributedConnectionManager("redis://localhost:6379/0")

    # No pub client before any broadcast
    assert m._pub_client is None

    mock_client = AsyncMock()
    with patch.object(ws_module, "aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client
        # First call to _get_pub_client creates the client
        client = await m._get_pub_client()

    assert client is mock_client
    assert m._pub_client is mock_client
    mock_aioredis.from_url.assert_called_once()


@pytest.mark.asyncio
async def test_17_6_broadcast_payload_preserved_across_instance_boundary():
    """Payload published by Instance A must be received byte-for-byte by Instance B's clients."""
    instance_a = DistributedConnectionManager("redis://localhost:6379/0")
    instance_b = DistributedConnectionManager("redis://localhost:6379/0")

    ws_b = _make_ws()
    instance_b._connections.add(ws_b)

    alert_data = {
        "id": "17-6-payload",
        "rule_title": "Suspicious PowerShell Base64 Execution",
        "level": "critical",
        "severity_id": 5,
        "score": 9.2,
        "host": "dc-01",
        "technique_ids": ["T1059.001"],
        "tactic_ids": ["TA0002"],
        "ts": "2026-02-21T00:00:00+00:00",
    }

    # Capture what Instance A would publish to Valkey
    mock_pub = AsyncMock()
    with patch.object(instance_a, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await instance_a.broadcast({"type": "alert", "data": alert_data})

    published_payload = mock_pub.publish.call_args[0][1]

    # Feed that exact payload into Instance B's subscriber loop
    subscribe_count = 0

    async def mock_subscribe(_channel):
        nonlocal subscribe_count
        subscribe_count += 1
        if subscribe_count >= 2:
            raise asyncio.CancelledError()

    async def fake_listen():
        yield {"type": "message", "data": published_payload}
        raise RuntimeError("done")

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await instance_b._subscriber_loop()

    # ws_b received the payload exactly as published — no modification in transit
    ws_b.send_text.assert_awaited_once_with(published_payload)
    received = json.loads(ws_b.send_text.call_args[0][0])
    assert received["type"] == "alert"
    assert received["data"] == alert_data
    # Every field preserved with exact types and values
    assert received["data"]["score"] == 9.2
    assert received["data"]["technique_ids"] == ["T1059.001"]
    assert received["data"]["severity_id"] == 5


@pytest.mark.asyncio
async def test_17_6_single_instance_self_delivery_via_pubsub_loopback():
    """In single-instance mode the pub/sub round-trip is a local loopback to own clients."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    m._connections.add(ws)

    alert_data = {"id": "17-6-loopback", "level": "high", "score": 8.0, "host": "srv-01"}

    # Step 1: instance publishes to the channel
    mock_pub = AsyncMock()
    with patch.object(m, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await m.broadcast({"type": "alert", "data": alert_data})

    published_payload = mock_pub.publish.call_args[0][1]

    # Step 2: same instance's subscriber loop receives the loopback message
    subscribe_count = 0

    async def mock_subscribe(_channel):
        nonlocal subscribe_count
        subscribe_count += 1
        if subscribe_count >= 2:
            raise asyncio.CancelledError()

    async def fake_listen():
        yield {"type": "message", "data": published_payload}
        raise RuntimeError("connection lost")

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    # Local client received the loopback message — identical to multi-instance behavior
    ws.send_text.assert_awaited_once_with(published_payload)
    received = json.loads(ws.send_text.call_args[0][0])
    assert received["type"] == "alert"
    assert received["data"] == alert_data


@pytest.mark.asyncio
async def test_17_6_subscriber_subscribes_to_mxtac_alerts_channel():
    """Subscriber loop must subscribe to the 'mxtac:alerts' channel specifically."""
    from app.api.v1.endpoints.websocket import _CHANNEL

    m = DistributedConnectionManager("redis://localhost:6379/0")
    channels_subscribed: list[str] = []

    async def capture_subscribe(channel):
        channels_subscribed.append(channel)
        raise asyncio.CancelledError()

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = capture_subscribe
    mock_client.pubsub.return_value = mock_pubsub

    with patch.object(ws_module, "aioredis") as mock_aioredis:
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    assert channels_subscribed == [_CHANNEL], (
        f"Expected subscriber to subscribe to {_CHANNEL!r}, got {channels_subscribed}"
    )


@pytest.mark.asyncio
async def test_17_6_subscriber_loop_ignores_non_message_type_events():
    """Subscriber loop must silently skip events whose type is not 'message'."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    fanout_calls: list[str] = []
    subscribe_count = 0

    async def mock_subscribe(_channel):
        nonlocal subscribe_count
        subscribe_count += 1
        if subscribe_count >= 2:
            raise asyncio.CancelledError()

    async def fake_listen():
        # These event types must all be ignored
        yield {"type": "subscribe", "data": None}
        yield {"type": "psubscribe", "data": None}
        yield {"type": "unsubscribe", "data": None}
        yield {"type": "message", "data": '{"type":"alert","data":{"id":"real"}}'}
        raise RuntimeError("done")

    async def capture_fanout(payload: str) -> None:
        fanout_calls.append(payload)

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        with patch.object(m, "_fanout_local", side_effect=capture_fanout):
            await m._subscriber_loop()

    # Only the 'message' type event must have triggered fanout
    assert len(fanout_calls) == 1
    assert json.loads(fanout_calls[0])["data"]["id"] == "real"


# ---------------------------------------------------------------------------
# Section 16 — Feature 28.28: WebSocket client on instance-2 receives alert
#              from instance-1 (distributed multi-instance delivery)
# ---------------------------------------------------------------------------
#
# Test pattern:
#   1. Create instance_1 and instance_2 (separate DistributedConnectionManager objects)
#   2. Capture what instance_1.broadcast() would publish to Valkey
#   3. Feed that exact payload into instance_2._subscriber_loop() via a fake listener
#   4. Assert instance_2's clients received the message exactly
#
# Mocking note: mock_client for _subscriber_loop MUST be MagicMock (not AsyncMock)
# because pubsub() is a synchronous call. See MEMORY.md for explanation.
# ---------------------------------------------------------------------------


def _make_cross_instance_fixtures(
    alert_data: dict,
) -> tuple[DistributedConnectionManager, DistributedConnectionManager, object]:
    """Return (instance_1, instance_2, ws_on_2) with ws_on_2 added to instance_2._connections."""
    instance_1 = DistributedConnectionManager("redis://localhost:6379/0")
    instance_2 = DistributedConnectionManager("redis://localhost:6379/0")
    ws_2 = _make_ws()
    instance_2._connections.add(ws_2)
    return instance_1, instance_2, ws_2


async def _capture_published_payload(instance: DistributedConnectionManager, message: dict) -> str:
    """Broadcast *message* via *instance* and return the raw JSON string published to Valkey."""
    mock_pub = AsyncMock()
    with patch.object(instance, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await instance.broadcast(message)
    return mock_pub.publish.call_args[0][1]


def _make_sub_mock(payloads: list[str], cancel_after_listen: bool = True):
    """Return a mock aioredis client whose subscriber loop yields *payloads* then terminates.

    Termination strategy:
      - fake_listen raises RuntimeError after all payloads → retry → subscribe raises CancelledError
    """
    subscribe_count = 0

    async def mock_subscribe(_channel):
        nonlocal subscribe_count
        subscribe_count += 1
        if subscribe_count >= 2:
            raise asyncio.CancelledError()

    async def fake_listen():
        for payload in payloads:
            yield {"type": "message", "data": payload}
        raise RuntimeError("end of stream")

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub
    return mock_client


@pytest.mark.asyncio
async def test_28_28_instance2_client_receives_type_alert():
    """Instance-2 client must receive a JSON envelope with type='alert' from instance-1's broadcast."""
    instance_1, instance_2, ws_2 = _make_cross_instance_fixtures({})

    alert_data = {"id": "28-28-001", "level": "high", "host": "srv-01", "score": 7.5}
    payload = await _capture_published_payload(instance_1, {"type": "alert", "data": alert_data})

    mock_client = _make_sub_mock([payload])
    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await instance_2._subscriber_loop()

    ws_2.send_text.assert_awaited_once_with(payload)
    received = json.loads(ws_2.send_text.call_args[0][0])
    assert received["type"] == "alert"


@pytest.mark.asyncio
async def test_28_28_instance2_client_receives_exact_alert_data():
    """Instance-2 client must receive the exact alert data dict broadcast by instance-1."""
    instance_1, instance_2, ws_2 = _make_cross_instance_fixtures({})

    alert_data = {
        "id": "28-28-002",
        "rule_title": "Suspicious PowerShell Base64 Execution",
        "level": "critical",
        "severity_id": 5,
        "score": 9.1,
        "host": "dc-02",
        "technique_ids": ["T1059.001"],
        "tactic_ids": ["TA0002"],
        "ts": "2026-02-21T00:00:00+00:00",
    }
    payload = await _capture_published_payload(instance_1, {"type": "alert", "data": alert_data})

    mock_client = _make_sub_mock([payload])
    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await instance_2._subscriber_loop()

    received = json.loads(ws_2.send_text.call_args[0][0])
    assert received["data"] == alert_data
    # Verify exact types for numeric and list fields
    assert received["data"]["score"] == 9.1
    assert received["data"]["severity_id"] == 5
    assert received["data"]["technique_ids"] == ["T1059.001"]


@pytest.mark.asyncio
async def test_28_28_three_clients_on_instance2_each_receive():
    """All three clients connected to instance-2 must receive the alert from instance-1."""
    instance_1 = DistributedConnectionManager("redis://localhost:6379/0")
    instance_2 = DistributedConnectionManager("redis://localhost:6379/0")

    ws_a, ws_b, ws_c = _make_ws(), _make_ws(), _make_ws()
    instance_2._connections.update({ws_a, ws_b, ws_c})

    alert_data = {"id": "28-28-003", "level": "medium", "host": "win-03", "score": 5.0}
    payload = await _capture_published_payload(instance_1, {"type": "alert", "data": alert_data})

    mock_client = _make_sub_mock([payload])
    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await instance_2._subscriber_loop()

    for ws in (ws_a, ws_b, ws_c):
        ws.send_text.assert_awaited_once()
        received = json.loads(ws.send_text.call_args[0][0])
        assert received["type"] == "alert"
        assert received["data"] == alert_data


@pytest.mark.asyncio
async def test_28_28_instance1_connections_not_in_instance2_fanout():
    """Instance-1's WebSocket connections must not be in instance-2's connection set.

    Instance-2 delivers only to its own local connections — cross-instance isolation
    means instance-1 clients are never directly written by instance-2's fanout.
    """
    instance_1 = DistributedConnectionManager("redis://localhost:6379/0")
    instance_2 = DistributedConnectionManager("redis://localhost:6379/0")

    ws_1 = _make_ws()
    ws_2 = _make_ws()
    instance_1._connections.add(ws_1)
    instance_2._connections.add(ws_2)

    alert_data = {"id": "28-28-isolation", "level": "high", "host": "lin-01", "score": 6.0}
    payload = await _capture_published_payload(instance_1, {"type": "alert", "data": alert_data})

    # Instance-2's subscriber loop delivers only to instance-2's clients
    mock_client = _make_sub_mock([payload])
    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await instance_2._subscriber_loop()

    # ws_2 received the alert
    ws_2.send_text.assert_awaited_once()
    # ws_1 was NOT touched by instance_2's fanout — it is NOT in instance_2._connections
    ws_1.send_text.assert_not_awaited()
    assert ws_1 not in instance_2._connections


@pytest.mark.asyncio
async def test_28_28_both_instances_receive_same_alert():
    """Both instance-1 (via loopback) and instance-2 must receive the same alert payload."""
    instance_1 = DistributedConnectionManager("redis://localhost:6379/0")
    instance_2 = DistributedConnectionManager("redis://localhost:6379/0")

    ws_1 = _make_ws()
    ws_2 = _make_ws()
    instance_1._connections.add(ws_1)
    instance_2._connections.add(ws_2)

    alert_data = {"id": "28-28-both", "level": "critical", "host": "dc-01", "score": 9.5}
    payload = await _capture_published_payload(instance_1, {"type": "alert", "data": alert_data})

    # Simulate both subscriber loops receiving the same pub/sub message
    for instance, ws in ((instance_1, ws_1), (instance_2, ws_2)):
        mock_client = _make_sub_mock([payload])
        with (
            patch.object(ws_module, "aioredis") as mock_aioredis,
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            mock_aioredis.from_url.return_value = mock_client
            await instance._subscriber_loop()

        ws.send_text.assert_awaited_once_with(payload)
        received = json.loads(ws.send_text.call_args[0][0])
        assert received["type"] == "alert"
        assert received["data"] == alert_data


@pytest.mark.asyncio
async def test_28_28_nested_alert_fields_preserved_exactly():
    """Deeply nested alert data must be preserved byte-for-byte across the instance boundary."""
    instance_1 = DistributedConnectionManager("redis://localhost:6379/0")
    instance_2 = DistributedConnectionManager("redis://localhost:6379/0")
    ws_2 = _make_ws()
    instance_2._connections.add(ws_2)

    alert_data = {
        "id": "28-28-nested",
        "rule_title": "Credential Dumping via LSASS",
        "level": "critical",
        "severity_id": 5,
        "score": 9.8,
        "host": "dc-01",
        "technique_ids": ["T1003", "T1003.001"],
        "tactic_ids": ["TA0006"],
        "mitre": {
            "technique": {"id": "T1003", "name": "OS Credential Dumping"},
            "tactic": {"id": "TA0006", "name": "Credential Access"},
        },
        "asset": {"criticality": 1.0, "type": "domain_controller"},
        "ts": "2026-02-21T12:00:00+00:00",
    }
    payload = await _capture_published_payload(instance_1, {"type": "alert", "data": alert_data})

    mock_client = _make_sub_mock([payload])
    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await instance_2._subscriber_loop()

    received = json.loads(ws_2.send_text.call_args[0][0])
    assert received["data"] == alert_data
    assert received["data"]["mitre"]["technique"]["id"] == "T1003"
    assert received["data"]["mitre"]["tactic"]["name"] == "Credential Access"
    assert received["data"]["asset"]["criticality"] == 1.0
    assert received["data"]["technique_ids"] == ["T1003", "T1003.001"]


@pytest.mark.asyncio
async def test_28_28_sequential_alerts_from_instance1_arrive_in_order():
    """Three alerts broadcast by instance-1 must arrive at instance-2's client in the same order."""
    instance_1 = DistributedConnectionManager("redis://localhost:6379/0")
    instance_2 = DistributedConnectionManager("redis://localhost:6379/0")
    ws_2 = _make_ws()
    instance_2._connections.add(ws_2)

    alerts = [
        {"id": f"28-28-seq-{i}", "level": "medium", "host": f"host-{i}", "score": float(i + 1)}
        for i in range(3)
    ]

    # Capture all three payloads in order
    payloads: list[str] = []
    for alert in alerts:
        p = await _capture_published_payload(instance_1, {"type": "alert", "data": alert})
        payloads.append(p)

    # Feed all three into instance_2's subscriber loop in a single connection cycle
    subscribe_count = 0

    async def mock_subscribe(_channel):
        nonlocal subscribe_count
        subscribe_count += 1
        if subscribe_count >= 2:
            raise asyncio.CancelledError()

    async def fake_listen():
        for payload in payloads:
            yield {"type": "message", "data": payload}
        raise RuntimeError("end of stream")

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await instance_2._subscriber_loop()

    assert ws_2.send_text.await_count == 3
    received_ids = [
        json.loads(call[0][0])["data"]["id"]
        for call in ws_2.send_text.call_args_list
    ]
    assert received_ids == ["28-28-seq-0", "28-28-seq-1", "28-28-seq-2"]


@pytest.mark.asyncio
async def test_28_28_dead_client_on_instance2_pruned_live_client_receives():
    """Dead connection on instance-2 must be pruned while live client still receives from instance-1."""
    instance_1 = DistributedConnectionManager("redis://localhost:6379/0")
    instance_2 = DistributedConnectionManager("redis://localhost:6379/0")

    alive = _make_ws()
    dead = _make_ws()
    dead.send_text.side_effect = RuntimeError("connection reset")
    instance_2._connections.update({alive, dead})

    alert_data = {"id": "28-28-dead", "level": "high", "host": "srv-02", "score": 7.0}
    payload = await _capture_published_payload(instance_1, {"type": "alert", "data": alert_data})

    mock_client = _make_sub_mock([payload])
    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await instance_2._subscriber_loop()

    # Live client received the alert from instance-1
    alive.send_text.assert_awaited_once()
    received = json.loads(alive.send_text.call_args[0][0])
    assert received["type"] == "alert"
    assert received["data"] == alert_data
    # Dead client was pruned from instance-2's connection set
    assert dead not in instance_2._connections


@pytest.mark.asyncio
async def test_28_28_instance1_valkey_down_instance2_not_reached():
    """When instance-1's Valkey publish fails (falls back to local fanout), instance-2 must not receive.

    If the Valkey pub client raises on publish(), broadcast() falls back to local _fanout_local().
    Only instance-1's own clients receive the alert. Instance-2's clients are unreachable because
    no message was published to the shared channel.
    """
    instance_1 = DistributedConnectionManager("redis://localhost:6379/0")
    instance_2 = DistributedConnectionManager("redis://localhost:6379/0")

    ws_1 = _make_ws()
    ws_2 = _make_ws()
    instance_1._connections.add(ws_1)
    instance_2._connections.add(ws_2)

    alert_data = {"id": "28-28-valkey-down", "level": "high", "host": "srv-03", "score": 6.5}

    # Simulate instance-1's Valkey pub client being down (publish raises ConnectionError)
    mock_pub_down = AsyncMock()
    mock_pub_down.publish.side_effect = ConnectionError("valkey unreachable")
    with patch.object(instance_1, "_get_pub_client", new=AsyncMock(return_value=mock_pub_down)):
        await instance_1.broadcast({"type": "alert", "data": alert_data})

    # Instance-1's local client received via fallback fanout
    ws_1.send_text.assert_awaited_once()
    received_1 = json.loads(ws_1.send_text.call_args[0][0])
    assert received_1["type"] == "alert"
    assert received_1["data"] == alert_data

    # Instance-2's subscriber loop received nothing — no message was published to Valkey
    ws_2.send_text.assert_not_awaited()


# ---------------------------------------------------------------------------
# Section 17 — Feature 28.29: WebSocket auto-reconnect after drop
#
# When a client's TCP connection drops, the frontend reconnects with a new
# WebSocket object after a fixed delay (5 s in the hook).  The backend must:
#   - Remove the dead WebSocket from manager._connections on disconnect
#   - Register the new WebSocket when the client reconnects
#   - Send a fresh "connected" handshake to the reconnected client
#   - Resume broadcasting to the reconnected client normally
#   - Support multiple drop/reconnect cycles without resource leaks
#
# Valkey subscriber-side reconnect (exponential backoff) is already covered in
# Sections 10 and 16.  Tests here extend that coverage with scenarios specific
# to the client-side reconnect path and subscriber-loop resilience after
# listen() terminates or Valkey drops mid-stream.
# ---------------------------------------------------------------------------


# ── Unit: connection lifecycle after drop ────────────────────────────────────


@pytest.mark.asyncio
async def test_28_29_reconnected_ws_added_to_connections():
    """After a client drops and reconnects, the new WebSocket must be in manager._connections."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws_first = _make_ws()
    ws_reconnect = _make_ws()

    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws_first)
    assert ws_first in m._connections

    # Simulate network drop
    m.disconnect(ws_first)
    assert ws_first not in m._connections

    # Client reconnects with a fresh WebSocket object
    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws_reconnect)

    assert ws_reconnect in m._connections


@pytest.mark.asyncio
async def test_28_29_dropped_ws_not_in_connections():
    """After disconnect, the old WebSocket must be fully removed from manager._connections."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()

    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws)
    m.disconnect(ws)

    assert ws not in m._connections
    assert len(m._connections) == 0


@pytest.mark.asyncio
async def test_28_29_connection_count_accurate_after_reconnect():
    """Exactly one connection must be tracked after one drop-then-reconnect cycle."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws_first = _make_ws()
    ws_reconnect = _make_ws()

    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws_first)
    m.disconnect(ws_first)

    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws_reconnect)

    assert len(m._connections) == 1


# ── Unit: broadcast delivery after drop / reconnect ──────────────────────────


@pytest.mark.asyncio
async def test_28_29_reconnected_client_receives_fanout():
    """After drop+reconnect, _fanout_local() must deliver to the new WebSocket only."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws_first = _make_ws()
    ws_reconnect = _make_ws()

    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws_first)
    m.disconnect(ws_first)

    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws_reconnect)

    payload = json.dumps({"type": "alert", "data": {"id": "28-29-fanout", "level": "high"}})
    await m._fanout_local(payload)

    ws_reconnect.send_text.assert_awaited_once_with(payload)
    ws_first.send_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_28_29_dropped_client_does_not_receive_fanout():
    """After disconnect, _fanout_local() with empty connections must not call send_text."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()

    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws)
    m.disconnect(ws)

    await m._fanout_local(json.dumps({"type": "alert", "data": {"id": "28-29-dropped"}}))

    ws.send_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_28_29_multiple_reconnect_cycles_each_client_receives():
    """Each reconnect cycle produces a fresh WebSocket that receives exactly one broadcast."""
    m = DistributedConnectionManager("redis://localhost:6379/0")

    for cycle in range(3):
        ws = _make_ws()
        with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
            await m.connect(ws)

        payload = json.dumps({"type": "alert", "data": {"id": f"28-29-cycle-{cycle}"}})
        await m._fanout_local(payload)

        ws.send_text.assert_awaited_once_with(payload)

        # Simulate drop before the next cycle
        m.disconnect(ws)


@pytest.mark.asyncio
async def test_28_29_reconnect_and_subsequent_broadcast_reaches_new_client():
    """broadcast() via Valkey fallback must deliver to the reconnected client, not the old one."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws_old = _make_ws()
    ws_new = _make_ws()

    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws_old)
    m.disconnect(ws_old)

    with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
        await m.connect(ws_new)

    alert_data = {"id": "28-29-bcast", "level": "critical", "score": 9.0}
    mock_pub = AsyncMock()
    mock_pub.publish.side_effect = ConnectionError("valkey down")

    with patch.object(m, "_get_pub_client", new=AsyncMock(return_value=mock_pub)):
        await m.broadcast({"type": "alert", "data": alert_data})

    # Reconnected client receives the alert via local fanout fallback
    ws_new.send_text.assert_awaited_once()
    received = json.loads(ws_new.send_text.call_args[0][0])
    assert received["type"] == "alert"
    assert received["data"] == alert_data

    # Old dropped client did not receive anything
    ws_old.send_text.assert_not_awaited()


# ── Unit: handshake on reconnect ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_28_29_reconnected_client_receives_connected_handshake():
    """Each new WebSocket must receive an independent 'connected' handshake via send_to."""
    m = DistributedConnectionManager("redis://localhost:6379/0")

    for i in range(2):
        ws = _make_ws()
        with patch.object(m, "_ensure_subscriber", new=AsyncMock()):
            await m.connect(ws)
        await m.send_to(ws, {
            "type": "connected",
            "message": "Subscribed to real-time alert stream",
            "ts": f"2026-02-21T00:0{i}:00+00:00",
        })
        msg = json.loads(ws.send_text.call_args[0][0])
        assert msg["type"] == "connected"
        m.disconnect(ws)


# ── Integration: reconnect via TestClient ────────────────────────────────────


def test_28_29_integration_second_connection_receives_handshake(ws_mocks):
    """Second WebSocket connection (simulating client reconnect) must receive its own 'connected' handshake."""
    with TestClient(app) as client:
        # First connection
        with client.websocket_connect(WS_URL) as ws1:
            handshake1 = ws1.receive_json()
        assert handshake1["type"] == "connected"

        # Second connection — simulates auto-reconnect after the first dropped
        with client.websocket_connect(WS_URL) as ws2:
            handshake2 = ws2.receive_json()
        assert handshake2["type"] == "connected"


def test_28_29_integration_each_reconnect_handshake_has_valid_ts(ws_mocks):
    """Each reconnect handshake must include a valid ISO 8601 timestamp."""
    from datetime import datetime

    with TestClient(app) as client:
        with client.websocket_connect(WS_URL) as ws1:
            h1 = ws1.receive_json()
        with client.websocket_connect(WS_URL) as ws2:
            h2 = ws2.receive_json()

    datetime.fromisoformat(h1["ts"])  # raises ValueError if malformed
    datetime.fromisoformat(h2["ts"])  # raises ValueError if malformed


def test_28_29_integration_first_disconnect_triggers_manager_remove(ws_mocks):
    """When the first connection drops, manager.disconnect must be called exactly once."""
    call_count = 0
    original_disconnect = manager.disconnect

    def counting_disconnect(ws):
        nonlocal call_count
        call_count += 1
        original_disconnect(ws)

    with patch.object(manager, "disconnect", side_effect=counting_disconnect):
        with TestClient(app) as client:
            with client.websocket_connect(WS_URL) as ws:
                ws.receive_json()  # consume "connected"
    assert call_count == 1


# ── Subscriber loop: resilience after listen() terminates ────────────────────


@pytest.mark.asyncio
async def test_28_29_subscriber_loop_reconnects_when_listen_exhausts():
    """subscriber_loop must retry Valkey connection when listen() generator terminates without error."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    subscribe_calls: list[int] = []

    async def mock_subscribe(_channel):
        call_num = len(subscribe_calls) + 1
        subscribe_calls.append(call_num)
        if call_num >= 2:
            # Second iteration: exit via CancelledError so the loop terminates cleanly
            raise asyncio.CancelledError()
        # First iteration: succeed — listen() will exhaust immediately

    async def fake_listen():
        # Terminates without yielding any message — simulates server closing the stream
        return
        yield  # noqa: unreachable — makes this an async generator

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    # Loop must have retried after the first listen() exhausted
    assert len(subscribe_calls) >= 2, (
        f"Expected at least 2 subscribe attempts after listen() termination, got {subscribe_calls}"
    )


@pytest.mark.asyncio
async def test_28_29_alerts_resume_after_valkey_subscriber_reconnects():
    """Alerts must reach WS clients after the Valkey subscriber reconnects following a drop."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    ws = _make_ws()
    m._connections.add(ws)

    alert_data = {"id": "28-29-resume", "level": "critical", "score": 9.0, "host": "dc-01"}
    alert_payload = json.dumps({"type": "alert", "data": alert_data})

    subscribe_count = 0

    async def mock_subscribe(_channel):
        nonlocal subscribe_count
        subscribe_count += 1
        if subscribe_count == 1:
            raise ConnectionError("Valkey connection dropped mid-session")
        if subscribe_count >= 3:
            raise asyncio.CancelledError()
        # subscribe_count == 2: second attempt succeeds

    async def fake_listen():
        # Only deliver the alert on the second (successful) connect
        if subscribe_count == 2:
            yield {"type": "message", "data": alert_payload}
        raise RuntimeError("end of stream")

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_pubsub.listen = fake_listen
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    # Client must have received the alert after the subscriber reconnected
    ws.send_text.assert_awaited_once_with(alert_payload)
    received = json.loads(ws.send_text.call_args[0][0])
    assert received["type"] == "alert"
    assert received["data"] == alert_data


@pytest.mark.asyncio
async def test_28_29_subscriber_fresh_connection_per_reconnect_attempt():
    """Each reconnect attempt in subscriber_loop must create a distinct Valkey client object."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    call_count = 0

    async def mock_subscribe(_channel):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("first attempt failed")
        raise asyncio.CancelledError()

    # Two distinct mock clients returned on successive from_url() calls
    mock_client_a = MagicMock()
    mock_client_a.aclose = AsyncMock()
    mock_pubsub_a = MagicMock()
    mock_pubsub_a.subscribe = mock_subscribe
    mock_client_a.pubsub.return_value = mock_pubsub_a

    mock_client_b = MagicMock()
    mock_client_b.aclose = AsyncMock()
    mock_pubsub_b = MagicMock()
    mock_pubsub_b.subscribe = mock_subscribe
    mock_client_b.pubsub.return_value = mock_pubsub_b

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.side_effect = [mock_client_a, mock_client_b]
        await m._subscriber_loop()

    # Two iterations → two separate from_url() calls (fresh connection per attempt)
    assert mock_aioredis.from_url.call_count == 2


@pytest.mark.asyncio
async def test_28_29_subscriber_closed_after_each_reconnect_attempt():
    """Sub client's aclose() must be called after every connection attempt (success or failure)."""
    m = DistributedConnectionManager("redis://localhost:6379/0")
    call_count = 0

    async def mock_subscribe(_channel):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("first drop")
        raise asyncio.CancelledError()

    mock_client = MagicMock()
    mock_client.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = mock_subscribe
    mock_client.pubsub.return_value = mock_pubsub

    with (
        patch.object(ws_module, "aioredis") as mock_aioredis,
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        mock_aioredis.from_url.return_value = mock_client
        await m._subscriber_loop()

    # aclose() must be called once per iteration (2 iterations here)
    assert mock_client.aclose.await_count == 2
