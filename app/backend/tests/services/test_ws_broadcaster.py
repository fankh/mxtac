"""Tests for websocket_broadcaster — reads enriched alerts from queue and broadcasts to clients.

Coverage:
  - websocket_broadcaster(): subscribes to Topic.ENRICHED
  - websocket_broadcaster(): uses "ws-broadcaster" as the consumer group
  - websocket_broadcaster(): calls broadcast_alert with the alert payload on each message
  - websocket_broadcaster(): processes each message independently (multiple alerts)
  - websocket_broadcaster(): handles broadcast_alert exceptions non-fatally (does not re-raise)
  - websocket_broadcaster(): consumer task survives a broadcast_alert failure and processes next message
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.ws_broadcaster import websocket_broadcaster


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(*, rule_id: str = "sigma-T1059", host: str = "srv-01") -> dict:
    return {
        "id": "test-uuid-001",
        "rule_id": rule_id,
        "rule_title": "Command Shell Execution",
        "level": "high",
        "host": host,
    }


# ---------------------------------------------------------------------------
# Section 1 — subscription registration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_subscribes_to_enriched_topic():
    """websocket_broadcaster() must subscribe to Topic.ENRICHED."""
    queue = InMemoryQueue()
    await queue.start()

    subscribed_topics: list[str] = []
    original_subscribe = queue.subscribe

    async def capture_subscribe(topic, group, handler):
        subscribed_topics.append(topic)
        return await original_subscribe(topic, group, handler)

    with patch.object(queue, "subscribe", side_effect=capture_subscribe):
        await websocket_broadcaster(queue)

    assert Topic.ENRICHED in subscribed_topics

    await queue.stop()


@pytest.mark.asyncio
async def test_uses_ws_broadcaster_consumer_group():
    """websocket_broadcaster() must register with the 'ws-broadcaster' consumer group."""
    queue = InMemoryQueue()
    await queue.start()

    captured_groups: list[str] = []
    original_subscribe = queue.subscribe

    async def capture_subscribe(topic, group, handler):
        captured_groups.append(group)
        return await original_subscribe(topic, group, handler)

    with patch.object(queue, "subscribe", side_effect=capture_subscribe):
        await websocket_broadcaster(queue)

    assert "ws-broadcaster" in captured_groups

    await queue.stop()


# ---------------------------------------------------------------------------
# Section 2 — message handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_calls_broadcast_alert_with_alert_payload():
    """Publishing to mxtac.enriched must trigger broadcast_alert with the alert payload."""
    queue = InMemoryQueue()
    await queue.start()

    mock_broadcast = AsyncMock()

    with patch("app.api.v1.endpoints.websocket.broadcast_alert", mock_broadcast):
        await websocket_broadcaster(queue)

        alert = _make_alert()
        await queue.publish(Topic.ENRICHED, alert)
        await asyncio.sleep(0.05)

    await queue.stop()

    mock_broadcast.assert_awaited_once()
    called_alert = mock_broadcast.call_args[0][0]
    assert called_alert["id"] == alert["id"]
    assert called_alert["rule_id"] == alert["rule_id"]


@pytest.mark.asyncio
async def test_calls_broadcast_alert_for_each_message():
    """Each message published to mxtac.enriched triggers a separate broadcast_alert call."""
    queue = InMemoryQueue()
    await queue.start()

    mock_broadcast = AsyncMock()

    with patch("app.api.v1.endpoints.websocket.broadcast_alert", mock_broadcast):
        await websocket_broadcaster(queue)

        alerts = [_make_alert(rule_id=f"sigma-T{i}", host=f"host-{i}") for i in range(3)]
        for a in alerts:
            await queue.publish(Topic.ENRICHED, a)
        await asyncio.sleep(0.1)

    await queue.stop()

    assert mock_broadcast.await_count == 3


# ---------------------------------------------------------------------------
# Section 3 — error handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_exception_is_non_fatal():
    """When broadcast_alert raises, _handle must swallow the exception without crashing."""
    queue = InMemoryQueue()
    await queue.start()

    mock_broadcast = AsyncMock(side_effect=RuntimeError("connection lost"))

    with patch("app.api.v1.endpoints.websocket.broadcast_alert", mock_broadcast):
        await websocket_broadcaster(queue)

        # Must not raise despite broadcast_alert failing
        await queue.publish(Topic.ENRICHED, _make_alert())
        await asyncio.sleep(0.05)

    await queue.stop()

    # broadcast_alert was still called — the message was not skipped
    mock_broadcast.assert_awaited_once()


@pytest.mark.asyncio
async def test_consumer_task_survives_broadcast_failure():
    """Consumer task must remain alive after a broadcast_alert failure and process next message."""
    queue = InMemoryQueue()
    await queue.start()

    call_count = 0

    async def fail_then_succeed(alert: dict) -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("transient error")

    mock_broadcast = AsyncMock(side_effect=fail_then_succeed)

    with patch("app.api.v1.endpoints.websocket.broadcast_alert", mock_broadcast):
        await websocket_broadcaster(queue)

        await queue.publish(Topic.ENRICHED, _make_alert(host="host-1"))
        await queue.publish(Topic.ENRICHED, _make_alert(host="host-2"))
        await asyncio.sleep(0.1)

    await queue.stop()

    # Both messages were processed — task stayed alive after the first error
    assert call_count == 2
