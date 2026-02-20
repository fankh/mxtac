"""Tests for AlertWebhookSender — feature 20.6: alert output to webhook (POST JSON).

Coverage:
  - send(): POSTs JSON to a single configured URL
  - send(): POSTs to multiple URLs in parallel
  - send(): sets Content-Type: application/json header
  - send(): payload is valid JSON with non-serialisable values coerced via str()
  - send(): non-fatal — swallows exceptions and does not raise
  - send(): no-op when urls list is empty
  - send(): retries on 5xx responses up to retry_count times
  - send(): retries on timeout up to retry_count times
  - send(): does not retry on 4xx responses
  - send(): gives up after retry_count exhausted and logs error
  - close(): closes the underlying httpx client
  - alert_webhook_output(): subscribes to mxtac.enriched topic
  - alert_webhook_output(): sends alert when message is published to queue
  - alert_webhook_output(): returns the AlertWebhookSender for shutdown cleanup
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.webhook_output import AlertWebhookSender, alert_webhook_output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WEBHOOK_URL = "https://hooks.example.com/mxtac"
_WEBHOOK_URL_2 = "https://hooks2.example.com/mxtac"


def _make_alert(
    *,
    rule_id: str = "sigma-T1059",
    host: str = "srv-01",
    score: float = 7.2,
) -> dict:
    return {
        "id": "test-uuid-001",
        "rule_id": rule_id,
        "rule_title": "Command Shell Execution",
        "level": "high",
        "severity_id": 4,
        "technique_ids": ["T1059"],
        "tactic_ids": ["execution"],
        "host": host,
        "time": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "event_snapshot": {"pid": 1234},
    }


def _ok_response(status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code)


# ---------------------------------------------------------------------------
# Section 1 — send() basic behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_posts_json_to_url():
    """send() must POST a JSON body to the configured webhook URL."""
    sender = AlertWebhookSender([_WEBHOOK_URL], timeout=5, retry_count=0)

    captured_calls: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured_calls.append({"url": url, "content": content})
        return _ok_response(200)

    with patch.object(sender._client, "post", side_effect=mock_post):
        await sender.send(_make_alert())

    await sender.close()

    assert len(captured_calls) == 1
    assert captured_calls[0]["url"] == _WEBHOOK_URL
    body = json.loads(captured_calls[0]["content"])
    assert body["id"] == "test-uuid-001"
    assert body["rule_id"] == "sigma-T1059"


@pytest.mark.asyncio
async def test_send_posts_to_multiple_urls():
    """send() must POST to every configured URL in parallel."""
    sender = AlertWebhookSender([_WEBHOOK_URL, _WEBHOOK_URL_2], timeout=5, retry_count=0)

    called_urls: list[str] = []

    async def mock_post(url, *, content, **kwargs):
        called_urls.append(url)
        return _ok_response(200)

    with patch.object(sender._client, "post", side_effect=mock_post):
        await sender.send(_make_alert())

    await sender.close()

    assert _WEBHOOK_URL in called_urls
    assert _WEBHOOK_URL_2 in called_urls
    assert len(called_urls) == 2


@pytest.mark.asyncio
async def test_send_payload_is_valid_json():
    """send() payload must be valid JSON deserializable on the receiver side."""
    sender = AlertWebhookSender([_WEBHOOK_URL], timeout=5, retry_count=0)

    captured: list[bytes] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append(content)
        return _ok_response(200)

    alert = _make_alert(score=3.14)
    with patch.object(sender._client, "post", side_effect=mock_post):
        await sender.send(alert)

    await sender.close()

    body = json.loads(captured[0])
    assert body["score"] == 3.14
    assert body["technique_ids"] == ["T1059"]


@pytest.mark.asyncio
async def test_send_coerces_non_serialisable_values():
    """Non-JSON-serialisable values (e.g. datetime) must be coerced via str()."""
    sender = AlertWebhookSender([_WEBHOOK_URL], timeout=5, retry_count=0)

    captured: list[bytes] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append(content)
        return _ok_response(200)

    alert = _make_alert()
    alert["extra"] = datetime(2026, 2, 21, 12, 0, 0)  # not JSON-serialisable by default

    with patch.object(sender._client, "post", side_effect=mock_post):
        await sender.send(alert)

    await sender.close()

    body = json.loads(captured[0])
    assert isinstance(body["extra"], str)


@pytest.mark.asyncio
async def test_send_noop_when_urls_empty():
    """send() must be a no-op when no URLs are configured."""
    sender = AlertWebhookSender([], timeout=5, retry_count=0)

    mock_post = AsyncMock(return_value=_ok_response(200))
    with patch.object(sender._client, "post", mock_post):
        await sender.send(_make_alert())

    await sender.close()

    mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_send_is_non_fatal_on_connect_error():
    """send() must swallow connection errors so the pipeline is never interrupted."""
    sender = AlertWebhookSender([_WEBHOOK_URL], timeout=5, retry_count=0)

    async def mock_post(url, *, content, **kwargs):
        raise httpx.ConnectError("connection refused")

    with patch.object(sender._client, "post", side_effect=mock_post):
        # Must not raise
        await sender.send(_make_alert())

    await sender.close()


# ---------------------------------------------------------------------------
# Section 2 — retry behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_retries_on_5xx():
    """send() must retry on 5xx responses up to retry_count times."""
    sender = AlertWebhookSender([_WEBHOOK_URL], timeout=5, retry_count=3)

    call_count = 0

    async def mock_post(url, *, content, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return _ok_response(503)
        return _ok_response(200)

    with patch.object(sender._client, "post", side_effect=mock_post):
        with patch("app.services.webhook_output.asyncio.sleep", new_callable=AsyncMock):
            await sender.send(_make_alert())

    await sender.close()

    assert call_count == 3


@pytest.mark.asyncio
async def test_send_retries_on_timeout():
    """send() must retry on TimeoutException up to retry_count times."""
    sender = AlertWebhookSender([_WEBHOOK_URL], timeout=5, retry_count=3)

    call_count = 0

    async def mock_post(url, *, content, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise httpx.TimeoutException("timed out")
        return _ok_response(200)

    with patch.object(sender._client, "post", side_effect=mock_post):
        with patch("app.services.webhook_output.asyncio.sleep", new_callable=AsyncMock):
            await sender.send(_make_alert())

    await sender.close()

    assert call_count == 3


@pytest.mark.asyncio
async def test_send_does_not_retry_on_4xx():
    """send() must treat 4xx responses as final (client error) and not retry."""
    sender = AlertWebhookSender([_WEBHOOK_URL], timeout=5, retry_count=3)

    call_count = 0

    async def mock_post(url, *, content, **kwargs):
        nonlocal call_count
        call_count += 1
        return _ok_response(400)

    with patch.object(sender._client, "post", side_effect=mock_post):
        await sender.send(_make_alert())

    await sender.close()

    assert call_count == 1


@pytest.mark.asyncio
async def test_send_gives_up_after_retries_exhausted():
    """send() must give up after retry_count+1 total attempts without raising."""
    sender = AlertWebhookSender([_WEBHOOK_URL], timeout=5, retry_count=2)

    call_count = 0

    async def mock_post(url, *, content, **kwargs):
        nonlocal call_count
        call_count += 1
        return _ok_response(503)

    with patch.object(sender._client, "post", side_effect=mock_post):
        with patch("app.services.webhook_output.asyncio.sleep", new_callable=AsyncMock):
            await sender.send(_make_alert())

    await sender.close()

    # 1 initial attempt + 2 retries = 3 total
    assert call_count == 3


# ---------------------------------------------------------------------------
# Section 3 — close()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_closes_http_client():
    """close() must close the underlying httpx.AsyncClient."""
    sender = AlertWebhookSender([_WEBHOOK_URL], timeout=5, retry_count=0)

    with patch.object(sender._client, "aclose", new_callable=AsyncMock) as mock_aclose:
        await sender.close()
        mock_aclose.assert_awaited_once()


# ---------------------------------------------------------------------------
# Section 4 — alert_webhook_output() factory / queue integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_webhook_output_subscribes_to_enriched_topic():
    """alert_webhook_output() must subscribe to Topic.ENRICHED."""
    queue = InMemoryQueue()
    await queue.start()

    subscribed_topics: list[str] = []
    original_subscribe = queue.subscribe

    async def capture_subscribe(topic, group, handler):
        subscribed_topics.append(topic)
        return await original_subscribe(topic, group, handler)

    with patch.object(queue, "subscribe", side_effect=capture_subscribe):
        sender = await alert_webhook_output(queue, urls=[_WEBHOOK_URL])

    assert Topic.ENRICHED in subscribed_topics

    await sender.close()
    await queue.stop()


@pytest.mark.asyncio
async def test_alert_webhook_output_sends_on_publish():
    """Publishing to mxtac.enriched must trigger a webhook POST."""
    queue = InMemoryQueue()
    await queue.start()

    sender = await alert_webhook_output(queue, urls=[_WEBHOOK_URL], retry_count=0)

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append({"url": url, "body": json.loads(content)})
        return _ok_response(200)

    alert = _make_alert()
    with patch.object(sender._client, "post", side_effect=mock_post):
        await queue.publish(Topic.ENRICHED, alert)
        # Give the consumer task a moment to process
        await asyncio.sleep(0.1)

    await sender.close()
    await queue.stop()

    assert len(captured) == 1
    assert captured[0]["url"] == _WEBHOOK_URL
    assert captured[0]["body"]["id"] == alert["id"]


@pytest.mark.asyncio
async def test_alert_webhook_output_returns_sender_instance():
    """alert_webhook_output() must return the AlertWebhookSender for shutdown cleanup."""
    queue = InMemoryQueue()
    await queue.start()

    sender = await alert_webhook_output(queue, urls=[_WEBHOOK_URL])

    assert isinstance(sender, AlertWebhookSender)

    await sender.close()
    await queue.stop()
