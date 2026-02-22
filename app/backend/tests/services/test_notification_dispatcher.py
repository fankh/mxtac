"""Tests for NotificationDispatcher — feature 27.2 / 27.3 / 27.4.

Coverage:
  dispatch():
    - routes to slack channel when severity >= min_severity
    - skips channel when alert severity < min_severity
    - skips when rate-limited (same channel+rule+host within 5 min)
    - allows dispatch after rate limit window expires
    - handles multiple channels concurrently
    - non-fatal when a channel send raises an exception
    - no-op when no channels are enabled

  _send_slack() — Block Kit (27.4):
    - POSTs formatted Block Kit JSON payload to webhook_url
    - payload contains header, section, and context blocks
    - header block includes severity emoji for each level (🔴🟠🟡⚪)
    - section block includes host, rule name, tactic, and technique
    - context block includes timestamp and score
    - attachment color sidebar matches severity (red/orange/yellow/gray)
    - channel and username are set in payload when configured
    - channel and username keys absent when not configured
    - skips and logs warning when webhook_url is empty
    - logs warning on non-2xx response (no retry on 400)

  _send_webhook():
    - POSTs alert JSON to configured url
    - includes Authorization header when auth_token is set
    - uses configured method (PUT)
    - skips and logs warning when url is empty

  _send_msteams():
    - POSTs adaptive card JSON to webhook_url
    - skips and logs warning when webhook_url is empty

  _send_email():
    - sends via aiosmtplib (async SMTP)
    - subject line follows "[MxTac {SEVERITY}] {title} on {host}" format
    - HTML body contains title, severity, host, tactic, technique, timestamp
    - uses implicit TLS when use_tls=True
    - uses STARTTLS when use_tls=False
    - supports multiple to_addresses
    - skips and logs warning when to_addresses is empty

  load_channels():
    - caches channels and skips DB on second call within TTL
    - refreshes from DB after TTL expires
    - returns stale cache when DB call fails
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.notification_dispatcher import NotificationDispatcher, _RATE_LIMIT_WINDOW


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    *,
    rule_id: str = "sigma-T1059",
    host: str = "srv-01",
    level: str = "high",
    score: float = 7.5,
) -> dict:
    return {
        "id": "test-uuid-001",
        "rule_id": rule_id,
        "rule_title": "Command Shell Execution",
        "level": level,
        "severity_id": 4,
        "technique_ids": ["T1059"],
        "tactic_ids": ["execution"],
        "host": host,
        "time": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "event_snapshot": {"pid": 1234},
    }


def _make_channel(
    *,
    id: int = 1,
    name: str = "test-slack",
    channel_type: str = "slack",
    config_json: str = '{"webhook_url": "https://hooks.slack.com/test"}',
    enabled: bool = True,
    min_severity: str = "high",
) -> MagicMock:
    ch = MagicMock()
    ch.id = id
    ch.name = name
    ch.channel_type = channel_type
    ch.config_json = config_json
    ch.enabled = enabled
    ch.min_severity = min_severity
    return ch


def _ok_response(status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code)


# ---------------------------------------------------------------------------
# Section 1 — dispatch() routing and filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_routes_to_matching_channel():
    """dispatch() sends to channels whose min_severity is met."""
    dispatcher = NotificationDispatcher()
    channel = _make_channel(channel_type="slack", min_severity="high")

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append({"url": url, "body": json.loads(content)})
        return _ok_response(200)

    with patch.object(dispatcher, "load_channels", new=AsyncMock(return_value=[channel])):
        with patch.object(dispatcher._client, "post", side_effect=mock_post):
            await dispatcher.dispatch(_make_alert(level="high"))

    await dispatcher.close()
    assert len(captured) == 1
    assert "hooks.slack.com" in captured[0]["url"]


@pytest.mark.asyncio
async def test_dispatch_skips_channel_below_min_severity():
    """dispatch() must skip channels whose min_severity is higher than the alert level."""
    dispatcher = NotificationDispatcher()
    channel = _make_channel(channel_type="slack", min_severity="critical")

    mock_post = AsyncMock(return_value=_ok_response(200))

    with patch.object(dispatcher, "load_channels", new=AsyncMock(return_value=[channel])):
        with patch.object(dispatcher._client, "post", mock_post):
            await dispatcher.dispatch(_make_alert(level="high"))  # high < critical

    await dispatcher.close()
    mock_post.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatch_skips_rate_limited_channel():
    """dispatch() must skip a channel that was already notified within the rate window."""
    dispatcher = NotificationDispatcher()
    channel = _make_channel(channel_type="slack", min_severity="low")
    alert = _make_alert(level="high")

    call_count = 0

    async def mock_post(url, *, content, **kwargs):
        nonlocal call_count
        call_count += 1
        return _ok_response(200)

    with patch.object(dispatcher, "load_channels", new=AsyncMock(return_value=[channel])):
        with patch.object(dispatcher._client, "post", side_effect=mock_post):
            await dispatcher.dispatch(alert)   # first dispatch — should send
            await dispatcher.dispatch(alert)   # second dispatch — rate-limited

    await dispatcher.close()
    assert call_count == 1


@pytest.mark.asyncio
async def test_dispatch_allows_after_rate_limit_expires():
    """dispatch() must send again after the rate limit window has passed."""
    dispatcher = NotificationDispatcher()
    channel = _make_channel(channel_type="slack", min_severity="low")
    alert = _make_alert(level="high")
    key = f"{channel.id}:{alert['rule_id']}:{alert['host']}"

    call_count = 0

    async def mock_post(url, *, content, **kwargs):
        nonlocal call_count
        call_count += 1
        return _ok_response(200)

    # Pre-populate cache with a timestamp that is already expired
    expired_ts = time.monotonic() - _RATE_LIMIT_WINDOW - 1
    dispatcher._rate_cache[key] = expired_ts

    with patch.object(dispatcher, "load_channels", new=AsyncMock(return_value=[channel])):
        with patch.object(dispatcher._client, "post", side_effect=mock_post):
            await dispatcher.dispatch(alert)

    await dispatcher.close()
    assert call_count == 1


@pytest.mark.asyncio
async def test_dispatch_handles_multiple_channels():
    """dispatch() must send to all matching channels concurrently."""
    dispatcher = NotificationDispatcher()
    slack_channel = _make_channel(id=1, channel_type="slack", min_severity="low")
    webhook_channel = _make_channel(
        id=2,
        channel_type="webhook",
        config_json='{"url": "https://webhook.example.com/alerts"}',
        min_severity="low",
    )

    captured_urls: list[str] = []

    async def mock_post(url, *, content, **kwargs):
        captured_urls.append(url)
        return _ok_response(200)

    async def mock_request(method, url, *, content, headers, **kwargs):
        captured_urls.append(url)
        return _ok_response(200)

    with patch.object(
        dispatcher,
        "load_channels",
        new=AsyncMock(return_value=[slack_channel, webhook_channel]),
    ):
        with patch.object(dispatcher._client, "post", side_effect=mock_post):
            with patch.object(dispatcher._client, "request", side_effect=mock_request):
                await dispatcher.dispatch(_make_alert(level="high"))

    await dispatcher.close()
    assert any("hooks.slack.com" in u for u in captured_urls)
    assert any("webhook.example.com" in u for u in captured_urls)


@pytest.mark.asyncio
async def test_dispatch_non_fatal_on_channel_error():
    """dispatch() must swallow channel send exceptions (non-fatal)."""
    dispatcher = NotificationDispatcher()
    channel = _make_channel(channel_type="slack", min_severity="low")

    async def mock_post(url, *, content, **kwargs):
        raise httpx.ConnectError("refused")

    with patch.object(dispatcher, "load_channels", new=AsyncMock(return_value=[channel])):
        with patch.object(dispatcher._client, "post", side_effect=mock_post):
            # Must not raise
            await dispatcher.dispatch(_make_alert(level="high"))

    await dispatcher.close()


@pytest.mark.asyncio
async def test_dispatch_noop_when_no_channels():
    """dispatch() must be a no-op when no enabled channels exist."""
    dispatcher = NotificationDispatcher()
    mock_post = AsyncMock(return_value=_ok_response(200))

    with patch.object(dispatcher, "load_channels", new=AsyncMock(return_value=[])):
        with patch.object(dispatcher._client, "post", mock_post):
            await dispatcher.dispatch(_make_alert())

    await dispatcher.close()
    mock_post.assert_not_awaited()


# ---------------------------------------------------------------------------
# Section 2 — _send_slack()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_slack_posts_to_webhook_url():
    """_send_slack() must POST a JSON payload to the configured webhook_url."""
    dispatcher = NotificationDispatcher()
    config = {"webhook_url": "https://hooks.slack.com/test", "channel": "#alerts"}

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append({"url": url, "body": json.loads(content)})
        return _ok_response(200)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        await dispatcher._send_slack(config, _make_alert(level="critical"))

    await dispatcher.close()
    assert len(captured) == 1
    assert captured[0]["url"] == "https://hooks.slack.com/test"
    body = captured[0]["body"]
    assert body["channel"] == "#alerts"
    assert "CRITICAL" in body["text"]
    assert "attachments" in body


@pytest.mark.asyncio
async def test_send_slack_skips_when_no_webhook_url():
    """_send_slack() must skip silently when webhook_url is empty."""
    dispatcher = NotificationDispatcher()
    mock_post = AsyncMock(return_value=_ok_response(200))

    with patch.object(dispatcher._client, "post", mock_post):
        await dispatcher._send_slack({}, _make_alert())

    await dispatcher.close()
    mock_post.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_slack_logs_warning_on_4xx():
    """_send_slack() must log a warning when the server returns a 4xx response."""
    dispatcher = NotificationDispatcher()
    config = {"webhook_url": "https://hooks.slack.com/test"}

    async def mock_post(url, *, content, **kwargs):
        return _ok_response(400)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        with patch("app.services.notification_dispatcher.logger") as mock_logger:
            await dispatcher._send_slack(config, _make_alert())
            mock_logger.warning.assert_called()

    await dispatcher.close()


@pytest.mark.asyncio
async def test_send_slack_block_kit_structure():
    """_send_slack() payload must contain header, section, and context blocks."""
    dispatcher = NotificationDispatcher()
    config = {"webhook_url": "https://hooks.slack.com/test"}

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append(json.loads(content))
        return _ok_response(200)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        await dispatcher._send_slack(config, _make_alert(level="high"))

    await dispatcher.close()
    body = captured[0]
    assert "attachments" in body
    attachment = body["attachments"][0]
    assert "blocks" in attachment
    block_types = [b["type"] for b in attachment["blocks"]]
    assert "header" in block_types
    assert "section" in block_types
    assert "context" in block_types


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "level, emoji",
    [
        ("critical", "\U0001f534"),  # 🔴
        ("high",     "\U0001f7e0"),  # 🟠
        ("medium",   "\U0001f7e1"),  # 🟡
        ("low",      "\u26aa"),      # ⚪
    ],
)
async def test_send_slack_severity_emojis(level: str, emoji: str):
    """_send_slack() header block must include the correct severity emoji."""
    dispatcher = NotificationDispatcher()
    config = {"webhook_url": "https://hooks.slack.com/test"}

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append(json.loads(content))
        return _ok_response(200)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        await dispatcher._send_slack(config, _make_alert(level=level))

    await dispatcher.close()
    header = captured[0]["attachments"][0]["blocks"][0]
    assert header["type"] == "header"
    assert emoji in header["text"]["text"]


@pytest.mark.asyncio
async def test_send_slack_section_contains_alert_fields():
    """_send_slack() section block must include host, rule name, tactic, and technique."""
    dispatcher = NotificationDispatcher()
    config = {"webhook_url": "https://hooks.slack.com/test"}
    alert = _make_alert(level="high", host="srv-db")
    alert["rule_title"] = "Credential Access"
    alert["tactic_ids"] = ["credential-access"]
    alert["technique_ids"] = ["T1003"]

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append(json.loads(content))
        return _ok_response(200)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        await dispatcher._send_slack(config, alert)

    await dispatcher.close()
    attachment = captured[0]["attachments"][0]
    section = next(b for b in attachment["blocks"] if b["type"] == "section")
    all_field_text = " ".join(f["text"] for f in section["fields"])
    assert "srv-db" in all_field_text
    assert "Credential Access" in all_field_text
    assert "credential-access" in all_field_text
    assert "T1003" in all_field_text


@pytest.mark.asyncio
async def test_send_slack_context_contains_timestamp_and_score():
    """_send_slack() context block must include timestamp and score."""
    dispatcher = NotificationDispatcher()
    config = {"webhook_url": "https://hooks.slack.com/test"}
    alert = _make_alert(level="medium", score=6.5)
    alert["time"] = "2024-03-15T08:00:00Z"

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append(json.loads(content))
        return _ok_response(200)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        await dispatcher._send_slack(config, alert)

    await dispatcher.close()
    attachment = captured[0]["attachments"][0]
    context = next(b for b in attachment["blocks"] if b["type"] == "context")
    context_text = " ".join(e["text"] for e in context["elements"])
    assert "2024-03-15T08:00:00Z" in context_text
    assert "6.5" in context_text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "level, expected_color",
    [
        ("critical", "#CC0000"),
        ("high",     "#FF8C00"),
        ("medium",   "#FFD700"),
        ("low",      "#808080"),
    ],
)
async def test_send_slack_color_sidebar_per_severity(level: str, expected_color: str):
    """_send_slack() attachment color must match severity: red/orange/yellow/gray."""
    dispatcher = NotificationDispatcher()
    config = {"webhook_url": "https://hooks.slack.com/test"}

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append(json.loads(content))
        return _ok_response(200)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        await dispatcher._send_slack(config, _make_alert(level=level))

    await dispatcher.close()
    assert captured[0]["attachments"][0]["color"] == expected_color


@pytest.mark.asyncio
async def test_send_slack_channel_and_username_override():
    """_send_slack() must set channel and username in payload when configured."""
    dispatcher = NotificationDispatcher()
    config = {
        "webhook_url": "https://hooks.slack.com/test",
        "channel": "#security-ops",
        "username": "MxTac-Bot",
    }

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append(json.loads(content))
        return _ok_response(200)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        await dispatcher._send_slack(config, _make_alert())

    await dispatcher.close()
    body = captured[0]
    assert body["channel"] == "#security-ops"
    assert body["username"] == "MxTac-Bot"


@pytest.mark.asyncio
async def test_send_slack_no_channel_key_when_not_configured():
    """_send_slack() must omit channel and username keys when not set in config."""
    dispatcher = NotificationDispatcher()
    config = {"webhook_url": "https://hooks.slack.com/test"}

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append(json.loads(content))
        return _ok_response(200)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        await dispatcher._send_slack(config, _make_alert())

    await dispatcher.close()
    body = captured[0]
    assert "channel" not in body
    assert "username" not in body


# ---------------------------------------------------------------------------
# Section 3 — _send_webhook()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_webhook_posts_alert_json():
    """_send_webhook() must POST the full alert dict as JSON."""
    dispatcher = NotificationDispatcher()
    config = {"url": "https://webhook.example.com/alerts"}

    captured: list[dict] = []

    async def mock_request(method, url, *, content, headers, **kwargs):
        captured.append({"method": method, "url": url, "body": json.loads(content)})
        return _ok_response(200)

    alert = _make_alert()
    with patch.object(dispatcher._client, "request", side_effect=mock_request):
        await dispatcher._send_webhook(config, alert)

    await dispatcher.close()
    assert len(captured) == 1
    assert captured[0]["method"] == "POST"
    assert captured[0]["url"] == "https://webhook.example.com/alerts"
    assert captured[0]["body"]["id"] == alert["id"]


@pytest.mark.asyncio
async def test_send_webhook_includes_auth_token():
    """_send_webhook() must add Authorization header when auth_token is set."""
    dispatcher = NotificationDispatcher()
    config = {"url": "https://webhook.example.com/alerts", "auth_token": "s3cr3t"}

    captured_headers: dict = {}

    async def mock_request(method, url, *, content, headers, **kwargs):
        captured_headers.update(headers)
        return _ok_response(200)

    with patch.object(dispatcher._client, "request", side_effect=mock_request):
        await dispatcher._send_webhook(config, _make_alert())

    await dispatcher.close()
    assert captured_headers.get("Authorization") == "Bearer s3cr3t"


@pytest.mark.asyncio
async def test_send_webhook_uses_configured_method():
    """_send_webhook() must use the method from the channel config."""
    dispatcher = NotificationDispatcher()
    config = {"url": "https://webhook.example.com/alerts", "method": "PUT"}

    captured_methods: list[str] = []

    async def mock_request(method, url, *, content, headers, **kwargs):
        captured_methods.append(method)
        return _ok_response(200)

    with patch.object(dispatcher._client, "request", side_effect=mock_request):
        await dispatcher._send_webhook(config, _make_alert())

    await dispatcher.close()
    assert captured_methods == ["PUT"]


@pytest.mark.asyncio
async def test_send_webhook_skips_when_no_url():
    """_send_webhook() must skip silently when url is empty."""
    dispatcher = NotificationDispatcher()
    mock_request = AsyncMock(return_value=_ok_response(200))

    with patch.object(dispatcher._client, "request", mock_request):
        await dispatcher._send_webhook({}, _make_alert())

    await dispatcher.close()
    mock_request.assert_not_awaited()


# ---------------------------------------------------------------------------
# Section 4 — _send_msteams()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_msteams_posts_adaptive_card():
    """_send_msteams() must POST an adaptive card payload."""
    dispatcher = NotificationDispatcher()
    config = {"webhook_url": "https://outlook.office.com/webhooks/test"}

    captured: list[dict] = []

    async def mock_post(url, *, content, **kwargs):
        captured.append({"url": url, "body": json.loads(content)})
        return _ok_response(200)

    with patch.object(dispatcher._client, "post", side_effect=mock_post):
        await dispatcher._send_msteams(config, _make_alert(level="critical"))

    await dispatcher.close()
    assert len(captured) == 1
    body = captured[0]["body"]
    assert body["type"] == "message"
    attachments = body["attachments"]
    assert len(attachments) == 1
    card = attachments[0]["content"]
    assert card["type"] == "AdaptiveCard"
    # Verify the title TextBlock contains the alert level
    title_block = card["body"][0]
    assert "CRITICAL" in title_block["text"]


@pytest.mark.asyncio
async def test_send_msteams_skips_when_no_webhook_url():
    """_send_msteams() must skip silently when webhook_url is empty."""
    dispatcher = NotificationDispatcher()
    mock_post = AsyncMock(return_value=_ok_response(200))

    with patch.object(dispatcher._client, "post", mock_post):
        await dispatcher._send_msteams({}, _make_alert())

    await dispatcher.close()
    mock_post.assert_not_awaited()


# ---------------------------------------------------------------------------
# Section 5 — _send_email()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_sends_via_aiosmtplib():
    """_send_email() must send via aiosmtplib.send (async SMTP)."""
    dispatcher = NotificationDispatcher()
    config = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "from_address": "alerts@example.com",
        "to_addresses": ["analyst@example.com"],
        "use_tls": False,
        "username": "user",
        "password": "pass",
    }

    with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send:
        await dispatcher._send_email(config, _make_alert())

    await dispatcher.close()
    mock_send.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_email_subject_format():
    """_send_email() subject must follow '[MxTac {SEVERITY}] {title} on {host}'."""
    dispatcher = NotificationDispatcher()
    config = {
        "smtp_host": "smtp.example.com",
        "from_address": "alerts@example.com",
        "to_addresses": ["analyst@example.com"],
    }
    alert = _make_alert(level="critical", host="dc-01")
    alert["rule_title"] = "Credential Dumping"

    captured_msg = {}

    async def _capture(msg, **kwargs):
        captured_msg["subject"] = msg["Subject"]

    with patch("aiosmtplib.send", side_effect=_capture):
        await dispatcher._send_email(config, alert)

    await dispatcher.close()
    assert captured_msg["subject"] == "[MxTac CRITICAL] Credential Dumping on dc-01"


@pytest.mark.asyncio
async def test_send_email_html_body_contains_alert_details():
    """_send_email() HTML body must include title, severity, host, tactic, technique, timestamp."""
    dispatcher = NotificationDispatcher()
    config = {
        "smtp_host": "smtp.example.com",
        "from_address": "alerts@example.com",
        "to_addresses": ["analyst@example.com"],
    }
    alert = _make_alert(level="high", host="srv-web")
    alert["rule_title"] = "Suspicious PowerShell"
    alert["tactic_ids"] = ["execution"]
    alert["technique_ids"] = ["T1059.001"]
    alert["time"] = "2024-01-15T10:30:00Z"

    captured_html = {}

    async def _capture(msg, **kwargs):
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                captured_html["body"] = part.get_payload(decode=True).decode("utf-8")

    with patch("aiosmtplib.send", side_effect=_capture):
        await dispatcher._send_email(config, alert)

    await dispatcher.close()
    body = captured_html["body"]
    assert "Suspicious PowerShell" in body
    assert "HIGH" in body
    assert "srv-web" in body
    assert "execution" in body
    assert "T1059.001" in body
    assert "2024-01-15T10:30:00Z" in body


@pytest.mark.asyncio
async def test_send_email_uses_implicit_tls_when_use_tls_true():
    """_send_email() must pass use_tls=True and start_tls=False to aiosmtplib."""
    dispatcher = NotificationDispatcher()
    config = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 465,
        "from_address": "alerts@example.com",
        "to_addresses": ["analyst@example.com"],
        "use_tls": True,
    }

    captured_kwargs: dict = {}

    async def _capture(msg, **kwargs):
        captured_kwargs.update(kwargs)

    with patch("aiosmtplib.send", side_effect=_capture):
        await dispatcher._send_email(config, _make_alert())

    await dispatcher.close()
    assert captured_kwargs.get("use_tls") is True
    assert captured_kwargs.get("start_tls") is False


@pytest.mark.asyncio
async def test_send_email_uses_starttls_when_use_tls_false():
    """_send_email() must pass use_tls=False and start_tls=True when use_tls is False."""
    dispatcher = NotificationDispatcher()
    config = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "from_address": "alerts@example.com",
        "to_addresses": ["analyst@example.com"],
        "use_tls": False,
    }

    captured_kwargs: dict = {}

    async def _capture(msg, **kwargs):
        captured_kwargs.update(kwargs)

    with patch("aiosmtplib.send", side_effect=_capture):
        await dispatcher._send_email(config, _make_alert())

    await dispatcher.close()
    assert captured_kwargs.get("use_tls") is False
    assert captured_kwargs.get("start_tls") is True


@pytest.mark.asyncio
async def test_send_email_supports_multiple_to_addresses():
    """_send_email() To header must include all recipient addresses."""
    dispatcher = NotificationDispatcher()
    recipients = ["soc@example.com", "analyst@example.com", "ciso@example.com"]
    config = {
        "smtp_host": "smtp.example.com",
        "from_address": "alerts@example.com",
        "to_addresses": recipients,
    }

    captured_msg = {}

    async def _capture(msg, **kwargs):
        captured_msg["to"] = msg["To"]

    with patch("aiosmtplib.send", side_effect=_capture):
        await dispatcher._send_email(config, _make_alert())

    await dispatcher.close()
    for addr in recipients:
        assert addr in captured_msg["to"]


@pytest.mark.asyncio
async def test_send_email_skips_when_no_to_addresses():
    """_send_email() must skip silently when to_addresses is empty."""
    dispatcher = NotificationDispatcher()
    config = {
        "smtp_host": "smtp.example.com",
        "from_address": "alerts@example.com",
        "to_addresses": [],
    }

    with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send:
        await dispatcher._send_email(config, _make_alert())

    await dispatcher.close()
    mock_send.assert_not_awaited()


# ---------------------------------------------------------------------------
# Section 6 — load_channels()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_load_channels_caches_within_ttl():
    """load_channels() must not hit the DB again within the TTL window."""
    dispatcher = NotificationDispatcher()
    channel = _make_channel()

    mock_session_ctx = MagicMock()
    mock_session = AsyncMock()
    mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

    call_count = 0

    async def fake_list_enabled(session):
        nonlocal call_count
        call_count += 1
        return [channel]

    # Patch at the source module paths — the dispatcher imports them lazily inside the method
    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session_ctx):
        with patch(
            "app.repositories.notification_channel_repo.NotificationChannelRepo.list_enabled",
            new=AsyncMock(side_effect=fake_list_enabled),
        ):
            result1 = await dispatcher.load_channels()
            result2 = await dispatcher.load_channels()  # within TTL — should use cache

    await dispatcher.close()
    assert call_count == 1  # DB queried only once
    assert result1 == result2


@pytest.mark.asyncio
async def test_load_channels_refreshes_after_ttl():
    """load_channels() must re-query the DB once the cache TTL has expired."""
    dispatcher = NotificationDispatcher()
    channel = _make_channel()

    # Force cache to be stale by setting cache time far in the past
    dispatcher._channels_cache = [channel]
    dispatcher._channels_cache_at = time.monotonic() - 999.0  # well past TTL

    call_count = 0

    mock_session_ctx = MagicMock()
    mock_session = AsyncMock()
    mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

    async def fake_list_enabled(session):
        nonlocal call_count
        call_count += 1
        return [channel]

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session_ctx):
        with patch(
            "app.repositories.notification_channel_repo.NotificationChannelRepo.list_enabled",
            new=AsyncMock(side_effect=fake_list_enabled),
        ):
            await dispatcher.load_channels()

    await dispatcher.close()
    assert call_count == 1  # DB was re-queried after TTL expired


@pytest.mark.asyncio
async def test_load_channels_returns_stale_cache_on_db_error():
    """load_channels() must return the stale cache when the DB call fails."""
    dispatcher = NotificationDispatcher()
    stale_channel = _make_channel(name="stale")

    # Pre-populate cache with stale data (expired TTL)
    dispatcher._channels_cache = [stale_channel]
    dispatcher._channels_cache_at = 0.0  # expired

    # Make the DB session factory raise to simulate a DB connection failure
    with patch("app.core.database.AsyncSessionLocal", side_effect=RuntimeError("DB lost")):
        result = await dispatcher.load_channels()

    await dispatcher.close()
    assert result == [stale_channel]


# ---------------------------------------------------------------------------
# Section 7 — close()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_releases_http_client():
    """close() must call aclose() on the underlying httpx.AsyncClient."""
    dispatcher = NotificationDispatcher()

    with patch.object(
        dispatcher._client, "aclose", new_callable=AsyncMock
    ) as mock_aclose:
        await dispatcher.close()
        mock_aclose.assert_awaited_once()
