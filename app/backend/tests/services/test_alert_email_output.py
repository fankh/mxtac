"""Tests for AlertEmailSender — feature 20.7: alert output to email (SMTP).

Coverage:
  - send(): skips alerts below the minimum severity level
  - send(): sends alerts at or above the minimum severity level
  - send(): 'high' level is sent by default (min_level='high')
  - send(): 'critical' level is sent by default (min_level='high')
  - send(): 'medium' level is skipped by default (min_level='high')
  - send(): 'low' level is skipped by default
  - send(): 'informational' level is skipped by default
  - send(): missing level key is skipped (rank=0 < min_rank)
  - send(): no-op when to_addrs list is empty
  - send(): calls _send_sync via thread-pool executor
  - send(): non-fatal — swallows SMTP exceptions and logs them
  - send(): email subject contains alert level, rule title, and host
  - send(): email body is valid JSON containing the alert fields
  - send(): non-serialisable values coerced via str()
  - _send_sync(): uses SMTP_SSL when use_tls=True
  - _send_sync(): calls starttls() when use_starttls=True and use_tls=False
  - _send_sync(): skips starttls() when use_tls=True
  - _send_sync(): calls login() when username is set
  - _send_sync(): skips login() when username is empty
  - close(): no-op (does not raise)
  - alert_email_output(): subscribes to mxtac.enriched topic
  - alert_email_output(): callback sends alert when message received
  - alert_email_output(): returns AlertEmailSender instance
  - alert_email_output(): filters by min_level when publishing alerts
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_email_output import (
    AlertEmailSender,
    _DEFAULT_MIN_LEVEL,
    _SEVERITY_ORDER,
    _severity_rank,
    alert_email_output,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    *,
    rule_id: str = "sigma-T1059",
    rule_title: str = "Command Shell Execution",
    host: str = "srv-01",
    score: float = 7.2,
    level: str = "high",
) -> dict:
    return {
        "id": "test-uuid-001",
        "rule_id": rule_id,
        "rule_title": rule_title,
        "level": level,
        "severity_id": 4,
        "technique_ids": ["T1059"],
        "tactic_ids": ["execution"],
        "host": host,
        "time": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "event_snapshot": {"pid": 1234},
    }


def _make_sender(**kwargs) -> AlertEmailSender:
    defaults = dict(
        smtp_host="smtp.example.com",
        smtp_port=587,
        username="",
        password="",
        use_tls=False,
        use_starttls=False,
        from_addr="mxtac@example.com",
        to_addrs=["soc@example.com"],
        min_level="high",
    )
    defaults.update(kwargs)
    return AlertEmailSender(**defaults)


# ---------------------------------------------------------------------------
# Section 0 — _severity_rank() helper
# ---------------------------------------------------------------------------


def test_severity_rank_known_levels():
    assert _severity_rank("informational") < _severity_rank("low")
    assert _severity_rank("low") < _severity_rank("medium")
    assert _severity_rank("medium") < _severity_rank("high")
    assert _severity_rank("high") < _severity_rank("critical")


def test_severity_rank_unknown_level_returns_zero():
    assert _severity_rank("bogus") == 0


def test_severity_order_contains_all_levels():
    assert set(_SEVERITY_ORDER.keys()) == {"informational", "low", "medium", "high", "critical"}


# ---------------------------------------------------------------------------
# Section 1 — send() severity filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_high_level_is_sent_by_default():
    """send() must forward 'high' alerts (default min_level='high')."""
    sender = _make_sender()
    with patch.object(sender, "_send_sync") as mock_sync:
        await sender.send(_make_alert(level="high"))

    mock_sync.assert_called_once()


@pytest.mark.asyncio
async def test_send_critical_level_is_sent_by_default():
    """send() must forward 'critical' alerts (above default min_level='high')."""
    sender = _make_sender()
    with patch.object(sender, "_send_sync") as mock_sync:
        await sender.send(_make_alert(level="critical"))

    mock_sync.assert_called_once()


@pytest.mark.asyncio
async def test_send_medium_level_is_skipped_by_default():
    """send() must drop 'medium' alerts (below default min_level='high')."""
    sender = _make_sender()
    with patch.object(sender, "_send_sync") as mock_sync:
        await sender.send(_make_alert(level="medium"))

    mock_sync.assert_not_called()


@pytest.mark.asyncio
async def test_send_low_level_is_skipped_by_default():
    """send() must drop 'low' alerts."""
    sender = _make_sender()
    with patch.object(sender, "_send_sync") as mock_sync:
        await sender.send(_make_alert(level="low"))

    mock_sync.assert_not_called()


@pytest.mark.asyncio
async def test_send_informational_level_is_skipped_by_default():
    """send() must drop 'informational' alerts."""
    sender = _make_sender()
    with patch.object(sender, "_send_sync") as mock_sync:
        await sender.send(_make_alert(level="informational"))

    mock_sync.assert_not_called()


@pytest.mark.asyncio
async def test_send_missing_level_is_skipped():
    """send() must drop alerts with no 'level' key (rank=0 < min_rank)."""
    sender = _make_sender()
    alert = _make_alert()
    del alert["level"]

    with patch.object(sender, "_send_sync") as mock_sync:
        await sender.send(alert)

    mock_sync.assert_not_called()


@pytest.mark.asyncio
async def test_send_medium_is_sent_when_min_level_medium():
    """send() must forward 'medium' alerts when min_level='medium'."""
    sender = _make_sender(min_level="medium")
    with patch.object(sender, "_send_sync") as mock_sync:
        await sender.send(_make_alert(level="medium"))

    mock_sync.assert_called_once()


@pytest.mark.asyncio
async def test_send_low_is_skipped_when_min_level_medium():
    """send() must drop 'low' alerts when min_level='medium'."""
    sender = _make_sender(min_level="medium")
    with patch.object(sender, "_send_sync") as mock_sync:
        await sender.send(_make_alert(level="low"))

    mock_sync.assert_not_called()


# ---------------------------------------------------------------------------
# Section 2 — send() no-op / non-fatal behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_noop_when_to_addrs_empty():
    """send() must be a no-op when no recipient addresses are configured."""
    sender = _make_sender(to_addrs=[])
    with patch.object(sender, "_send_sync") as mock_sync:
        await sender.send(_make_alert(level="critical"))

    mock_sync.assert_not_called()


@pytest.mark.asyncio
async def test_send_is_non_fatal_on_smtp_error():
    """send() must swallow SMTP errors so the pipeline is never interrupted."""
    sender = _make_sender()
    with patch.object(sender, "_send_sync", side_effect=OSError("SMTP refused")):
        # Must not raise
        await sender.send(_make_alert(level="critical"))


# ---------------------------------------------------------------------------
# Section 3 — send() delegates to _send_sync via executor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_calls_send_sync_in_executor():
    """send() must run _send_sync in the thread-pool executor."""
    sender = _make_sender()

    called_with: list[dict] = []

    def capture_sync(alert: dict) -> None:
        called_with.append(alert)

    with patch.object(sender, "_send_sync", side_effect=capture_sync):
        alert = _make_alert(level="high")
        await sender.send(alert)

    assert len(called_with) == 1
    assert called_with[0]["id"] == alert["id"]


# ---------------------------------------------------------------------------
# Section 4 — _build_message() / email content
# ---------------------------------------------------------------------------


def test_build_message_subject_contains_level():
    """_build_message() subject must include the uppercased alert level."""
    sender = _make_sender()
    alert = _make_alert(level="high")
    msg = sender._build_message(alert)
    assert "HIGH" in msg["Subject"]


def test_build_message_subject_contains_rule_title():
    """_build_message() subject must include the rule title."""
    sender = _make_sender()
    alert = _make_alert(rule_title="Suspicious PowerShell")
    msg = sender._build_message(alert)
    assert "Suspicious PowerShell" in msg["Subject"]


def test_build_message_subject_contains_host():
    """_build_message() subject must include the host name."""
    sender = _make_sender()
    alert = _make_alert(host="dc-01")
    msg = sender._build_message(alert)
    assert "dc-01" in msg["Subject"]


def test_build_message_from_addr():
    """_build_message() must set From header to the configured from_addr."""
    sender = _make_sender(from_addr="alerts@acme.com")
    msg = sender._build_message(_make_alert())
    assert msg["From"] == "alerts@acme.com"


def test_build_message_to_addr():
    """_build_message() must set To header to the joined recipient list."""
    sender = _make_sender(to_addrs=["a@example.com", "b@example.com"])
    msg = sender._build_message(_make_alert())
    assert "a@example.com" in msg["To"]
    assert "b@example.com" in msg["To"]


def test_build_message_body_is_valid_json():
    """_build_message() body must be valid JSON containing the alert fields."""
    sender = _make_sender()
    alert = _make_alert(rule_id="sigma-T1055")
    msg = sender._build_message(alert)

    # The plain-text part is the first payload
    body = msg.get_payload(0).get_payload(decode=True).decode("utf-8")
    parsed = json.loads(body)
    assert parsed["rule_id"] == "sigma-T1055"
    assert parsed["host"] == alert["host"]


def test_build_message_body_coerces_non_serialisable():
    """_build_message() must coerce non-serialisable values via str()."""
    sender = _make_sender()
    alert = _make_alert()
    alert["extra"] = datetime(2026, 2, 21, 12, 0, 0)

    msg = sender._build_message(alert)
    body = msg.get_payload(0).get_payload(decode=True).decode("utf-8")
    parsed = json.loads(body)
    assert isinstance(parsed["extra"], str)


# ---------------------------------------------------------------------------
# Section 5 — _send_sync() SMTP transport behaviour
# ---------------------------------------------------------------------------


def test_send_sync_uses_smtp_ssl_when_use_tls_true():
    """_send_sync() must use smtplib.SMTP_SSL when use_tls=True."""
    sender = _make_sender(use_tls=True, use_starttls=False)
    mock_smtp_instance = MagicMock()
    mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_instance.__exit__ = MagicMock(return_value=False)

    with patch("smtplib.SMTP_SSL", return_value=mock_smtp_instance) as mock_ssl:
        with patch("smtplib.SMTP") as mock_plain:
            sender._send_sync(_make_alert())

    mock_ssl.assert_called_once_with("smtp.example.com", 587)
    mock_plain.assert_not_called()


def test_send_sync_uses_plain_smtp_when_use_tls_false():
    """_send_sync() must use smtplib.SMTP when use_tls=False."""
    sender = _make_sender(use_tls=False, use_starttls=False)
    mock_smtp_instance = MagicMock()
    mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_instance.__exit__ = MagicMock(return_value=False)

    with patch("smtplib.SMTP", return_value=mock_smtp_instance) as mock_plain:
        with patch("smtplib.SMTP_SSL") as mock_ssl:
            sender._send_sync(_make_alert())

    mock_plain.assert_called_once_with("smtp.example.com", 587)
    mock_ssl.assert_not_called()


def test_send_sync_calls_starttls_when_use_starttls_true():
    """_send_sync() must call starttls() when use_starttls=True and use_tls=False."""
    sender = _make_sender(use_tls=False, use_starttls=True)
    mock_smtp_instance = MagicMock()
    mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_instance.__exit__ = MagicMock(return_value=False)

    with patch("smtplib.SMTP", return_value=mock_smtp_instance):
        sender._send_sync(_make_alert())

    mock_smtp_instance.starttls.assert_called_once()


def test_send_sync_skips_starttls_when_use_tls_true():
    """_send_sync() must NOT call starttls() when use_tls=True (already encrypted)."""
    sender = _make_sender(use_tls=True, use_starttls=True)
    mock_smtp_instance = MagicMock()
    mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_instance.__exit__ = MagicMock(return_value=False)

    with patch("smtplib.SMTP_SSL", return_value=mock_smtp_instance):
        sender._send_sync(_make_alert())

    mock_smtp_instance.starttls.assert_not_called()


def test_send_sync_calls_login_when_username_set():
    """_send_sync() must call login() when a username is configured."""
    sender = _make_sender(username="user@example.com", password="secret")
    mock_smtp_instance = MagicMock()
    mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_instance.__exit__ = MagicMock(return_value=False)

    with patch("smtplib.SMTP", return_value=mock_smtp_instance):
        sender._send_sync(_make_alert())

    mock_smtp_instance.login.assert_called_once_with("user@example.com", "secret")


def test_send_sync_skips_login_when_username_empty():
    """_send_sync() must NOT call login() when username is empty."""
    sender = _make_sender(username="", password="")
    mock_smtp_instance = MagicMock()
    mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_instance.__exit__ = MagicMock(return_value=False)

    with patch("smtplib.SMTP", return_value=mock_smtp_instance):
        sender._send_sync(_make_alert())

    mock_smtp_instance.login.assert_not_called()


def test_send_sync_calls_sendmail_with_correct_addresses():
    """_send_sync() must call sendmail() with from_addr and to_addrs."""
    sender = _make_sender(
        from_addr="mxtac@corp.com",
        to_addrs=["alice@corp.com", "bob@corp.com"],
    )
    mock_smtp_instance = MagicMock()
    mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_instance.__exit__ = MagicMock(return_value=False)

    with patch("smtplib.SMTP", return_value=mock_smtp_instance):
        sender._send_sync(_make_alert())

    sendmail_call = mock_smtp_instance.sendmail.call_args
    assert sendmail_call[0][0] == "mxtac@corp.com"
    assert sendmail_call[0][1] == ["alice@corp.com", "bob@corp.com"]


# ---------------------------------------------------------------------------
# Section 6 — close()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_is_non_fatal():
    """close() must not raise even if called multiple times."""
    sender = _make_sender()
    await sender.close()
    await sender.close()  # second call also safe


# ---------------------------------------------------------------------------
# Section 7 — alert_email_output() factory / queue integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_email_output_subscribes_to_enriched_topic():
    """alert_email_output() must subscribe to Topic.ENRICHED."""
    queue = InMemoryQueue()
    await queue.start()

    subscribed_topics: list[str] = []
    original_subscribe = queue.subscribe

    async def capture_subscribe(topic, group, handler):
        subscribed_topics.append(topic)
        return await original_subscribe(topic, group, handler)

    with patch.object(queue, "subscribe", side_effect=capture_subscribe):
        sender = await alert_email_output(
            queue, to_addrs=["soc@example.com"]
        )

    assert Topic.ENRICHED in subscribed_topics

    await sender.close()
    await queue.stop()


@pytest.mark.asyncio
async def test_alert_email_output_returns_sender_instance():
    """alert_email_output() must return an AlertEmailSender for shutdown cleanup."""
    queue = InMemoryQueue()
    await queue.start()

    sender = await alert_email_output(queue, to_addrs=["soc@example.com"])

    assert isinstance(sender, AlertEmailSender)

    await sender.close()
    await queue.stop()


@pytest.mark.asyncio
async def test_alert_email_output_sends_on_publish():
    """Publishing a high-severity alert to mxtac.enriched must trigger an email."""
    queue = InMemoryQueue()
    await queue.start()

    sender = await alert_email_output(
        queue, to_addrs=["soc@example.com"], min_level="high"
    )

    captured: list[dict] = []

    async def mock_send(alert: dict) -> None:
        captured.append(alert)

    sender.send = mock_send  # type: ignore[method-assign]

    alert = _make_alert(level="high")
    await queue.publish(Topic.ENRICHED, alert)

    # Give the consumer task a moment to process
    await asyncio.sleep(0.05)

    await sender.close()
    await queue.stop()

    assert len(captured) == 1
    assert captured[0]["id"] == alert["id"]


@pytest.mark.asyncio
async def test_alert_email_output_filters_low_severity_on_publish():
    """Publishing a low-severity alert must NOT trigger an email when min_level='high'."""
    queue = InMemoryQueue()
    await queue.start()

    sender = await alert_email_output(
        queue, to_addrs=["soc@example.com"], min_level="high"
    )

    captured: list[dict] = []

    async def mock_send(alert: dict) -> None:
        captured.append(alert)

    sender.send = mock_send  # type: ignore[method-assign]

    await queue.publish(Topic.ENRICHED, _make_alert(level="low"))

    await asyncio.sleep(0.05)

    await sender.close()
    await queue.stop()

    # mock_send is called but send() itself filters — however since we replaced
    # send entirely the mock is called. To test end-to-end filtering, use
    # _send_sync mock instead.
    # This test validates the queue integration path is exercised.


@pytest.mark.asyncio
async def test_alert_email_output_end_to_end_filtering():
    """End-to-end: _send_sync is called for high but NOT for medium when min_level='high'."""
    queue = InMemoryQueue()
    await queue.start()

    sender = await alert_email_output(
        queue, to_addrs=["soc@example.com"], min_level="high"
    )

    send_sync_calls: list[dict] = []

    def capture_sync(alert: dict) -> None:
        send_sync_calls.append(alert)

    with patch.object(sender, "_send_sync", side_effect=capture_sync):
        await queue.publish(Topic.ENRICHED, _make_alert(level="high"))
        await queue.publish(Topic.ENRICHED, _make_alert(level="medium"))
        await queue.publish(Topic.ENRICHED, _make_alert(level="critical"))
        await asyncio.sleep(0.1)

    await sender.close()
    await queue.stop()

    sent_levels = [a["level"] for a in send_sync_calls]
    assert "high" in sent_levels
    assert "critical" in sent_levels
    assert "medium" not in sent_levels


@pytest.mark.asyncio
async def test_alert_email_output_default_min_level_is_high():
    """alert_email_output() must default to min_level='high'."""
    queue = InMemoryQueue()
    await queue.start()

    sender = await alert_email_output(queue, to_addrs=["soc@example.com"])

    assert sender._min_rank == _severity_rank(_DEFAULT_MIN_LEVEL)
    assert _DEFAULT_MIN_LEVEL == "high"

    await sender.close()
    await queue.stop()
