"""Tests for escalation background task — feature 27.7.

Coverage:
  _build_escalation_alert():
    - returns dict with expected keys and values
    - escalation_message contains "ESCALATED" and the minutes count
    - technique_ids and tactic_ids are lists
    - empty technique_id / tactic → empty list

  _is_already_escalated():
    - returns True when Valkey key exists
    - returns False when Valkey key is absent
    - returns False (fail-open) when Valkey raises

  _mark_escalated():
    - calls SET NX on the expected key
    - swallows Valkey errors silently

  _run_escalation_cycle():
    - skips when channel not found in DB
    - skips when channel is disabled
    - skips when no overdue detections exist
    - escalates a single overdue critical detection
    - escalates a single overdue high detection
    - skips detections already tracked in Valkey
    - does not re-escalate on second call
    - swallows _dispatch_one errors and continues to next detection
    - escalates multiple detections in one cycle

  escalation_task():
    - skips cycle when escalation_channel_id is None
    - calls _run_escalation_cycle when channel_id is set
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.escalation import (
    _build_escalation_alert,
    _is_already_escalated,
    _mark_escalated,
    _run_escalation_cycle,
    _VALKEY_KEY_PREFIX,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_detection(
    *,
    id: str = "det-001",
    severity: str = "critical",
    status: str = "active",
    host: str = "srv-01",
    name: str = "Suspicious PowerShell",
    rule_name: str = "sigma-T1059",
    technique_id: str = "T1059",
    tactic: str = "execution",
    score: float = 9.0,
    created_at: datetime | None = None,
) -> MagicMock:
    det = MagicMock()
    det.id = id
    det.severity = severity
    det.status = status
    det.host = host
    det.name = name
    det.rule_name = rule_name
    det.technique_id = technique_id
    det.tactic = tactic
    det.score = score
    det.created_at = created_at or datetime.now(timezone.utc) - timedelta(minutes=45)
    return det


def _make_channel(
    *,
    id: int = 99,
    name: str = "escalation-channel",
    channel_type: str = "slack",
    config_json: str = '{"webhook_url": "https://hooks.slack.com/escalation"}',
    enabled: bool = True,
    min_severity: str = "low",
    routing_rules: str = "[]",
) -> MagicMock:
    ch = MagicMock()
    ch.id = id
    ch.name = name
    ch.channel_type = channel_type
    ch.config_json = config_json
    ch.enabled = enabled
    ch.min_severity = min_severity
    ch.routing_rules = routing_rules
    return ch


def _make_mock_session(detections: list | None = None, channel=None) -> tuple:
    """Return (session_ctx, session) with pre-configured scalars/execute stubs."""
    session = AsyncMock()

    # Stub execute() for detection query
    det_result = MagicMock()
    det_result.scalars.return_value.all.return_value = detections or []
    session.execute = AsyncMock(return_value=det_result)

    session_ctx = MagicMock()
    session_ctx.__aenter__ = AsyncMock(return_value=session)
    session_ctx.__aexit__ = AsyncMock(return_value=False)

    return session_ctx, session


# ---------------------------------------------------------------------------
# Section 1 — _build_escalation_alert()
# ---------------------------------------------------------------------------


def test_build_escalation_alert_structure():
    """_build_escalation_alert() must return a dict with all expected keys."""
    det = _make_detection()
    alert = _build_escalation_alert(det, minutes_active=42)

    assert alert["id"] == det.id
    assert alert["rule_id"] == det.rule_name
    assert alert["rule_title"] == det.name
    assert alert["level"] == det.severity
    assert alert["host"] == det.host
    assert alert["score"] == det.score
    assert alert["escalated"] is True
    assert isinstance(alert["technique_ids"], list)
    assert isinstance(alert["tactic_ids"], list)


def test_build_escalation_alert_message_contains_minutes():
    """escalation_message must mention the number of minutes active."""
    det = _make_detection()
    alert = _build_escalation_alert(det, minutes_active=67)
    assert "67" in alert["escalation_message"]
    assert "ESCALATED" in alert["escalation_message"]


def test_build_escalation_alert_technique_in_list():
    """technique_id is wrapped in a list."""
    det = _make_detection(technique_id="T1078")
    alert = _build_escalation_alert(det, minutes_active=30)
    assert alert["technique_ids"] == ["T1078"]


def test_build_escalation_alert_empty_technique():
    """When technique_id is falsy, technique_ids should be an empty list."""
    det = _make_detection(technique_id="")
    alert = _build_escalation_alert(det, minutes_active=30)
    assert alert["technique_ids"] == []


def test_build_escalation_alert_tactic_in_list():
    """tactic is wrapped in a list."""
    det = _make_detection(tactic="lateral-movement")
    alert = _build_escalation_alert(det, minutes_active=30)
    assert alert["tactic_ids"] == ["lateral-movement"]


def test_build_escalation_alert_uses_rule_name_as_rule_id():
    """rule_id falls back to detection id when rule_name is falsy."""
    det = _make_detection(rule_name="")
    alert = _build_escalation_alert(det, minutes_active=30)
    assert alert["rule_id"] == det.id


# ---------------------------------------------------------------------------
# Section 2 — _is_already_escalated()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_already_escalated_returns_true_when_key_exists():
    """Returns True when the Valkey key exists."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value="1")

    with patch("app.services.escalation.get_valkey_client", return_value=mock_client):
        result = await _is_already_escalated("det-001")

    assert result is True
    mock_client.get.assert_awaited_once_with(f"{_VALKEY_KEY_PREFIX}det-001")


@pytest.mark.asyncio
async def test_is_already_escalated_returns_false_when_key_missing():
    """Returns False when the Valkey key is absent."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=None)

    with patch("app.services.escalation.get_valkey_client", return_value=mock_client):
        result = await _is_already_escalated("det-002")

    assert result is False


@pytest.mark.asyncio
async def test_is_already_escalated_fail_open_on_valkey_error():
    """Returns False (fail-open) when Valkey raises an exception."""
    async def _raise():
        raise ConnectionError("Valkey down")

    with patch(
        "app.services.escalation.get_valkey_client",
        side_effect=ConnectionError("Valkey down"),
    ):
        result = await _is_already_escalated("det-003")

    assert result is False


# ---------------------------------------------------------------------------
# Section 3 — _mark_escalated()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_escalated_calls_set_nx():
    """_mark_escalated() must call client.set(..., nx=True)."""
    mock_client = AsyncMock()
    mock_client.set = AsyncMock(return_value=True)

    with patch("app.services.escalation.get_valkey_client", return_value=mock_client):
        await _mark_escalated("det-001")

    mock_client.set.assert_awaited_once_with(
        f"{_VALKEY_KEY_PREFIX}det-001", "1", nx=True
    )


@pytest.mark.asyncio
async def test_mark_escalated_swallows_valkey_error():
    """_mark_escalated() must not raise when Valkey is unavailable."""
    with patch(
        "app.services.escalation.get_valkey_client",
        side_effect=ConnectionError("Valkey down"),
    ):
        await _mark_escalated("det-001")  # must not raise


# ---------------------------------------------------------------------------
# Section 4 — _run_escalation_cycle()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_cycle_skips_when_channel_not_found():
    """Cycle is a no-op when the escalation channel does not exist in DB."""
    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    session_ctx, session = _make_mock_session()

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 99
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation.AsyncSessionLocal", return_value=session_ctx):
                with patch(
                    "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                    new=AsyncMock(return_value=None),
                ):
                    await _run_escalation_cycle(dispatcher)

    dispatcher._dispatch_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_cycle_skips_when_channel_disabled():
    """Cycle is a no-op when the escalation channel is disabled."""
    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    channel = _make_channel(enabled=False)
    session_ctx, session = _make_mock_session()

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 99
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation.AsyncSessionLocal", return_value=session_ctx):
                with patch(
                    "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                    new=AsyncMock(return_value=channel),
                ):
                    await _run_escalation_cycle(dispatcher)

    dispatcher._dispatch_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_cycle_skips_when_no_overdue_detections():
    """Cycle is a no-op when no detections are overdue."""
    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    channel = _make_channel()
    session_ctx, session = _make_mock_session(detections=[])  # empty result

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 99
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation.AsyncSessionLocal", return_value=session_ctx):
                with patch(
                    "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                    new=AsyncMock(return_value=channel),
                ):
                    await _run_escalation_cycle(dispatcher)

    dispatcher._dispatch_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_cycle_escalates_overdue_critical_detection():
    """Cycle dispatches to the escalation channel for an overdue critical detection."""
    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    channel = _make_channel()
    detection = _make_detection(severity="critical")
    session_ctx, _ = _make_mock_session(detections=[detection])

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 99
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation.AsyncSessionLocal", return_value=session_ctx):
                with patch(
                    "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                    new=AsyncMock(return_value=channel),
                ):
                    with patch(
                        "app.services.escalation._is_already_escalated",
                        new=AsyncMock(return_value=False),
                    ):
                        with patch(
                            "app.services.escalation._mark_escalated",
                            new=AsyncMock(),
                        ):
                            await _run_escalation_cycle(dispatcher)

    dispatcher._dispatch_one.assert_awaited_once()
    call_args = dispatcher._dispatch_one.await_args
    dispatched_channel, alert = call_args.args
    assert dispatched_channel is channel
    assert alert["level"] == "critical"
    assert alert["escalated"] is True
    assert "ESCALATED" in alert["escalation_message"]


@pytest.mark.asyncio
async def test_run_cycle_escalates_overdue_high_detection():
    """Cycle dispatches to the escalation channel for an overdue high detection."""
    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    channel = _make_channel()
    detection = _make_detection(severity="high")
    session_ctx, _ = _make_mock_session(detections=[detection])

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 99
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation.AsyncSessionLocal", return_value=session_ctx):
                with patch(
                    "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                    new=AsyncMock(return_value=channel),
                ):
                    with patch(
                        "app.services.escalation._is_already_escalated",
                        new=AsyncMock(return_value=False),
                    ):
                        with patch(
                            "app.services.escalation._mark_escalated",
                            new=AsyncMock(),
                        ):
                            await _run_escalation_cycle(dispatcher)

    dispatcher._dispatch_one.assert_awaited_once()
    _, alert = dispatcher._dispatch_one.await_args.args
    assert alert["level"] == "high"


@pytest.mark.asyncio
async def test_run_cycle_skips_already_escalated_detection():
    """Cycle skips detections that are already tracked in Valkey."""
    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    channel = _make_channel()
    detection = _make_detection()
    session_ctx, _ = _make_mock_session(detections=[detection])

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 99
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation.AsyncSessionLocal", return_value=session_ctx):
                with patch(
                    "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                    new=AsyncMock(return_value=channel),
                ):
                    with patch(
                        "app.services.escalation._is_already_escalated",
                        new=AsyncMock(return_value=True),  # already escalated
                    ):
                        await _run_escalation_cycle(dispatcher)

    dispatcher._dispatch_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_cycle_marks_escalated_after_dispatch():
    """Cycle records the escalation in Valkey after a successful dispatch."""
    dispatcher = MagicMock()
    dispatcher._dispatch_one = AsyncMock()

    channel = _make_channel()
    detection = _make_detection(id="det-xyz")
    session_ctx, _ = _make_mock_session(detections=[detection])

    mark_escalated = AsyncMock()

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 99
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation.AsyncSessionLocal", return_value=session_ctx):
                with patch(
                    "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                    new=AsyncMock(return_value=channel),
                ):
                    with patch(
                        "app.services.escalation._is_already_escalated",
                        new=AsyncMock(return_value=False),
                    ):
                        with patch(
                            "app.services.escalation._mark_escalated",
                            new=mark_escalated,
                        ):
                            await _run_escalation_cycle(dispatcher)

    mark_escalated.assert_awaited_once_with("det-xyz")


@pytest.mark.asyncio
async def test_run_cycle_swallows_dispatch_error_and_continues():
    """Cycle logs and swallows _dispatch_one errors; other detections proceed."""
    dispatcher = MagicMock()
    fail_count = 0

    async def _dispatch_side_effect(channel, alert):
        nonlocal fail_count
        if alert["id"] == "det-001":
            raise RuntimeError("webhook timeout")
        fail_count += 1

    dispatcher._dispatch_one = AsyncMock(side_effect=_dispatch_side_effect)

    channel = _make_channel()
    det1 = _make_detection(id="det-001")
    det2 = _make_detection(id="det-002")
    session_ctx, _ = _make_mock_session(detections=[det1, det2])

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 99
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation.AsyncSessionLocal", return_value=session_ctx):
                with patch(
                    "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                    new=AsyncMock(return_value=channel),
                ):
                    with patch(
                        "app.services.escalation._is_already_escalated",
                        new=AsyncMock(return_value=False),
                    ):
                        with patch(
                            "app.services.escalation._mark_escalated",
                            new=AsyncMock(),
                        ):
                            # Must not raise
                            await _run_escalation_cycle(dispatcher)

    # det-002 was still dispatched despite det-001 failing
    assert fail_count == 1


@pytest.mark.asyncio
async def test_run_cycle_escalates_multiple_detections():
    """Cycle dispatches once per overdue, unescalated detection."""
    dispatcher = MagicMock()
    dispatched_ids: list[str] = []

    async def _capture(ch, alert):
        dispatched_ids.append(alert["id"])

    dispatcher._dispatch_one = AsyncMock(side_effect=_capture)

    channel = _make_channel()
    det1 = _make_detection(id="det-001", severity="critical")
    det2 = _make_detection(id="det-002", severity="high")
    session_ctx, _ = _make_mock_session(detections=[det1, det2])

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 99
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation.AsyncSessionLocal", return_value=session_ctx):
                with patch(
                    "app.repositories.notification_channel_repo.NotificationChannelRepo.get_by_id",
                    new=AsyncMock(return_value=channel),
                ):
                    with patch(
                        "app.services.escalation._is_already_escalated",
                        new=AsyncMock(return_value=False),
                    ):
                        with patch(
                            "app.services.escalation._mark_escalated",
                            new=AsyncMock(),
                        ):
                            await _run_escalation_cycle(dispatcher)

    assert sorted(dispatched_ids) == ["det-001", "det-002"]


# ---------------------------------------------------------------------------
# Section 5 — escalation_task() outer loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_escalation_task_skips_when_no_channel_id():
    """escalation_task() skips _run_escalation_cycle when channel_id is None."""
    run_cycle = AsyncMock()

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = None  # not configured
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation._run_escalation_cycle", new=run_cycle):
                with patch("app.services.escalation._CHECK_INTERVAL_SECS", 0):
                    # Run one iteration then cancel
                    task = asyncio.create_task(
                        __import__(
                            "app.services.escalation", fromlist=["escalation_task"]
                        ).escalation_task()
                    )
                    await asyncio.sleep(0)  # let the task run one sleep
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

    run_cycle.assert_not_awaited()


@pytest.mark.asyncio
async def test_escalation_task_calls_run_cycle_when_channel_id_set():
    """escalation_task() calls _run_escalation_cycle when channel_id is configured."""
    from app.services.escalation import escalation_task

    cycles_run: list[int] = []

    async def fake_cycle(dispatcher):
        cycles_run.append(1)

    dispatcher = MagicMock()
    dispatcher.close = AsyncMock()

    with patch("app.core.config.settings") as mock_settings:
        mock_settings.escalation_timeout_minutes = 30
        mock_settings.escalation_channel_id = 42
        with patch("app.services.escalation.settings", mock_settings):
            with patch("app.services.escalation._run_escalation_cycle", side_effect=fake_cycle):
                with patch("app.services.escalation._CHECK_INTERVAL_SECS", 0):
                    task = asyncio.create_task(escalation_task(dispatcher=dispatcher))
                    # Allow one sleep(0) iteration
                    await asyncio.sleep(0)
                    await asyncio.sleep(0)
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

    assert len(cycles_run) >= 1
