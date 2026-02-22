"""Tests for AlertManager suppression integration (feature 9.11).

Coverage:
  - _is_suppressed(): returns False when no matching rule exists
  - _is_suppressed(): returns True when a matching suppression rule exists
  - _is_suppressed(): fail-open — returns False when DB raises
  - _is_suppressed(): commits session when rule is matched (to persist hit_count update)
  - _is_suppressed(): uses first technique_id from alert.technique_ids
  - _is_suppressed(): uses first tactic from alert.tactic_ids
  - _is_suppressed(): empty technique_ids -> empty string passed to SuppressionRepo
  - _is_suppressed(): empty tactic_ids -> empty string passed to SuppressionRepo
  - process(): suppressed alert skips enrich, score, publish, and persist
  - process(): non-suppressed alert proceeds normally after suppression check
  - process(): _is_suppressed is not called for duplicate alerts
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.pipeline.queue import InMemoryQueue
from app.services.alert_manager import AlertManager
from app.engine.sigma_engine import SigmaAlert


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc).isoformat()

_ALERT_DICT = {
    "id": "alert-001",
    "rule_id": "sigma-lsass",
    "rule_title": "LSASS Memory Dump",
    "level": "high",
    "severity_id": 4,
    "technique_ids": ["T1003.001"],
    "tactic_ids": ["Credential Access"],
    "host": "win-dc01",
    "time": _NOW,
    "event_snapshot": {},
}


def _make_session_ctx(session=None):
    """Return a context-manager mock wrapping *session*."""
    mock_ctx = AsyncMock()
    mock_session = session or AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_ctx._session = mock_session
    return mock_ctx


def _make_manager(valkey_set_return=True) -> AlertManager:
    queue = InMemoryQueue()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue
    mgr._dispatcher = None
    mgr._valkey = MagicMock()
    mgr._valkey.set = AsyncMock(return_value=valkey_set_return)
    mgr._valkey.aclose = AsyncMock()
    return mgr


# ---------------------------------------------------------------------------
# Unit tests for _is_suppressed()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_suppressed_no_matching_rule():
    """Returns False when SuppressionRepo.match returns None."""
    mgr = _make_manager()
    ctx = _make_session_ctx()

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch(
            "app.repositories.suppression_repo.SuppressionRepo.match",
            new=AsyncMock(return_value=None),
        ),
    ):
        alert = SigmaAlert(
            id="a1", rule_id="sigma-lsass", level="high", severity_id=4,
            technique_ids=["T1003.001"], tactic_ids=["Credential Access"], host="win-dc01",
        )
        result = await mgr._is_suppressed(alert)

    assert result is False


@pytest.mark.asyncio
async def test_is_suppressed_matching_rule_returns_true():
    """Returns True when SuppressionRepo.match returns a rule."""
    mgr = _make_manager()
    mock_rule = MagicMock()
    mock_session = AsyncMock()
    ctx = _make_session_ctx(mock_session)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch(
            "app.repositories.suppression_repo.SuppressionRepo.match",
            new=AsyncMock(return_value=mock_rule),
        ),
    ):
        alert = SigmaAlert(
            id="a1", rule_id="sigma-lsass", level="high", severity_id=4,
            technique_ids=["T1003.001"], tactic_ids=["Credential Access"], host="win-dc01",
        )
        result = await mgr._is_suppressed(alert)

    assert result is True
    mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_is_suppressed_fail_open_on_exception():
    """Returns False (fail-open) when DB raises."""
    mgr = _make_manager()

    with patch(
        "app.core.database.AsyncSessionLocal", side_effect=Exception("DB down")
    ):
        alert = SigmaAlert(id="a1", rule_id="r1", level="medium", severity_id=3, host="host")
        result = await mgr._is_suppressed(alert)

    assert result is False


@pytest.mark.asyncio
async def test_is_suppressed_passes_first_technique_and_tactic():
    """Extracts the first technique_id and tactic_id for matching."""
    mgr = _make_manager()
    ctx = _make_session_ctx()

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch(
            "app.repositories.suppression_repo.SuppressionRepo.match",
            new=AsyncMock(return_value=None),
        ) as mock_match,
    ):
        alert = SigmaAlert(
            id="a1", rule_id="r1", level="medium", severity_id=3, host="srv-01",
            technique_ids=["T1059.001", "T1059.002"],
            tactic_ids=["Execution", "Persistence"],
        )
        await mgr._is_suppressed(alert)

    mock_match.assert_awaited_once()
    call_kwargs = mock_match.call_args.kwargs
    assert call_kwargs["rule_id_val"] == "r1"
    assert call_kwargs["host_val"] == "srv-01"
    assert call_kwargs["technique_id_val"] == "T1059.001"
    assert call_kwargs["tactic_val"] == "Execution"
    assert call_kwargs["severity_val"] == "medium"


@pytest.mark.asyncio
async def test_is_suppressed_empty_lists_use_empty_strings():
    """Empty technique_ids/tactic_ids -> empty strings passed to SuppressionRepo."""
    mgr = _make_manager()
    ctx = _make_session_ctx()

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch(
            "app.repositories.suppression_repo.SuppressionRepo.match",
            new=AsyncMock(return_value=None),
        ) as mock_match,
    ):
        alert = SigmaAlert(
            id="a1", rule_id="r1", level="low", severity_id=2, host="host",
            technique_ids=[], tactic_ids=[],
        )
        await mgr._is_suppressed(alert)

    call_kwargs = mock_match.call_args.kwargs
    assert call_kwargs["technique_id_val"] == ""
    assert call_kwargs["tactic_val"] == ""


# ---------------------------------------------------------------------------
# End-to-end process() integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_suppressed_alert_skips_pipeline():
    """Suppressed alert must not be enriched, scored, published, or persisted."""
    mgr = _make_manager()

    with (
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=False)),
        patch.object(mgr, "_is_suppressed", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_enrich", new=AsyncMock()) as mock_enrich,
        patch.object(mgr, "_persist_to_db", new=AsyncMock()) as mock_persist,
        patch.object(mgr._queue, "publish", new=AsyncMock()) as mock_publish,
    ):
        await mgr.process(_ALERT_DICT)

    mock_enrich.assert_not_awaited()
    mock_publish.assert_not_awaited()
    mock_persist.assert_not_awaited()


@pytest.mark.asyncio
async def test_process_non_suppressed_alert_proceeds():
    """Non-suppressed alert proceeds through the full pipeline."""
    mgr = _make_manager()
    enriched = {**_ALERT_DICT, "asset_criticality": 0.6, "recurrence_count": 0}
    scored = {**enriched, "score": 5.5}

    with (
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=False)),
        patch.object(mgr, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(mgr, "_enrich", new=AsyncMock(return_value=enriched)),
        patch.object(mgr, "_score", new=MagicMock(return_value=scored)),
        patch.object(mgr._queue, "publish", new=AsyncMock()) as mock_publish,
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
    ):
        await mgr.process(_ALERT_DICT)

    mock_publish.assert_awaited_once()


@pytest.mark.asyncio
async def test_process_suppression_not_checked_for_duplicates():
    """_is_suppressed is skipped when the alert is already a duplicate."""
    mgr = _make_manager()

    with (
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_is_suppressed", new=AsyncMock()) as mock_suppressed,
    ):
        await mgr.process(_ALERT_DICT)

    mock_suppressed.assert_not_awaited()
