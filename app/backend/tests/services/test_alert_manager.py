"""Tests for AlertManager — feature 17.5 DB persistence.

Coverage:
  - process(): publishes enriched+scored alert to mxtac.enriched topic
  - process(): calls _persist_to_db after publishing
  - process(): skips duplicates (no publish, no persist)
  - _persist_to_db(): calls DetectionRepo.create with mapped fields
  - _persist_to_db(): logs and continues when DB raises (non-fatal)
  - _score(): attaches score field to enriched dict
  - _asset_criticality(): correct prefix-based lookup
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_manager import AlertManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert_dict(
    *,
    rule_id: str = "sigma-T1059",
    rule_title: str = "Command Shell Execution",
    level: str = "high",
    severity_id: int = 4,
    technique_ids: list[str] | None = None,
    tactic_ids: list[str] | None = None,
    host: str = "srv-01",
) -> dict:
    return {
        "id": "test-uuid-001",
        "rule_id": rule_id,
        "rule_title": rule_title,
        "level": level,
        "severity_id": severity_id,
        "technique_ids": technique_ids or ["T1059"],
        "tactic_ids": tactic_ids or ["execution"],
        "host": host,
        "time": datetime.now(timezone.utc).isoformat(),
        "event_snapshot": {"pid": 1234},
    }


# ---------------------------------------------------------------------------
# Section 1 — process() happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_publishes_to_enriched_topic():
    """process() must publish the enriched+scored alert to mxtac.enriched."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()

    published: list[dict] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert len(published) == 1
    topic, msg = published[0]
    assert topic == Topic.ENRICHED
    assert msg["id"] == "test-uuid-001"
    assert "score" in msg

    await queue.stop()


@pytest.mark.asyncio
async def test_process_calls_persist_to_db_after_publish():
    """process() must call _persist_to_db after publishing to mxtac.enriched."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()) as mock_persist,
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    mock_persist.assert_awaited_once()

    await queue.stop()


@pytest.mark.asyncio
async def test_process_skips_duplicate_alert():
    """process() must not publish or persist when _is_duplicate returns True."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()

    with (
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()) as mock_persist,
        patch.object(queue, "publish", new=AsyncMock()) as mock_publish,
    ):
        await mgr.process(alert_dict)

    mock_publish.assert_not_awaited()
    mock_persist.assert_not_awaited()

    await queue.stop()


# ---------------------------------------------------------------------------
# Section 2 — _persist_to_db()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_persist_to_db_calls_detection_repo_create():
    """_persist_to_db() must call DetectionRepo.create with mapped fields."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    scored = {
        "id": "persist-001",
        "score": 7.2,
        "level": "high",
        "rule_id": "sigma-T1059",
        "rule_title": "Command Shell",
        "technique_ids": ["T1059"],
        "tactic_ids": ["execution"],
        "host": "srv-01",
        "time": datetime.now(timezone.utc).isoformat(),
    }

    mock_session = AsyncMock()
    mock_session_ctx = AsyncMock()
    mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.services.alert_manager.AlertManager._persist_to_db.__wrapped__", create=True),
        patch("app.core.database.AsyncSessionLocal", return_value=mock_session_ctx),
        patch("app.repositories.detection_repo.DetectionRepo.create", new=AsyncMock()) as mock_create,
    ):
        await mgr._persist_to_db(scored)

    mock_create.assert_awaited_once()
    call_kwargs = mock_create.call_args[1]
    assert call_kwargs["id"] == "persist-001"
    assert call_kwargs["score"] == 7.2
    assert call_kwargs["severity"] == "high"
    assert call_kwargs["technique_id"] == "T1059"
    assert call_kwargs["tactic"] == "execution"
    assert call_kwargs["name"] == "Command Shell"
    assert call_kwargs["host"] == "srv-01"


@pytest.mark.asyncio
async def test_persist_to_db_handles_empty_technique_ids():
    """_persist_to_db() must use 'unknown' when technique_ids is empty."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    scored = {
        "id": "persist-002",
        "score": 3.0,
        "level": "low",
        "rule_id": "sigma-misc",
        "rule_title": "Misc Rule",
        "technique_ids": [],
        "tactic_ids": [],
        "host": "lin-01",
        "time": datetime.now(timezone.utc).isoformat(),
    }

    mock_session = AsyncMock()
    mock_session_ctx = AsyncMock()
    mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_session_ctx),
        patch("app.repositories.detection_repo.DetectionRepo.create", new=AsyncMock()) as mock_create,
    ):
        await mgr._persist_to_db(scored)

    call_kwargs = mock_create.call_args[1]
    assert call_kwargs["technique_id"] == "unknown"
    assert call_kwargs["tactic"] == "unknown"
    assert call_kwargs["tactic_id"] is None


@pytest.mark.asyncio
async def test_persist_to_db_is_non_fatal_on_db_error():
    """_persist_to_db() must log and continue when the database raises."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    scored = {
        "id": "persist-err",
        "score": 5.0,
        "level": "medium",
        "rule_id": "sigma-x",
        "rule_title": "Error Rule",
        "technique_ids": ["T1234"],
        "tactic_ids": ["discovery"],
        "host": "win-01",
        "time": datetime.now(timezone.utc).isoformat(),
    }

    mock_session_ctx = AsyncMock()
    mock_session_ctx.__aenter__ = AsyncMock(side_effect=RuntimeError("DB is down"))
    mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session_ctx):
        # Must not raise
        await mgr._persist_to_db(scored)


# ---------------------------------------------------------------------------
# Section 3 — _score()
# ---------------------------------------------------------------------------


def test_score_attaches_score_field():
    """_score() must add a 'score' key to the enriched dict."""
    queue = MagicMock()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue

    enriched = {
        "severity_id": 4,
        "asset_criticality": 0.8,
    }
    result = mgr._score(enriched)
    assert "score" in result
    assert 0.0 <= result["score"] <= 10.0


def test_score_high_severity_yields_higher_score_than_low():
    """_score() must produce a higher score for high severity than low."""
    queue = MagicMock()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue

    high = mgr._score({"severity_id": 5, "asset_criticality": 0.5})
    low  = mgr._score({"severity_id": 1, "asset_criticality": 0.5})
    assert high["score"] > low["score"]


# ---------------------------------------------------------------------------
# Section 4 — _asset_criticality()
# ---------------------------------------------------------------------------


def test_asset_criticality_dc_prefix():
    """DC prefix must yield the highest criticality (1.0)."""
    queue = MagicMock()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue
    assert mgr._asset_criticality("dc-01") == 1.0


def test_asset_criticality_unknown_prefix_defaults():
    """Unknown hostname prefix must return the default criticality (0.5)."""
    queue = MagicMock()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue
    assert mgr._asset_criticality("laptop-unknown") == 0.5


def test_asset_criticality_empty_hostname_defaults():
    """Empty hostname must return the default criticality (0.5)."""
    queue = MagicMock()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue
    assert mgr._asset_criticality("") == 0.5
