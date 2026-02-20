"""Tests for AlertManager — feature 17.5 DB persistence + feature 28.23 dedup + feature 28.24 TTL expiry + feature 28.25 risk score formula + feature 28.26 distributed dedup (two instances) + feature 21.4 mxtac_alerts_processed_total{severity} counter.

Coverage:
  - process(): publishes enriched+scored alert to mxtac.enriched topic
  - process(): calls _persist_to_db after publishing
  - process(): skips duplicates (no publish, no persist)
  - _persist_to_db(): calls DetectionRepo.create with mapped fields
  - _persist_to_db(): logs and continues when DB raises (non-fatal)
  - _score(): attaches score field to enriched dict
  - _score(): exact formula values for known (severity_id, asset_criticality) pairs
  - _score(): weight constants W_SEVERITY=0.60, W_ASSET=0.25, W_RECUR=0.15 sum to 1.0
  - _score(): severity_id normalised from 1→0.0 to 5→1.0 (zero-indexed, /4 range)
  - _score(): score capped at MAX_SCORE (10.0) when raw exceeds it
  - _score(): missing asset_criticality defaults to 0.5
  - _score(): recurrence bonus is currently 0.0 (placeholder)
  - _asset_criticality(): correct prefix-based lookup
  - _is_duplicate(): returns False for new alert (Valkey SET succeeds)
  - _is_duplicate(): returns True for seen alert within 5 min (Valkey SET returns None)
  - _is_duplicate(): returns False again after TTL expiry (Valkey SET succeeds again)
  - _is_duplicate(): Valkey called with nx=True, ex=300
  - _is_duplicate(): fail-open when Valkey raises
  - _dedup_key(): consistent for same (rule_id, host)
  - _dedup_key(): differs for different rule_id or host
  - process(): Valkey SET None → second identical alert is blocked end-to-end
  - process(): same alert after TTL expiry (Valkey SET True again) is published end-to-end
  - DEDUP_WINDOW_SECONDS: constant is 300 (5 minutes)
  - distributed: two instances produce the same dedup key for the same (rule_id, host)
  - distributed: instance B blocked when instance A processed the alert first
  - distributed: concurrent instances — exactly one publishes via shared Valkey SET NX
  - distributed: _is_duplicate() uses atomic SET NX (no GET-then-SET pattern)
  - distributed: both instances can process after shared TTL expires
  - counter: alerts_processed.labels(severity=level).inc() called on each alert (feature 21.4)
  - counter: severity label matches alert.level for all Sigma levels (low/medium/high/critical)
  - counter: severity label defaults to "medium" when alert level is empty
  - counter: counter NOT incremented for deduplicated alerts (only processed count)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_manager import AlertManager, DEDUP_WINDOW_SECONDS, MAX_SCORE, W_ASSET, W_RECUR, W_SEVERITY


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


# ---------------------------------------------------------------------------
# Section 5 — Dedup: Valkey-backed 5-minute window (feature 28.23)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_duplicate_returns_false_for_new_alert():
    """_is_duplicate() must return False when Valkey SET succeeds (key did not exist)."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    alert = _make_alert_dict()

    from app.engine.sigma_engine import SigmaAlert

    sigma_alert = SigmaAlert(
        id=alert["id"],
        rule_id=alert["rule_id"],
        rule_title=alert["rule_title"],
        level=alert["level"],
        severity_id=alert["severity_id"],
        technique_ids=alert["technique_ids"],
        tactic_ids=alert["tactic_ids"],
        host=alert["host"],
        time=datetime.now(timezone.utc),
        event_snapshot=alert["event_snapshot"],
    )

    # Valkey SET returns True → key was newly created → NOT a duplicate
    with patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)):
        result = await mgr._is_duplicate(sigma_alert)

    assert result is False


@pytest.mark.asyncio
async def test_is_duplicate_returns_true_for_seen_alert_within_window():
    """_is_duplicate() must return True when Valkey SET returns None (key exists = within 5-min window)."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    alert = _make_alert_dict()

    from app.engine.sigma_engine import SigmaAlert

    sigma_alert = SigmaAlert(
        id=alert["id"],
        rule_id=alert["rule_id"],
        rule_title=alert["rule_title"],
        level=alert["level"],
        severity_id=alert["severity_id"],
        technique_ids=alert["technique_ids"],
        tactic_ids=alert["tactic_ids"],
        host=alert["host"],
        time=datetime.now(timezone.utc),
        event_snapshot=alert["event_snapshot"],
    )

    # Valkey SET returns None → key already existed → IS a duplicate
    with patch.object(mgr._valkey, "set", new=AsyncMock(return_value=None)):
        result = await mgr._is_duplicate(sigma_alert)

    assert result is True


@pytest.mark.asyncio
async def test_is_duplicate_valkey_called_with_nx_ex_300():
    """_is_duplicate() must call Valkey SET with nx=True and ex=300 (5-min window)."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    alert = _make_alert_dict()

    from app.engine.sigma_engine import SigmaAlert

    sigma_alert = SigmaAlert(
        id=alert["id"],
        rule_id=alert["rule_id"],
        rule_title=alert["rule_title"],
        level=alert["level"],
        severity_id=alert["severity_id"],
        technique_ids=alert["technique_ids"],
        tactic_ids=alert["tactic_ids"],
        host=alert["host"],
        time=datetime.now(timezone.utc),
        event_snapshot=alert["event_snapshot"],
    )

    mock_set = AsyncMock(return_value=True)
    with patch.object(mgr._valkey, "set", new=mock_set):
        await mgr._is_duplicate(sigma_alert)

    mock_set.assert_awaited_once()
    _, call_kwargs = mock_set.call_args
    assert call_kwargs.get("nx") is True
    assert call_kwargs.get("ex") == 300


@pytest.mark.asyncio
async def test_is_duplicate_fail_open_on_valkey_error():
    """_is_duplicate() must return False (fail-open) when Valkey raises an exception."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    alert = _make_alert_dict()

    from app.engine.sigma_engine import SigmaAlert

    sigma_alert = SigmaAlert(
        id=alert["id"],
        rule_id=alert["rule_id"],
        rule_title=alert["rule_title"],
        level=alert["level"],
        severity_id=alert["severity_id"],
        technique_ids=alert["technique_ids"],
        tactic_ids=alert["tactic_ids"],
        host=alert["host"],
        time=datetime.now(timezone.utc),
        event_snapshot=alert["event_snapshot"],
    )

    with patch.object(mgr._valkey, "set", new=AsyncMock(side_effect=ConnectionError("Valkey down"))):
        result = await mgr._is_duplicate(sigma_alert)

    assert result is False


def test_dedup_key_is_consistent_for_same_rule_and_host():
    """_dedup_key() must return the same key for identical (rule_id, host)."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    alert = _make_alert_dict()

    from app.engine.sigma_engine import SigmaAlert

    sigma_alert = SigmaAlert(
        id=alert["id"],
        rule_id=alert["rule_id"],
        rule_title=alert["rule_title"],
        level=alert["level"],
        severity_id=alert["severity_id"],
        technique_ids=alert["technique_ids"],
        tactic_ids=alert["tactic_ids"],
        host=alert["host"],
        time=datetime.now(timezone.utc),
        event_snapshot=alert["event_snapshot"],
    )

    key1 = mgr._dedup_key(sigma_alert)
    key2 = mgr._dedup_key(sigma_alert)
    assert key1 == key2
    assert key1.startswith("mxtac:dedup:")


def test_dedup_key_differs_for_different_rule_id():
    """_dedup_key() must produce different keys for different rule_ids."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert

    base = dict(
        rule_title="Test", level="medium", severity_id=3,
        technique_ids=[], tactic_ids=[], host="srv-01",
        time=datetime.now(timezone.utc), event_snapshot={},
    )
    a1 = SigmaAlert(id="1", rule_id="sigma-A", **base)
    a2 = SigmaAlert(id="2", rule_id="sigma-B", **base)

    assert mgr._dedup_key(a1) != mgr._dedup_key(a2)


def test_dedup_key_differs_for_different_host():
    """_dedup_key() must produce different keys for different hosts."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert

    base = dict(
        rule_id="sigma-T1059", rule_title="Test", level="medium", severity_id=3,
        technique_ids=[], tactic_ids=[],
        time=datetime.now(timezone.utc), event_snapshot={},
    )
    a1 = SigmaAlert(id="1", host="srv-01", **base)
    a2 = SigmaAlert(id="2", host="dc-01", **base)

    assert mgr._dedup_key(a1) != mgr._dedup_key(a2)


@pytest.mark.asyncio
async def test_process_second_identical_alert_blocked_via_valkey():
    """End-to-end: second process() call with same (rule_id, host) is blocked by Valkey dedup.

    Simulates the 5-minute window: first SET returns True (new), second SET returns None (dup).
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="srv-01")

    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    # First call: Valkey SET returns True (new alert) → should publish
    # Second call: Valkey SET returns None (duplicate within window) → should NOT publish
    set_returns = [True, None]
    call_count = 0

    async def mock_set(*args, **kwargs):
        nonlocal call_count
        rv = set_returns[call_count]
        call_count += 1
        return rv

    with (
        patch.object(mgr._valkey, "set", side_effect=mock_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)   # first → new → published
        await mgr.process(alert_dict)   # second → duplicate → blocked

    assert len(published) == 1, "Only the first alert should be published; duplicate must be blocked"
    assert published[0][0] == Topic.ENRICHED

    await queue.stop()


# ---------------------------------------------------------------------------
# Section 6 — TTL expiry: same alert accepted after 5 min (feature 28.24)
# ---------------------------------------------------------------------------
#
# Valkey's SET NX EX auto-deletes the dedup key after DEDUP_WINDOW_SECONDS.
# Once the key is gone, a new SET NX succeeds (returns True) → alert accepted.
# These tests simulate that lifecycle: new → blocked → expired → accepted.


def test_dedup_window_seconds_is_300():
    """DEDUP_WINDOW_SECONDS constant must be 300 (5 minutes)."""
    assert DEDUP_WINDOW_SECONDS == 300


@pytest.mark.asyncio
async def test_is_duplicate_accepts_same_alert_after_ttl_expiry():
    """_is_duplicate() must return False once the Valkey TTL expires.

    Simulates three consecutive calls with the same (rule_id, host):
      call 1: Valkey SET returns True  → key was new  → NOT a duplicate (False)
      call 2: Valkey SET returns None  → key exists   → IS  a duplicate (True)
      call 3: Valkey SET returns True  → key expired  → NOT a duplicate (False)
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    alert = _make_alert_dict()

    from app.engine.sigma_engine import SigmaAlert

    sigma_alert = SigmaAlert(
        id=alert["id"],
        rule_id=alert["rule_id"],
        rule_title=alert["rule_title"],
        level=alert["level"],
        severity_id=alert["severity_id"],
        technique_ids=alert["technique_ids"],
        tactic_ids=alert["tactic_ids"],
        host=alert["host"],
        time=datetime.now(timezone.utc),
        event_snapshot=alert["event_snapshot"],
    )

    # Simulate: new → dup (within window) → expired (accepted again)
    set_sequence = [True, None, True]
    call_index = 0

    async def mock_set(*args, **kwargs):
        nonlocal call_index
        rv = set_sequence[call_index]
        call_index += 1
        return rv

    with patch.object(mgr._valkey, "set", side_effect=mock_set):
        result_new     = await mgr._is_duplicate(sigma_alert)  # 1st: new
        result_dup     = await mgr._is_duplicate(sigma_alert)  # 2nd: within window
        result_expired = await mgr._is_duplicate(sigma_alert)  # 3rd: TTL expired

    assert result_new     is False, "First alert must not be a duplicate"
    assert result_dup     is True,  "Second alert within 5-min window must be a duplicate"
    assert result_expired is False, "Alert after TTL expiry must be accepted (not a duplicate)"


@pytest.mark.asyncio
async def test_is_duplicate_renews_ttl_on_expiry_acceptance():
    """_is_duplicate() must call SET with ex=DEDUP_WINDOW_SECONDS on the post-expiry alert.

    After expiry, the new SET call must again use nx=True and ex=300 so the
    renewed alert starts a fresh 5-minute dedup window.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    alert = _make_alert_dict()

    from app.engine.sigma_engine import SigmaAlert

    sigma_alert = SigmaAlert(
        id=alert["id"],
        rule_id=alert["rule_id"],
        rule_title=alert["rule_title"],
        level=alert["level"],
        severity_id=alert["severity_id"],
        technique_ids=alert["technique_ids"],
        tactic_ids=alert["tactic_ids"],
        host=alert["host"],
        time=datetime.now(timezone.utc),
        event_snapshot=alert["event_snapshot"],
    )

    # First call blocked (within window), second call simulates post-expiry acceptance
    mock_set = AsyncMock(side_effect=[None, True])
    with patch.object(mgr._valkey, "set", new=mock_set):
        await mgr._is_duplicate(sigma_alert)  # dup (within window)
        await mgr._is_duplicate(sigma_alert)  # post-expiry

    # Verify both calls used nx=True and ex=300 (the post-expiry call renews the TTL)
    assert mock_set.await_count == 2
    for call in mock_set.await_args_list:
        _, kw = call
        assert kw.get("nx") is True,              "SET must use NX flag"
        assert kw.get("ex") == DEDUP_WINDOW_SECONDS, "SET must use ex=300 TTL"


@pytest.mark.asyncio
async def test_process_alert_accepted_again_after_ttl_expiry():
    """End-to-end: same alert is published again once the Valkey TTL expires.

    Sequence:
      process() #1 → Valkey returns True  → published to mxtac.enriched
      process() #2 → Valkey returns None  → blocked (duplicate within 5 min)
      process() #3 → Valkey returns True  → published again (TTL expired, new window)
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="srv-01")

    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    set_sequence = [True, None, True]
    call_index = 0

    async def mock_set(*args, **kwargs):
        nonlocal call_index
        rv = set_sequence[call_index]
        call_index += 1
        return rv

    with (
        patch.object(mgr._valkey, "set", side_effect=mock_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)  # #1 → new → published
        await mgr.process(alert_dict)  # #2 → dup within window → blocked
        await mgr.process(alert_dict)  # #3 → post-expiry → published again

    assert len(published) == 2, (
        "Alert should be published on 1st call and again after TTL expiry (3rd call); "
        "the duplicate within the 5-min window (2nd call) must be blocked"
    )
    assert published[0][0] == Topic.ENRICHED
    assert published[1][0] == Topic.ENRICHED
    assert published[0][1]["id"] == alert_dict["id"]
    assert published[1][1]["id"] == alert_dict["id"]

    await queue.stop()


# ---------------------------------------------------------------------------
# Section 7 — _score(): exact formula validation (feature 28.25)
# ---------------------------------------------------------------------------
#
# Formula (from alert_manager.py):
#   severity_norm = (severity_id - 1) / 4          # maps 1..5 → 0.0..1.0
#   raw  = (severity_norm * W_SEVERITY
#           + asset_crit  * W_ASSET
#           + recur_bonus * W_RECUR) * MAX_SCORE
#   score = round(min(raw, MAX_SCORE), 1)
#
# Constants: W_SEVERITY=0.60, W_ASSET=0.25, W_RECUR=0.15, MAX_SCORE=10.0


def _mgr_no_init() -> AlertManager:
    """Instantiate AlertManager without __init__ to avoid Valkey connection."""
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = MagicMock()
    return mgr


def test_score_formula_weight_constants_are_correct():
    """W_SEVERITY=0.60, W_ASSET=0.25, W_RECUR=0.15, MAX_SCORE=10.0 and weights sum to 1.0."""
    assert W_SEVERITY == pytest.approx(0.60)
    assert W_ASSET    == pytest.approx(0.25)
    assert W_RECUR    == pytest.approx(0.15)
    assert MAX_SCORE  == pytest.approx(10.0)
    assert W_SEVERITY + W_ASSET + W_RECUR == pytest.approx(1.0)


def test_score_formula_critical_dc_host():
    """Critical severity (id=5) + DC host (criticality=1.0) → score = 8.5.

    Derivation: ((5-1)/4 × 0.60 + 1.0 × 0.25 + 0.0 × 0.15) × 10 = 0.85 × 10 = 8.5
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 5, "asset_criticality": 1.0})
    assert result["score"] == pytest.approx(8.5, abs=0.05)


def test_score_formula_high_severity_srv_host():
    """High severity (id=4) + SRV host (criticality=0.8) → score = 6.5.

    Derivation: ((4-1)/4 × 0.60 + 0.8 × 0.25 + 0.0 × 0.15) × 10 = 0.65 × 10 = 6.5
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 4, "asset_criticality": 0.8})
    assert result["score"] == pytest.approx(6.5, abs=0.05)


def test_score_formula_low_severity_win_host():
    """Low severity (id=2) + WIN host (criticality=0.6) → score = 3.0.

    Derivation: ((2-1)/4 × 0.60 + 0.6 × 0.25 + 0.0 × 0.15) × 10 = 0.30 × 10 = 3.0
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 2, "asset_criticality": 0.6})
    assert result["score"] == pytest.approx(3.0, abs=0.05)


def test_score_formula_informational_zero_criticality():
    """Informational severity (id=1) + zero criticality → score = 0.0.

    Derivation: ((1-1)/4 × 0.60 + 0.0 × 0.25 + 0.0 × 0.15) × 10 = 0.0
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": 0.0})
    assert result["score"] == pytest.approx(0.0, abs=0.05)


def test_score_formula_severity_normalization_bounds():
    """severity_id=1 maps to 0.0 severity contribution; severity_id=5 maps to 1.0 (full weight).

    Isolate severity contribution by setting asset_criticality=0.0 in both cases.
    """
    mgr = _mgr_no_init()

    # severity_id=1 → severity_norm=0.0 → only asset component (0.0 here) contributes
    r_info = mgr._score({"severity_id": 1, "asset_criticality": 0.0})
    assert r_info["score"] == pytest.approx(0.0, abs=0.05)

    # severity_id=5 → severity_norm=1.0 → severity component alone: 1.0 × 0.60 × 10 = 6.0
    r_crit = mgr._score({"severity_id": 5, "asset_criticality": 0.0})
    assert r_crit["score"] == pytest.approx(6.0, abs=0.05)


def test_score_formula_score_capped_at_ten():
    """Score must be capped at MAX_SCORE (10.0) even when raw computation exceeds it."""
    mgr = _mgr_no_init()
    # asset_criticality=2.0 → raw = (1.0×0.60 + 2.0×0.25)×10 = 11.0 → capped to 10.0
    result = mgr._score({"severity_id": 5, "asset_criticality": 2.0})
    assert result["score"] <= 10.0
    assert result["score"] == pytest.approx(10.0, abs=0.05)


def test_score_formula_missing_asset_criticality_defaults_to_half():
    """_score() must treat missing asset_criticality as 0.5 (default).

    Derivation for severity_id=4, asset=0.5:
    ((4-1)/4 × 0.60 + 0.5 × 0.25) × 10 = (0.45 + 0.125) × 10 = 5.75
    """
    mgr = _mgr_no_init()
    result_default = mgr._score({"severity_id": 4})
    result_explicit = mgr._score({"severity_id": 4, "asset_criticality": 0.5})
    assert result_default["score"] == result_explicit["score"]
    assert result_default["score"] == pytest.approx(5.75, abs=0.05)


def test_score_formula_recurrence_bonus_is_currently_zero():
    """Recurrence bonus must currently contribute 0.0 (placeholder — not yet implemented).

    Verified by matching score against formula with recur_bonus=0.0.
    """
    mgr = _mgr_no_init()
    # High severity + SRV: expected 6.5 (verified in test_score_formula_high_severity_srv_host)
    result = mgr._score({"severity_id": 4, "asset_criticality": 0.8})
    # If recur bonus were active (e.g. recur_bonus=1.0, W_RECUR=0.15):
    #   raw would be (0.45 + 0.20 + 0.15) × 10 = 8.0 ≠ 6.5
    # Confirming it's 6.5 validates the bonus is 0.0
    assert result["score"] == pytest.approx(6.5, abs=0.05)


# ---------------------------------------------------------------------------
# Section 8 — Distributed dedup: two AlertManager instances (feature 28.26)
# ---------------------------------------------------------------------------
#
# Verifies that the Valkey SET NX EX mechanism correctly coordinates dedup
# across two separate AlertManager replicas sharing the same Valkey store.
#
# In production, both instances connect to the same Valkey server. The atomic
# SET NX acts as a distributed mutex: whichever replica calls SET NX first wins
# the dedup lock; all other replicas see the key and treat the alert as a dup.
#
# These tests use a shared in-memory dict as a stand-in for the Valkey keyspace,
# giving two independent mock clients that exhibit true NX semantics.


def _make_shared_valkey_pair() -> tuple:
    """Return two Valkey mocks that share the same in-memory NX keyspace.

    Simulates two AlertManager replicas connecting to the same Valkey server.
    The shared ``store`` dict represents the Valkey keyspace:
      - SET NX succeeds (True)  when the key is absent
      - SET NX fails   (None)   when the key already exists

    Returns (mock_a, mock_b, store).
    """
    store: dict[str, str] = {}

    async def shared_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        if nx and key in store:
            return None   # atomic NX: key already exists → fail
        store[key] = value
        return True       # key was set

    mock_a = MagicMock()
    mock_a.set = AsyncMock(side_effect=shared_set)
    mock_a.aclose = AsyncMock()

    mock_b = MagicMock()
    mock_b.set = AsyncMock(side_effect=shared_set)
    mock_b.aclose = AsyncMock()

    return mock_a, mock_b, store


def _make_sigma_alert(**overrides) -> "SigmaAlert":
    from app.engine.sigma_engine import SigmaAlert
    defaults = dict(
        id="dist-001",
        rule_id="sigma-T1059",
        rule_title="Command Shell Execution",
        level="high",
        severity_id=4,
        technique_ids=["T1059"],
        tactic_ids=["execution"],
        host="srv-01",
        time=datetime.now(timezone.utc),
        event_snapshot={"pid": 1234},
    )
    defaults.update(overrides)
    return SigmaAlert(**defaults)


def test_two_instances_produce_same_dedup_key():
    """Two AlertManager instances must derive the same dedup key for the same (rule_id, host).

    The key must be deterministic and instance-independent so either replica
    can atomically check or set the distributed dedup lock in the shared Valkey store.
    """
    queue = InMemoryQueue()
    mgr_a = AlertManager(queue)
    mgr_b = AlertManager(queue)

    alert = _make_sigma_alert()

    assert mgr_a._dedup_key(alert) == mgr_b._dedup_key(alert)


@pytest.mark.asyncio
async def test_instance_b_blocked_when_instance_a_processes_first():
    """Instance B must see the alert as a duplicate when Instance A processed it first.

    Distributed dedup sequence:
      1. Instance A calls SET NX → key absent → succeeds (True) → alert is new → published
      2. Instance B calls SET NX → key exists → fails (None)  → alert is duplicate → blocked
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr_a = AlertManager(queue)
    mgr_b = AlertManager(queue)

    mock_valkey_a, mock_valkey_b, _ = _make_shared_valkey_pair()
    mgr_a._valkey = mock_valkey_a
    mgr_b._valkey = mock_valkey_b

    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="srv-01")
    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    with (
        patch.object(mgr_a, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr_b, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr_a.process(alert_dict)   # Instance A processes first → published
        await mgr_b.process(alert_dict)   # Instance B sees key → blocked

    assert len(published) == 1, (
        "Instance A should publish; Instance B must be blocked by the shared Valkey key"
    )
    assert published[0][0] == Topic.ENRICHED

    await queue.stop()


@pytest.mark.asyncio
async def test_concurrent_instances_only_one_publishes():
    """When two instances race concurrently on the same alert, exactly one publishes.

    Uses asyncio.gather to simulate concurrent processing. The shared Valkey
    SET NX ensures that the first coroutine to reach the SET wins the dedup
    lock; the other is blocked regardless of scheduling order.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr_a = AlertManager(queue)
    mgr_b = AlertManager(queue)

    mock_valkey_a, mock_valkey_b, _ = _make_shared_valkey_pair()
    mgr_a._valkey = mock_valkey_a
    mgr_b._valkey = mock_valkey_b

    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="srv-01")
    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    with (
        patch.object(mgr_a, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr_b, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await asyncio.gather(
            mgr_a.process(alert_dict),
            mgr_b.process(alert_dict),
        )

    assert len(published) == 1, (
        "Exactly one instance should publish; the other must be blocked by the shared Valkey NX lock"
    )
    assert published[0][0] == Topic.ENRICHED

    await queue.stop()


@pytest.mark.asyncio
async def test_distributed_dedup_uses_atomic_set_nx_not_get_then_set():
    """_is_duplicate() must use a single atomic SET NX — not a GET-then-SET sequence.

    A GET-then-SET pattern would create a TOCTOU race window where two replicas
    could both observe the key absent and both publish the same alert. The atomic
    SET NX EX closes that window entirely.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    sigma_alert = _make_sigma_alert()

    mock_set = AsyncMock(return_value=True)
    mock_get = AsyncMock()   # must NOT be called

    with (
        patch.object(mgr._valkey, "set", new=mock_set),
        patch.object(mgr._valkey, "get", new=mock_get),
    ):
        await mgr._is_duplicate(sigma_alert)

    mock_set.assert_awaited_once()
    mock_get.assert_not_awaited()   # no GET involved — only atomic SET NX


@pytest.mark.asyncio
async def test_both_instances_accept_alert_after_shared_ttl_expires():
    """After the shared dedup TTL expires, either instance can process the alert again.

    Sequence:
      Instance A: SET NX → True  → published (starts 5-min TTL in shared store)
      Instance B: SET NX → None  → blocked   (key still exists within window)
      [Simulate TTL expiry: clear shared store]
      Instance A: SET NX → True  → published again (new 5-min window begins)

    This validates that the Valkey TTL mechanism restores availability across
    the entire cluster — not just for the instance that originally set the key.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr_a = AlertManager(queue)
    mgr_b = AlertManager(queue)

    mock_valkey_a, mock_valkey_b, store = _make_shared_valkey_pair()
    mgr_a._valkey = mock_valkey_a
    mgr_b._valkey = mock_valkey_b

    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="srv-01")
    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    with (
        patch.object(mgr_a, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr_b, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr_a.process(alert_dict)   # Instance A: new → published
        await mgr_b.process(alert_dict)   # Instance B: duplicate → blocked

        # Simulate TTL expiry: evict all dedup keys from the shared store
        store.clear()

        await mgr_a.process(alert_dict)   # Instance A: post-expiry → published again

    assert len(published) == 2, (
        "Alert published by Instance A (1st call) and again after TTL expiry (3rd call); "
        "Instance B within the window (2nd call) must be blocked"
    )
    assert published[0][0] == Topic.ENRICHED
    assert published[1][0] == Topic.ENRICHED

    await queue.stop()


# ---------------------------------------------------------------------------
# Section 9 — mxtac_alerts_processed_total{severity} counter (feature 21.4)
# ---------------------------------------------------------------------------
#
# The counter tracks every alert that enters the pipeline, labelled by the
# Sigma severity level string (low / medium / high / critical).  It must be
# incremented before the deduplication check so that each *received* alert is
# counted regardless of whether it is ultimately published.
#
# Implementation: alert_manager.py line 82-83
#   severity_label = alert.level or "medium"
#   alerts_processed.labels(severity=severity_label).inc()


@pytest.mark.asyncio
async def test_process_increments_alerts_processed_counter():
    """process() must call alerts_processed.labels(severity=...).inc() once per alert."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="high")

    with (
        patch("app.services.alert_manager.alerts_processed") as mock_counter,
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    mock_counter.labels.assert_called_once_with(severity="high")
    mock_counter.labels.return_value.inc.assert_called_once()

    await queue.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("level", ["low", "medium", "high", "critical"])
async def test_process_uses_alert_level_as_severity_label(level: str):
    """process() must pass alert.level as the severity label for all Sigma levels."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level=level)

    with (
        patch("app.services.alert_manager.alerts_processed") as mock_counter,
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    mock_counter.labels.assert_called_once_with(severity=level)

    await queue.stop()


@pytest.mark.asyncio
async def test_process_uses_medium_as_default_severity_when_level_empty():
    """process() must default to severity label 'medium' when alert.level is empty."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="")

    with (
        patch("app.services.alert_manager.alerts_processed") as mock_counter,
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    mock_counter.labels.assert_called_once_with(severity="medium")

    await queue.stop()


@pytest.mark.asyncio
async def test_process_increments_counter_even_for_deduplicated_alerts():
    """process() must increment alerts_processed BEFORE dedup check.

    Every alert that reaches the pipeline is counted, whether it is ultimately
    published or discarded as a duplicate.  The counter measures pipeline
    throughput, not unique published alerts.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="high")

    with (
        patch("app.services.alert_manager.alerts_processed") as mock_counter,
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    # Counter must have been incremented even though the alert was deduplicated
    mock_counter.labels.assert_called_once_with(severity="high")
    mock_counter.labels.return_value.inc.assert_called_once()

    await queue.stop()


@pytest.mark.asyncio
async def test_process_counter_incremented_before_dedup_check():
    """alerts_processed counter must be incremented before _is_duplicate() is called.

    The order matters: count first, then check dedup.  This ensures the
    counter reflects all received alerts, not just non-duplicates.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="critical")

    call_order: list[str] = []

    async def mock_is_duplicate(alert):
        call_order.append("is_duplicate")
        return False

    original_labels = None

    class MockCounter:
        def labels(self, **kwargs):
            call_order.append("counter_inc")
            mock_child = MagicMock()
            mock_child.inc = MagicMock()
            return mock_child

    with (
        patch("app.services.alert_manager.alerts_processed", MockCounter()),
        patch.object(mgr, "_is_duplicate", side_effect=mock_is_duplicate),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    assert call_order[0] == "counter_inc", (
        "alerts_processed counter must be incremented before _is_duplicate() check; "
        f"actual call order: {call_order}"
    )

    await queue.stop()
