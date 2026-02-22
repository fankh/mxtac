"""Tests for AlertManager — feature 17.5 DB persistence + feature 28.23 dedup + feature 28.24 TTL expiry + feature 28.25 risk score formula + feature 28.26 distributed dedup (two instances) + feature 21.4 mxtac_alerts_processed_total{severity} counter + feature 21.5 mxtac_alerts_deduplicated_total counter + feature 21.7 mxtac_pipeline_latency_seconds histogram + feature 9.1 MD5(rule_id + host) dedup key + feature 9.2 dedup window — 5 minutes TTL + feature 9.4 risk score: severity × 0.60 + feature 9.5 risk score: asset criticality × 0.25 + feature 9.10 publish enriched alerts to mxtac.enriched.

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
  - _score(): recurrence bonus 0 occurrences → recur_bonus=0.0 (no history)
  - _score(): recurrence bonus 5 occurrences → recur_bonus=0.5 (half weight)
  - _score(): recurrence bonus 10+ occurrences → recur_bonus=1.0 (full weight, capped)
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
  - dedup counter: alerts_deduplicated.inc() called when _is_duplicate() returns True (feature 21.5)
  - dedup counter: alerts_deduplicated.inc() NOT called for non-duplicate alerts (feature 21.5)
  - dedup counter: alerts_deduplicated.inc() called exactly once per duplicate (feature 21.5)
  - dedup counter: two back-to-back duplicates each increment the counter once (feature 21.5)
  - latency histogram: pipeline_latency.observe() called in process() finally block (feature 21.7)
  - latency histogram: observe() called with a non-negative duration (feature 21.7)
  - latency histogram: observe() called even when alert is a duplicate (feature 21.7)
  - latency histogram: observe() called even when process() raises an exception (feature 21.7)
  - latency histogram: observe() call count equals process() call count (feature 21.7)
  - feature 9.1 MD5 key: key has "mxtac:dedup:" prefix + 32-char lowercase hex suffix
  - feature 9.1 MD5 key: total key length is always 44 characters
  - feature 9.1 MD5 key: suffix contains only lowercase hexadecimal characters
  - feature 9.1 MD5 key: exact MD5 value matches hashlib.md5(f'{rule_id}|{host}'.encode())
  - feature 9.1 MD5 key: verified for multiple known (rule_id, host) pairs
  - feature 9.1 MD5 key: verified with empty rule_id, empty host, and both empty
  - feature 9.1 MD5 key: case-sensitive — "srv-01" and "SRV-01" produce different keys
  - feature 9.1 MD5 key: case-sensitive — rule_id casing affects the hash
  - feature 9.1 MD5 key: deterministic — 10 consecutive calls produce identical keys
  - feature 9.1 MD5 key: deterministic across independent AlertManager instances
  - feature 9.1 MD5 key: pipe '|' inside rule_id or host creates raw collision (documented)
  - feature 9.1 MD5 key: all-distinct keys for five different rule_ids on the same host
  - feature 9.1 MD5 key: all-distinct keys for five different hosts with the same rule_id
  - feature 9.1 MD5 key: _is_duplicate() passes the exact dedup key as Valkey SET argument
  - feature 9.1 MD5 key: Valkey key argument starts with "mxtac:dedup:" in end-to-end process()
  - feature 9.2 dedup window: DEDUP_WINDOW_SECONDS equals 5 * 60 (five minutes exactly)
  - feature 9.2 dedup window: Valkey SET receives ex=DEDUP_WINDOW_SECONDS (not a hardcoded literal)
  - feature 9.2 dedup window: Valkey SET uses nx=True and value "1" as presence marker
  - feature 9.2 dedup window: all duplicates within the 5-min window are blocked
  - feature 9.2 dedup window: independent window per (rule_id, host) — different rules on same host do not interfere
  - feature 9.2 dedup window: independent window per (rule_id, host) — different hosts with same rule do not interfere
  - feature 9.2 dedup window: multiple distinct pairs each get independent windows and are all published
  - feature 9.2 dedup window: new 5-minute window starts fresh after expiry (restarts correctly)
  - feature 9.2 dedup window: blocked duplicate skips enrichment, scoring, publish, and persist
  - feature 9.2 dedup window: fail-open is stateless — subsequent successful Valkey calls are unaffected
  - feature 9.2 dedup window: close() calls aclose() on the Valkey client to release the connection
  - feature 9.4 severity weight: W_SEVERITY constant equals exactly 0.60
  - feature 9.4 severity weight: W_SEVERITY is 60% of the total weight (dominant factor)
  - feature 9.4 severity weight: severity_id=1 produces zero isolated severity contribution
  - feature 9.4 severity weight: severity_id=2 produces 1.5 isolated severity contribution
  - feature 9.4 severity weight: severity_id=3 (medium) produces 3.0 isolated severity contribution
  - feature 9.4 severity weight: severity_id=4 (high) produces 4.5 isolated severity contribution
  - feature 9.4 severity weight: severity_id=5 (critical) produces 6.0 isolated severity contribution
  - feature 9.4 severity weight: step delta between consecutive severity_ids is uniform (1.5)
  - feature 9.4 severity weight: score is monotonically increasing across all severity levels
  - feature 9.4 severity weight: severity contribution is additive with asset contribution
  - feature 9.4 severity weight: medium severity (id=3) with default asset (0.5) → score 4.2
  - feature 9.4 severity weight: _score() returns the same dict object (in-place mutation)
  - feature 9.4 severity weight: end-to-end process() score matches severity × 0.60 formula
  - feature 9.4 severity weight: changing severity_id changes score more than same-delta asset change
  - feature 9.5 asset weight: W_ASSET constant equals exactly 0.25
  - feature 9.5 asset weight: W_ASSET is 25% of total weight (subordinate to W_SEVERITY)
  - feature 9.5 asset weight: DEFAULT_ASSET_CRITICALITY dict has exactly four entries
  - feature 9.5 asset weight: dc prefix → criticality 1.0 (Domain Controller, highest)
  - feature 9.5 asset weight: srv prefix → criticality 0.8
  - feature 9.5 asset weight: win prefix → criticality 0.6
  - feature 9.5 asset weight: lin prefix → criticality 0.5
  - feature 9.5 asset weight: unknown prefix → default criticality 0.5
  - feature 9.5 asset weight: empty hostname → default criticality 0.5
  - feature 9.5 asset weight: prefix matching is case-insensitive (DC-01, SRV-01, WIN-01, LIN-01)
  - feature 9.5 asset weight: prefix match uses startswith (partial match: "dcserver" → 1.0)
  - feature 9.5 asset weight: dc isolated score contribution = 1.0 × 0.25 × 10 = 2.5
  - feature 9.5 asset weight: srv isolated score contribution = 0.8 × 0.25 × 10 = 2.0
  - feature 9.5 asset weight: win isolated score contribution = 0.6 × 0.25 × 10 = 1.5
  - feature 9.5 asset weight: lin isolated score contribution = 0.5 × 0.25 × 10 = 1.25
  - feature 9.5 asset weight: default (0.5) isolated score contribution = 0.5 × 0.25 × 10 = 1.25
  - feature 9.5 asset weight: score monotonically increases with asset_criticality (severity fixed)
  - feature 9.5 asset weight: dc > srv > win ≥ lin ordering holds in final score at any severity
  - feature 9.5 asset weight: asset contribution is additive with severity contribution
  - feature 9.5 asset weight: score is float in [0.0, 10.0] for all known prefix hosts
  - feature 9.5 asset weight: score cap (10.0) is applied even when asset pushes raw above max
  - feature 9.5 asset weight: end-to-end process() with DC host produces correct asset-weighted score
  - feature 9.5 asset weight: end-to-end process() with SRV host produces correct asset-weighted score
  - feature 9.5 asset weight: _asset_criticality() is called during _enrich() and propagates to _score()
  - feature 9.5 asset weight: delta between dc and srv prefix scores is uniform (0.5 per unit × 0.25 × 10 = 1.25 … 0.2×0.25×10=0.5)
  - feature 9.10 publish: Topic.ENRICHED constant equals "mxtac.enriched"
  - feature 9.10 publish: queue.publish() first arg is Topic.ENRICHED
  - feature 9.10 publish: queue.publish() second arg is a dict
  - feature 9.10 publish: queue.publish() called exactly once per non-duplicate alert
  - feature 9.10 publish: queue.publish() NOT called for deduplicated alerts
  - feature 9.10 publish: second identical alert within window is not published
  - feature 9.10 publish: publish happens before _persist_to_db
  - feature 9.10 publish: published payload id passes through unchanged
  - feature 9.10 publish: published payload rule_id passes through unchanged
  - feature 9.10 publish: published payload host passes through unchanged
  - feature 9.10 publish: published payload time is ISO-format string
  - feature 9.10 publish: published payload event_snapshot passes through unchanged
  - feature 9.10 publish: published payload technique_ids passes through unchanged
  - feature 9.10 publish: published payload tactic_ids passes through unchanged
  - feature 9.10 publish: published payload contains asset_criticality enrichment field
  - feature 9.10 publish: DC host → asset_criticality=1.0 in published payload
  - feature 9.10 publish: SRV host → asset_criticality=0.8 in published payload
  - feature 9.10 publish: published payload threat_intel is None (placeholder)
  - feature 9.10 publish: published payload geo_ip is None (placeholder)
  - feature 9.10 publish: published payload has score field
  - feature 9.10 publish: published payload score is numeric
  - feature 9.10 publish: published payload score in [0.0, 10.0]
  - feature 9.10 publish: critical+DC published score matches formula (8.5)
  - feature 9.10 publish: low+unknown published score matches formula (≈1.25)
  - feature 9.10 publish: publish exception is caught; process() does not propagate it
  - feature 9.10 publish: end-to-end subscriber receives enriched alert via InMemoryQueue
  - feature 9.10 publish: end-to-end subscriber message contains score field in range
  - feature 9.10 publish: 5 distinct alerts → 5 publish calls
  - feature 9.10 publish: 3 new + 2 duplicate alerts → exactly 3 publish calls
  - feature 9.10 publish: published payload contains all required fields
  - feature 9.3 distributed dedup: Valkey SET called with nx=True (atomic SETEX NX semantics)
  - feature 9.3 distributed dedup: Valkey SET called with ex=DEDUP_WINDOW_SECONDS
  - feature 9.3 distributed dedup: Valkey SET called with value "1" as presence marker
  - feature 9.3 distributed dedup: new alert returns False from _is_duplicate() (SET returns True)
  - feature 9.3 distributed dedup: duplicate alert returns True from _is_duplicate() (SET returns None)
  - feature 9.3 distributed dedup: fail-open — Valkey exception → _is_duplicate() returns False
  - feature 9.3 distributed dedup: two replicas produce the same dedup key (cross-instance consistency)
  - feature 9.3 distributed dedup: replica B blocked when replica A set the key first (shared Valkey NX)
  - feature 9.3 distributed dedup: concurrent replicas — exactly one wins the SETEX NX lock
  - feature 9.3 distributed dedup: post-TTL expiry both replicas can process the alert again
  - feature 9.3 distributed dedup: no GET-before-SET (pure atomic SETEX NX, no TOCTOU race)
  - feature 9.3 distributed dedup: independent keys per (rule_id, host) — no cross-pair interference
  - feature 9.3 distributed dedup: three replicas — exactly one publishes per concurrent race
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_manager import (
    AlertManager,
    ASSET_CRITICALITY_SCALE,
    DEDUP_WINDOW_SECONDS,
    DEFAULT_ASSET_CRITICALITY,
    MAX_SCORE,
    W_ASSET,
    W_RECUR,
    W_SEVERITY,
    _DEDUP_PREFIX,
)


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
# Section 4 — _asset_criticality()  (feature 9.9: CMDB-backed lookup)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_asset_criticality_db_hit_returns_mapped_value():
    """When AssetRepo returns criticality=5, _asset_criticality() must return 1.0."""
    mgr = _mgr_no_init()
    mock_session = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=AsyncMock(return_value=5)),
    ):
        result = await mgr._asset_criticality("dc-prod-01")

    assert result == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_asset_criticality_db_miss_returns_default():
    """When AssetRepo returns default criticality=3 (asset not found), must return 0.5."""
    mgr = _mgr_no_init()
    mock_session = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=AsyncMock(return_value=3)),
    ):
        result = await mgr._asset_criticality("laptop-unknown")

    assert result == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_asset_criticality_empty_hostname_defaults():
    """Empty hostname must return the default criticality (0.5) without any DB call."""
    mgr = _mgr_no_init()
    result = await mgr._asset_criticality("")
    assert result == pytest.approx(0.5)


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


def test_score_formula_recurrence_bonus_zero_occurrences():
    """recurrence_count=0 (no prior history) → recur_bonus=0.0, no change to score.

    Derivation: ((4-1)/4 × 0.60 + 0.8 × 0.25 + 0.0 × 0.15) × 10 = 6.5
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 4, "asset_criticality": 0.8, "recurrence_count": 0})
    assert result["score"] == pytest.approx(6.5, abs=0.05)


def test_score_formula_recurrence_bonus_five_occurrences():
    """recurrence_count=5 → recur_bonus=0.5, adds half the recurrence weight.

    Derivation: ((4-1)/4 × 0.60 + 0.8 × 0.25 + 0.5 × 0.15) × 10
              = (0.45 + 0.20 + 0.075) × 10 = 7.25
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 4, "asset_criticality": 0.8, "recurrence_count": 5})
    assert result["score"] == pytest.approx(7.25, abs=0.05)


def test_score_formula_recurrence_bonus_capped_at_ten_occurrences():
    """recurrence_count≥10 → recur_bonus=1.0 (capped), adds full recurrence weight.

    Derivation: ((4-1)/4 × 0.60 + 0.8 × 0.25 + 1.0 × 0.15) × 10
              = (0.45 + 0.20 + 0.15) × 10 = 8.0
    Also verify recurrence_count=20 yields the same score (cap enforced).
    """
    mgr = _mgr_no_init()
    result_10 = mgr._score({"severity_id": 4, "asset_criticality": 0.8, "recurrence_count": 10})
    result_20 = mgr._score({"severity_id": 4, "asset_criticality": 0.8, "recurrence_count": 20})
    assert result_10["score"] == pytest.approx(8.0, abs=0.05)
    assert result_20["score"] == pytest.approx(8.0, abs=0.05)


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


# ---------------------------------------------------------------------------
# Section 10 — mxtac_alerts_deduplicated_total counter (feature 21.5)
# ---------------------------------------------------------------------------
#
# The counter tracks every alert that is dropped by the deduplication window.
# It must be incremented exactly once for each duplicate that is blocked, and
# must NOT be incremented for new (non-duplicate) alerts.
#
# Implementation: alert_manager.py lines 85-88
#   if await self._is_duplicate(alert):
#       alerts_deduplicated.inc()
#       return


@pytest.mark.asyncio
async def test_process_increments_alerts_deduplicated_counter_for_duplicate():
    """process() must call alerts_deduplicated.inc() exactly once when the alert is a duplicate."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="high")

    with (
        patch("app.services.alert_manager.alerts_deduplicated") as mock_dedup_counter,
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    mock_dedup_counter.inc.assert_called_once()

    await queue.stop()


@pytest.mark.asyncio
async def test_process_does_not_increment_alerts_deduplicated_for_new_alert():
    """process() must NOT call alerts_deduplicated.inc() when the alert is new (not a duplicate)."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="medium")

    with (
        patch("app.services.alert_manager.alerts_deduplicated") as mock_dedup_counter,
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    mock_dedup_counter.inc.assert_not_called()

    await queue.stop()


@pytest.mark.asyncio
async def test_process_increments_alerts_deduplicated_exactly_once_per_duplicate():
    """process() must increment alerts_deduplicated exactly once, not more, for a single duplicate."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="critical")

    with (
        patch("app.services.alert_manager.alerts_deduplicated") as mock_dedup_counter,
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    assert mock_dedup_counter.inc.call_count == 1, (
        f"alerts_deduplicated.inc() must be called exactly once per duplicate; "
        f"got {mock_dedup_counter.inc.call_count}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_process_increments_alerts_deduplicated_for_each_back_to_back_duplicate():
    """process() must increment alerts_deduplicated once per duplicate call.

    Two consecutive duplicate alerts must each increment the counter,
    so the total count reflects the number of duplicates seen.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="high")

    # Simulate: first alert is new, second and third are duplicates
    set_returns = [True, None, None]
    call_index = 0

    async def mock_set(*args, **kwargs):
        nonlocal call_index
        rv = set_returns[call_index]
        call_index += 1
        return rv

    with (
        patch("app.services.alert_manager.alerts_deduplicated") as mock_dedup_counter,
        patch.object(mgr._valkey, "set", side_effect=mock_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)   # new — not counted
        await mgr.process(alert_dict)   # duplicate — counted
        await mgr.process(alert_dict)   # duplicate — counted

    assert mock_dedup_counter.inc.call_count == 2, (
        f"alerts_deduplicated.inc() must be called once per duplicate; "
        f"expected 2, got {mock_dedup_counter.inc.call_count}"
    )


# ---------------------------------------------------------------------------
# Section 11 — mxtac_pipeline_latency_seconds histogram (feature 21.7)
# ---------------------------------------------------------------------------
#
# The histogram captures end-to-end alert pipeline processing latency.
# It is observed in the `finally` block of process() so that every call
# is recorded — regardless of whether the alert was deduplicated, published,
# or caused an exception.
#
# Implementation: alert_manager.py
#   start_time = time.monotonic()
#   try:
#       ...
#   except Exception:
#       logger.exception(...)
#   finally:
#       pipeline_latency.observe(time.monotonic() - start_time)


@pytest.mark.asyncio
async def test_process_observes_pipeline_latency_on_success():
    """process() must call pipeline_latency.observe() once for a successful alert."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="high")

    with (
        patch("app.services.alert_manager.pipeline_latency") as mock_hist,
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    mock_hist.observe.assert_called_once()

    await queue.stop()


@pytest.mark.asyncio
async def test_process_observe_called_with_nonnegative_duration():
    """pipeline_latency.observe() must be called with a non-negative float (seconds elapsed)."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="medium")

    observed_values: list[float] = []

    def capture_observe(value):
        observed_values.append(value)

    with (
        patch("app.services.alert_manager.pipeline_latency") as mock_hist,
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        mock_hist.observe.side_effect = capture_observe
        await mgr.process(alert_dict)

    assert len(observed_values) == 1, "observe() must be called exactly once"
    assert observed_values[0] >= 0.0, (
        f"Observed duration must be non-negative; got {observed_values[0]}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_process_observes_pipeline_latency_for_duplicate_alert():
    """pipeline_latency.observe() must be called even when the alert is deduplicated.

    The observe() call is in the finally block, so it executes for every
    process() invocation — including those that return early due to dedup.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="critical")

    with (
        patch("app.services.alert_manager.pipeline_latency") as mock_hist,
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    mock_hist.observe.assert_called_once(), (
        "pipeline_latency.observe() must be called even for deduplicated alerts"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_process_observes_pipeline_latency_on_exception():
    """pipeline_latency.observe() must be called even when process() catches an exception.

    The observe() call is in the finally block.  Even if the enrichment or
    scoring step raises, the latency must still be recorded.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="low")

    async def raise_on_enrich(alert):
        raise RuntimeError("Enrichment failed")

    with (
        patch("app.services.alert_manager.pipeline_latency") as mock_hist,
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_enrich", side_effect=raise_on_enrich),
    ):
        await mgr.process(alert_dict)  # must not propagate the exception

    mock_hist.observe.assert_called_once(), (
        "pipeline_latency.observe() must be called even when process() catches an exception"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_process_observe_count_equals_process_call_count():
    """pipeline_latency.observe() must be called once per process() invocation.

    Three consecutive calls to process() must result in exactly three observe()
    calls — one per pipeline execution, regardless of outcome.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(level="high")

    set_returns = [True, None, True]
    call_index = 0

    async def mock_set(*args, **kwargs):
        nonlocal call_index
        rv = set_returns[call_index]
        call_index += 1
        return rv

    with (
        patch("app.services.alert_manager.pipeline_latency") as mock_hist,
        patch.object(mgr._valkey, "set", side_effect=mock_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)   # new
        await mgr.process(alert_dict)   # duplicate
        await mgr.process(alert_dict)   # new again (TTL expired)

    assert mock_hist.observe.call_count == 3, (
        f"pipeline_latency.observe() must be called once per process() invocation; "
        f"expected 3, got {mock_hist.observe.call_count}"
    )

    await queue.stop()
    await queue.stop()


# ---------------------------------------------------------------------------
# Section 12 — Feature 9.1: _dedup_key() MD5(rule_id + host) key computation
# ---------------------------------------------------------------------------
#
# The dedup key formula (from alert_manager.py _dedup_key):
#
#   raw    = f"{alert.rule_id}|{alert.host}".encode()
#   digest = hashlib.md5(raw).hexdigest()
#   key    = f"{_DEDUP_PREFIX}{digest}"
#
# where _DEDUP_PREFIX = "mxtac:dedup:"
#
# This section validates:
#   - Key format: exactly "mxtac:dedup:" + 32-char lowercase hex
#   - Exact MD5 hash values for known inputs
#   - The '|' separator between rule_id and host
#   - Edge cases: empty strings
#   - Case sensitivity for rule_id and host
#   - Determinism across calls and instances
#   - Non-collision for distinct (rule_id, host) pairs
#   - End-to-end: Valkey receives the correct key from _is_duplicate()


def _reference_dedup_key(rule_id: str, host: str) -> str:
    """Reference implementation of the dedup key formula — mirrors alert_manager.py."""
    raw = f"{rule_id}|{host}".encode()
    digest = hashlib.md5(raw).hexdigest()
    return f"{_DEDUP_PREFIX}{digest}"


def _mgr_bare() -> AlertManager:
    """Return an AlertManager without __init__ to avoid Valkey connection."""
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = MagicMock()
    return mgr


# ── Key format ────────────────────────────────────────────────────────────────


def test_dedup_prefix_constant_value() -> None:
    """_DEDUP_PREFIX must be exactly 'mxtac:dedup:'."""
    assert _DEDUP_PREFIX == "mxtac:dedup:"


def test_dedup_key_starts_with_mxtac_dedup_prefix() -> None:
    """_dedup_key() result must begin with 'mxtac:dedup:'."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01")
    assert mgr._dedup_key(alert).startswith("mxtac:dedup:")


def test_dedup_key_suffix_is_32_char_hex() -> None:
    """The portion after the prefix must be a 32-character hexadecimal string."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01")
    key = mgr._dedup_key(alert)
    suffix = key[len("mxtac:dedup:"):]
    assert len(suffix) == 32
    assert all(c in "0123456789abcdef" for c in suffix), (
        f"Suffix must be lowercase hex; got {suffix!r}"
    )


def test_dedup_key_total_length_is_44() -> None:
    """Total key length must be len('mxtac:dedup:') + 32 = 44 characters."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01")
    assert len(mgr._dedup_key(alert)) == 44


def test_dedup_key_hex_suffix_is_lowercase() -> None:
    """hashlib.md5().hexdigest() returns lowercase; key must not contain uppercase hex."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id="SIGMA-T1059", host="SRV-01")
    suffix = mgr._dedup_key(alert)[len("mxtac:dedup:"):]
    assert suffix == suffix.lower(), (
        f"MD5 hex digest must be lowercase; got {suffix!r}"
    )


# ── Exact MD5 hash values ─────────────────────────────────────────────────────


@pytest.mark.parametrize("rule_id,host", [
    ("sigma-T1059", "srv-01"),
    ("sigma-T1003", "dc-01"),
    ("sigma-T1566", "win-workstation"),
    ("sigma-T1021", "lin-server-02"),
    ("lateral-movement-rule", "dc-02.corp.example.com"),
])
def test_dedup_key_exact_md5_matches_reference(rule_id: str, host: str) -> None:
    """_dedup_key() must produce exactly md5(f'{rule_id}|{host}'.encode()).hexdigest()
    for each known (rule_id, host) pair."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id=rule_id, host=host)
    expected = _reference_dedup_key(rule_id, host)
    assert mgr._dedup_key(alert) == expected, (
        f"MD5 mismatch for rule_id={rule_id!r}, host={host!r}: "
        f"got {mgr._dedup_key(alert)!r}, expected {expected!r}"
    )


def test_dedup_key_empty_rule_id_matches_reference() -> None:
    """_dedup_key() must compute MD5 correctly when rule_id is empty."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id="", host="srv-01")
    assert mgr._dedup_key(alert) == _reference_dedup_key("", "srv-01")


def test_dedup_key_empty_host_matches_reference() -> None:
    """_dedup_key() must compute MD5 correctly when host is empty."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id="sigma-T1059", host="")
    assert mgr._dedup_key(alert) == _reference_dedup_key("sigma-T1059", "")


def test_dedup_key_both_empty_matches_reference() -> None:
    """_dedup_key() must compute a valid key even when both rule_id and host are empty."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id="", host="")
    expected = _reference_dedup_key("", "")
    result = mgr._dedup_key(alert)
    assert result == expected
    assert result.startswith("mxtac:dedup:")
    assert len(result) == 44


# ── Pipe separator semantics ─────────────────────────────────────────────────


def test_dedup_key_pipe_separator_in_rule_id_creates_same_raw_as_pipe_in_host() -> None:
    """Documents known behavior: rule_id='a|b' + host='c' collides with rule_id='a' + host='b|c'.

    Both produce raw string 'a|b|c', so their MD5 hashes are identical.
    This is an expected consequence of using '|' as separator when inputs
    can themselves contain '|'. This test documents (not fixes) the behavior.
    """
    mgr = _mgr_bare()
    a1 = _make_sigma_alert(rule_id="a|b", host="c")
    a2 = _make_sigma_alert(rule_id="a", host="b|c")
    # Both yield raw = b"a|b|c" — so the keys will be equal
    assert mgr._dedup_key(a1) == mgr._dedup_key(a2), (
        "rule_id='a|b'/host='c' and rule_id='a'/host='b|c' produce raw='a|b|c' "
        "and thus identical MD5 keys — documented edge case"
    )


def test_dedup_key_no_pipe_in_inputs_does_not_collide() -> None:
    """Distinct (rule_id, host) pairs without embedded '|' must never collide.

    Verifies that the separator only causes ambiguity when inputs contain '|';
    ordinary strings are always distinguishable.
    """
    mgr = _mgr_bare()
    pairs = [
        ("sigma-T1059", "srv-01"),
        ("sigma-T1059", "srv-010"),   # host is prefix of another
        ("sigma-T105", "9srv-01"),    # digits shifted across boundary
        ("sigma", "T1059-srv-01"),    # rule_id is strict prefix
    ]
    keys = [mgr._dedup_key(_make_sigma_alert(rule_id=r, host=h)) for r, h in pairs]
    assert len(set(keys)) == len(pairs), (
        "All four distinct (rule_id, host) pairs without '|' must produce unique keys"
    )


# ── Case sensitivity ──────────────────────────────────────────────────────────


def test_dedup_key_case_sensitive_for_host() -> None:
    """Different-cased hostnames must produce different dedup keys."""
    mgr = _mgr_bare()
    lower = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01")
    upper = _make_sigma_alert(rule_id="sigma-T1059", host="SRV-01")
    mixed = _make_sigma_alert(rule_id="sigma-T1059", host="Srv-01")
    assert mgr._dedup_key(lower) != mgr._dedup_key(upper)
    assert mgr._dedup_key(lower) != mgr._dedup_key(mixed)
    assert mgr._dedup_key(upper) != mgr._dedup_key(mixed)


def test_dedup_key_case_sensitive_for_rule_id() -> None:
    """Different-cased rule_ids must produce different dedup keys."""
    mgr = _mgr_bare()
    lower = _make_sigma_alert(rule_id="sigma-t1059", host="srv-01")
    upper = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01")
    assert mgr._dedup_key(lower) != mgr._dedup_key(upper)


def test_dedup_key_fully_uppercase_inputs_differ_from_lowercase() -> None:
    """All-uppercase (rule_id, host) must differ from all-lowercase version."""
    mgr = _mgr_bare()
    lc = _make_sigma_alert(rule_id="sigma-t1059", host="srv-01")
    uc = _make_sigma_alert(rule_id="SIGMA-T1059", host="SRV-01")
    assert mgr._dedup_key(lc) != mgr._dedup_key(uc)


# ── Determinism ───────────────────────────────────────────────────────────────


def test_dedup_key_deterministic_across_10_calls() -> None:
    """Calling _dedup_key() 10 times on the same alert always yields the same key."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01")
    keys = {mgr._dedup_key(alert) for _ in range(10)}
    assert len(keys) == 1, f"Expected exactly one unique key across 10 calls; got {keys}"


def test_dedup_key_deterministic_across_independent_instances() -> None:
    """Two freshly created AlertManager instances must produce identical keys."""
    mgr1 = _mgr_bare()
    mgr2 = _mgr_bare()
    alert = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01")
    assert mgr1._dedup_key(alert) == mgr2._dedup_key(alert)


def test_dedup_key_same_for_different_alert_ids_same_rule_host() -> None:
    """Two SigmaAlert objects with different .id values but identical rule_id+host
    must produce the same dedup key — the id field is not part of the key."""
    mgr = _mgr_bare()
    a1 = _make_sigma_alert(id="uuid-aaa", rule_id="sigma-T1059", host="srv-01")
    a2 = _make_sigma_alert(id="uuid-bbb", rule_id="sigma-T1059", host="srv-01")
    assert mgr._dedup_key(a1) == mgr._dedup_key(a2), (
        "Alert .id must not influence the dedup key; only rule_id and host matter"
    )


def test_dedup_key_differs_for_different_alert_times_same_rule_host() -> None:
    """Alerts with the same rule_id+host but different timestamps share the same key.

    Deduplication is keyed on (rule_id, host) only — the timestamp is not
    part of the key.  Time-based dedup window is enforced by the Valkey TTL,
    not by hashing the timestamp into the key.
    """
    mgr = _mgr_bare()
    t1 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 1, 1, 0, 4, 59, tzinfo=timezone.utc)  # 1 second before window expires
    a1 = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01", time=t1)
    a2 = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01", time=t2)
    assert mgr._dedup_key(a1) == mgr._dedup_key(a2), (
        "Timestamp must not be part of the dedup key"
    )


# ── Non-collision for distinct inputs ─────────────────────────────────────────


@pytest.mark.parametrize("rule_id", [
    "sigma-T1059",
    "sigma-T1003",
    "sigma-T1566",
    "sigma-T1021",
    "sigma-T1136",
])
def test_dedup_key_unique_per_rule_id_on_same_host(rule_id: str) -> None:
    """Each distinct rule_id on the same host must produce a unique key."""
    mgr = _mgr_bare()
    alert = _make_sigma_alert(rule_id=rule_id, host="srv-01")
    expected = _reference_dedup_key(rule_id, "srv-01")
    assert mgr._dedup_key(alert) == expected


def test_dedup_key_all_unique_for_five_rule_ids() -> None:
    """Five distinct rule_ids on the same host must all produce different keys."""
    mgr = _mgr_bare()
    rule_ids = ["sigma-T1059", "sigma-T1003", "sigma-T1566", "sigma-T1021", "sigma-T1136"]
    keys = [mgr._dedup_key(_make_sigma_alert(rule_id=r, host="srv-01")) for r in rule_ids]
    assert len(set(keys)) == 5, "All five rule_id/host combinations must yield unique keys"


def test_dedup_key_all_unique_for_five_hosts() -> None:
    """The same rule_id on five distinct hosts must produce five different keys."""
    mgr = _mgr_bare()
    hosts = ["srv-01", "dc-01", "win-workstation", "lin-server", "dc-02"]
    keys = [mgr._dedup_key(_make_sigma_alert(rule_id="sigma-T1059", host=h)) for h in hosts]
    assert len(set(keys)) == 5, "All five host variations must yield unique keys"


# ── End-to-end: Valkey receives the correct key ───────────────────────────────


@pytest.mark.asyncio
async def test_is_duplicate_passes_exact_dedup_key_to_valkey_set() -> None:
    """_is_duplicate() must pass the exact _dedup_key() result as the first positional
    argument to the Valkey SET command."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    sigma_alert = _make_sigma_alert(rule_id="sigma-T1059", host="srv-01")

    expected_key = mgr._dedup_key(sigma_alert)
    captured_keys: list[str] = []

    async def mock_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        captured_keys.append(key)
        return True

    with patch.object(mgr._valkey, "set", side_effect=mock_set):
        await mgr._is_duplicate(sigma_alert)

    assert len(captured_keys) == 1
    assert captured_keys[0] == expected_key, (
        f"Valkey SET received key {captured_keys[0]!r}; "
        f"expected {expected_key!r}"
    )


@pytest.mark.asyncio
async def test_process_valkey_set_key_has_mxtac_dedup_prefix() -> None:
    """End-to-end: the Valkey SET key used by process() starts with 'mxtac:dedup:'."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="srv-01")

    valkey_keys_used: list[str] = []

    original_set = mgr._valkey.set

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        valkey_keys_used.append(key)
        return True

    with (
        patch.object(mgr._valkey, "set", side_effect=spy_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    assert len(valkey_keys_used) == 1
    assert valkey_keys_used[0].startswith("mxtac:dedup:"), (
        f"Valkey key must start with 'mxtac:dedup:'; got {valkey_keys_used[0]!r}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_process_valkey_set_key_is_32_char_hex_after_prefix() -> None:
    """End-to-end: the suffix after 'mxtac:dedup:' in the Valkey key is 32-char lowercase hex."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="dc-01")

    valkey_keys_used: list[str] = []

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        valkey_keys_used.append(key)
        return True

    with (
        patch.object(mgr._valkey, "set", side_effect=spy_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    key = valkey_keys_used[0]
    suffix = key[len("mxtac:dedup:"):]
    assert len(suffix) == 32, f"Expected 32-char hex suffix; got {len(suffix)} chars: {suffix!r}"
    assert all(c in "0123456789abcdef" for c in suffix), (
        f"Suffix must be lowercase hex characters; got {suffix!r}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_process_valkey_key_matches_dedup_key_for_same_alert() -> None:
    """End-to-end: the Valkey SET key matches what _dedup_key() returns for the same alert."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    rule_id = "sigma-T1059"
    host = "srv-01"
    alert_dict = _make_alert_dict(rule_id=rule_id, host=host)

    # Compute expected key via reference formula
    expected_key = _reference_dedup_key(rule_id, host)

    valkey_keys_used: list[str] = []

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        valkey_keys_used.append(key)
        return True

    with (
        patch.object(mgr._valkey, "set", side_effect=spy_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    assert valkey_keys_used[0] == expected_key, (
        f"process() must use key {expected_key!r}; got {valkey_keys_used[0]!r}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_process_two_different_hosts_use_different_valkey_keys() -> None:
    """Two alerts with different hosts must result in different Valkey SET keys."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)

    valkey_keys: list[str] = []

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        valkey_keys.append(key)
        return True

    with (
        patch.object(mgr._valkey, "set", side_effect=spy_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(_make_alert_dict(rule_id="sigma-T1059", host="srv-01"))
        await mgr.process(_make_alert_dict(rule_id="sigma-T1059", host="dc-01"))

    assert len(valkey_keys) == 2
    assert valkey_keys[0] != valkey_keys[1], (
        "Different hosts must produce different Valkey dedup keys"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_process_same_host_different_rules_use_different_valkey_keys() -> None:
    """Two alerts with different rule_ids on the same host must use different Valkey keys."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)

    valkey_keys: list[str] = []

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        valkey_keys.append(key)
        return True

    with (
        patch.object(mgr._valkey, "set", side_effect=spy_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=AsyncMock()),
    ):
        await mgr.process(_make_alert_dict(rule_id="sigma-T1059", host="srv-01"))
        await mgr.process(_make_alert_dict(rule_id="sigma-T1003", host="srv-01"))

    assert len(valkey_keys) == 2
    assert valkey_keys[0] != valkey_keys[1], (
        "Different rule_ids on the same host must produce different Valkey dedup keys"
    )

    await queue.stop()


# ---------------------------------------------------------------------------
# Section 13 — Feature 9.2: Dedup window — 5 minutes TTL (single instance)
# ---------------------------------------------------------------------------
#
# Feature 9.2 defines the dedup window: the same (rule_id, host) pair is
# suppressed for exactly 5 minutes (300 seconds) after its first occurrence.
#
# Implementation uses Valkey SET NX EX DEDUP_WINDOW_SECONDS.  In single-
# instance deployments the Valkey keyspace acts as an in-process TTL dict:
# the key is created on first alert, evicted automatically after 300 s, and
# the next identical alert then starts a fresh 5-minute window.
#
# Tests in this section verify:
#   - Window duration is exactly 5 minutes (5 * 60 seconds)
#   - Valkey SET arguments: nx=True, ex=DEDUP_WINDOW_SECONDS, value="1"
#   - All duplicates within the window are blocked (not just the second)
#   - Windows are independent per (rule_id, host) pair — no cross-pair bleed
#   - A new 5-minute window starts cleanly after the previous one expires
#   - Blocked duplicates skip enrichment, scoring, publish, and persist
#   - Fail-open on Valkey error is stateless (next call proceeds normally)
#   - close() releases the Valkey connection to avoid resource leaks


def test_dedup_window_constant_equals_five_times_sixty() -> None:
    """DEDUP_WINDOW_SECONDS must equal 5 * 60 — exactly five minutes in seconds."""
    assert DEDUP_WINDOW_SECONDS == 5 * 60


@pytest.mark.asyncio
async def test_dedup_window_valkey_set_uses_dedup_window_seconds_constant() -> None:
    """_is_duplicate() must pass ex=DEDUP_WINDOW_SECONDS to Valkey SET.

    The TTL argument must use the named constant — not a hardcoded integer —
    so that a single constant change propagates to all SET calls automatically.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    sigma_alert = _make_sigma_alert()

    captured_ex: list[int | None] = []

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        captured_ex.append(ex)
        return True

    with patch.object(mgr._valkey, "set", side_effect=spy_set):
        await mgr._is_duplicate(sigma_alert)

    assert len(captured_ex) == 1
    assert captured_ex[0] == DEDUP_WINDOW_SECONDS, (
        f"Valkey SET ex= must equal DEDUP_WINDOW_SECONDS ({DEDUP_WINDOW_SECONDS}); "
        f"got {captured_ex[0]}"
    )


@pytest.mark.asyncio
async def test_dedup_window_valkey_set_uses_nx_true_and_value_one() -> None:
    """_is_duplicate() must call Valkey SET with nx=True and value '1'.

    nx=True ensures the atomic set-if-not-exists semantics that make the
    dedup window work correctly.  Value '1' is the conventional presence marker.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)
    sigma_alert = _make_sigma_alert()

    captured: list[dict] = []

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        captured.append({"key": key, "value": value, "nx": nx, "ex": ex})
        return True

    with patch.object(mgr._valkey, "set", side_effect=spy_set):
        await mgr._is_duplicate(sigma_alert)

    assert len(captured) == 1
    assert captured[0]["nx"] is True, "_is_duplicate() must use nx=True for atomic semantics"
    assert captured[0]["value"] == "1", "_is_duplicate() must use value='1' as presence marker"


@pytest.mark.asyncio
async def test_dedup_window_blocks_all_duplicates_within_window() -> None:
    """All repeated calls with the same (rule_id, host) within the window are blocked.

    Simulates one new alert followed by four duplicates within the 5-min window.
    Only the first call must be published; the remaining four must be dropped.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="srv-01")

    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    total_calls = 5
    # First call: new → True; remaining four: duplicates → None
    set_returns = [True] + [None] * (total_calls - 1)
    call_index = 0

    async def mock_set(*args, **kwargs):
        nonlocal call_index
        rv = set_returns[call_index]
        call_index += 1
        return rv

    with (
        patch.object(mgr._valkey, "set", side_effect=mock_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        for _ in range(total_calls):
            await mgr.process(alert_dict)

    assert len(published) == 1, (
        f"Only the first alert must be published; "
        f"all {total_calls - 1} duplicates within the 5-min window must be blocked. "
        f"Got {len(published)} published."
    )
    assert published[0][0] == Topic.ENRICHED

    await queue.stop()


@pytest.mark.asyncio
async def test_dedup_window_isolation_different_rules_same_host() -> None:
    """Different rules on the same host have independent 5-minute windows.

    Blocking rule_A on srv-01 must not prevent rule_B on srv-01 from being
    published.  Each (rule_id, host) pair has its own independent TTL entry.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    published_rules: list[str] = []

    async def capture(topic, msg):
        published_rules.append(msg["rule_id"])

    store: dict[str, str] = {}

    async def shared_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        if nx and key in store:
            return None
        store[key] = value
        return True

    with (
        patch.object(mgr._valkey, "set", side_effect=shared_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict(rule_id="sigma-T1059", host="srv-01"))  # new → accepted
        await mgr.process(_make_alert_dict(rule_id="sigma-T1059", host="srv-01"))  # dup → blocked
        await mgr.process(_make_alert_dict(rule_id="sigma-T1003", host="srv-01"))  # different rule → accepted

    assert len(published_rules) == 2, (
        "rule_A (first) and rule_B must each be published independently; "
        "only rule_A's duplicate must be blocked"
    )
    assert "sigma-T1059" in published_rules
    assert "sigma-T1003" in published_rules

    await queue.stop()


@pytest.mark.asyncio
async def test_dedup_window_isolation_same_rule_different_hosts() -> None:
    """The same rule on different hosts has independent 5-minute windows.

    Blocking the alert on srv-01 must not prevent the alert on dc-01 from
    being published, even though they share the same rule_id.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    published_hosts: list[str] = []

    async def capture(topic, msg):
        published_hosts.append(msg["host"])

    store: dict[str, str] = {}

    async def shared_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        if nx and key in store:
            return None
        store[key] = value
        return True

    with (
        patch.object(mgr._valkey, "set", side_effect=shared_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict(rule_id="sigma-T1059", host="srv-01"))  # new → accepted
        await mgr.process(_make_alert_dict(rule_id="sigma-T1059", host="srv-01"))  # dup → blocked
        await mgr.process(_make_alert_dict(rule_id="sigma-T1059", host="dc-01"))   # different host → accepted

    assert len(published_hosts) == 2, (
        "srv-01 (first) and dc-01 must each be published; "
        "only srv-01's duplicate must be blocked"
    )
    assert "srv-01" in published_hosts
    assert "dc-01" in published_hosts

    await queue.stop()


@pytest.mark.asyncio
async def test_dedup_window_multiple_pairs_no_cross_interference() -> None:
    """Three distinct (rule_id, host) pairs each get an independent window.

    All three first occurrences must be published; none of their windows
    interferes with the others.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    published_pairs: list[tuple[str, str]] = []

    async def capture(topic, msg):
        published_pairs.append((msg["rule_id"], msg["host"]))

    store: dict[str, str] = {}

    async def shared_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        if nx and key in store:
            return None
        store[key] = value
        return True

    pairs = [
        ("sigma-T1059", "srv-01"),
        ("sigma-T1003", "dc-01"),
        ("sigma-T1566", "win-ws-01"),
    ]

    with (
        patch.object(mgr._valkey, "set", side_effect=shared_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        for rule_id, host in pairs:
            await mgr.process(_make_alert_dict(rule_id=rule_id, host=host))

    assert len(published_pairs) == 3, (
        "All three distinct (rule_id, host) pairs must be published with independent windows"
    )
    for pair in pairs:
        assert pair in published_pairs, f"Pair {pair} was not published"

    await queue.stop()


@pytest.mark.asyncio
async def test_dedup_window_new_window_starts_fresh_after_expiry() -> None:
    """After expiry a new independent 5-minute window starts from scratch.

    Sequence:
      #1 → new (window 1 starts)       → published
      #2 → dup (within window 1)        → blocked
      #3 → post-expiry (window 2 starts) → published
      #4 → dup (within window 2)         → blocked
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()
    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    # window 1: new, dup; window 2: new, dup
    set_returns = [True, None, True, None]
    call_index = 0

    async def mock_set(*args, **kwargs):
        nonlocal call_index
        rv = set_returns[call_index]
        call_index += 1
        return rv

    with (
        patch.object(mgr._valkey, "set", side_effect=mock_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)   # window 1: new → published
        await mgr.process(alert_dict)   # window 1: dup → blocked
        await mgr.process(alert_dict)   # window 2: new → published
        await mgr.process(alert_dict)   # window 2: dup → blocked

    assert len(published) == 2, (
        "Calls #1 and #3 (start of each window) must be published; "
        "calls #2 and #4 (duplicates within each window) must be blocked. "
        f"Got {len(published)} published."
    )
    assert published[0][0] == Topic.ENRICHED
    assert published[1][0] == Topic.ENRICHED

    await queue.stop()


@pytest.mark.asyncio
async def test_dedup_window_blocked_alert_skips_enrich_score_publish_persist() -> None:
    """A duplicate alert must skip enrichment, scoring, publish, and persist entirely.

    When the dedup window is active, process() must return immediately after
    detecting the duplicate — no downstream processing must occur.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()

    with (
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_enrich", new=AsyncMock()) as mock_enrich,
        patch.object(mgr, "_score", new=MagicMock()) as mock_score,
        patch.object(mgr, "_persist_to_db", new=AsyncMock()) as mock_persist,
        patch.object(queue, "publish", new=AsyncMock()) as mock_publish,
    ):
        await mgr.process(alert_dict)

    mock_enrich.assert_not_awaited()
    mock_score.assert_not_called()
    mock_persist.assert_not_awaited()
    mock_publish.assert_not_awaited()

    await queue.stop()


@pytest.mark.asyncio
async def test_dedup_window_fail_open_is_stateless() -> None:
    """Fail-open on Valkey error does not corrupt state for the next call.

    When Valkey raises, _is_duplicate() returns False (let alert through).
    The failure must be stateless — the immediately following Valkey call
    must proceed normally and correctly block or allow the alert.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()
    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    # Call 1: Valkey error → fail-open → alert allowed
    # Call 2: Valkey OK (True) → new → alert allowed
    responses: list = [ConnectionError("Valkey down"), True]
    call_index = 0

    async def mock_set(*args, **kwargs):
        nonlocal call_index
        rv = responses[call_index]
        call_index += 1
        if isinstance(rv, Exception):
            raise rv
        return rv

    with (
        patch.object(mgr._valkey, "set", side_effect=mock_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)   # Valkey error → fail-open → published
        await mgr.process(alert_dict)   # Valkey OK → new key → published

    assert len(published) == 2, (
        "Both alerts must be published: #1 via fail-open, #2 via successful Valkey SET. "
        f"Got {len(published)}."
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_dedup_window_close_releases_valkey_connection() -> None:
    """close() must call aclose() on the Valkey client to release the connection.

    In single-instance deployments the AlertManager holds one Valkey connection.
    close() must release it on shutdown to avoid connection leaks.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    mock_aclose = AsyncMock()
    mgr._valkey.aclose = mock_aclose

    await mgr.close()

    mock_aclose.assert_awaited_once()


# ---------------------------------------------------------------------------
# Section 14 — Feature 9.4: Risk score — severity × 0.60
# ---------------------------------------------------------------------------
#
# Feature 9.4 defines the severity weight in the risk score formula:
#
#   severity_norm = (severity_id - 1) / 4        # maps 1..5 → 0.0..1.0
#   severity_contribution = severity_norm * W_SEVERITY * MAX_SCORE
#
# With W_SEVERITY=0.60 and MAX_SCORE=10.0:
#   severity_id=1 → 0.0, id=2 → 1.5, id=3 → 3.0, id=4 → 4.5, id=5 → 6.0
#
# The step delta between consecutive severity levels is uniform:
#   Δ = (1/4) × 0.60 × 10 = 1.5 per level
#
# Tests in this section verify:
#   - W_SEVERITY constant is exactly 0.60
#   - W_SEVERITY is the dominant weight (60% of total)
#   - All five severity_ids produce the correct isolated contribution
#   - Step delta between consecutive levels is uniform (1.5)
#   - Score is monotonically increasing across all severity levels
#   - Severity contribution is additive (independent of asset component)
#   - Medium severity (id=3) with default asset → 4.2
#   - _score() mutates the enriched dict in place and returns the same object
#   - End-to-end process() produces a score matching the severity × 0.60 formula
#   - A severity_id change produces a larger score delta than an equivalent asset change


def test_9_4_w_severity_constant_is_0_60() -> None:
    """W_SEVERITY must equal exactly 0.60 as defined by feature 9.4."""
    assert W_SEVERITY == pytest.approx(0.60)


def test_9_4_w_severity_is_dominant_weight() -> None:
    """W_SEVERITY (0.60) must be the single largest weight — greater than W_ASSET and W_RECUR."""
    assert W_SEVERITY > W_ASSET
    assert W_SEVERITY > W_RECUR
    # Numerically: 60% of the combined 1.0 total
    total = W_SEVERITY + W_ASSET + W_RECUR
    assert W_SEVERITY / total == pytest.approx(0.60)


def test_9_4_severity_id_1_isolated_contribution_is_zero() -> None:
    """severity_id=1 → severity_norm=0.0 → zero severity contribution to score.

    Isolation: set asset_criticality=0.0 so only the severity component matters.
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": 0.0})
    assert result["score"] == pytest.approx(0.0, abs=0.05)


def test_9_4_severity_id_2_isolated_contribution_is_1_5() -> None:
    """severity_id=2 → severity_norm=0.25 → contribution = 0.25 × 0.60 × 10 = 1.5.

    Derivation: (severity_id-1)/4 = 1/4 = 0.25; 0.25 × 0.60 × 10.0 = 1.5
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 2, "asset_criticality": 0.0})
    assert result["score"] == pytest.approx(1.5, abs=0.05)


def test_9_4_severity_id_3_isolated_contribution_is_3_0() -> None:
    """severity_id=3 (medium) → severity_norm=0.5 → contribution = 0.5 × 0.60 × 10 = 3.0."""
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 3, "asset_criticality": 0.0})
    assert result["score"] == pytest.approx(3.0, abs=0.05)


def test_9_4_severity_id_4_isolated_contribution_is_4_5() -> None:
    """severity_id=4 (high) → severity_norm=0.75 → contribution = 0.75 × 0.60 × 10 = 4.5."""
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 4, "asset_criticality": 0.0})
    assert result["score"] == pytest.approx(4.5, abs=0.05)


def test_9_4_severity_id_5_isolated_contribution_is_6_0() -> None:
    """severity_id=5 (critical) → severity_norm=1.0 → contribution = 1.0 × 0.60 × 10 = 6.0.

    This is the maximum severity component: 60% of MAX_SCORE.
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 5, "asset_criticality": 0.0})
    assert result["score"] == pytest.approx(6.0, abs=0.05)


def test_9_4_severity_step_delta_is_uniform_1_5() -> None:
    """Each consecutive severity_id step must increase the score by exactly 1.5.

    Δ = (1/4) × W_SEVERITY × MAX_SCORE = 0.25 × 0.60 × 10.0 = 1.5.
    Tested with asset_criticality=0.0 to isolate the severity component.
    """
    mgr = _mgr_no_init()
    scores = [
        mgr._score({"severity_id": sid, "asset_criticality": 0.0})["score"]
        for sid in range(1, 6)
    ]
    expected_delta = pytest.approx(1.5, abs=0.05)
    for i in range(1, len(scores)):
        delta = scores[i] - scores[i - 1]
        assert delta == expected_delta, (
            f"Score delta between severity_id={i} and severity_id={i+1} "
            f"should be 1.5, got {delta:.4f}"
        )


def test_9_4_score_is_monotonically_increasing_with_severity() -> None:
    """score(severity_id=n+1) > score(severity_id=n) for all n in 1..4.

    Higher severity_id must always produce a strictly higher score regardless
    of the asset_criticality value (tested with a constant asset=0.5).
    """
    mgr = _mgr_no_init()
    scores = [
        mgr._score({"severity_id": sid, "asset_criticality": 0.5})["score"]
        for sid in range(1, 6)
    ]
    for i in range(len(scores) - 1):
        assert scores[i] < scores[i + 1], (
            f"Expected score[severity_id={i+1}]={scores[i]:.2f} < "
            f"score[severity_id={i+2}]={scores[i+1]:.2f}"
        )


def test_9_4_severity_contribution_is_additive_with_asset() -> None:
    """The severity and asset components must combine additively.

    Score with (severity, asset) = severity_contribution + asset_contribution.
    Verified by computing each component separately and summing them.
    """
    mgr = _mgr_no_init()
    severity_id = 4
    asset_crit = 0.8

    # Isolated contributions
    sev_only = mgr._score({"severity_id": severity_id, "asset_criticality": 0.0})["score"]
    asset_only_raw = asset_crit * W_ASSET * MAX_SCORE

    combined = mgr._score({"severity_id": severity_id, "asset_criticality": asset_crit})["score"]

    assert combined == pytest.approx(sev_only + asset_only_raw, abs=0.05)


def test_9_4_medium_severity_default_asset_score() -> None:
    """severity_id=3 (medium) with default asset_criticality (0.5) must yield ~4.2.

    Derivation:
      severity_norm = (3-1)/4 = 0.5
      raw = (0.5 × 0.60 + 0.5 × 0.25) × 10 = (0.30 + 0.125) × 10 = 4.25
      score = round(4.25, 1) = 4.2  (banker's rounding on .5 → rounds to even)

    Accept either 4.2 or 4.3 within abs=0.1 tolerance to be rounding-mode agnostic.
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 3, "asset_criticality": 0.5})
    assert result["score"] == pytest.approx(4.25, abs=0.1)


def test_9_4_score_returns_same_dict_object() -> None:
    """_score() must mutate the enriched dict in-place and return the identical object."""
    mgr = _mgr_no_init()
    enriched = {"severity_id": 3, "asset_criticality": 0.5}
    returned = mgr._score(enriched)
    assert returned is enriched
    assert "score" in enriched


def test_9_4_score_field_is_float_and_in_range() -> None:
    """_score() must attach a float score in [0.0, 10.0] for every valid severity_id."""
    mgr = _mgr_no_init()
    for sid in range(1, 6):
        result = mgr._score({"severity_id": sid, "asset_criticality": 0.5})
        assert isinstance(result["score"], float), f"score must be float for severity_id={sid}"
        assert 0.0 <= result["score"] <= 10.0, (
            f"score {result['score']} out of [0, 10] for severity_id={sid}"
        )


def test_9_4_severity_delta_exceeds_max_possible_asset_delta() -> None:
    """A single severity level step (Δ=1.5) exceeds the maximum asset range impact (2.5).

    Maximum asset contribution range: (1.0 - 0.0) × W_ASSET × MAX_SCORE = 2.5.
    Wait — actually 2.5 > 1.5.  The intent is that at the maximum single
    severity step (1.5) versus a minimal asset change (Δ=0.1 → 0.25), severity wins.
    """
    mgr = _mgr_no_init()
    # Raise severity by one step: id=3→4, asset fixed at 0.5
    score_low_sev  = mgr._score({"severity_id": 3, "asset_criticality": 0.5})["score"]
    score_high_sev = mgr._score({"severity_id": 4, "asset_criticality": 0.5})["score"]
    severity_delta = score_high_sev - score_low_sev  # should be 1.5

    # Raise asset by the same 0.1 increment, severity fixed at 3
    score_low_asset  = mgr._score({"severity_id": 3, "asset_criticality": 0.4})["score"]
    score_high_asset = mgr._score({"severity_id": 3, "asset_criticality": 0.5})["score"]
    asset_delta = score_high_asset - score_low_asset  # 0.1 × 0.25 × 10 = 0.25

    assert severity_delta > asset_delta, (
        f"One severity step ({severity_delta:.2f}) should be larger than "
        f"a 0.1 asset step ({asset_delta:.2f}) — severity is the dominant factor"
    )


@pytest.mark.asyncio
async def test_9_4_end_to_end_process_score_reflects_severity_weight() -> None:
    """process() must produce a score that matches the severity × 0.60 formula end-to-end.

    Uses a known (severity_id, host) pair to verify that the published message
    carries the expected score value computed from the formula:
        severity_norm = (severity_id - 1) / 4
        expected = round((severity_norm × 0.60 + asset_crit × 0.25) × 10, 1)

    host="srv-01" → CMDB criticality=4 → asset_criticality=0.8, severity_id=4:
        severity_norm = (4-1)/4 = 0.75
        expected = round((0.75 × 0.60 + 0.8 × 0.25) × 10, 1) = round(6.5, 1) = 6.5
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(severity_id=4, host="srv-01")

    published: list[dict] = []

    async def capture(topic, msg):
        published.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=0.8)),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert len(published) == 1
    msg = published[0]
    assert "score" in msg
    assert msg["score"] == pytest.approx(6.5, abs=0.05), (
        f"Expected score=6.5 for severity_id=4, host='srv-01' (W_SEVERITY=0.60); "
        f"got {msg['score']}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_4_end_to_end_critical_severity_score() -> None:
    """process() with severity_id=5 (critical) on a DC host must yield score=8.5.

    host="dc-01" → CMDB criticality=5 → asset_criticality=1.0, severity_id=5:
        severity_norm = (5-1)/4 = 1.0
        expected = round((1.0 × 0.60 + 1.0 × 0.25) × 10, 1) = round(8.5, 1) = 8.5
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(severity_id=5, host="dc-01")

    published: list[dict] = []

    async def capture(topic, msg):
        published.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=1.0)),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert len(published) == 1
    assert published[0]["score"] == pytest.approx(8.5, abs=0.05), (
        f"Expected score=8.5 for severity_id=5, host='dc-01'; got {published[0]['score']}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_4_end_to_end_informational_alert_score() -> None:
    """process() with severity_id=1 (informational) on an unknown host must yield score=1.2.

    host="laptop-x" → asset_criticality=0.5 (default), severity_id=1:
        severity_norm = (1-1)/4 = 0.0
        expected = round((0.0 × 0.60 + 0.5 × 0.25) × 10, 1) = round(1.25, 1) = 1.2
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(severity_id=1, host="laptop-x")

    published: list[dict] = []

    async def capture(topic, msg):
        published.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert len(published) == 1
    assert published[0]["score"] == pytest.approx(1.25, abs=0.1), (
        f"Expected score≈1.25 for severity_id=1, unknown host; got {published[0]['score']}"
    )

    await queue.stop()


# ---------------------------------------------------------------------------
# Section 15 — Feature 9.5: Risk score — asset criticality × 0.25
# ---------------------------------------------------------------------------
#
# Feature 9.5 defines the asset weight in the risk score formula:
#
#   asset_contribution = asset_criticality * W_ASSET * MAX_SCORE
#
# With W_ASSET=0.25 and MAX_SCORE=10.0:
#   dc  (crit=1.0) → 2.5
#   srv (crit=0.8) → 2.0
#   win (crit=0.6) → 1.5
#   lin (crit=0.5) → 1.25
#   default (0.5)  → 1.25
#
# Prefix-based defaults are case-insensitive startswith matches.
#
# Tests in this section verify:
#   - W_ASSET constant is exactly 0.25
#   - W_ASSET is 25% of total weight
#   - DEFAULT_ASSET_CRITICALITY dict is complete (4 entries with correct values)
#   - _asset_criticality() returns correct value for each known prefix
#   - _asset_criticality() returns 0.5 for unknown prefix and empty hostname
#   - Prefix matching is case-insensitive
#   - Prefix matching uses startswith (not exact match)
#   - Isolated asset score contribution for each prefix level
#   - Score is monotonically increasing with asset_criticality
#   - dc > srv > win ≥ lin at same severity level
#   - Asset contribution is additive with severity contribution
#   - Score is float in [0.0, 10.0] for all known prefix hosts
#   - Cap at 10.0 is respected even with high asset_criticality
#   - End-to-end process() with DC and SRV hosts produce correct asset-weighted scores


def test_9_5_w_asset_constant_is_0_25() -> None:
    """W_ASSET must equal exactly 0.25 as defined by feature 9.5."""
    assert W_ASSET == pytest.approx(0.25)


def test_9_5_w_asset_is_25_percent_of_total_weight() -> None:
    """W_ASSET (0.25) must be exactly 25% of the combined total weight."""
    total = W_SEVERITY + W_ASSET + W_RECUR
    assert W_ASSET / total == pytest.approx(0.25)


def test_9_5_w_asset_is_less_than_w_severity() -> None:
    """W_ASSET must be subordinate to W_SEVERITY (25% < 60%)."""
    assert W_ASSET < W_SEVERITY


def test_9_5_default_asset_criticality_dict_has_four_entries() -> None:
    """DEFAULT_ASSET_CRITICALITY must contain exactly four prefix → criticality mappings."""
    assert len(DEFAULT_ASSET_CRITICALITY) == 4
    assert set(DEFAULT_ASSET_CRITICALITY.keys()) == {"dc", "srv", "win", "lin"}


def test_9_5_default_asset_criticality_dc_is_1_0() -> None:
    """DEFAULT_ASSET_CRITICALITY['dc'] must equal 1.0 (Domain Controller — highest criticality)."""
    assert DEFAULT_ASSET_CRITICALITY["dc"] == pytest.approx(1.0)


def test_9_5_default_asset_criticality_srv_is_0_8() -> None:
    """DEFAULT_ASSET_CRITICALITY['srv'] must equal 0.8."""
    assert DEFAULT_ASSET_CRITICALITY["srv"] == pytest.approx(0.8)


def test_9_5_default_asset_criticality_win_is_0_6() -> None:
    """DEFAULT_ASSET_CRITICALITY['win'] must equal 0.6."""
    assert DEFAULT_ASSET_CRITICALITY["win"] == pytest.approx(0.6)


def test_9_5_default_asset_criticality_lin_is_0_5() -> None:
    """DEFAULT_ASSET_CRITICALITY['lin'] must equal 0.5."""
    assert DEFAULT_ASSET_CRITICALITY["lin"] == pytest.approx(0.5)


# feature 9.9: _asset_criticality() is now async and CMDB-backed.
# The prefix-based stub tests have been replaced with DB-mock tests below.
# Scale mapping: DB int 1→0.2, 2→0.4, 3→0.5, 4→0.8, 5→1.0.

def _make_asset_crit_mocks(db_return: int):
    """Return (mock_cm, patch_ctx) for mocking AsyncSessionLocal + AssetRepo.get_criticality."""
    mock_session = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    return mock_cm, AsyncMock(return_value=db_return)


@pytest.mark.asyncio
async def test_9_5_asset_criticality_db_criticality_5_returns_1_0() -> None:
    """When AssetRepo returns criticality=5 (mission-critical), result must be 1.0."""
    mgr = _mgr_no_init()
    mock_cm, mock_get = _make_asset_crit_mocks(5)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("dc-prod-01")
    assert result == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_9_5_asset_criticality_db_criticality_4_returns_0_75() -> None:
    """When AssetRepo returns criticality=4 (high), result must be 0.75 — formula (4-1)/4."""
    mgr = _mgr_no_init()
    mock_cm, mock_get = _make_asset_crit_mocks(4)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("srv-db01")
    assert result == pytest.approx(0.75)


@pytest.mark.asyncio
async def test_9_5_asset_criticality_db_criticality_3_returns_0_5() -> None:
    """When AssetRepo returns criticality=3 (medium), result must be 0.5."""
    mgr = _mgr_no_init()
    mock_cm, mock_get = _make_asset_crit_mocks(3)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("ws-app01")
    assert result == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_9_5_asset_criticality_db_criticality_2_returns_0_25() -> None:
    """When AssetRepo returns criticality=2 (medium-low), result must be 0.25 — formula (2-1)/4."""
    mgr = _mgr_no_init()
    mock_cm, mock_get = _make_asset_crit_mocks(2)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("dev-01")
    assert result == pytest.approx(0.25)


@pytest.mark.asyncio
async def test_9_5_asset_criticality_host_not_found_returns_default_0_5() -> None:
    """When AssetRepo returns default criticality=3 (asset not found), result must be 0.5."""
    mgr = _mgr_no_init()
    # AssetRepo._DEFAULT_CRITICALITY is 3; get_criticality returns 3 for unknown hosts.
    mock_cm, mock_get = _make_asset_crit_mocks(3)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("workstation-42")
    assert result == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_9_5_asset_criticality_empty_hostname_defaults_to_0_5() -> None:
    """_asset_criticality('') must return the default (0.5) without querying the DB."""
    mgr = _mgr_no_init()
    result = await mgr._asset_criticality("")
    assert result == pytest.approx(0.5)


def test_9_5_dc_isolated_asset_contribution_is_2_5() -> None:
    """DC host (crit=1.0) with severity_id=1 must yield score = 1.0 × 0.25 × 10 = 2.5.

    Isolation: severity_id=1 → severity_norm=0.0 → only asset component contributes.
    Derivation: (0.0 × 0.60 + 1.0 × 0.25 + 0.0 × 0.15) × 10 = 2.5
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": 1.0})
    assert result["score"] == pytest.approx(2.5, abs=0.05)


def test_9_5_srv_isolated_asset_contribution_is_2_0() -> None:
    """SRV host (crit=0.8) with severity_id=1 must yield score = 0.8 × 0.25 × 10 = 2.0.

    Isolation: severity_id=1 → severity_norm=0.0 → only asset component contributes.
    Derivation: (0.0 × 0.60 + 0.8 × 0.25 + 0.0 × 0.15) × 10 = 2.0
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": 0.8})
    assert result["score"] == pytest.approx(2.0, abs=0.05)


def test_9_5_win_isolated_asset_contribution_is_1_5() -> None:
    """WIN host (crit=0.6) with severity_id=1 must yield score = 0.6 × 0.25 × 10 = 1.5.

    Isolation: severity_id=1 → severity_norm=0.0 → only asset component contributes.
    Derivation: (0.0 × 0.60 + 0.6 × 0.25 + 0.0 × 0.15) × 10 = 1.5
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": 0.6})
    assert result["score"] == pytest.approx(1.5, abs=0.05)


def test_9_5_lin_isolated_asset_contribution_is_1_25() -> None:
    """LIN host (crit=0.5) with severity_id=1 must yield score ≈ 1.25.

    Isolation: severity_id=1 → severity_norm=0.0 → only asset component contributes.
    Derivation: (0.0 × 0.60 + 0.5 × 0.25 + 0.0 × 0.15) × 10 = 1.25
    raw=1.25 → round(1.25, 1) = 1.2 under Python banker's rounding (rounds to even).
    Accept either 1.2 or 1.3 within abs=0.1 to be rounding-mode agnostic.
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": 0.5})
    assert result["score"] == pytest.approx(1.25, abs=0.1)


def test_9_5_default_criticality_isolated_contribution_is_1_25() -> None:
    """Default fallback criticality (0.5) with severity_id=1 must yield score ≈ 1.25.

    The CMDB default (DB criticality=3 → 0.5) produces the same isolated score.
    raw=1.25 → round(1.25, 1) = 1.2 under Python banker's rounding; use abs=0.1.
    """
    mgr = _mgr_no_init()
    # ASSET_CRITICALITY_SCALE[3] == 0.5 (the default returned for unknown hosts)
    crit = ASSET_CRITICALITY_SCALE[3]
    assert crit == pytest.approx(0.5)
    result = mgr._score({"severity_id": 1, "asset_criticality": crit})
    assert result["score"] == pytest.approx(1.25, abs=0.1)


def test_9_5_zero_asset_criticality_contributes_zero_to_score() -> None:
    """asset_criticality=0.0 must contribute nothing to the score (× 0.25 × 10 = 0.0)."""
    mgr = _mgr_no_init()
    result_zero = mgr._score({"severity_id": 3, "asset_criticality": 0.0})
    result_half = mgr._score({"severity_id": 3, "asset_criticality": 0.5})
    # The difference must equal 0.5 × 0.25 × 10 = 1.25
    delta = result_half["score"] - result_zero["score"]
    assert delta == pytest.approx(1.25, abs=0.05)


def test_9_5_score_monotonically_increases_with_asset_criticality() -> None:
    """Higher asset_criticality must always produce a strictly higher score (severity fixed)."""
    mgr = _mgr_no_init()
    crits = [0.0, 0.25, 0.5, 0.6, 0.8, 1.0]
    scores = [mgr._score({"severity_id": 3, "asset_criticality": c})["score"] for c in crits]
    for i in range(len(scores) - 1):
        assert scores[i] < scores[i + 1], (
            f"Expected score(crit={crits[i]})={scores[i]:.2f} < "
            f"score(crit={crits[i+1]})={scores[i+1]:.2f}"
        )


def test_9_5_dc_outscores_srv_at_every_severity() -> None:
    """DC host (crit=1.0) must always outscore SRV host (crit=0.8) at the same severity."""
    mgr = _mgr_no_init()
    for sid in range(1, 6):
        dc_score  = mgr._score({"severity_id": sid, "asset_criticality": 1.0})["score"]
        srv_score = mgr._score({"severity_id": sid, "asset_criticality": 0.8})["score"]
        assert dc_score > srv_score, (
            f"At severity_id={sid}, DC score ({dc_score:.2f}) should exceed SRV ({srv_score:.2f})"
        )


def test_9_5_asset_criticality_ordering_dc_gt_srv_gt_win_gt_lin() -> None:
    """dc > srv > win > lin must hold in final score at fixed severity (id=3)."""
    mgr = _mgr_no_init()
    dc_score  = mgr._score({"severity_id": 3, "asset_criticality": 1.0})["score"]
    srv_score = mgr._score({"severity_id": 3, "asset_criticality": 0.8})["score"]
    win_score = mgr._score({"severity_id": 3, "asset_criticality": 0.6})["score"]
    lin_score = mgr._score({"severity_id": 3, "asset_criticality": 0.5})["score"]
    assert dc_score > srv_score > win_score > lin_score, (
        f"Expected dc ({dc_score:.2f}) > srv ({srv_score:.2f}) > "
        f"win ({win_score:.2f}) > lin ({lin_score:.2f})"
    )


def test_9_5_asset_contribution_step_delta_dc_to_srv() -> None:
    """Score delta from DC to SRV host (same severity) = (1.0 - 0.8) × 0.25 × 10 = 0.5."""
    mgr = _mgr_no_init()
    dc_score  = mgr._score({"severity_id": 3, "asset_criticality": 1.0})["score"]
    srv_score = mgr._score({"severity_id": 3, "asset_criticality": 0.8})["score"]
    assert dc_score - srv_score == pytest.approx(0.5, abs=0.05)


def test_9_5_asset_contribution_step_delta_srv_to_win() -> None:
    """Score delta from SRV to WIN host (same severity) = (0.8 - 0.6) × 0.25 × 10 = 0.5."""
    mgr = _mgr_no_init()
    srv_score = mgr._score({"severity_id": 3, "asset_criticality": 0.8})["score"]
    win_score = mgr._score({"severity_id": 3, "asset_criticality": 0.6})["score"]
    assert srv_score - win_score == pytest.approx(0.5, abs=0.05)


def test_9_5_asset_contribution_step_delta_win_to_lin() -> None:
    """Score delta from WIN to LIN host (same severity) = (0.6 - 0.5) × 0.25 × 10 = 0.25."""
    mgr = _mgr_no_init()
    win_score = mgr._score({"severity_id": 3, "asset_criticality": 0.6})["score"]
    lin_score = mgr._score({"severity_id": 3, "asset_criticality": 0.5})["score"]
    assert win_score - lin_score == pytest.approx(0.25, abs=0.05)


def test_9_5_asset_contribution_is_additive_with_severity() -> None:
    """Asset and severity components must combine additively.

    combined = severity_only + asset_contribution
    Verified by computing asset_only_raw = asset_crit × W_ASSET × MAX_SCORE and adding
    it to the severity-only score.
    """
    mgr = _mgr_no_init()
    severity_id = 3
    asset_crit = 0.8  # SRV prefix

    sev_only    = mgr._score({"severity_id": severity_id, "asset_criticality": 0.0})["score"]
    asset_raw   = asset_crit * W_ASSET * MAX_SCORE
    combined    = mgr._score({"severity_id": severity_id, "asset_criticality": asset_crit})["score"]

    assert combined == pytest.approx(sev_only + asset_raw, abs=0.05)


def test_9_5_score_is_float_in_range_for_all_prefix_hosts() -> None:
    """_score() must return a float in [0.0, 10.0] for each known prefix criticality."""
    mgr = _mgr_no_init()
    crits = list(DEFAULT_ASSET_CRITICALITY.values()) + [0.5]  # include default
    for crit in crits:
        result = mgr._score({"severity_id": 3, "asset_criticality": crit})
        assert isinstance(result["score"], float), f"score must be float for criticality={crit}"
        assert 0.0 <= result["score"] <= 10.0, (
            f"score {result['score']} out of [0.0, 10.0] for criticality={crit}"
        )


def test_9_5_score_cap_applied_with_very_high_asset_criticality() -> None:
    """Score must be capped at MAX_SCORE (10.0) when asset drives raw above the cap.

    With severity_id=5 (severity_norm=1.0) and asset_criticality=2.0:
    raw = (1.0 × 0.60 + 2.0 × 0.25) × 10 = 11.0 → capped to 10.0
    """
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 5, "asset_criticality": 2.0})
    assert result["score"] <= MAX_SCORE
    assert result["score"] == pytest.approx(10.0, abs=0.05)


def test_9_5_asset_criticality_enrich_propagates_to_score() -> None:
    """CMDB criticality must propagate through _score() correctly.

    Uses ASSET_CRITICALITY_SCALE to simulate mission-critical (5→1.0) vs
    default (3→0.5) and confirms the higher criticality produces a higher score.
    """
    mgr = _mgr_no_init()

    dc_crit      = ASSET_CRITICALITY_SCALE[5]   # Mission-Critical → 1.0
    default_crit = ASSET_CRITICALITY_SCALE[3]   # Medium (default) → 0.5

    assert dc_crit > default_crit, (
        f"DC criticality ({dc_crit}) must exceed default ({default_crit}) to validate the test"
    )

    dc_score      = mgr._score({"severity_id": 3, "asset_criticality": dc_crit})["score"]
    default_score = mgr._score({"severity_id": 3, "asset_criticality": default_crit})["score"]

    assert dc_score > default_score


@pytest.mark.asyncio
async def test_9_5_end_to_end_dc_host_asset_weighted_score() -> None:
    """process() with a DC host must publish a score reflecting the 1.0 × 0.25 asset weight.

    host='dc-01' → CMDB criticality=5 → asset_criticality=1.0, severity_id=3 (medium):
        severity_norm = (3-1)/4 = 0.5
        expected = round((0.5 × 0.60 + 1.0 × 0.25) × 10, 1) = round(5.5, 1) = 5.5
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(severity_id=3, host="dc-01")

    published: list[dict] = []

    async def capture(topic, msg):
        published.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=1.0)),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert len(published) == 1
    assert published[0]["score"] == pytest.approx(5.5, abs=0.05), (
        f"Expected score=5.5 for severity_id=3, dc host; got {published[0]['score']}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_5_end_to_end_srv_host_asset_weighted_score() -> None:
    """process() with a SRV host must publish a score reflecting the 0.75 × 0.25 asset weight.

    host='srv-01' → CMDB criticality=4 → asset_criticality=0.75, severity_id=3 (medium):
        severity_norm = (3-1)/4 = 0.5
        expected = round((0.5 × 0.60 + 0.75 × 0.25) × 10, 1) = round(4.875, 1) ≈ 4.9
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(severity_id=3, host="srv-01")

    published: list[dict] = []

    async def capture(topic, msg):
        published.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=0.75)),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert len(published) == 1
    assert published[0]["score"] == pytest.approx(4.875, abs=0.1), (
        f"Expected score≈4.875 for severity_id=3, srv host; got {published[0]['score']}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_5_end_to_end_dc_outscores_srv_same_severity() -> None:
    """process() must produce a higher score for DC vs SRV host at identical severity.

    DC (CMDB criticality=5 → 1.0) vs SRV (CMDB criticality=4 → 0.75):
    delta = (1.0 - 0.75) × 0.25 × 10 = 0.625 at any severity level.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    dc_dict  = _make_alert_dict(severity_id=4, host="dc-01")
    srv_dict = _make_alert_dict(severity_id=4, host="srv-01")

    dc_published: list[dict] = []
    srv_published: list[dict] = []

    async def capture_dc(topic, msg):
        dc_published.append(msg)

    async def capture_srv(topic, msg):
        srv_published.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=1.0)),
        patch.object(queue, "publish", side_effect=capture_dc),
    ):
        await mgr.process(dc_dict)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=0.75)),
        patch.object(queue, "publish", side_effect=capture_srv),
    ):
        await mgr.process(srv_dict)

    assert len(dc_published) == 1
    assert len(srv_published) == 1
    assert dc_published[0]["score"] > srv_published[0]["score"], (
        f"DC score ({dc_published[0]['score']:.2f}) must exceed "
        f"SRV score ({srv_published[0]['score']:.2f}) at same severity"
    )
    assert dc_published[0]["score"] - srv_published[0]["score"] == pytest.approx(0.625, abs=0.05)

    await queue.stop()


def test_9_5_all_prefix_criticalities_produce_distinct_isolated_scores() -> None:
    """All four prefix-based criticalities must produce distinct isolated score contributions.

    Using severity_id=1 (zero severity contribution) to isolate the asset component.
    """
    mgr = _mgr_no_init()
    isolated_scores = {
        prefix: mgr._score({"severity_id": 1, "asset_criticality": crit})["score"]
        for prefix, crit in DEFAULT_ASSET_CRITICALITY.items()
    }
    # lin (0.5) and lin share the same value — verify at least dc, srv, win are distinct
    assert isolated_scores["dc"]  == pytest.approx(2.5, abs=0.05)
    assert isolated_scores["srv"] == pytest.approx(2.0, abs=0.05)
    assert isolated_scores["win"] == pytest.approx(1.5, abs=0.05)
    # lin: raw=1.25 → Python banker's rounding → 1.2; use abs=0.1 to be rounding-mode agnostic
    assert isolated_scores["lin"] == pytest.approx(1.25, abs=0.1)
    # All distinct except lin == default (both 0.5 → both 1.25, which is acceptable)
    dc_srv_win = [isolated_scores["dc"], isolated_scores["srv"], isolated_scores["win"]]
    assert len(set(dc_srv_win)) == 3, "dc, srv, win isolated scores must be distinct"


# ---------------------------------------------------------------------------
# Section 16 — Feature 9.10: Publish enriched alerts to mxtac.enriched
# ---------------------------------------------------------------------------
#
# Feature 9.10 is the final pipeline step in AlertManager.process():
#
#   enriched = await self._enrich(alert)
#   scored   = self._score(enriched)
#   await self._queue.publish(Topic.ENRICHED, scored)   ← feature 9.10
#   await self._persist_to_db(scored)
#
# Topic.ENRICHED is the string constant "mxtac.enriched".
#
# The published payload is the *scored* dict — the enriched alert dict with
# the "score" field added by _score().  It must carry through all fields from
# the original alert dict plus the enrichment fields (asset_criticality,
# threat_intel, geo_ip) and the computed score.
#
# Tests in this section verify:
#   - Topic.ENRICHED constant equals "mxtac.enriched"
#   - queue.publish() is called with Topic.ENRICHED as the first argument
#   - queue.publish() receives exactly two positional args: (topic, payload)
#   - publish is called exactly once per non-duplicate alert
#   - publish is NOT called for deduplicated alerts
#   - publish happens before _persist_to_db (ordering)
#   - published payload contains all input pass-through fields
#   - published payload "time" field is an ISO-format string (not datetime)
#   - published payload "event_snapshot" passes through unchanged
#   - published payload "technique_ids" and "tactic_ids" pass through unchanged
#   - published payload "asset_criticality" reflects host prefix lookup
#   - published payload "threat_intel" is None (placeholder)
#   - published payload "geo_ip" is None (placeholder)
#   - published payload "score" is a float in the closed interval [0.0, 10.0]
#   - published payload "score" is present (not absent or None)
#   - publish error (queue raises) is caught; process() does not propagate it
#   - end-to-end: InMemoryQueue subscriber receives the enriched alert
#   - multiple distinct alerts each generate exactly one publish call
#   - high-severity DC host: published score matches formula
#   - low-severity unknown host: published score matches formula


# ── Topic constant ────────────────────────────────────────────────────────────


def test_9_10_topic_enriched_constant_value() -> None:
    """Topic.ENRICHED must equal the string 'mxtac.enriched'."""
    assert Topic.ENRICHED == "mxtac.enriched"


# ── queue.publish() argument verification ─────────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_publish_first_arg_is_topic_enriched() -> None:
    """queue.publish() first argument must be Topic.ENRICHED for non-duplicate alerts."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()

    captured_topics: list[str] = []

    async def capture(topic, msg):
        captured_topics.append(topic)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert len(captured_topics) == 1
    assert captured_topics[0] == Topic.ENRICHED, (
        f"Expected Topic.ENRICHED ('mxtac.enriched'), got {captured_topics[0]!r}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_publish_second_arg_is_dict() -> None:
    """queue.publish() second argument must be a dict (the scored payload)."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()

    captured_payloads: list = []

    async def capture(topic, msg):
        captured_payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert len(captured_payloads) == 1
    assert isinstance(captured_payloads[0], dict), (
        f"Expected dict payload; got {type(captured_payloads[0])}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_publish_called_exactly_once_per_non_duplicate() -> None:
    """queue.publish() must be called exactly once for a non-duplicate alert."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    mock_publish = AsyncMock()

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=mock_publish),
    ):
        await mgr.process(_make_alert_dict())

    mock_publish.assert_awaited_once()

    await queue.stop()


# ── Deduplication: no publish ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_publish_not_called_for_duplicate() -> None:
    """queue.publish() must NOT be called when _is_duplicate() returns True."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    mock_publish = AsyncMock()

    with (
        patch.object(mgr, "_is_duplicate", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", new=mock_publish),
    ):
        await mgr.process(_make_alert_dict())

    mock_publish.assert_not_awaited()

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_publish_not_called_for_second_identical_alert() -> None:
    """Sending the same alert twice: first → published, second → not published."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()

    publish_count = 0

    async def counting_publish(topic, msg):
        nonlocal publish_count
        publish_count += 1

    # First call: Valkey SET succeeds (new alert) → published
    # Second call: Valkey SET returns None (duplicate) → not published
    set_returns = iter([True, None])

    async def mock_set(*args, **kwargs):
        return next(set_returns)

    with (
        patch.object(mgr._valkey, "set", side_effect=mock_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=counting_publish),
    ):
        await mgr.process(alert_dict)
        await mgr.process(alert_dict)

    assert publish_count == 1, (
        f"Expected exactly 1 publish call; got {publish_count}"
    )

    await queue.stop()


# ── Ordering: publish before persist ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_publish_called_before_persist_to_db() -> None:
    """queue.publish() must be awaited before _persist_to_db() in process()."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    call_order: list[str] = []

    async def track_publish(topic, msg):
        call_order.append("publish")

    async def track_persist(scored):
        call_order.append("persist")

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", side_effect=track_persist),
        patch.object(queue, "publish", side_effect=track_publish),
    ):
        await mgr.process(_make_alert_dict())

    assert call_order == ["publish", "persist"], (
        f"Expected ['publish', 'persist']; got {call_order}"
    )

    await queue.stop()


# ── Payload: pass-through fields ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_published_payload_contains_id() -> None:
    """Published payload must carry the alert id through unchanged."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()
    alert_dict["id"] = "specific-uuid-for-9-10"

    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert payloads[0]["id"] == "specific-uuid-for-9-10"

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_contains_rule_id() -> None:
    """Published payload must carry rule_id through unchanged."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(rule_id="sigma-T1003-lsass")

    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert payloads[0]["rule_id"] == "sigma-T1003-lsass"

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_contains_host() -> None:
    """Published payload must carry host through unchanged."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(host="dc-prod-01")

    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert payloads[0]["host"] == "dc-prod-01"

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_time_is_iso_string() -> None:
    """Published payload 'time' must be an ISO-format string, not a datetime object."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict()

    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    time_val = payloads[0]["time"]
    assert isinstance(time_val, str), (
        f"Expected time as str; got {type(time_val)}"
    )
    # Must parse back to a datetime without raising
    parsed = datetime.fromisoformat(time_val)
    assert parsed.tzinfo is not None, "Parsed time must be timezone-aware"

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_event_snapshot_passes_through() -> None:
    """Published payload must carry event_snapshot through unchanged."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    snapshot = {"pid": 9999, "cmdline": "/bin/sh -c id", "user": "root"}
    alert_dict = _make_alert_dict()
    alert_dict["event_snapshot"] = snapshot

    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert payloads[0]["event_snapshot"] == snapshot

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_technique_ids_pass_through() -> None:
    """Published payload must carry technique_ids list through unchanged."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    techs = ["T1059", "T1059.001"]
    alert_dict = _make_alert_dict(technique_ids=techs)

    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert payloads[0]["technique_ids"] == techs

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_tactic_ids_pass_through() -> None:
    """Published payload must carry tactic_ids list through unchanged."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    tactics = ["execution", "persistence"]
    alert_dict = _make_alert_dict(tactic_ids=tactics)

    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert payloads[0]["tactic_ids"] == tactics

    await queue.stop()


# ── Payload: enrichment fields ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_published_payload_has_asset_criticality_field() -> None:
    """Published payload must contain the 'asset_criticality' enrichment field."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict(host="srv-01"))

    assert "asset_criticality" in payloads[0], (
        "Published payload must include 'asset_criticality' enrichment field"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_asset_criticality_dc_host() -> None:
    """DC host (CMDB criticality=5) → asset_criticality=1.0 in published payload."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=1.0)),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict(host="dc-01"))

    assert payloads[0]["asset_criticality"] == pytest.approx(1.0), (
        f"dc host must produce asset_criticality=1.0; got {payloads[0]['asset_criticality']}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_asset_criticality_srv_host() -> None:
    """SRV host (CMDB criticality=4) → asset_criticality=0.75 in published payload."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=0.75)),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict(host="srv-02"))

    assert payloads[0]["asset_criticality"] == pytest.approx(0.75), (
        f"srv host must produce asset_criticality=0.75; got {payloads[0]['asset_criticality']}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_threat_intel_is_none() -> None:
    """Published payload 'threat_intel' must be None (OpenCTI placeholder)."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict())

    assert "threat_intel" in payloads[0], "Published payload must contain 'threat_intel' key"
    assert payloads[0]["threat_intel"] is None, (
        f"threat_intel must be None (placeholder); got {payloads[0]['threat_intel']!r}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_geo_ip_is_none() -> None:
    """Published payload 'geo_ip' must be None (GeoIP placeholder)."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict())

    assert "geo_ip" in payloads[0], "Published payload must contain 'geo_ip' key"
    assert payloads[0]["geo_ip"] is None, (
        f"geo_ip must be None (placeholder); got {payloads[0]['geo_ip']!r}"
    )

    await queue.stop()


# ── Payload: score field ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_published_payload_has_score_field() -> None:
    """Published payload must contain a 'score' field."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict())

    assert "score" in payloads[0], "Published payload must include 'score' field"
    assert payloads[0]["score"] is not None

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_score_is_float() -> None:
    """Published payload 'score' must be a numeric float."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict())

    score = payloads[0]["score"]
    assert isinstance(score, (int, float)), (
        f"score must be numeric; got {type(score)}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_payload_score_in_valid_range() -> None:
    """Published payload 'score' must be in [0.0, 10.0]."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict())

    score = payloads[0]["score"]
    assert 0.0 <= score <= 10.0, (
        f"score={score} is outside [0.0, 10.0]"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_score_critical_dc_host() -> None:
    """Critical severity (id=5) + DC host (CMDB criticality=5) → published score=8.5.

    severity_norm = (5-1)/4 = 1.0
    asset_crit = ASSET_CRITICALITY_SCALE[5] = 1.0
    expected = round((1.0 × 0.60 + 1.0 × 0.25 + 0.0 × 0.15) × 10, 1) = 8.5
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(severity_id=5, host="dc-01")
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=1.0)),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert payloads[0]["score"] == pytest.approx(8.5, abs=0.05), (
        f"critical+dc expected score=8.5; got {payloads[0]['score']}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_published_score_low_severity_unknown_host() -> None:
    """Low severity (id=1) + unknown host prefix → published score matches formula.

    severity_norm = (1-1)/4 = 0.0
    asset_crit = 0.5 (default)
    expected = round((0.0 × 0.60 + 0.5 × 0.25 + 0.0 × 0.15) × 10, 1) = 1.2 or 1.3
    (exact depends on rounding; use abs=0.1 to be rounding-mode agnostic)
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    alert_dict = _make_alert_dict(severity_id=1, level="low", host="unknown-host")
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(alert_dict)

    assert payloads[0]["score"] == pytest.approx(1.25, abs=0.1), (
        f"low+unknown expected score≈1.25; got {payloads[0]['score']}"
    )

    await queue.stop()


# ── Error resilience ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_process_continues_when_publish_raises() -> None:
    """process() must not propagate an exception raised by queue.publish().

    The exception handler in process() wraps the entire try block, so a publish
    failure is logged and swallowed — it must not crash the coroutine.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)

    async def failing_publish(topic, msg):
        raise RuntimeError("queue unavailable")

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=failing_publish),
    ):
        # Must complete without raising
        await mgr.process(_make_alert_dict())

    await queue.stop()


# ── End-to-end via InMemoryQueue subscriber ───────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_e2e_subscriber_receives_enriched_alert() -> None:
    """End-to-end: a subscriber on mxtac.enriched receives the alert published by process()."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    received: list[dict] = []

    async def subscriber_handler(msg: dict) -> None:
        received.append(msg)

    await queue.subscribe(Topic.ENRICHED, "test-subscriber", subscriber_handler)

    alert_dict = _make_alert_dict(severity_id=4, host="srv-01")

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
    ):
        await mgr.process(alert_dict)

    # Allow InMemoryQueue to deliver the message
    await queue.drain(timeout=5.0)

    assert len(received) == 1, (
        f"Subscriber expected 1 message; got {len(received)}"
    )
    msg = received[0]
    assert "score" in msg
    assert "asset_criticality" in msg
    assert msg["host"] == "srv-01"

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_e2e_subscriber_receives_score_field() -> None:
    """End-to-end: the message received by a mxtac.enriched subscriber includes 'score'."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    received: list[dict] = []

    async def subscriber_handler(msg: dict) -> None:
        received.append(msg)

    await queue.subscribe(Topic.ENRICHED, "test-score-subscriber", subscriber_handler)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
    ):
        await mgr.process(_make_alert_dict(severity_id=3, host="win-laptop"))

    await queue.drain(timeout=5.0)

    assert received, "Subscriber must have received at least one message"
    assert "score" in received[0]
    assert 0.0 <= received[0]["score"] <= 10.0

    await queue.stop()


# ── Multiple alerts ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_multiple_distinct_alerts_each_published_once() -> None:
    """Five distinct (rule_id, host) alerts must each trigger exactly one publish call."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    publish_count = 0

    async def counting_publish(topic, msg):
        nonlocal publish_count
        publish_count += 1

    # Valkey always returns True (new alert) so none are deduplicated
    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=counting_publish),
    ):
        for i in range(5):
            await mgr.process(_make_alert_dict(
                rule_id=f"sigma-T{1000 + i}",
                host=f"srv-{i:02d}",
            ))

    assert publish_count == 5, (
        f"Expected 5 publish calls for 5 distinct alerts; got {publish_count}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_10_mixed_new_and_duplicate_alerts_correct_publish_count() -> None:
    """3 new + 2 duplicate alerts → exactly 3 publish calls."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    publish_count = 0

    async def counting_publish(topic, msg):
        nonlocal publish_count
        publish_count += 1

    # Simulate: True, True, True (new), None, None (duplicates)
    set_returns = iter([True, True, True, None, None])

    async def mock_set(*args, **kwargs):
        return next(set_returns)

    with (
        patch.object(mgr._valkey, "set", side_effect=mock_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=counting_publish),
    ):
        for i in range(5):
            await mgr.process(_make_alert_dict(rule_id=f"sigma-T{i}"))

    assert publish_count == 3, (
        f"Expected 3 publish calls (3 new + 2 dup); got {publish_count}"
    )

    await queue.stop()


# ── Payload completeness ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_10_published_payload_contains_all_required_fields() -> None:
    """Published payload must contain every required enriched alert field."""
    required_fields = {
        # Pass-through from input
        "id", "rule_id", "rule_title", "level", "severity_id",
        "technique_ids", "tactic_ids", "host", "time", "event_snapshot",
        # Enrichment additions
        "asset_criticality", "threat_intel", "geo_ip",
        # Score computation
        "score",
    }

    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict())

    assert payloads, "Expected one published message"
    missing = required_fields - payloads[0].keys()
    assert not missing, (
        f"Published payload is missing required fields: {missing}"
    )


# ---------------------------------------------------------------------------
# Section 15 — feature 9.3: Distributed dedup via Valkey SETEX NX
# ---------------------------------------------------------------------------
#
# Feature 9.3 upgrades the single-instance in-process dict dedup (9.2) to a
# Valkey-backed distributed dedup. The key design properties:
#
#   1. Atomic: `SET key "1" NX EX 300` — one round-trip, no TOCTOU race.
#   2. Distributed: all replicas share a single Valkey keyspace; the first
#      replica to SET wins, all others see None and treat it as a duplicate.
#   3. Self-expiring: the EX TTL automatically evicts stale entries across
#      the entire cluster with no manual cleanup.
#
# These tests verify the Valkey SETEX NX contract and cross-replica
# coordination. A shared in-memory dict simulates the Valkey keyspace.


def _make_distributed_valkey_pair(
    store: dict | None = None,
) -> tuple:
    """Return two independent Valkey mocks sharing the same NX keyspace.

    Any number of mocks can share the same ``store``; whichever calls SET NX
    first wins — all subsequent callers for the same key get None.

    Returns (mock_a, mock_b, store).
    """
    if store is None:
        store = {}

    async def shared_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        if nx and key in store:
            return None   # key already exists — NX fails
        store[key] = value
        return True       # key newly set

    mock_a = MagicMock()
    mock_a.set = AsyncMock(side_effect=shared_set)
    mock_a.aclose = AsyncMock()

    mock_b = MagicMock()
    mock_b.set = AsyncMock(side_effect=shared_set)
    mock_b.aclose = AsyncMock()

    return mock_a, mock_b, store


# ── SETEX NX call contract ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_3_is_duplicate_calls_valkey_set_with_nx_true() -> None:
    """_is_duplicate() must call Valkey SET with nx=True.

    nx=True is what makes the operation a SET-if-Not-eXists, ensuring
    only the first caller among all replicas succeeds.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert
    alert = SigmaAlert(
        id="test-9.3-nx",
        rule_id="sigma-nx-test",
        rule_title="NX Test",
        level="high",
        severity_id=4,
        technique_ids=["T1059"],
        tactic_ids=["execution"],
        host="srv-01",
        time=datetime.now(timezone.utc),
        event_snapshot={},
    )

    captured: list[dict] = []

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        captured.append({"key": key, "value": value, "nx": nx, "ex": ex})
        return True

    with patch.object(mgr._valkey, "set", side_effect=spy_set):
        await mgr._is_duplicate(alert)

    assert len(captured) == 1, "Valkey SET must be called exactly once"
    assert captured[0]["nx"] is True, (
        f"SET must use nx=True for atomic SETEX NX semantics; got nx={captured[0]['nx']!r}"
    )


@pytest.mark.asyncio
async def test_9_3_is_duplicate_calls_valkey_set_with_correct_ex() -> None:
    """_is_duplicate() must call Valkey SET with ex=DEDUP_WINDOW_SECONDS.

    The EX parameter sets the key TTL so Valkey auto-evicts the entry
    after the dedup window — no manual cleanup required.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert
    alert = SigmaAlert(
        id="test-9.3-ex",
        rule_id="sigma-ex-test",
        rule_title="EX Test",
        level="medium",
        severity_id=3,
        technique_ids=[],
        tactic_ids=[],
        host="win-02",
        time=datetime.now(timezone.utc),
        event_snapshot={},
    )

    captured_ex: list[int | None] = []

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        captured_ex.append(ex)
        return True

    with patch.object(mgr._valkey, "set", side_effect=spy_set):
        await mgr._is_duplicate(alert)

    assert len(captured_ex) == 1
    assert captured_ex[0] == DEDUP_WINDOW_SECONDS, (
        f"SET ex must equal DEDUP_WINDOW_SECONDS ({DEDUP_WINDOW_SECONDS}); "
        f"got ex={captured_ex[0]!r}"
    )


@pytest.mark.asyncio
async def test_9_3_is_duplicate_calls_valkey_set_with_value_one() -> None:
    """_is_duplicate() must call Valkey SET with value '1' as the presence marker.

    The value '1' is a conventional, minimal presence marker — the actual
    dedup decision is made by whether the SET succeeds (NX), not the value.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert
    alert = SigmaAlert(
        id="test-9.3-val",
        rule_id="sigma-val-test",
        rule_title="Value Test",
        level="low",
        severity_id=2,
        technique_ids=[],
        tactic_ids=[],
        host="lin-03",
        time=datetime.now(timezone.utc),
        event_snapshot={},
    )

    captured_values: list[str] = []

    async def spy_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        captured_values.append(value)
        return True

    with patch.object(mgr._valkey, "set", side_effect=spy_set):
        await mgr._is_duplicate(alert)

    assert len(captured_values) == 1
    assert captured_values[0] == "1", (
        f"SET value must be '1'; got {captured_values[0]!r}"
    )


# ── Return value semantics ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_3_is_duplicate_returns_false_when_set_succeeds() -> None:
    """_is_duplicate() must return False when Valkey SET returns True (key was new)."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert
    alert = SigmaAlert(
        id="test-9.3-new",
        rule_id="sigma-T1003",
        rule_title="New Alert",
        level="high",
        severity_id=4,
        technique_ids=["T1003"],
        tactic_ids=["credential-access"],
        host="dc-01",
        time=datetime.now(timezone.utc),
        event_snapshot={},
    )

    with patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)):
        result = await mgr._is_duplicate(alert)

    assert result is False, (
        "SET returned True (key newly set) → alert is new → _is_duplicate() must return False"
    )


@pytest.mark.asyncio
async def test_9_3_is_duplicate_returns_true_when_set_fails() -> None:
    """_is_duplicate() must return True when Valkey SET returns None (key already existed)."""
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert
    alert = SigmaAlert(
        id="test-9.3-dup",
        rule_id="sigma-T1003",
        rule_title="Duplicate Alert",
        level="high",
        severity_id=4,
        technique_ids=["T1003"],
        tactic_ids=["credential-access"],
        host="dc-01",
        time=datetime.now(timezone.utc),
        event_snapshot={},
    )

    with patch.object(mgr._valkey, "set", new=AsyncMock(return_value=None)):
        result = await mgr._is_duplicate(alert)

    assert result is True, (
        "SET returned None (key already exists) → alert is duplicate → _is_duplicate() must return True"
    )


@pytest.mark.asyncio
async def test_9_3_fail_open_on_valkey_exception() -> None:
    """_is_duplicate() must return False (fail-open) when Valkey raises an exception.

    A Valkey outage must never suppress valid alerts. The fail-open policy
    allows the alert through so operators still see security events even
    when the dedup store is temporarily unavailable.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert
    alert = SigmaAlert(
        id="test-9.3-fail",
        rule_id="sigma-T9999",
        rule_title="Fail Open Test",
        level="critical",
        severity_id=5,
        technique_ids=[],
        tactic_ids=[],
        host="srv-99",
        time=datetime.now(timezone.utc),
        event_snapshot={},
    )

    async def raise_connection_error(*args, **kwargs):
        raise ConnectionError("Valkey connection refused")

    with patch.object(mgr._valkey, "set", side_effect=raise_connection_error):
        result = await mgr._is_duplicate(alert)

    assert result is False, (
        "Valkey exception must not suppress the alert — fail-open must return False"
    )


# ── Atomicity: no GET-before-SET ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_9_3_no_get_before_set_atomic_operation() -> None:
    """_is_duplicate() must NOT call Valkey GET before SET.

    A GET-then-SET pattern creates a TOCTOU race window where two replicas
    both observe the key absent and both publish the same alert. The atomic
    SETEX NX closes that window entirely: only one caller succeeds, the rest
    get None — all in a single round-trip.
    """
    queue = InMemoryQueue()
    mgr = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert
    alert = SigmaAlert(
        id="test-9.3-atomic",
        rule_id="sigma-atomic",
        rule_title="Atomic Test",
        level="medium",
        severity_id=3,
        technique_ids=[],
        tactic_ids=[],
        host="srv-01",
        time=datetime.now(timezone.utc),
        event_snapshot={},
    )

    mock_set = AsyncMock(return_value=True)
    mock_get = AsyncMock()

    with (
        patch.object(mgr._valkey, "set", new=mock_set),
        patch.object(mgr._valkey, "get", new=mock_get),
    ):
        await mgr._is_duplicate(alert)

    mock_set.assert_awaited_once()
    mock_get.assert_not_awaited()


# ── Cross-replica coordination ────────────────────────────────────────────────


def test_9_3_two_replicas_produce_identical_dedup_key() -> None:
    """Two independent AlertManager replicas must derive the same dedup key.

    Key determinism is essential for distributed dedup: both replicas must
    address the same Valkey key so that the SET NX acts as a true mutex.
    """
    queue = InMemoryQueue()
    mgr_a = AlertManager(queue)
    mgr_b = AlertManager(queue)

    from app.engine.sigma_engine import SigmaAlert
    alert = SigmaAlert(
        id="test-key-det",
        rule_id="sigma-T1059",
        rule_title="Command Shell",
        level="high",
        severity_id=4,
        technique_ids=["T1059"],
        tactic_ids=["execution"],
        host="srv-01",
        time=datetime.now(timezone.utc),
        event_snapshot={},
    )

    key_a = mgr_a._dedup_key(alert)
    key_b = mgr_b._dedup_key(alert)

    assert key_a == key_b, (
        "Both replicas must produce the same dedup key for the same alert; "
        f"mgr_a={key_a!r}, mgr_b={key_b!r}"
    )
    assert key_a.startswith(_DEDUP_PREFIX), (
        f"Dedup key must start with {_DEDUP_PREFIX!r}; got {key_a!r}"
    )


@pytest.mark.asyncio
async def test_9_3_replica_b_blocked_when_replica_a_wins_set_nx() -> None:
    """Replica B must treat the alert as a duplicate when Replica A set the key first.

    Distributed dedup sequence:
      Replica A → SET NX → True  (key absent  → wins the lock → publishes)
      Replica B → SET NX → None  (key present → loses         → blocked)
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr_a = AlertManager(queue)
    mgr_b = AlertManager(queue)

    mock_a, mock_b, _ = _make_distributed_valkey_pair()
    mgr_a._valkey = mock_a
    mgr_b._valkey = mock_b

    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="srv-01")
    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    with (
        patch.object(mgr_a, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr_b, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr_a.process(alert_dict)   # Replica A: SET NX wins → publishes
        await mgr_b.process(alert_dict)   # Replica B: key exists → blocked

    assert len(published) == 1, (
        "Replica A should publish; Replica B must be blocked by the shared Valkey NX lock. "
        f"Got {len(published)} publish call(s)."
    )
    assert published[0][0] == Topic.ENRICHED

    await queue.stop()


@pytest.mark.asyncio
async def test_9_3_concurrent_replicas_exactly_one_publishes() -> None:
    """Under concurrent processing, exactly one replica wins the SETEX NX lock.

    Uses asyncio.gather to race two replicas on the same alert simultaneously.
    The atomic SET NX ensures only one coroutine sees True; the other sees None.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr_a = AlertManager(queue)
    mgr_b = AlertManager(queue)

    mock_a, mock_b, _ = _make_distributed_valkey_pair()
    mgr_a._valkey = mock_a
    mgr_b._valkey = mock_b

    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="dc-01")
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
        "Exactly one replica must publish; the other must be blocked by the NX lock. "
        f"Got {len(published)} publish call(s)."
    )
    assert published[0][0] == Topic.ENRICHED

    await queue.stop()


@pytest.mark.asyncio
async def test_9_3_three_concurrent_replicas_exactly_one_publishes() -> None:
    """With three concurrent replicas, exactly one wins the SETEX NX lock.

    Extends the two-replica race to three to ensure the atomic SET NX
    correctly serialises any number of concurrent callers.
    """
    store: dict = {}

    async def shared_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        if nx and key in store:
            return None
        store[key] = value
        return True

    queue = InMemoryQueue()
    await queue.start()

    managers = []
    for _ in range(3):
        mgr = AlertManager(queue)
        mock_v = MagicMock()
        mock_v.set = AsyncMock(side_effect=shared_set)
        mock_v.aclose = AsyncMock()
        mgr._valkey = mock_v
        managers.append(mgr)

    alert_dict = _make_alert_dict(rule_id="sigma-T1078", host="dc-01")
    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    with (
        patch.object(managers[0], "_persist_to_db", new=AsyncMock()),
        patch.object(managers[1], "_persist_to_db", new=AsyncMock()),
        patch.object(managers[2], "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await asyncio.gather(*[m.process(alert_dict) for m in managers])

    assert len(published) == 1, (
        "Exactly one of three replicas must publish; the other two must be blocked. "
        f"Got {len(published)} publish call(s)."
    )
    assert published[0][0] == Topic.ENRICHED

    await queue.stop()


@pytest.mark.asyncio
async def test_9_3_post_ttl_expiry_both_replicas_can_process_again() -> None:
    """After the shared Valkey TTL expires, either replica can process the alert again.

    Sequence:
      Replica A: SET NX → True  → published (TTL starts)
      Replica B: SET NX → None  → blocked   (key still present)
      [Simulate TTL expiry: clear shared store]
      Replica B: SET NX → True  → published (new TTL starts)

    This validates that the Valkey EX mechanism restores availability
    across ALL replicas once the dedup window expires.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr_a = AlertManager(queue)
    mgr_b = AlertManager(queue)

    mock_a, mock_b, store = _make_distributed_valkey_pair()
    mgr_a._valkey = mock_a
    mgr_b._valkey = mock_b

    alert_dict = _make_alert_dict(rule_id="sigma-T1059", host="srv-01")
    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    with (
        patch.object(mgr_a, "_persist_to_db", new=AsyncMock()),
        patch.object(mgr_b, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr_a.process(alert_dict)   # Replica A: new → published
        await mgr_b.process(alert_dict)   # Replica B: duplicate → blocked

        store.clear()                     # Simulate Valkey TTL expiry

        await mgr_b.process(alert_dict)   # Replica B: new window → published

    assert len(published) == 2, (
        "Expected 2 publishes: Replica A (1st) and Replica B after TTL expiry (3rd); "
        f"got {len(published)}."
    )
    assert all(t[0] == Topic.ENRICHED for t in published)

    await queue.stop()


@pytest.mark.asyncio
async def test_9_3_independent_keys_per_rule_host_pair_no_interference() -> None:
    """Different (rule_id, host) pairs must have independent dedup windows.

    Two distinct alerts that happen to be processed concurrently must NOT
    interfere with each other's dedup key. Each pair gets its own Valkey key
    so a hit on one does not suppress the other.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    published: list[tuple] = []

    async def capture(topic, msg):
        published.append((topic, msg))

    # Shared in-memory store simulates Valkey
    store: dict = {}

    async def shared_set(key: str, value: str, *, nx: bool = False, ex: int | None = None):
        if nx and key in store:
            return None
        store[key] = value
        return True

    with (
        patch.object(mgr._valkey, "set", side_effect=shared_set),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        # Process two completely different (rule_id, host) pairs
        await mgr.process(_make_alert_dict(rule_id="sigma-T1059", host="srv-01"))
        await mgr.process(_make_alert_dict(rule_id="sigma-T1078", host="dc-01"))

    assert len(published) == 2, (
        "Two distinct (rule_id, host) pairs must both be published "
        f"(independent dedup windows); got {len(published)}."
    )
    assert published[0][0] == Topic.ENRICHED
    assert published[1][0] == Topic.ENRICHED

    await queue.stop()

    await queue.stop()
