"""Tests for feature 9.9 — Enrichment: asset criticality from CMDB.

Coverage:
  - ASSET_CRITICALITY_SCALE: constant has exactly 5 entries (keys 1-5)
  - ASSET_CRITICALITY_SCALE: 1→0.2, 2→0.4, 3→0.5, 4→0.8, 5→1.0
  - _asset_criticality(): empty hostname returns ASSET_CRITICALITY_SCALE[3]=0.5 without DB call
  - _asset_criticality(): DB criticality=5 (mission-critical) → returns 1.0
  - _asset_criticality(): DB criticality=4 (high) → returns 0.8
  - _asset_criticality(): DB criticality=3 (medium / default) → returns 0.5
  - _asset_criticality(): DB criticality=2 (medium-low) → returns 0.4
  - _asset_criticality(): DB criticality=1 (low) → returns 0.2
  - _asset_criticality(): DB returns default criticality=3 for unknown host → 0.5
  - _asset_criticality(): DB error → fail-open returns 0.5 (pipeline not blocked)
  - _asset_criticality(): all five scale values in [0.0, 1.0] range
  - _asset_criticality(): values strictly increase with DB criticality level
  - _enrich(): asset_criticality field populated with CMDB-backed value
  - _enrich(): high-criticality asset (DB=5) produces higher score than default (DB=3)
  - process(): asset_criticality=1.0 (mission-critical) propagates to published payload
  - process(): asset_criticality=0.5 (default) propagates to published payload
  - process(): CMDB DB error → pipeline continues (fail-open), score still published
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.pipeline.queue import InMemoryQueue, Topic
from app.services.alert_manager import (
    AlertManager,
    ASSET_CRITICALITY_SCALE,
    MAX_SCORE,
    W_ASSET,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mgr_no_init() -> AlertManager:
    """Create an AlertManager instance without calling __init__ (avoids Valkey connection)."""
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = MagicMock()
    return mgr


def _make_alert_dict(
    *,
    host: str = "srv-01",
    severity_id: int = 3,
    level: str = "medium",
) -> dict:
    from datetime import datetime, timezone
    return {
        "id": "test-cmdb-uuid",
        "rule_id": "sigma-T1059",
        "rule_title": "Command Shell Execution",
        "level": level,
        "severity_id": severity_id,
        "technique_ids": ["T1059"],
        "tactic_ids": ["execution"],
        "host": host,
        "time": datetime.now(timezone.utc).isoformat(),
        "event_snapshot": {"pid": 1234},
    }


def _make_db_mocks(db_return: int):
    """Return (mock_context_manager, mock_get_criticality) for patching DB calls."""
    mock_session = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    mock_get = AsyncMock(return_value=db_return)
    return mock_cm, mock_get


# ---------------------------------------------------------------------------
# ASSET_CRITICALITY_SCALE constant
# ---------------------------------------------------------------------------


def test_9_9_scale_has_five_entries() -> None:
    """ASSET_CRITICALITY_SCALE must have exactly five entries, one per DB criticality level."""
    assert len(ASSET_CRITICALITY_SCALE) == 5
    assert set(ASSET_CRITICALITY_SCALE.keys()) == {1, 2, 3, 4, 5}


def test_9_9_scale_level_1_is_0_2() -> None:
    """ASSET_CRITICALITY_SCALE[1] (Low) must equal 0.2."""
    assert ASSET_CRITICALITY_SCALE[1] == pytest.approx(0.2)


def test_9_9_scale_level_2_is_0_4() -> None:
    """ASSET_CRITICALITY_SCALE[2] (Medium-Low) must equal 0.4."""
    assert ASSET_CRITICALITY_SCALE[2] == pytest.approx(0.4)


def test_9_9_scale_level_3_is_0_5() -> None:
    """ASSET_CRITICALITY_SCALE[3] (Medium, default) must equal 0.5."""
    assert ASSET_CRITICALITY_SCALE[3] == pytest.approx(0.5)


def test_9_9_scale_level_4_is_0_8() -> None:
    """ASSET_CRITICALITY_SCALE[4] (High) must equal 0.8."""
    assert ASSET_CRITICALITY_SCALE[4] == pytest.approx(0.8)


def test_9_9_scale_level_5_is_1_0() -> None:
    """ASSET_CRITICALITY_SCALE[5] (Mission-Critical) must equal 1.0."""
    assert ASSET_CRITICALITY_SCALE[5] == pytest.approx(1.0)


def test_9_9_scale_values_in_unit_range() -> None:
    """All ASSET_CRITICALITY_SCALE values must be in [0.0, 1.0]."""
    for level, val in ASSET_CRITICALITY_SCALE.items():
        assert 0.0 <= val <= 1.0, f"Scale[{level}]={val} is outside [0, 1]"


def test_9_9_scale_strictly_increasing() -> None:
    """ASSET_CRITICALITY_SCALE values must strictly increase with the DB criticality level."""
    values = [ASSET_CRITICALITY_SCALE[k] for k in sorted(ASSET_CRITICALITY_SCALE)]
    for i in range(len(values) - 1):
        assert values[i] < values[i + 1], (
            f"Scale is not strictly increasing at index {i}: {values[i]} >= {values[i + 1]}"
        )


def test_9_9_w_asset_weight_used_in_formula() -> None:
    """W_ASSET (0.25) is the weight applied to asset_criticality in the scoring formula."""
    assert W_ASSET == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# _asset_criticality() — unit tests with DB mock
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_9_9_empty_hostname_skips_db() -> None:
    """Empty hostname must return ASSET_CRITICALITY_SCALE[3]=0.5 without any DB call."""
    mgr = _mgr_no_init()
    mock_get = AsyncMock()

    with patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get):
        result = await mgr._asset_criticality("")

    assert result == pytest.approx(0.5)
    mock_get.assert_not_awaited()


@pytest.mark.asyncio
async def test_9_9_db_criticality_5_returns_1_0() -> None:
    """AssetRepo returns criticality=5 (Mission-Critical) → _asset_criticality() returns 1.0."""
    mgr = _mgr_no_init()
    mock_cm, mock_get = _make_db_mocks(5)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("dc-prod-01")

    assert result == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_9_9_db_criticality_4_returns_0_8() -> None:
    """AssetRepo returns criticality=4 (High) → _asset_criticality() returns 0.8."""
    mgr = _mgr_no_init()
    mock_cm, mock_get = _make_db_mocks(4)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("srv-db01")

    assert result == pytest.approx(0.8)


@pytest.mark.asyncio
async def test_9_9_db_criticality_3_returns_0_5() -> None:
    """AssetRepo returns criticality=3 (Medium) → _asset_criticality() returns 0.5."""
    mgr = _mgr_no_init()
    mock_cm, mock_get = _make_db_mocks(3)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("ws-app01")

    assert result == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_9_9_db_criticality_2_returns_0_4() -> None:
    """AssetRepo returns criticality=2 (Medium-Low) → _asset_criticality() returns 0.4."""
    mgr = _mgr_no_init()
    mock_cm, mock_get = _make_db_mocks(2)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("dev-laptop-01")

    assert result == pytest.approx(0.4)


@pytest.mark.asyncio
async def test_9_9_db_criticality_1_returns_0_2() -> None:
    """AssetRepo returns criticality=1 (Low) → _asset_criticality() returns 0.2."""
    mgr = _mgr_no_init()
    mock_cm, mock_get = _make_db_mocks(1)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("printer-01")

    assert result == pytest.approx(0.2)


@pytest.mark.asyncio
async def test_9_9_asset_not_in_cmdb_returns_default_0_5() -> None:
    """AssetRepo returns default criticality=3 for unknown host → result is 0.5.

    AssetRepo._DEFAULT_CRITICALITY is 3 (returned when hostname and IP don't match any record).
    """
    mgr = _mgr_no_init()
    # Simulate AssetRepo.get_criticality returning _DEFAULT_CRITICALITY=3
    mock_cm, mock_get = _make_db_mocks(3)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("unknown-host-xyz")

    assert result == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_9_9_db_error_fail_open_returns_0_5() -> None:
    """DB connection failure must be caught; _asset_criticality() returns 0.5 (fail-open)."""
    mgr = _mgr_no_init()

    class _MockCM:
        async def __aenter__(self):
            raise ConnectionRefusedError("DB unavailable")
        async def __aexit__(self, *args):
            return None

    with patch("app.core.database.AsyncSessionLocal", return_value=_MockCM()):
        result = await mgr._asset_criticality("dc-01")

    assert result == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_9_9_repo_exception_fail_open_returns_0_5() -> None:
    """AssetRepo.get_criticality raising an exception must be caught; returns 0.5 (fail-open)."""
    mgr = _mgr_no_init()
    mock_cm, _ = _make_db_mocks(5)
    failing_get = AsyncMock(side_effect=RuntimeError("query failed"))

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=failing_get),
    ):
        result = await mgr._asset_criticality("dc-01")

    assert result == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_9_9_all_scale_levels_produce_correct_float() -> None:
    """All five DB criticality levels must map to their correct float values."""
    mgr = _mgr_no_init()
    expected = {1: 0.2, 2: 0.4, 3: 0.5, 4: 0.8, 5: 1.0}

    for db_level, expected_float in expected.items():
        mock_cm, mock_get = _make_db_mocks(db_level)
        with (
            patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
            patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
        ):
            result = await mgr._asset_criticality(f"host-crit-{db_level}")

        assert result == pytest.approx(expected_float), (
            f"DB criticality={db_level} must map to {expected_float}; got {result}"
        )


# ---------------------------------------------------------------------------
# Scoring: asset criticality contribution
# ---------------------------------------------------------------------------


def test_9_9_mission_critical_isolated_score_contribution() -> None:
    """Mission-Critical asset (scale[5]=1.0) with severity_id=1 → score = 1.0 × 0.25 × 10 = 2.5."""
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": ASSET_CRITICALITY_SCALE[5]})
    assert result["score"] == pytest.approx(2.5, abs=0.05)


def test_9_9_high_criticality_isolated_score_contribution() -> None:
    """High asset (scale[4]=0.8) with severity_id=1 → score = 0.8 × 0.25 × 10 = 2.0."""
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": ASSET_CRITICALITY_SCALE[4]})
    assert result["score"] == pytest.approx(2.0, abs=0.05)


def test_9_9_medium_criticality_isolated_score_contribution() -> None:
    """Medium asset (scale[3]=0.5) with severity_id=1 → score ≈ 1.25."""
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": ASSET_CRITICALITY_SCALE[3]})
    assert result["score"] == pytest.approx(1.25, abs=0.1)


def test_9_9_low_criticality_isolated_score_contribution() -> None:
    """Low asset (scale[1]=0.2) with severity_id=1 → score = 0.2 × 0.25 × 10 = 0.5."""
    mgr = _mgr_no_init()
    result = mgr._score({"severity_id": 1, "asset_criticality": ASSET_CRITICALITY_SCALE[1]})
    assert result["score"] == pytest.approx(0.5, abs=0.05)


def test_9_9_scores_strictly_increase_with_cmdb_criticality() -> None:
    """Higher CMDB criticality must always produce a strictly higher score (severity fixed)."""
    mgr = _mgr_no_init()
    scores = [
        mgr._score({"severity_id": 3, "asset_criticality": ASSET_CRITICALITY_SCALE[k]})["score"]
        for k in sorted(ASSET_CRITICALITY_SCALE)
    ]
    for i in range(len(scores) - 1):
        assert scores[i] < scores[i + 1], (
            f"Score must strictly increase: scale[{i+1}]={scores[i]:.2f} >= "
            f"scale[{i+2}]={scores[i+1]:.2f}"
        )


# ---------------------------------------------------------------------------
# _enrich() integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_9_9_enrich_asset_criticality_field_present() -> None:
    """_enrich() must include 'asset_criticality' in the returned dict."""
    mgr = _mgr_no_init()
    mgr._ioc_matcher = MagicMock()
    mgr._ioc_matcher.match_event = AsyncMock(return_value=[])
    mgr._ioc_matcher.update_hits = AsyncMock()
    mgr._geoip_reader = object()  # _GEOIP_NOT_AVAILABLE sentinel

    from app.engine.sigma_engine import SigmaAlert
    from datetime import datetime, timezone

    alert = SigmaAlert(
        id="enrich-test",
        rule_id="sigma-T1059",
        rule_title="Test Rule",
        level="high",
        severity_id=4,
        technique_ids=["T1059"],
        tactic_ids=["execution"],
        host="dc-prod-01",
        time=datetime.now(timezone.utc),
        event_snapshot={},
    )

    mock_cm, mock_get = _make_db_mocks(5)  # mission-critical
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        enriched = await mgr._enrich(alert)

    assert "asset_criticality" in enriched
    assert enriched["asset_criticality"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_9_9_enrich_mission_critical_outscores_default() -> None:
    """Mission-critical asset (DB=5) must produce a higher score than default (DB=3)."""
    mgr = _mgr_no_init()
    mgr._ioc_matcher = MagicMock()
    mgr._ioc_matcher.match_event = AsyncMock(return_value=[])
    mgr._ioc_matcher.update_hits = AsyncMock()
    mgr._geoip_reader = object()  # _GEOIP_NOT_AVAILABLE sentinel

    from app.engine.sigma_engine import SigmaAlert
    from datetime import datetime, timezone

    def _alert(host: str) -> SigmaAlert:
        return SigmaAlert(
            id="enrich-score-test",
            rule_id="sigma-T1059",
            rule_title="Test Rule",
            level="medium",
            severity_id=3,
            technique_ids=["T1059"],
            tactic_ids=["execution"],
            host=host,
            time=datetime.now(timezone.utc),
            event_snapshot={},
        )

    # Mission-critical asset (DB=5 → 1.0)
    mock_cm5, mock_get5 = _make_db_mocks(5)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm5),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get5),
    ):
        enriched_mc = await mgr._enrich(_alert("dc-prod-01"))
    score_mc = mgr._score(enriched_mc)["score"]

    # Default asset (DB=3 → 0.5)
    mock_cm3, mock_get3 = _make_db_mocks(3)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm3),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get3),
    ):
        enriched_def = await mgr._enrich(_alert("unknown-host"))
    score_def = mgr._score(enriched_def)["score"]

    assert score_mc > score_def, (
        f"Mission-critical score ({score_mc:.2f}) must exceed default score ({score_def:.2f})"
    )


# ---------------------------------------------------------------------------
# process() end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_9_9_process_mission_critical_asset_in_payload() -> None:
    """process() with CMDB criticality=5 host must publish asset_criticality=1.0."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    mock_cm, mock_get = _make_db_mocks(5)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict(host="dc-prod-01"))

    assert len(payloads) == 1
    assert payloads[0]["asset_criticality"] == pytest.approx(1.0), (
        f"Expected asset_criticality=1.0; got {payloads[0]['asset_criticality']}"
    )
    assert 0.0 <= payloads[0]["score"] <= MAX_SCORE

    await queue.stop()


@pytest.mark.asyncio
async def test_9_9_process_default_criticality_in_payload() -> None:
    """process() with CMDB default criticality=3 must publish asset_criticality=0.5."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    mock_cm, mock_get = _make_db_mocks(3)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict(host="workstation-42"))

    assert len(payloads) == 1
    assert payloads[0]["asset_criticality"] == pytest.approx(0.5), (
        f"Expected asset_criticality=0.5; got {payloads[0]['asset_criticality']}"
    )

    await queue.stop()


@pytest.mark.asyncio
async def test_9_9_process_db_error_pipeline_continues() -> None:
    """DB connection failure in _asset_criticality() must not block the pipeline (fail-open)."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    payloads: list[dict] = []

    async def capture(topic, msg):
        payloads.append(msg)

    class _FailingCM:
        async def __aenter__(self):
            raise ConnectionRefusedError("PostgreSQL unavailable")
        async def __aexit__(self, *args):
            return None

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch("app.core.database.AsyncSessionLocal", return_value=_FailingCM()),
        patch.object(queue, "publish", side_effect=capture),
    ):
        await mgr.process(_make_alert_dict(host="dc-prod-01"))

    # Pipeline must have continued despite DB failure
    assert len(payloads) == 1, "Alert must be published even when CMDB is unavailable"
    assert payloads[0]["asset_criticality"] == pytest.approx(0.5), (
        "Fail-open must return 0.5 when CMDB is unreachable"
    )
    assert 0.0 <= payloads[0]["score"] <= MAX_SCORE

    await queue.stop()


@pytest.mark.asyncio
async def test_9_9_process_mission_critical_outscores_default_same_severity() -> None:
    """process(): mission-critical asset (DB=5) must produce a higher score than default (DB=3).

    Both alerts have severity_id=3 (medium); only CMDB criticality differs.
    """
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    mc_payloads: list[dict] = []
    def_payloads: list[dict] = []

    async def capture_mc(topic, msg):
        mc_payloads.append(msg)

    async def capture_def(topic, msg):
        def_payloads.append(msg)

    mock_cm5, mock_get5 = _make_db_mocks(5)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm5),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get5),
        patch.object(queue, "publish", side_effect=capture_mc),
    ):
        await mgr.process(_make_alert_dict(host="dc-prod-01", severity_id=3))

    mock_cm3, mock_get3 = _make_db_mocks(3)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr, "_persist_to_db", new=AsyncMock()),
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm3),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get3),
        patch.object(queue, "publish", side_effect=capture_def),
    ):
        await mgr.process(_make_alert_dict(host="workstation-42", severity_id=3))

    assert mc_payloads[0]["score"] > def_payloads[0]["score"], (
        f"Mission-critical ({mc_payloads[0]['score']:.2f}) must outscore "
        f"default ({def_payloads[0]['score']:.2f}) at same severity"
    )
    # Delta = (1.0 - 0.5) × 0.25 × 10 = 1.25
    delta = mc_payloads[0]["score"] - def_payloads[0]["score"]
    assert delta == pytest.approx(1.25, abs=0.1)

    await queue.stop()
