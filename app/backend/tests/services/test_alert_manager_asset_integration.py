"""Tests for feature 30.4 — Asset criticality Valkey cache + asset stat updates.

Coverage:
  - ASSET_CRIT_CACHE_TTL: constant equals 300 (5 minutes)
  - _ASSET_CRIT_CACHE_PREFIX: constant equals "mxtac:asset_crit:"
  - _asset_criticality(): Valkey cache hit returns correct mapped value (no DB call)
  - _asset_criticality(): Valkey cache miss falls through to DB and writes cache
  - _asset_criticality(): Valkey GET error is non-fatal (falls through to DB)
  - _asset_criticality(): Valkey SET error after DB lookup is non-fatal (returns DB value)
  - _asset_criticality(): cache key format is "mxtac:asset_crit:{hostname}"
  - _asset_criticality(): cache stores raw integer criticality, not the float
  - _asset_criticality(): cached value respects ASSET_CRIT_CACHE_TTL on SET
  - _update_asset_stats(): calls update_last_seen and increment_detection_count
  - _update_asset_stats(): empty hostname is a no-op (no DB calls)
  - _update_asset_stats(): DB error is non-fatal (exception caught, logged)
  - _persist_to_db(): calls _update_asset_stats after creating detection
  - _persist_to_db(): asset stats updated in same DB session as detection
  - process(): end-to-end — asset last_seen_at and detection_count updated on each alert
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from app.pipeline.queue import InMemoryQueue
from app.services.alert_manager import (
    AlertManager,
    ASSET_CRIT_CACHE_TTL,
    ASSET_CRITICALITY_SCALE,
    _ASSET_CRIT_CACHE_PREFIX,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mgr_no_init() -> AlertManager:
    """Create AlertManager without calling __init__ (no Valkey connection)."""
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = MagicMock()
    return mgr


def _make_alert_dict(
    *,
    host: str = "srv-01",
    severity_id: int = 3,
    level: str = "medium",
) -> dict:
    return {
        "id": "test-30-4-uuid",
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


def _make_valkey_mock(*, get_return=None, set_return=True) -> MagicMock:
    """Return a MagicMock Valkey client with async get/set."""
    mock = MagicMock()
    mock.get = AsyncMock(return_value=get_return)
    mock.set = AsyncMock(return_value=set_return)
    mock.aclose = AsyncMock()
    return mock


def _make_db_mocks(db_return: int):
    """Return (mock_context_manager, mock_get_criticality)."""
    mock_session = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    mock_get = AsyncMock(return_value=db_return)
    return mock_cm, mock_get


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_30_4_cache_ttl_is_300() -> None:
    """ASSET_CRIT_CACHE_TTL must equal 300 seconds (5 minutes)."""
    assert ASSET_CRIT_CACHE_TTL == 300


def test_30_4_cache_prefix_is_correct() -> None:
    """_ASSET_CRIT_CACHE_PREFIX must be 'mxtac:asset_crit:'."""
    assert _ASSET_CRIT_CACHE_PREFIX == "mxtac:asset_crit:"


# ---------------------------------------------------------------------------
# Valkey cache — hit path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_30_4_cache_hit_returns_mapped_value_no_db_call() -> None:
    """Cache hit: Valkey.get returns '5' → criticality=1.0, no DB call made."""
    mgr = _mgr_no_init()
    mgr._valkey = _make_valkey_mock(get_return="5")

    mock_get_crit = AsyncMock()
    with patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get_crit):
        result = await mgr._asset_criticality("dc-prod-01")

    assert result == pytest.approx(ASSET_CRITICALITY_SCALE[5])  # 1.0
    mock_get_crit.assert_not_awaited()


@pytest.mark.asyncio
async def test_30_4_cache_hit_all_levels() -> None:
    """Cache hit for each cached level (1-5) returns the correct float value."""
    mgr = _mgr_no_init()
    for level in range(1, 6):
        mgr._valkey = _make_valkey_mock(get_return=str(level))
        result = await mgr._asset_criticality(f"host-{level}")
        assert result == pytest.approx(ASSET_CRITICALITY_SCALE[level]), (
            f"Cached level={level} must return {ASSET_CRITICALITY_SCALE[level]}"
        )


@pytest.mark.asyncio
async def test_30_4_cache_hit_uses_correct_cache_key() -> None:
    """Cache GET is called with key 'mxtac:asset_crit:{hostname}'."""
    mgr = _mgr_no_init()
    mgr._valkey = _make_valkey_mock(get_return="3")  # hit

    await mgr._asset_criticality("my-server-01")

    mgr._valkey.get.assert_awaited_once_with("mxtac:asset_crit:my-server-01")


# ---------------------------------------------------------------------------
# Valkey cache — miss path (DB fallback + cache write)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_30_4_cache_miss_falls_through_to_db() -> None:
    """Cache miss (get returns None) → DB queried → result returned."""
    mgr = _mgr_no_init()
    mgr._valkey = _make_valkey_mock(get_return=None)  # cache miss

    mock_cm, mock_get = _make_db_mocks(4)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("srv-db01")

    assert result == pytest.approx(ASSET_CRITICALITY_SCALE[4])  # 0.75
    mock_get.assert_awaited_once()


@pytest.mark.asyncio
async def test_30_4_cache_miss_writes_db_value_to_cache() -> None:
    """After DB lookup, the raw criticality integer is written to Valkey with correct TTL."""
    mgr = _mgr_no_init()
    mgr._valkey = _make_valkey_mock(get_return=None)  # cache miss

    mock_cm, mock_get = _make_db_mocks(5)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        await mgr._asset_criticality("dc-critical-01")

    # Cache SET must be called with the raw integer ("5") and ASSET_CRIT_CACHE_TTL
    mgr._valkey.set.assert_awaited_once_with(
        "mxtac:asset_crit:dc-critical-01", "5", ex=ASSET_CRIT_CACHE_TTL
    )


@pytest.mark.asyncio
async def test_30_4_cache_miss_default_criticality_written_to_cache() -> None:
    """When asset not found (DB returns 3), '3' is cached with correct TTL."""
    mgr = _mgr_no_init()
    mgr._valkey = _make_valkey_mock(get_return=None)

    mock_cm, mock_get = _make_db_mocks(3)  # _DEFAULT_CRITICALITY
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        await mgr._asset_criticality("unknown-host")

    mgr._valkey.set.assert_awaited_once_with(
        "mxtac:asset_crit:unknown-host", "3", ex=ASSET_CRIT_CACHE_TTL
    )


# ---------------------------------------------------------------------------
# Valkey cache — error paths (fail-open)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_30_4_valkey_get_error_falls_through_to_db() -> None:
    """If Valkey.get raises, fall through to DB lookup (non-fatal, fail-open)."""
    mgr = _mgr_no_init()
    mock_valkey = MagicMock()
    mock_valkey.get = AsyncMock(side_effect=ConnectionRefusedError("Valkey down"))
    mock_valkey.set = AsyncMock(return_value=True)
    mgr._valkey = mock_valkey

    mock_cm, mock_get = _make_db_mocks(5)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("dc-prod-01")

    assert result == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_30_4_valkey_set_error_is_non_fatal() -> None:
    """If Valkey.set raises after DB lookup, exception is caught and DB value is returned."""
    mgr = _mgr_no_init()
    mock_valkey = MagicMock()
    mock_valkey.get = AsyncMock(return_value=None)  # cache miss
    mock_valkey.set = AsyncMock(side_effect=ConnectionRefusedError("Valkey write failed"))
    mgr._valkey = mock_valkey

    mock_cm, mock_get = _make_db_mocks(4)
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.asset_repo.AssetRepo.get_criticality", new=mock_get),
    ):
        result = await mgr._asset_criticality("srv-db01")

    # Must return DB value even though cache write failed
    assert result == pytest.approx(ASSET_CRITICALITY_SCALE[4])  # 0.75


@pytest.mark.asyncio
async def test_30_4_db_error_after_cache_miss_returns_default() -> None:
    """Cache miss + DB error → returns fail-open default 0.5."""
    mgr = _mgr_no_init()
    mgr._valkey = _make_valkey_mock(get_return=None)

    class _FailingCM:
        async def __aenter__(self):
            raise ConnectionRefusedError("DB down")
        async def __aexit__(self, *args):
            return None

    with patch("app.core.database.AsyncSessionLocal", return_value=_FailingCM()):
        result = await mgr._asset_criticality("some-host")

    assert result == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# _update_asset_stats()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_30_4_update_asset_stats_calls_update_last_seen() -> None:
    """_update_asset_stats() calls AssetRepo.update_last_seen with the hostname."""
    mgr = _mgr_no_init()
    mock_session = MagicMock()

    mock_update_last_seen = AsyncMock()
    mock_increment = AsyncMock()

    with (
        patch("app.repositories.asset_repo.AssetRepo.update_last_seen", new=mock_update_last_seen),
        patch("app.repositories.asset_repo.AssetRepo.increment_detection_count", new=mock_increment),
    ):
        await mgr._update_asset_stats(mock_session, "dc-prod-01")

    mock_update_last_seen.assert_awaited_once_with(mock_session, "dc-prod-01")


@pytest.mark.asyncio
async def test_30_4_update_asset_stats_calls_increment_detection_count() -> None:
    """_update_asset_stats() calls AssetRepo.increment_detection_count with the hostname."""
    mgr = _mgr_no_init()
    mock_session = MagicMock()

    mock_update_last_seen = AsyncMock()
    mock_increment = AsyncMock()

    with (
        patch("app.repositories.asset_repo.AssetRepo.update_last_seen", new=mock_update_last_seen),
        patch("app.repositories.asset_repo.AssetRepo.increment_detection_count", new=mock_increment),
    ):
        await mgr._update_asset_stats(mock_session, "dc-prod-01")

    mock_increment.assert_awaited_once_with(mock_session, "dc-prod-01")


@pytest.mark.asyncio
async def test_30_4_update_asset_stats_empty_hostname_is_noop() -> None:
    """_update_asset_stats() with empty hostname makes no DB calls."""
    mgr = _mgr_no_init()
    mock_session = MagicMock()

    mock_update = AsyncMock()
    mock_increment = AsyncMock()

    with (
        patch("app.repositories.asset_repo.AssetRepo.update_last_seen", new=mock_update),
        patch("app.repositories.asset_repo.AssetRepo.increment_detection_count", new=mock_increment),
    ):
        await mgr._update_asset_stats(mock_session, "")

    mock_update.assert_not_awaited()
    mock_increment.assert_not_awaited()


@pytest.mark.asyncio
async def test_30_4_update_asset_stats_db_error_is_non_fatal() -> None:
    """If AssetRepo calls raise, _update_asset_stats() catches and does not propagate."""
    mgr = _mgr_no_init()
    mock_session = MagicMock()

    with (
        patch(
            "app.repositories.asset_repo.AssetRepo.update_last_seen",
            new=AsyncMock(side_effect=RuntimeError("DB error")),
        ),
    ):
        # Must not raise
        await mgr._update_asset_stats(mock_session, "dc-prod-01")


# ---------------------------------------------------------------------------
# _persist_to_db(): asset stats integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_30_4_persist_to_db_calls_update_asset_stats() -> None:
    """_persist_to_db() calls _update_asset_stats with host from scored alert."""
    mgr = _mgr_no_init()

    scored = {
        "id": "det-123",
        "score": 5.0,
        "level": "medium",
        "severity_id": 3,
        "technique_ids": ["T1059"],
        "tactic_ids": ["execution"],
        "rule_title": "Test Rule",
        "host": "dc-prod-01",
        "time": datetime.now(timezone.utc).isoformat(),
        "rule_id": "sigma-T1059",
    }

    mock_update_stats = AsyncMock()

    mock_session = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    mock_session.commit = AsyncMock()

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.detection_repo.DetectionRepo.create", new=AsyncMock()),
        patch.object(mgr, "_correlate_incident", new=AsyncMock()),
        patch.object(mgr, "_update_asset_stats", new=mock_update_stats),
    ):
        await mgr._persist_to_db(scored)

    mock_update_stats.assert_awaited_once_with(mock_session, "dc-prod-01")


@pytest.mark.asyncio
async def test_30_4_persist_to_db_asset_stats_in_same_session() -> None:
    """_update_asset_stats is called with the same session as DetectionRepo.create."""
    mgr = _mgr_no_init()

    scored = {
        "id": "det-456",
        "score": 7.0,
        "level": "high",
        "severity_id": 4,
        "technique_ids": ["T1003"],
        "tactic_ids": ["Credential Access"],
        "rule_title": "Credential Dump",
        "host": "srv-db01",
        "time": datetime.now(timezone.utc).isoformat(),
        "rule_id": "sigma-T1003",
    }

    sessions_seen: list = []

    async def capture_session(session, hostname):
        sessions_seen.append(session)

    mock_session = MagicMock()
    mock_session.commit = AsyncMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.detection_repo.DetectionRepo.create", new=AsyncMock()),
        patch.object(mgr, "_correlate_incident", new=AsyncMock()),
        patch.object(mgr, "_update_asset_stats", new=capture_session),
    ):
        await mgr._persist_to_db(scored)

    assert len(sessions_seen) == 1
    assert sessions_seen[0] is mock_session, (
        "_update_asset_stats must receive the same session object as DetectionRepo.create"
    )


# ---------------------------------------------------------------------------
# End-to-end: process() with asset stat update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_30_4_process_updates_asset_last_seen_and_detection_count() -> None:
    """process() triggers update_last_seen + increment_detection_count for the alert host."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)

    published: list[dict] = []

    async def capture(topic, msg):
        published.append(msg)

    mock_update_last_seen = AsyncMock()
    mock_increment = AsyncMock()

    mock_session = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.flush = AsyncMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(mgr._valkey, "get", new=AsyncMock(return_value=None)),
        patch.object(queue, "publish", side_effect=capture),
        patch.object(mgr, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=0.5)),
        patch.object(mgr, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(mgr, "_lookup_geoip", new=AsyncMock(return_value=None)),
        patch("app.core.database.AsyncSessionLocal", return_value=mock_cm),
        patch("app.repositories.detection_repo.DetectionRepo.create", new=AsyncMock()),
        patch.object(mgr, "_correlate_incident", new=AsyncMock()),
        patch("app.repositories.asset_repo.AssetRepo.update_last_seen", new=mock_update_last_seen),
        patch("app.repositories.asset_repo.AssetRepo.increment_detection_count", new=mock_increment),
    ):
        await mgr.process(_make_alert_dict(host="dc-prod-01"))

    assert len(published) == 1
    mock_update_last_seen.assert_awaited_once_with(mock_session, "dc-prod-01")
    mock_increment.assert_awaited_once_with(mock_session, "dc-prod-01")

    await queue.stop()


@pytest.mark.asyncio
async def test_30_4_process_asset_stat_failure_does_not_block_pipeline() -> None:
    """Asset stat update failure is non-fatal: alert is still published."""
    queue = InMemoryQueue()
    await queue.start()

    mgr = AlertManager(queue)
    published: list[dict] = []

    async def capture(topic, msg):
        published.append(msg)

    with (
        patch.object(mgr._valkey, "set", new=AsyncMock(return_value=True)),
        patch.object(queue, "publish", side_effect=capture),
        patch.object(mgr, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(mgr, "_asset_criticality", new=AsyncMock(return_value=0.5)),
        patch.object(mgr, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(mgr, "_lookup_geoip", new=AsyncMock(return_value=None)),
        patch.object(
            mgr,
            "_persist_to_db",
            new=AsyncMock(side_effect=RuntimeError("DB failure")),
        ),
    ):
        await mgr.process(_make_alert_dict(host="srv-01"))

    # Alert must still be published even if persist (including asset update) fails
    assert len(published) == 1

    await queue.stop()
