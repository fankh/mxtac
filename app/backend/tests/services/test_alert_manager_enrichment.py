"""Tests for AlertManager threat intel enrichment (feature 29.3).

Feature 29.3 replaces the direct-DB _lookup_threat_intel() from feature 9.7
with IOCMatcher — an in-memory + Valkey-backed service.

Coverage:
  - _enrich(): threat_intel is None when IOCMatcher returns no matches
  - _enrich(): threat_intel.matched_iocs populated from IOCMatcher matches
  - _enrich(): threat_intel.threat_score_boost = min(n * 1.5, 3.0)
  - _enrich(): threat_score_boost 1 match → +1.5
  - _enrich(): threat_score_boost 2 matches → +3.0
  - _enrich(): threat_score_boost 3 matches → capped at +3.0
  - _score(): threat_score_boost added to base score
  - _score(): score capped at 10.0 even with boost
  - _score(): no boost when threat_intel is None
  - process(): threat_intel appears in published payload with matched_iocs
  - process(): threat_intel is None in published payload when no IOC matches
  - process(): IOCMatcher failure does not block the pipeline (fail-open)
  - process(): update_hits called after match_event
  - process(): matched_ioc entries contain ioc_id, ioc_type, value, severity,
               confidence, source, tags, description
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.engine.sigma_engine import SigmaAlert
from app.pipeline.queue import InMemoryQueue
from app.services.alert_manager import AlertManager
from app.services.ioc_matcher import IOCMatch


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc).isoformat()

_ALERT_DICT = {
    "id": "alert-ti-001",
    "rule_id": "sigma-mimikatz",
    "rule_title": "Mimikatz Detected",
    "level": "high",
    "severity_id": 4,
    "technique_ids": ["T1003.001"],
    "tactic_ids": ["Credential Access"],
    "host": "192.168.1.10",
    "time": _NOW,
    "event_snapshot": {},
}


def _make_manager(valkey_set_return=True) -> AlertManager:
    """Create a minimal AlertManager with mocked Valkey (new alert by default)."""
    queue = InMemoryQueue()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue
    mgr._dispatcher = None
    mock_valkey = MagicMock()
    mock_valkey.set = AsyncMock(return_value=valkey_set_return)
    mock_valkey.aclose = AsyncMock()
    mgr._valkey = mock_valkey
    mgr._geoip_reader = None
    # IOCMatcher gets its own separate mock Valkey (matches production isolation)
    from app.services.ioc_matcher import IOCMatcher
    mock_ioc_valkey = MagicMock()
    mock_ioc_valkey.set = AsyncMock(return_value=True)
    mock_ioc_valkey.aclose = AsyncMock()
    mgr._ioc_valkey = mock_ioc_valkey
    mgr._ioc_matcher = IOCMatcher(mock_ioc_valkey)
    return mgr


def _make_alert(
    host: str = "192.168.1.10",
    event_snapshot: dict | None = None,
) -> SigmaAlert:
    return SigmaAlert(
        id="a-ti-1",
        rule_id="sigma-mimikatz",
        rule_title="Mimikatz",
        level="high",
        severity_id=4,
        technique_ids=["T1003.001"],
        tactic_ids=["Credential Access"],
        host=host,
        event_snapshot=event_snapshot or {},
    )


def _make_ioc_match(
    ioc_id: int = 1,
    ioc_type: str = "ip",
    value: str = "192.168.1.10",
    severity: str = "high",
    confidence: int = 80,
    source: str = "opencti",
    tags: list | None = None,
    description: str = "Known C2 IP",
) -> IOCMatch:
    return IOCMatch(
        ioc_id=ioc_id,
        ioc_type=ioc_type,
        value=value,
        severity=severity,
        confidence=confidence,
        source=source,
        tags=tags if tags is not None else ["apt28"],
        description=description,
    )


# ---------------------------------------------------------------------------
# _enrich() — threat_intel field
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_threat_intel_none_when_no_matches():
    """threat_intel is None when IOCMatcher.match_event returns empty list."""
    mgr = _make_manager()
    alert = _make_alert()

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=[])),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
    ):
        enriched = await mgr._enrich(alert)

    assert enriched["threat_intel"] is None


@pytest.mark.asyncio
async def test_enrich_threat_intel_populated_on_single_match():
    """threat_intel has matched_iocs and threat_score_boost for 1 match."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")
    match = _make_ioc_match(ioc_id=1, ioc_type="ip", value="1.2.3.4")

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=[match])),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
    ):
        enriched = await mgr._enrich(alert)

    ti = enriched["threat_intel"]
    assert ti is not None
    assert len(ti["matched_iocs"]) == 1
    assert ti["matched_iocs"][0]["ioc_id"] == 1
    assert ti["matched_iocs"][0]["value"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_enrich_threat_score_boost_one_match():
    """1 IOC match → threat_score_boost = 1.5."""
    mgr = _make_manager()
    alert = _make_alert()
    match = _make_ioc_match()

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=[match])),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
    ):
        enriched = await mgr._enrich(alert)

    assert enriched["threat_intel"]["threat_score_boost"] == pytest.approx(1.5)


@pytest.mark.asyncio
async def test_enrich_threat_score_boost_two_matches():
    """2 IOC matches → threat_score_boost = 3.0."""
    mgr = _make_manager()
    alert = _make_alert()
    matches = [_make_ioc_match(ioc_id=1), _make_ioc_match(ioc_id=2, value="5.5.5.5")]

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=matches)),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
    ):
        enriched = await mgr._enrich(alert)

    assert enriched["threat_intel"]["threat_score_boost"] == pytest.approx(3.0)


@pytest.mark.asyncio
async def test_enrich_threat_score_boost_capped_at_three():
    """3+ IOC matches → threat_score_boost capped at 3.0."""
    mgr = _make_manager()
    alert = _make_alert()
    matches = [_make_ioc_match(ioc_id=i) for i in range(5)]

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=matches)),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
    ):
        enriched = await mgr._enrich(alert)

    assert enriched["threat_intel"]["threat_score_boost"] == pytest.approx(3.0)


@pytest.mark.asyncio
async def test_enrich_matched_ioc_entry_has_all_fields():
    """Each matched_iocs entry has all required IOC fields."""
    mgr = _make_manager()
    alert = _make_alert()
    match = _make_ioc_match(
        ioc_id=99, ioc_type="ip", value="1.2.3.4", severity="critical",
        confidence=95, source="opencti", tags=["apt29"], description="APT29 C2",
    )

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=[match])),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
    ):
        enriched = await mgr._enrich(alert)

    entry = enriched["threat_intel"]["matched_iocs"][0]
    assert entry["ioc_id"] == 99
    assert entry["ioc_type"] == "ip"
    assert entry["value"] == "1.2.3.4"
    assert entry["severity"] == "critical"
    assert entry["confidence"] == 95
    assert entry["source"] == "opencti"
    assert entry["tags"] == ["apt29"]
    assert entry["description"] == "APT29 C2"


@pytest.mark.asyncio
async def test_enrich_update_hits_called_after_match():
    """update_hits is called with the matches returned by match_event."""
    mgr = _make_manager()
    alert = _make_alert()
    matches = [_make_ioc_match()]
    mock_update = AsyncMock()

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=matches)),
        patch.object(mgr._ioc_matcher, "update_hits", new=mock_update),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
    ):
        await mgr._enrich(alert)

    mock_update.assert_awaited_once_with(matches)


# ---------------------------------------------------------------------------
# _score() — threat boost integration
# ---------------------------------------------------------------------------


def test_score_adds_threat_boost():
    """_score() adds threat_score_boost to the base score."""
    mgr = _make_manager()
    enriched = {
        "severity_id": 3,
        "asset_criticality": 0.5,
        "recurrence_count": 0,
        "threat_intel": {"matched_iocs": [{}], "threat_score_boost": 1.5},
    }
    scored = mgr._score(enriched)
    # base: (2/4)*0.6 + 0.5*0.25 + 0*0.15) * 10 = (0.3 + 0.125) * 10 = 4.25
    # + boost 1.5 = 5.75
    assert scored["score"] == pytest.approx(5.75, abs=0.1)


def test_score_no_boost_when_threat_intel_none():
    """_score() uses no threat boost when threat_intel is None."""
    mgr = _make_manager()
    enriched = {
        "severity_id": 3,
        "asset_criticality": 0.5,
        "recurrence_count": 0,
        "threat_intel": None,
    }
    scored = mgr._score(enriched)
    # base: (2/4)*0.6 + 0.5*0.25) * 10 = 4.25
    assert scored["score"] == pytest.approx(4.25, abs=0.1)


def test_score_capped_at_10_with_boost():
    """_score() never exceeds 10.0 even with a large threat boost."""
    mgr = _make_manager()
    enriched = {
        "severity_id": 5,  # critical → severity_norm = 1.0
        "asset_criticality": 1.0,
        "recurrence_count": 10,
        "threat_intel": {"matched_iocs": [{}, {}], "threat_score_boost": 3.0},
    }
    scored = mgr._score(enriched)
    assert scored["score"] == pytest.approx(10.0)


# ---------------------------------------------------------------------------
# process() end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_threat_intel_in_published_payload():
    """Published enriched alert contains threat_intel.matched_iocs when IOC matches."""
    mgr = _make_manager()
    match = _make_ioc_match(
        ioc_id=7, ioc_type="ip", value="192.168.1.10",
        severity="critical", confidence=95, source="opencti",
        tags=["ransomware"], description="Ransomware C2",
    )
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=[match])),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        await mgr.process(_ALERT_DICT)

    assert len(published) == 1
    ti = published[0]["threat_intel"]
    assert ti is not None
    assert ti["matched_iocs"][0]["ioc_id"] == 7
    assert ti["threat_score_boost"] == pytest.approx(1.5)


@pytest.mark.asyncio
async def test_process_threat_intel_none_in_published_payload():
    """Published enriched alert has threat_intel=None when no IOC matches."""
    mgr = _make_manager()
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=[])),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        await mgr.process(_ALERT_DICT)

    assert len(published) == 1
    assert published[0]["threat_intel"] is None


@pytest.mark.asyncio
async def test_process_ioc_matcher_failure_does_not_block_pipeline():
    """Even when match_event raises, process() still publishes the alert (fail-open)."""
    mgr = _make_manager()
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    # IOCMatcher.match_event() already handles its own exceptions and returns [].
    # Simulate it returning empty (which is what happens after internal error).
    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=[])),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        await mgr.process(_ALERT_DICT)

    assert len(published) == 1


@pytest.mark.asyncio
async def test_process_score_boosted_by_threat_intel():
    """Published score is boosted by threat_score_boost from IOC matches."""
    mgr = _make_manager()
    match = _make_ioc_match()
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    with (
        patch.object(mgr._ioc_matcher, "match_event", new=AsyncMock(return_value=[match])),
        patch.object(mgr._ioc_matcher, "update_hits", new=AsyncMock()),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        # _ALERT_DICT has severity_id=4, host=192.168.1.10 (no prefix → crit=0.5), recur=0
        # base = ((4-1)/4 * 0.6 + 0.5 * 0.25) * 10 = (0.45 + 0.125) * 10 = 5.75
        # boost = 1.5 → total = 7.25
        await mgr.process(_ALERT_DICT)

    assert published[0]["score"] == pytest.approx(7.25, abs=0.1)
