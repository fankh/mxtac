"""Unit tests for IOCMatcher service (feature 29.3).

Coverage:
  IOCMatch.to_dict():
    - returns dict with all required fields

  IOCMatcher.load_active_iocs():
    - loads IOCs from DB into in-memory cache grouped by type
    - no-op when cache is fresh (within 5-min TTL)
    - fail-open: logs and continues on DB error, existing cache intact

  IOCMatcher._extract_candidates():
    - extracts host as both ip and domain
    - extracts src_ip, dst_ip, domain, hostname, hash_md5, hash_sha256, url (flat)
    - extracts OCSF nested src.ip, dst.ip, process.file.hash_md5/sha256
    - returns empty dict for empty host and snapshot
    - deduplicates the same value seen multiple times

  IOCMatcher._valkey_get():
    - returns "skip" when key not found in Valkey (None response)
    - returns None (cached miss) when Valkey returns sentinel _VALKEY_MISS
    - returns IOCMatch when Valkey returns JSON-encoded IOC data
    - returns "skip" on Valkey exception

  IOCMatcher._valkey_set():
    - stores _VALKEY_MISS for None match
    - stores JSON-encoded match for IOCMatch
    - silently ignores Valkey exceptions

  IOCMatcher.match_event():
    - returns empty list when no candidates extracted
    - returns empty list when IOC not in in-memory cache
    - returns matched IOCMatch when in-memory cache has the value
    - deduplicates: same IOC matched via multiple candidate paths returns once
    - Valkey cache hit returns cached match without touching in-memory
    - Valkey cached miss skips in-memory lookup
    - Valkey unavailable ("skip") falls back to in-memory
    - stores in-memory result in Valkey after lookup

  IOCMatcher.update_hits():
    - calls IOCRepo.increment_hit for each matched IOC
    - commits session after all increments
    - no-op (no DB call) when matches list is empty
    - fail-open: logs and returns on DB error
"""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.ioc_matcher import (
    IOCMatch,
    IOCMatcher,
    _MEM_CACHE_TTL,
    _VALKEY_MISS,
    _VALKEY_PREFIX,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_valkey(get_return=None) -> MagicMock:
    """Return a MagicMock Valkey client."""
    valkey = MagicMock()
    valkey.get = AsyncMock(return_value=get_return)
    valkey.set = AsyncMock(return_value=True)
    return valkey


def _make_matcher(valkey=None) -> IOCMatcher:
    return IOCMatcher(valkey or _make_valkey())


def _make_ioc_match(**kwargs) -> IOCMatch:
    defaults = dict(
        ioc_id=1, ioc_type="ip", value="1.2.3.4",
        severity="high", confidence=80, source="opencti",
        tags=["apt28"], description="C2 IP",
    )
    defaults.update(kwargs)
    return IOCMatch(**defaults)


def _make_db_ioc(
    ioc_id=1, ioc_type="ip", value="1.2.3.4",
    severity="high", confidence=80, source="opencti",
    tags=None, description="C2 IP", is_active=True,
) -> MagicMock:
    ioc = MagicMock()
    ioc.id = ioc_id
    ioc.ioc_type = ioc_type
    ioc.value = value
    ioc.severity = severity
    ioc.confidence = confidence
    ioc.source = source
    ioc.tags = tags if tags is not None else ["apt28"]
    ioc.description = description
    ioc.is_active = is_active
    return ioc


def _make_session_ctx(iocs: list) -> MagicMock:
    """Async context manager that returns iocs from session.execute().scalars().all()."""
    session = MagicMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = iocs
    session.execute = AsyncMock(return_value=result)
    session.commit = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    ctx._session = session
    return ctx


# ---------------------------------------------------------------------------
# IOCMatch.to_dict()
# ---------------------------------------------------------------------------


def test_ioc_match_to_dict_has_all_fields():
    match = _make_ioc_match()
    d = match.to_dict()
    assert d["ioc_id"] == 1
    assert d["ioc_type"] == "ip"
    assert d["value"] == "1.2.3.4"
    assert d["severity"] == "high"
    assert d["confidence"] == 80
    assert d["source"] == "opencti"
    assert d["tags"] == ["apt28"]
    assert d["description"] == "C2 IP"


# ---------------------------------------------------------------------------
# IOCMatcher.load_active_iocs()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_load_active_iocs_populates_cache():
    """Active IOCs are loaded into _ioc_map grouped by type."""
    matcher = _make_matcher()
    db_ioc = _make_db_ioc(ioc_id=1, ioc_type="ip", value="1.2.3.4")
    ctx = _make_session_ctx([db_ioc])

    with patch("app.core.database.AsyncSessionLocal", return_value=ctx):
        await matcher.load_active_iocs()

    assert "ip" in matcher._ioc_map
    assert "1.2.3.4" in matcher._ioc_map["ip"]
    match = matcher._ioc_map["ip"]["1.2.3.4"]
    assert isinstance(match, IOCMatch)
    assert match.ioc_id == 1
    assert match.ioc_type == "ip"
    assert match.value == "1.2.3.4"


@pytest.mark.asyncio
async def test_load_active_iocs_noop_when_cache_fresh():
    """load_active_iocs() is a no-op when the cache was refreshed recently."""
    matcher = _make_matcher()
    matcher._cache_loaded_at = time.monotonic()  # Mark as fresh

    with patch("app.core.database.AsyncSessionLocal") as mock_db:
        await matcher.load_active_iocs()

    mock_db.assert_not_called()


@pytest.mark.asyncio
async def test_load_active_iocs_refreshes_after_ttl():
    """load_active_iocs() refreshes when cache TTL has expired."""
    matcher = _make_matcher()
    # Expired cache
    matcher._cache_loaded_at = time.monotonic() - _MEM_CACHE_TTL - 1
    ctx = _make_session_ctx([])

    with patch("app.core.database.AsyncSessionLocal", return_value=ctx):
        await matcher.load_active_iocs()

    # Session was used
    ctx._session.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_load_active_iocs_fail_open_on_db_error():
    """load_active_iocs() logs and keeps existing cache when DB raises."""
    matcher = _make_matcher()
    matcher._ioc_map = {"ip": {"1.0.0.1": _make_ioc_match()}}

    with patch("app.core.database.AsyncSessionLocal", side_effect=Exception("DB down")):
        await matcher.load_active_iocs()

    # Existing cache intact
    assert "1.0.0.1" in matcher._ioc_map["ip"]
    # Timestamp not updated — will retry next call
    assert matcher._cache_loaded_at == 0.0


# ---------------------------------------------------------------------------
# IOCMatcher._extract_candidates()
# ---------------------------------------------------------------------------


def test_extract_candidates_host_as_ip_and_domain():
    matcher = _make_matcher()
    candidates = matcher._extract_candidates("1.2.3.4", {})
    assert "1.2.3.4" in candidates.get("ip", set())
    assert "1.2.3.4" in candidates.get("domain", set())


def test_extract_candidates_empty_host_and_snapshot():
    matcher = _make_matcher()
    candidates = matcher._extract_candidates("", {})
    assert candidates == {}


def test_extract_candidates_flat_src_dst_ip():
    matcher = _make_matcher()
    snap = {"src_ip": "5.5.5.5", "dst_ip": "6.6.6.6"}
    candidates = matcher._extract_candidates("safe", snap)
    assert "5.5.5.5" in candidates["ip"]
    assert "6.6.6.6" in candidates["ip"]


def test_extract_candidates_flat_domain_and_hostname():
    matcher = _make_matcher()
    snap = {"domain": "evil.com", "hostname": "bad.host.org"}
    candidates = matcher._extract_candidates("safe", snap)
    assert "evil.com" in candidates["domain"]
    assert "bad.host.org" in candidates["domain"]


def test_extract_candidates_flat_hashes():
    matcher = _make_matcher()
    snap = {"hash_md5": "abcd1234", "hash_sha256": "efgh5678"}
    candidates = matcher._extract_candidates("safe", snap)
    assert "abcd1234" in candidates["hash_md5"]
    assert "efgh5678" in candidates["hash_sha256"]


def test_extract_candidates_flat_url():
    matcher = _make_matcher()
    snap = {"url": "http://evil.com/payload"}
    candidates = matcher._extract_candidates("safe", snap)
    assert "http://evil.com/payload" in candidates["url"]


def test_extract_candidates_ocsf_src_dst_ip():
    matcher = _make_matcher()
    snap = {"src": {"ip": "7.7.7.7"}, "dst": {"ip": "8.8.8.8"}}
    candidates = matcher._extract_candidates("safe", snap)
    assert "7.7.7.7" in candidates["ip"]
    assert "8.8.8.8" in candidates["ip"]


def test_extract_candidates_ocsf_process_file_hashes():
    matcher = _make_matcher()
    snap = {"process": {"file": {"hash_md5": "aabb", "hash_sha256": "ccdd"}}}
    candidates = matcher._extract_candidates("safe", snap)
    assert "aabb" in candidates["hash_md5"]
    assert "ccdd" in candidates["hash_sha256"]


def test_extract_candidates_deduplicates_same_value():
    """Same value from multiple fields appears only once per type."""
    matcher = _make_matcher()
    snap = {"src_ip": "1.2.3.4", "dst_ip": "1.2.3.4"}
    candidates = matcher._extract_candidates("1.2.3.4", snap)
    # Sets automatically deduplicate
    assert len([v for v in candidates["ip"] if v == "1.2.3.4"]) == 1


# ---------------------------------------------------------------------------
# IOCMatcher._valkey_get()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valkey_get_returns_skip_when_key_not_found():
    """Valkey returning None (key absent) → 'skip'."""
    matcher = _make_matcher(_make_valkey(get_return=None))
    result = await matcher._valkey_get("ip", "1.2.3.4")
    assert result == "skip"


@pytest.mark.asyncio
async def test_valkey_get_returns_none_for_cached_miss():
    """Valkey storing the miss sentinel → None (cached miss)."""
    matcher = _make_matcher(_make_valkey(get_return=_VALKEY_MISS))
    result = await matcher._valkey_get("ip", "1.2.3.4")
    assert result is None


@pytest.mark.asyncio
async def test_valkey_get_returns_ioc_match_from_json():
    """Valkey storing JSON → IOCMatch object."""
    match = _make_ioc_match(ioc_id=42, ioc_type="ip", value="1.2.3.4")
    valkey = _make_valkey(get_return=json.dumps(match.to_dict()))
    matcher = _make_matcher(valkey)
    result = await matcher._valkey_get("ip", "1.2.3.4")
    assert isinstance(result, IOCMatch)
    assert result.ioc_id == 42


@pytest.mark.asyncio
async def test_valkey_get_returns_skip_on_exception():
    """Valkey raising an exception → 'skip' (fail-open)."""
    valkey = MagicMock()
    valkey.get = AsyncMock(side_effect=Exception("connection refused"))
    matcher = _make_matcher(valkey)
    result = await matcher._valkey_get("ip", "1.2.3.4")
    assert result == "skip"


# ---------------------------------------------------------------------------
# IOCMatcher._valkey_set()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valkey_set_stores_miss_sentinel_for_none():
    valkey = _make_valkey()
    matcher = _make_matcher(valkey)
    await matcher._valkey_set("ip", "1.2.3.4", None)
    valkey.set.assert_awaited_once()
    call_args = valkey.set.call_args
    assert call_args.args[1] == _VALKEY_MISS


@pytest.mark.asyncio
async def test_valkey_set_stores_json_for_ioc_match():
    valkey = _make_valkey()
    matcher = _make_matcher(valkey)
    match = _make_ioc_match(ioc_id=7)
    await matcher._valkey_set("ip", "1.2.3.4", match)
    call_args = valkey.set.call_args
    stored = json.loads(call_args.args[1])
    assert stored["ioc_id"] == 7


@pytest.mark.asyncio
async def test_valkey_set_key_format():
    valkey = _make_valkey()
    matcher = _make_matcher(valkey)
    await matcher._valkey_set("ip", "1.2.3.4", None)
    key = valkey.set.call_args.args[0]
    assert key == f"{_VALKEY_PREFIX}ip:1.2.3.4"


@pytest.mark.asyncio
async def test_valkey_set_silently_ignores_exception():
    valkey = MagicMock()
    valkey.set = AsyncMock(side_effect=Exception("write error"))
    matcher = _make_matcher(valkey)
    # Should not raise
    await matcher._valkey_set("ip", "1.2.3.4", None)


# ---------------------------------------------------------------------------
# IOCMatcher.match_event()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_match_event_returns_empty_for_no_candidates():
    """No candidates → empty result, no Valkey calls."""
    matcher = _make_matcher()
    # Pre-populate cache so load_active_iocs won't hit DB
    matcher._ioc_map = {}
    matcher._cache_loaded_at = time.monotonic()

    result = await matcher.match_event("", {})
    assert result == []


@pytest.mark.asyncio
async def test_match_event_returns_empty_when_not_in_cache():
    """Value not in in-memory cache → no match."""
    valkey = _make_valkey(get_return=None)  # "skip"
    matcher = _make_matcher(valkey)
    matcher._ioc_map = {"ip": {}}  # empty ip map
    matcher._cache_loaded_at = time.monotonic()

    result = await matcher.match_event("1.2.3.4", {})
    assert result == []


@pytest.mark.asyncio
async def test_match_event_returns_match_from_in_memory_cache():
    """Value found in in-memory cache → IOCMatch returned."""
    valkey = _make_valkey(get_return=None)  # Valkey returns None → "skip"
    matcher = _make_matcher(valkey)
    expected_match = _make_ioc_match(ioc_id=5, ioc_type="ip", value="1.2.3.4")
    matcher._ioc_map = {"ip": {"1.2.3.4": expected_match}}
    matcher._cache_loaded_at = time.monotonic()

    result = await matcher.match_event("1.2.3.4", {})
    assert len(result) == 1
    assert result[0].ioc_id == 5


@pytest.mark.asyncio
async def test_match_event_deduplicates_same_ioc():
    """The same IOC matched via multiple candidate paths appears only once."""
    valkey = _make_valkey(get_return=None)  # all "skip"
    matcher = _make_matcher(valkey)
    match = _make_ioc_match(ioc_id=1, ioc_type="ip", value="1.2.3.4")
    matcher._ioc_map = {"ip": {"1.2.3.4": match}}
    matcher._cache_loaded_at = time.monotonic()

    # host + src_ip both resolve to "1.2.3.4"
    result = await matcher.match_event("1.2.3.4", {"src_ip": "1.2.3.4"})
    assert len(result) == 1


@pytest.mark.asyncio
async def test_match_event_uses_valkey_cache_hit():
    """Valkey cache hit returns cached IOCMatch without reading in-memory."""
    match = _make_ioc_match(ioc_id=99, ioc_type="ip", value="1.2.3.4")
    valkey = _make_valkey(get_return=json.dumps(match.to_dict()))
    matcher = _make_matcher(valkey)
    # in-memory is empty; only Valkey has the data
    matcher._ioc_map = {}
    matcher._cache_loaded_at = time.monotonic()

    result = await matcher.match_event("1.2.3.4", {})
    # Should still find via Valkey
    assert any(m.ioc_id == 99 for m in result)


@pytest.mark.asyncio
async def test_match_event_valkey_cached_miss_skips_in_memory():
    """Valkey cached miss → value skipped, in-memory not consulted for that value."""
    valkey = _make_valkey(get_return=_VALKEY_MISS)
    matcher = _make_matcher(valkey)
    # in-memory has the IOC but Valkey says it's a miss
    match = _make_ioc_match(ioc_id=1, ioc_type="ip", value="1.2.3.4")
    matcher._ioc_map = {"ip": {"1.2.3.4": match}}
    matcher._cache_loaded_at = time.monotonic()

    result = await matcher.match_event("1.2.3.4", {})
    assert result == []


@pytest.mark.asyncio
async def test_match_event_valkey_unavailable_falls_back_to_in_memory():
    """Valkey connection error → fall back to in-memory cache."""
    valkey = MagicMock()
    valkey.get = AsyncMock(side_effect=Exception("connection refused"))
    valkey.set = AsyncMock(side_effect=Exception("connection refused"))
    matcher = _make_matcher(valkey)
    match = _make_ioc_match(ioc_id=3, ioc_type="ip", value="1.2.3.4")
    matcher._ioc_map = {"ip": {"1.2.3.4": match}}
    matcher._cache_loaded_at = time.monotonic()

    result = await matcher.match_event("1.2.3.4", {})
    assert len(result) == 1
    assert result[0].ioc_id == 3


@pytest.mark.asyncio
async def test_match_event_stores_result_in_valkey():
    """In-memory hit is written to Valkey for subsequent requests."""
    valkey = _make_valkey(get_return=None)  # "skip" → check in-memory
    matcher = _make_matcher(valkey)
    match = _make_ioc_match(ioc_id=10, ioc_type="ip", value="1.2.3.4")
    matcher._ioc_map = {"ip": {"1.2.3.4": match}}
    matcher._cache_loaded_at = time.monotonic()

    await matcher.match_event("1.2.3.4", {})
    # Valkey.set should have been called at least once (for the cache write)
    valkey.set.assert_awaited()


@pytest.mark.asyncio
async def test_match_event_calls_load_active_iocs():
    """match_event() calls load_active_iocs() on each invocation."""
    matcher = _make_matcher()
    matcher._cache_loaded_at = time.monotonic()  # fresh

    with patch.object(matcher, "load_active_iocs", new=AsyncMock()) as mock_load:
        await matcher.match_event("", {})

    mock_load.assert_awaited_once()


# ---------------------------------------------------------------------------
# IOCMatcher.update_hits()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_hits_noop_for_empty_matches():
    """update_hits() does not open a DB session when matches is empty."""
    matcher = _make_matcher()

    with patch("app.core.database.AsyncSessionLocal") as mock_db:
        await matcher.update_hits([])

    mock_db.assert_not_called()


@pytest.mark.asyncio
async def test_update_hits_calls_increment_hit_for_each_match():
    """IOCRepo.increment_hit is called once per matched IOC."""
    matcher = _make_matcher()
    matches = [_make_ioc_match(ioc_id=1), _make_ioc_match(ioc_id=2)]

    session = MagicMock()
    session.commit = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)

    mock_inc = AsyncMock()
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=mock_inc),
    ):
        await matcher.update_hits(matches)

    assert mock_inc.await_count == 2
    ids_called = {call.args[1] for call in mock_inc.call_args_list}
    assert ids_called == {1, 2}


@pytest.mark.asyncio
async def test_update_hits_commits_session():
    """update_hits() commits the session after all increments."""
    matcher = _make_matcher()
    matches = [_make_ioc_match()]

    session = MagicMock()
    session.commit = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        await matcher.update_hits(matches)

    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_hits_fail_open_on_db_error():
    """update_hits() logs and returns silently on DB error."""
    matcher = _make_matcher()
    matches = [_make_ioc_match()]

    with patch("app.core.database.AsyncSessionLocal", side_effect=Exception("DB down")):
        # Should not raise
        await matcher.update_hits(matches)
