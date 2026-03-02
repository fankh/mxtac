"""Unit tests for DuckDBEventStore — feature 20.9.

Uses an in-memory DuckDB connection (path=":memory:") so tests run quickly
and leave no files on disk.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.duckdb_store import (
    DuckDBEventStore,
    _parse_time,
    _row_to_dict,
)


# ── Sample OCSF event ─────────────────────────────────────────────────────────

# Use a fixed time_from that falls before _SAMPLE_OCSF's timestamp so tests
# are deterministic regardless of when they run (avoids "now-1d" staleness).
_TIME_FROM = "2026-02-20T00:00:00Z"

_SAMPLE_OCSF: dict = {
    "class_uid":        4001,
    "class_name":       "Network Activity",
    "category_uid":     4,
    "time":             "2026-02-20T12:00:00+00:00",
    "severity_id":      3,
    "metadata_product": "Wazuh",
    "metadata_version": "1.1.0",
    "metadata_uid":     "evt-abc-123",
    "src_endpoint": {
        "ip":       "192.168.1.10",
        "hostname": "WIN-DC01",
    },
    "dst_endpoint": {
        "ip":       "10.0.0.1",
        "hostname": None,
    },
    "actor_user": {
        "name": "CORP\\admin",
    },
    "process": {
        "hash_sha256": "deadbeef1234",
    },
    "unmapped": {
        "summary": "Suspicious outbound connection",
    },
}


# ── _parse_time ───────────────────────────────────────────────────────────────


def test_parse_time_now() -> None:
    result = _parse_time("now")
    assert isinstance(result, datetime)
    assert result.tzinfo is not None


def test_parse_time_relative_days() -> None:
    result = _parse_time("now-7d")
    now = datetime.now(timezone.utc)
    diff = now - result
    assert 6 * 86400 < diff.total_seconds() < 8 * 86400


def test_parse_time_relative_hours() -> None:
    result = _parse_time("now-1h")
    now = datetime.now(timezone.utc)
    diff = now - result
    assert 3500 < diff.total_seconds() < 3700


def test_parse_time_iso() -> None:
    result = _parse_time("2026-02-20T12:00:00Z")
    assert result == datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_time_iso_with_offset() -> None:
    result = _parse_time("2026-02-20T12:00:00+00:00")
    assert result.year == 2026
    assert result.month == 2
    assert result.day == 20


# ── DuckDBEventStore lifecycle ────────────────────────────────────────────────


@pytest.fixture
async def store() -> DuckDBEventStore:
    """Fresh in-memory DuckDB store, connected and ready."""
    s = DuckDBEventStore(path=":memory:")
    await s.connect()
    assert s.is_available
    yield s
    await s.close()


@pytest.mark.asyncio
async def test_connect_sets_available() -> None:
    s = DuckDBEventStore(path=":memory:")
    assert not s.is_available
    await s.connect()
    assert s.is_available
    await s.close()


@pytest.mark.asyncio
async def test_close_clears_available(store: DuckDBEventStore) -> None:
    assert store.is_available
    await store.close()
    assert not store.is_available


@pytest.mark.asyncio
async def test_connect_fails_gracefully_when_duckdb_missing() -> None:
    """If duckdb is not importable, connect() sets available=False silently."""
    import sys

    s = DuckDBEventStore(path=":memory:")
    # Temporarily hide the duckdb module
    real_duckdb = sys.modules.get("duckdb")
    sys.modules["duckdb"] = None  # type: ignore[assignment]
    try:
        await s.connect()
        assert not s.is_available
    finally:
        if real_duckdb is not None:
            sys.modules["duckdb"] = real_duckdb
        else:
            del sys.modules["duckdb"]
        s._executor.shutdown(wait=False)


# ── index_event ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_index_event_inserts_row(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="test-uuid-001")
    count = await store.total_count()
    assert count == 1


@pytest.mark.asyncio
async def test_index_event_uses_doc_id(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="explicit-id-001")
    result = await store.search_events(time_from=_TIME_FROM)
    assert result["total"] == 1
    assert result["items"][0]["id"] == "explicit-id-001"


@pytest.mark.asyncio
async def test_index_event_replaces_on_duplicate_id(store: DuckDBEventStore) -> None:
    """INSERT OR REPLACE: same doc_id should update, not duplicate."""
    await store.index_event(_SAMPLE_OCSF, doc_id="dup-id")
    await store.index_event(
        {**_SAMPLE_OCSF, "unmapped": {"summary": "Updated summary"}},
        doc_id="dup-id",
    )
    count = await store.total_count()
    assert count == 1


@pytest.mark.asyncio
async def test_index_event_no_op_when_unavailable() -> None:
    """index_event is a no-op and does not raise when store is unavailable."""
    s = DuckDBEventStore(path=":memory:")
    # Do NOT connect — is_available remains False
    await s.index_event(_SAMPLE_OCSF, doc_id="should-not-insert")
    s._executor.shutdown(wait=False)


@pytest.mark.asyncio
async def test_index_event_generates_id_when_none(store: DuckDBEventStore) -> None:
    """When doc_id is None and event has no 'id', a UUID is generated."""
    event = {k: v for k, v in _SAMPLE_OCSF.items()}  # no 'id' key
    await store.index_event(event, doc_id=None)
    count = await store.total_count()
    assert count == 1


@pytest.mark.asyncio
async def test_index_event_extracts_nested_fields(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="nested-test")
    result = await store.search_events(
        filters=[
            type("F", (), {"field": "src_ip", "operator": "eq", "value": "192.168.1.10"})()
        ],
        time_from=_TIME_FROM,
    )
    assert result["total"] == 1


# ── search_events ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_no_results_empty_store(store: DuckDBEventStore) -> None:
    result = await store.search_events()
    assert result["total"] == 0
    assert result["items"] == []


@pytest.mark.asyncio
async def test_search_returns_inserted_event(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="search-test-01")
    result = await store.search_events(time_from=_TIME_FROM)
    assert result["total"] == 1
    assert result["items"][0]["id"] == "search-test-01"


@pytest.mark.asyncio
async def test_search_full_text_query(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="ft-test-01")
    # Should match on summary field
    result = await store.search_events(query="Suspicious", time_from=_TIME_FROM)
    assert result["total"] == 1
    # Should NOT match on unrelated query
    result2 = await store.search_events(query="ZeroMatchXYZ", time_from=_TIME_FROM)
    assert result2["total"] == 0


@pytest.mark.asyncio
async def test_search_text_matches_hostname(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="host-match-01")
    result = await store.search_events(query="WIN-DC01", time_from=_TIME_FROM)
    assert result["total"] == 1


@pytest.mark.asyncio
async def test_search_filter_eq(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="filter-eq-01")
    # Matching filter
    result = await store.search_events(
        filters=[type("F", (), {"field": "source", "operator": "eq", "value": "Wazuh"})()],
        time_from=_TIME_FROM,
    )
    assert result["total"] == 1
    # Non-matching filter
    result2 = await store.search_events(
        filters=[type("F", (), {"field": "source", "operator": "eq", "value": "Zeek"})()],
        time_from=_TIME_FROM,
    )
    assert result2["total"] == 0


@pytest.mark.asyncio
async def test_search_filter_ne(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="filter-ne-01")
    result = await store.search_events(
        filters=[type("F", (), {"field": "source", "operator": "ne", "value": "Zeek"})()],
        time_from=_TIME_FROM,
    )
    assert result["total"] == 1


@pytest.mark.asyncio
async def test_search_filter_contains(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="filter-cont-01")
    result = await store.search_events(
        filters=[type("F", (), {"field": "hostname", "operator": "contains", "value": "DC01"})()],
        time_from=_TIME_FROM,
    )
    assert result["total"] == 1


@pytest.mark.asyncio
async def test_search_filter_severity_gt(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="sev-gt-01")  # severity_id=3
    result = await store.search_events(
        filters=[type("F", (), {"field": "severity_id", "operator": "gt", "value": 2})()],
        time_from=_TIME_FROM,
    )
    assert result["total"] == 1
    result2 = await store.search_events(
        filters=[type("F", (), {"field": "severity_id", "operator": "gt", "value": 5})()],
        time_from=_TIME_FROM,
    )
    assert result2["total"] == 0


@pytest.mark.asyncio
async def test_search_pagination(store: DuckDBEventStore) -> None:
    for i in range(5):
        await store.index_event(
            {**_SAMPLE_OCSF, "time": f"2026-02-20T12:0{i}:00+00:00"},
            doc_id=f"page-{i}",
        )
    result = await store.search_events(time_from=_TIME_FROM, size=2, from_=0)
    assert len(result["items"]) == 2
    assert result["total"] == 5

    result2 = await store.search_events(time_from=_TIME_FROM, size=2, from_=4)
    assert len(result2["items"]) == 1


@pytest.mark.asyncio
async def test_search_time_range_excludes_old_events(store: DuckDBEventStore) -> None:
    # Old event (outside range)
    old_event = {**_SAMPLE_OCSF, "time": "2020-01-01T00:00:00+00:00"}
    await store.index_event(old_event, doc_id="old-evt")
    # Recent event (inside range)
    await store.index_event(_SAMPLE_OCSF, doc_id="recent-evt")
    result = await store.search_events(time_from=_TIME_FROM)
    assert result["total"] == 1
    assert result["items"][0]["id"] == "recent-evt"


@pytest.mark.asyncio
async def test_search_unknown_filter_field_ignored(store: DuckDBEventStore) -> None:
    """Filters for unknown fields are silently skipped, not errored."""
    await store.index_event(_SAMPLE_OCSF, doc_id="unknown-field")
    result = await store.search_events(
        filters=[
            type("F", (), {"field": "src_ip", "operator": "eq", "value": "192.168.1.10"})(),
            type("F", (), {"field": "unknown_field", "operator": "eq", "value": "x"})(),
        ],
        time_from=_TIME_FROM,
    )
    # Should not raise; unknown field is ignored
    assert result["total"] == 1


@pytest.mark.asyncio
async def test_search_returns_empty_when_unavailable() -> None:
    s = DuckDBEventStore(path=":memory:")  # not connected
    result = await s.search_events()
    assert result == {"total": 0, "items": []}
    s._executor.shutdown(wait=False)


# ── aggregate ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_aggregate_terms_empty_store(store: DuckDBEventStore) -> None:
    buckets = await store.aggregate("terms", field="source", time_from=_TIME_FROM)
    assert buckets == []


@pytest.mark.asyncio
async def test_aggregate_terms_counts_by_field(store: DuckDBEventStore) -> None:
    await store.index_event(_SAMPLE_OCSF, doc_id="agg-1")  # source=Wazuh
    await store.index_event(_SAMPLE_OCSF, doc_id="agg-2")  # source=Wazuh
    await store.index_event(
        {**_SAMPLE_OCSF, "metadata_product": "Zeek"}, doc_id="agg-3"
    )
    buckets = await store.aggregate("terms", field="source", time_from=_TIME_FROM, size=10)
    assert len(buckets) == 2
    # Wazuh should be first (higher count)
    keys = [b["key"] for b in buckets]
    assert "Wazuh" in keys
    assert "Zeek" in keys
    wazuh_bucket = next(b for b in buckets if b["key"] == "Wazuh")
    assert wazuh_bucket["count"] == 2


@pytest.mark.asyncio
async def test_aggregate_terms_respects_size_limit(store: DuckDBEventStore) -> None:
    for i in range(5):
        await store.index_event(
            {**_SAMPLE_OCSF, "metadata_product": f"Source{i}"},
            doc_id=f"sz-{i}",
        )
    buckets = await store.aggregate("terms", field="source", time_from=_TIME_FROM, size=3)
    assert len(buckets) == 3


@pytest.mark.asyncio
async def test_aggregate_terms_opensearch_alias(store: DuckDBEventStore) -> None:
    """OpenSearch nested-field alias 'actor_user.name' maps to username column."""
    await store.index_event(_SAMPLE_OCSF, doc_id="alias-1")
    buckets = await store.aggregate(
        "terms", field="actor_user.name", time_from=_TIME_FROM
    )
    assert len(buckets) == 1
    assert buckets[0]["key"] == "CORP\\admin"


@pytest.mark.asyncio
async def test_aggregate_date_histogram_hour(store: DuckDBEventStore) -> None:
    # Insert 3 events in the same hour and 1 in a different hour
    for i in range(3):
        await store.index_event(
            {**_SAMPLE_OCSF, "time": "2026-02-20T12:00:00+00:00"},
            doc_id=f"hist-same-{i}",
        )
    await store.index_event(
        {**_SAMPLE_OCSF, "time": "2026-02-20T14:00:00+00:00"},
        doc_id="hist-diff-1",
    )

    buckets = await store.aggregate(
        "date_histogram",
        interval="1h",
        time_from="2026-02-20T11:00:00+00:00",
        time_to="2026-02-20T15:00:00+00:00",
    )
    assert len(buckets) == 2
    counts = {b["count"] for b in buckets}
    assert 3 in counts
    assert 1 in counts


@pytest.mark.asyncio
async def test_aggregate_date_histogram_day(store: DuckDBEventStore) -> None:
    for day in range(3):
        await store.index_event(
            {**_SAMPLE_OCSF, "time": f"2026-02-{18 + day}T12:00:00+00:00"},
            doc_id=f"day-{day}",
        )
    buckets = await store.aggregate(
        "date_histogram",
        interval="1d",
        time_from="2026-02-17T00:00:00+00:00",
        time_to="2026-02-21T00:00:00+00:00",
    )
    assert len(buckets) == 3


@pytest.mark.asyncio
async def test_aggregate_returns_empty_when_unavailable() -> None:
    s = DuckDBEventStore(path=":memory:")  # not connected
    buckets = await s.aggregate("terms", field="source")
    assert buckets == []
    s._executor.shutdown(wait=False)


# ── total_count ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_total_count_empty(store: DuckDBEventStore) -> None:
    assert await store.total_count() == 0


@pytest.mark.asyncio
async def test_total_count_after_inserts(store: DuckDBEventStore) -> None:
    for i in range(4):
        await store.index_event(_SAMPLE_OCSF, doc_id=f"cnt-{i}")
    assert await store.total_count() == 4


@pytest.mark.asyncio
async def test_total_count_returns_zero_when_unavailable() -> None:
    s = DuckDBEventStore(path=":memory:")  # not connected
    assert await s.total_count() == 0
    s._executor.shutdown(wait=False)


# ── event_persister integration ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_event_persister_writes_to_duckdb() -> None:
    """event_persister() mirrors normalised events to DuckDB when available."""
    import asyncio

    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.event_persister import event_persister

    queue = InMemoryQueue()
    await queue.start()

    mock_os = MagicMock()
    mock_os.is_available = False

    duckdb_store = DuckDBEventStore(path=":memory:")
    await duckdb_store.connect()

    mock_event = MagicMock()
    mock_event.id = "pg-uuid-duck-01"

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_session),
        patch("app.repositories.event_repo.EventRepo") as mock_repo,
    ):
        mock_repo.create = AsyncMock(return_value=mock_event)

        await event_persister(queue, mock_os, duckdb_store=duckdb_store)
        await queue.publish(Topic.NORMALIZED, _SAMPLE_OCSF)
        await asyncio.sleep(0.2)

        count = await duckdb_store.total_count()
        assert count == 1

    await queue.stop()
    await duckdb_store.close()


@pytest.mark.asyncio
async def test_event_persister_skips_duckdb_when_none() -> None:
    """event_persister() works normally when duckdb_store=None (default)."""
    import asyncio

    from app.pipeline.queue import InMemoryQueue, Topic
    from app.services.event_persister import event_persister

    queue = InMemoryQueue()
    await queue.start()

    mock_os = MagicMock()
    mock_os.is_available = False

    mock_event = MagicMock()
    mock_event.id = "pg-uuid-no-duck"

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=mock_session),
        patch("app.repositories.event_repo.EventRepo") as mock_repo,
    ):
        mock_repo.create = AsyncMock(return_value=mock_event)

        # No duckdb_store passed — should not raise
        await event_persister(queue, mock_os, duckdb_store=None)
        await queue.publish(Topic.NORMALIZED, _SAMPLE_OCSF)
        await asyncio.sleep(0.1)

        mock_repo.create.assert_called_once()

    await queue.stop()


# ── _row_to_dict ──────────────────────────────────────────────────────────────


def test_row_to_dict_basic() -> None:
    t = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    row = (
        "id-1", "uid-1", t, "Network Activity", 4001, 3,
        "192.168.1.1", "10.0.0.1", "WIN-DC01", "admin", "abc", "wazuh",
        "Test summary", '{"extra_field": "extra_value"}',
    )
    d = _row_to_dict(row)
    assert d["id"] == "id-1"
    assert d["class_name"] == "Network Activity"
    assert d["src_ip"] == "192.168.1.1"
    assert d["summary"] == "Test summary"
    # raw JSON merged in
    assert d["extra_field"] == "extra_value"


def test_row_to_dict_none_raw() -> None:
    t = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    row = (
        "id-1", None, t, None, None, None,
        None, None, None, None, None, None,
        None, None,
    )
    d = _row_to_dict(row)
    assert d["id"] == "id-1"
    assert d["summary"] is None


def test_row_to_dict_invalid_raw_json_handled() -> None:
    t = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    row = (
        "id-1", None, t, None, None, None,
        None, None, None, None, None, None,
        None, "not-valid-json{{{",
    )
    # Should not raise even with broken JSON
    d = _row_to_dict(row)
    assert d["id"] == "id-1"
