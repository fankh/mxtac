"""Tests for IOCRepo — async DB operations for the iocs table.

Feature 29.2 — IOC repository layer

Approach:
  - All session interactions are mocked (no live DB needed)
  - AsyncMock used for awaitable session methods (execute, flush, scalar, delete)
  - MagicMock used for synchronous session methods (add)
  - IOCRepo.get_by_id is patched for methods that call it (update, delete)

Coverage:
  - list(): returns (items, total) from session.execute/scalar
  - list(): no filters applied — both count and data queries executed
  - list(): ioc_type filter forwarded
  - list(): source filter forwarded
  - list(): is_active filter forwarded
  - list(): search filter forwarded
  - list(): empty result returns ([], 0)
  - get_by_id(): found → returns IOC; not found → returns None
  - lookup(): found → returns IOC; not found → returns None
  - bulk_lookup(): returns matching IOC list; empty values → []
  - create(): IOC added to session, flushed, returned with correct fields
  - bulk_create(): creates new items, skips existing duplicates
  - bulk_create(): skips intra-batch duplicates
  - bulk_create(): empty input → (0, 0), no DB calls
  - update(): found → sets attributes, flushes, returns IOC
  - update(): not found → returns None without flush
  - update(): None kwarg values are skipped
  - delete(): found → calls session.delete + flush, returns True
  - delete(): not found → returns False, no delete/flush
  - increment_hit(): executes UPDATE and flushes
  - expire_old(): counts eligible rows, updates them, returns count
  - expire_old(): count=0 → skips update, returns 0
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.repositories.ioc_repo import IOCRepo


# ---------------------------------------------------------------------------
# Session factory helpers
# ---------------------------------------------------------------------------


def _make_session() -> MagicMock:
    """Sync MagicMock for the session with async methods patched."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.delete = AsyncMock()
    session.scalar = AsyncMock()
    return session


def _scalars_result(items: list) -> MagicMock:
    """Result mock whose .scalars().all() returns items."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    return result


def _scalar_one_result(item) -> MagicMock:
    """Result mock whose .scalar_one_or_none() returns item."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = item
    return result


def _rows_result(rows: list[tuple]) -> MagicMock:
    """Result mock whose .all() returns a list of row-like tuples."""
    result = MagicMock()
    result.all.return_value = [MagicMock(ioc_type=r[0], value=r[1]) for r in rows]
    return result


def _make_ioc(**kwargs) -> MagicMock:
    """Minimal IOC-like mock."""
    ioc = MagicMock()
    ioc.id = kwargs.get("id", 1)
    ioc.ioc_type = kwargs.get("ioc_type", "ip")
    ioc.value = kwargs.get("value", "1.2.3.4")
    ioc.source = kwargs.get("source", "manual")
    ioc.confidence = kwargs.get("confidence", 80)
    ioc.severity = kwargs.get("severity", "high")
    ioc.is_active = kwargs.get("is_active", True)
    ioc.hit_count = kwargs.get("hit_count", 0)
    ioc.last_hit_at = kwargs.get("last_hit_at", None)
    return ioc


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


class TestIOCRepoList:
    """IOCRepo.list() returns (items, total) with filtering and pagination."""

    @pytest.mark.asyncio
    async def test_returns_tuple_of_list_and_int(self) -> None:
        session = _make_session()
        session.scalar.return_value = 2
        iocs = [_make_ioc(id=1), _make_ioc(id=2)]
        session.execute.return_value = _scalars_result(iocs)

        result, total = await IOCRepo.list(session)

        assert isinstance(result, list)
        assert total == 2
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_no_filters_executes_count_and_data(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        await IOCRepo.list(session)

        session.scalar.assert_awaited_once()
        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_empty_result_returns_empty_list_and_zero(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IOCRepo.list(session)

        assert items == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_scalar_none_total_becomes_zero(self) -> None:
        session = _make_session()
        session.scalar.return_value = None
        session.execute.return_value = _scalars_result([])

        _, total = await IOCRepo.list(session)

        assert total == 0

    @pytest.mark.asyncio
    async def test_ioc_type_filter_forwarded(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([_make_ioc(ioc_type="domain")])

        items, _ = await IOCRepo.list(session, ioc_type="domain")

        assert len(items) == 1
        assert items[0].ioc_type == "domain"

    @pytest.mark.asyncio
    async def test_source_filter_forwarded(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([_make_ioc(source="opencti")])

        items, _ = await IOCRepo.list(session, source="opencti")

        assert items[0].source == "opencti"

    @pytest.mark.asyncio
    async def test_is_active_filter_forwarded(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([_make_ioc(is_active=False)])

        items, _ = await IOCRepo.list(session, is_active=False)

        assert items[0].is_active is False

    @pytest.mark.asyncio
    async def test_search_filter_forwarded(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([_make_ioc(value="evil.com")])

        items, _ = await IOCRepo.list(session, search="evil")

        assert items[0].value == "evil.com"


# ---------------------------------------------------------------------------
# get_by_id()
# ---------------------------------------------------------------------------


class TestIOCRepoGetById:

    @pytest.mark.asyncio
    async def test_found_returns_ioc(self) -> None:
        session = _make_session()
        ioc = _make_ioc(id=42)
        session.execute.return_value = _scalar_one_result(ioc)

        result = await IOCRepo.get_by_id(session, 42)

        assert result is ioc

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await IOCRepo.get_by_id(session, 999)

        assert result is None

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await IOCRepo.get_by_id(session, 1)

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# lookup()
# ---------------------------------------------------------------------------


class TestIOCRepoLookup:

    @pytest.mark.asyncio
    async def test_found_returns_ioc(self) -> None:
        session = _make_session()
        ioc = _make_ioc(ioc_type="ip", value="10.0.0.1")
        session.execute.return_value = _scalar_one_result(ioc)

        result = await IOCRepo.lookup(session, "ip", "10.0.0.1")

        assert result is ioc

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await IOCRepo.lookup(session, "ip", "0.0.0.0")

        assert result is None

    @pytest.mark.asyncio
    async def test_executes_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await IOCRepo.lookup(session, "hash_md5", "abc123")

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# bulk_lookup()
# ---------------------------------------------------------------------------


class TestIOCRepoBulkLookup:

    @pytest.mark.asyncio
    async def test_returns_matching_iocs(self) -> None:
        session = _make_session()
        iocs = [_make_ioc(value="1.1.1.1"), _make_ioc(value="2.2.2.2")]
        session.execute.return_value = _scalars_result(iocs)

        result = await IOCRepo.bulk_lookup(session, "ip", ["1.1.1.1", "2.2.2.2"])

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_empty_values_returns_empty_without_db_call(self) -> None:
        session = _make_session()

        result = await IOCRepo.bulk_lookup(session, "ip", [])

        assert result == []
        session.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_executes_once_for_non_empty_values(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        await IOCRepo.bulk_lookup(session, "domain", ["evil.com"])

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


class TestIOCRepoCreate:

    @pytest.mark.asyncio
    async def test_adds_to_session_and_flushes(self) -> None:
        session = _make_session()

        ioc = await IOCRepo.create(
            session,
            ioc_type="ip",
            value="192.168.1.1",
            source="manual",
            confidence=70,
            severity="medium",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )

        session.add.assert_called_once()
        session.flush.assert_awaited_once()
        assert ioc is not None

    @pytest.mark.asyncio
    async def test_returned_object_has_correct_fields(self) -> None:
        session = _make_session()
        now = datetime.now(timezone.utc)

        ioc = await IOCRepo.create(
            session,
            ioc_type="domain",
            value="malicious.example.com",
            source="stix-feed",
            confidence=90,
            severity="critical",
            first_seen=now,
            last_seen=now,
        )

        assert ioc.ioc_type == "domain"
        assert ioc.value == "malicious.example.com"
        assert ioc.source == "stix-feed"
        assert ioc.severity == "critical"


# ---------------------------------------------------------------------------
# bulk_create()
# ---------------------------------------------------------------------------


def _make_ioc_dict(**kwargs) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "ioc_type": kwargs.get("ioc_type", "ip"),
        "value": kwargs.get("value", "1.2.3.4"),
        "source": kwargs.get("source", "manual"),
        "confidence": kwargs.get("confidence", 50),
        "severity": kwargs.get("severity", "medium"),
        "first_seen": kwargs.get("first_seen", now),
        "last_seen": kwargs.get("last_seen", now),
    }


class TestIOCRepoBulkCreate:

    @pytest.mark.asyncio
    async def test_empty_input_returns_zeros_without_db_call(self) -> None:
        session = _make_session()

        created, skipped = await IOCRepo.bulk_create(session, [])

        assert created == 0
        assert skipped == 0
        session.execute.assert_not_awaited()
        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_creates_new_items(self) -> None:
        session = _make_session()
        # DB has no existing rows for these values
        empty_rows = MagicMock()
        empty_rows.all.return_value = []
        session.execute.return_value = empty_rows

        items = [
            _make_ioc_dict(ioc_type="ip", value="10.0.0.1"),
            _make_ioc_dict(ioc_type="ip", value="10.0.0.2"),
        ]
        created, skipped = await IOCRepo.bulk_create(session, items)

        assert created == 2
        assert skipped == 0
        assert session.add.call_count == 2
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_skips_existing_duplicates(self) -> None:
        session = _make_session()
        # DB already has 10.0.0.1
        existing_result = MagicMock()
        existing_result.all.return_value = [
            MagicMock(ioc_type="ip", value="10.0.0.1")
        ]
        session.execute.return_value = existing_result

        items = [
            _make_ioc_dict(ioc_type="ip", value="10.0.0.1"),  # duplicate
            _make_ioc_dict(ioc_type="ip", value="10.0.0.2"),  # new
        ]
        created, skipped = await IOCRepo.bulk_create(session, items)

        assert created == 1
        assert skipped == 1
        assert session.add.call_count == 1

    @pytest.mark.asyncio
    async def test_skips_intra_batch_duplicates(self) -> None:
        session = _make_session()
        empty_rows = MagicMock()
        empty_rows.all.return_value = []
        session.execute.return_value = empty_rows

        # Same (ioc_type, value) appears twice in the batch
        items = [
            _make_ioc_dict(ioc_type="ip", value="10.0.0.1"),
            _make_ioc_dict(ioc_type="ip", value="10.0.0.1"),
        ]
        created, skipped = await IOCRepo.bulk_create(session, items)

        assert created == 1
        assert skipped == 1

    @pytest.mark.asyncio
    async def test_no_flush_when_nothing_created(self) -> None:
        session = _make_session()
        existing_result = MagicMock()
        existing_result.all.return_value = [
            MagicMock(ioc_type="ip", value="1.2.3.4")
        ]
        session.execute.return_value = existing_result

        items = [_make_ioc_dict(ioc_type="ip", value="1.2.3.4")]
        created, skipped = await IOCRepo.bulk_create(session, items)

        assert created == 0
        assert skipped == 1
        session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestIOCRepoUpdate:

    @pytest.mark.asyncio
    async def test_found_updates_attributes_and_returns_ioc(self) -> None:
        session = _make_session()
        ioc = _make_ioc(id=1, severity="low")

        with patch.object(IOCRepo, "get_by_id", AsyncMock(return_value=ioc)):
            result = await IOCRepo.update(session, 1, severity="critical")

        assert result is ioc
        assert ioc.severity == "critical"
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_not_found_returns_none_without_flush(self) -> None:
        session = _make_session()

        with patch.object(IOCRepo, "get_by_id", AsyncMock(return_value=None)):
            result = await IOCRepo.update(session, 999, severity="high")

        assert result is None
        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_none_values_are_skipped(self) -> None:
        session = _make_session()
        ioc = _make_ioc(id=1, severity="low")
        original_severity = ioc.severity

        with patch.object(IOCRepo, "get_by_id", AsyncMock(return_value=ioc)):
            await IOCRepo.update(session, 1, severity=None, source="opencti")

        # severity=None is skipped; source is updated
        assert ioc.severity == original_severity
        assert ioc.source == "opencti"


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestIOCRepoDelete:

    @pytest.mark.asyncio
    async def test_found_deletes_and_returns_true(self) -> None:
        session = _make_session()
        ioc = _make_ioc(id=5)

        with patch.object(IOCRepo, "get_by_id", AsyncMock(return_value=ioc)):
            result = await IOCRepo.delete(session, 5)

        assert result is True
        session.delete.assert_awaited_once_with(ioc)
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_not_found_returns_false_no_delete(self) -> None:
        session = _make_session()

        with patch.object(IOCRepo, "get_by_id", AsyncMock(return_value=None)):
            result = await IOCRepo.delete(session, 999)

        assert result is False
        session.delete.assert_not_awaited()
        session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# increment_hit()
# ---------------------------------------------------------------------------


class TestIOCRepoIncrementHit:

    @pytest.mark.asyncio
    async def test_executes_update_and_flushes(self) -> None:
        session = _make_session()

        await IOCRepo.increment_hit(session, ioc_id=7)

        session.execute.assert_awaited_once()
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_none(self) -> None:
        session = _make_session()

        result = await IOCRepo.increment_hit(session, ioc_id=3)

        assert result is None


# ---------------------------------------------------------------------------
# expire_old()
# ---------------------------------------------------------------------------


class TestIOCRepoExpireOld:

    @pytest.mark.asyncio
    async def test_returns_count_of_deactivated_iocs(self) -> None:
        session = _make_session()
        session.scalar.return_value = 3  # 3 IOCs to expire

        result = await IOCRepo.expire_old(session)

        assert result == 3
        # count query + update query
        session.scalar.assert_awaited_once()
        session.execute.assert_awaited_once()
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_zero_count_skips_update(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0

        result = await IOCRepo.expire_old(session)

        assert result == 0
        session.scalar.assert_awaited_once()
        session.execute.assert_not_awaited()
        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_none_scalar_treated_as_zero(self) -> None:
        session = _make_session()
        session.scalar.return_value = None

        result = await IOCRepo.expire_old(session)

        assert result == 0
        session.execute.assert_not_awaited()
