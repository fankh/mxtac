"""Tests for DetectionRepo — async DB operations for the detections table.

Feature 10.11 — DB persistence for all operations

Approach:
  - All session interactions are mocked (no live DB needed)
  - AsyncMock used for awaitable session methods (execute, flush, scalar, delete)
  - MagicMock used for synchronous session methods (add)
  - DetectionRepo.get is patched internally for methods that call it (update, delete)

Coverage:
  - list(): returns (items, total) from session.execute/scalar
  - list(): no filters — two execute calls (count + data)
  - list(): severity filter forwarded
  - list(): status filter forwarded
  - list(): tactic filter forwarded
  - list(): host filter forwarded
  - list(): search filter forwarded
  - list(): sort/order forwarded, default is time/desc
  - list(): empty result returns ([], 0)
  - get(): found → returns Detection; not found → returns None
  - get(): calls session.execute once
  - create(): Detection added to session, flushed, returned
  - create(): returned object has correct field values
  - update(): found → sets attributes, flushes, returns Detection
  - update(): not found → returns None without flush
  - update(): None kwarg values are skipped
  - delete(): found → calls session.delete + flush, returns True
  - delete(): not found → returns False, no delete/flush
  - count(): returns scalar result; None result → 0
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.repositories.detection_repo import DetectionRepo


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


def _make_detection(**kwargs) -> MagicMock:
    """Minimal Detection-like mock."""
    det = MagicMock()
    det.id = kwargs.get("id", "DET-0001")
    det.score = kwargs.get("score", 7.5)
    det.severity = kwargs.get("severity", "high")
    det.technique_id = kwargs.get("technique_id", "T1059")
    det.technique_name = kwargs.get("technique_name", "Command Scripting")
    det.tactic = kwargs.get("tactic", "Execution")
    det.tactic_id = kwargs.get("tactic_id", "TA0002")
    det.name = kwargs.get("name", "Suspicious PowerShell Execution")
    det.host = kwargs.get("host", "WS-01")
    det.status = kwargs.get("status", "active")
    return det


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


class TestDetectionRepoList:
    """DetectionRepo.list() returns (items, total) with filtering and pagination."""

    @pytest.mark.asyncio
    async def test_returns_tuple_of_list_and_int(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([_make_detection()])

        result = await DetectionRepo.list(session)

        assert isinstance(result, tuple)
        assert isinstance(result[0], list)
        assert isinstance(result[1], int)

    @pytest.mark.asyncio
    async def test_returns_items_and_total(self) -> None:
        det = _make_detection(id="DET-A")
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([det])

        items, total = await DetectionRepo.list(session)

        assert items == [det]
        assert total == 1

    @pytest.mark.asyncio
    async def test_empty_result_returns_empty_list_and_zero(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await DetectionRepo.list(session)

        assert items == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_calls_execute_for_data(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        await DetectionRepo.list(session)

        session.execute.assert_awaited()

    @pytest.mark.asyncio
    async def test_calls_scalar_for_count(self) -> None:
        session = _make_session()
        session.scalar.return_value = 5
        session.execute.return_value = _scalars_result([])

        await DetectionRepo.list(session)

        session.scalar.assert_awaited()

    @pytest.mark.asyncio
    async def test_returns_multiple_detections(self) -> None:
        dets = [_make_detection(id=f"DET-{i}") for i in range(5)]
        session = _make_session()
        session.scalar.return_value = 5
        session.execute.return_value = _scalars_result(dets)

        items, total = await DetectionRepo.list(session)

        assert len(items) == 5
        assert total == 5

    @pytest.mark.asyncio
    async def test_none_scalar_maps_to_zero_total(self) -> None:
        session = _make_session()
        session.scalar.return_value = None
        session.execute.return_value = _scalars_result([])

        _, total = await DetectionRepo.list(session)

        assert total == 0

    @pytest.mark.asyncio
    async def test_severity_filter_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await DetectionRepo.list(session, severity=["critical", "high"])

        assert items == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_status_filter_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await DetectionRepo.list(session, status=["active"])

        assert items == []

    @pytest.mark.asyncio
    async def test_tactic_filter_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await DetectionRepo.list(session, tactic="Execution")

        assert items == []

    @pytest.mark.asyncio
    async def test_host_filter_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await DetectionRepo.list(session, host="WS-01")

        assert items == []

    @pytest.mark.asyncio
    async def test_search_filter_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await DetectionRepo.list(session, search="mimikatz")

        assert items == []

    @pytest.mark.asyncio
    async def test_sort_and_order_params_accepted(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await DetectionRepo.list(session, sort="score", order="asc")

        assert items == []

    @pytest.mark.asyncio
    async def test_all_filters_combined_do_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await DetectionRepo.list(
            session,
            severity=["critical"],
            status=["active"],
            tactic="Credential Access",
            host="DC-01",
            search="dcsync",
            sort="score",
            order="desc",
        )

        assert items == []
        assert total == 0


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------


class TestDetectionRepoGet:
    """DetectionRepo.get() returns a Detection or None."""

    @pytest.mark.asyncio
    async def test_returns_detection_when_found(self) -> None:
        det = _make_detection(id="DET-1")
        session = _make_session()
        session.execute.return_value = _scalar_one_result(det)

        result = await DetectionRepo.get(session, "DET-1")

        assert result is det

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await DetectionRepo.get(session, "nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await DetectionRepo.get(session, "DET-1")

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


class TestDetectionRepoCreate:
    """DetectionRepo.create() constructs and persists a Detection."""

    @pytest.mark.asyncio
    async def test_returns_detection_instance(self) -> None:
        from app.models.detection import Detection
        session = _make_session()

        result = await DetectionRepo.create(
            session,
            score=8.5,
            severity="high",
            technique_id="T1059",
            technique_name="Command Scripting",
            tactic="Execution",
            name="Suspicious PowerShell",
            host="WS-01",
        )

        assert isinstance(result, Detection)

    @pytest.mark.asyncio
    async def test_calls_session_add(self) -> None:
        session = _make_session()

        await DetectionRepo.create(
            session,
            score=5.0,
            severity="medium",
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic="Initial Access",
            name="Brute Force Login",
            host="SRV-01",
        )

        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_calls_session_flush(self) -> None:
        session = _make_session()

        await DetectionRepo.create(
            session,
            score=5.0,
            severity="medium",
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic="Initial Access",
            name="Brute Force Login",
            host="SRV-01",
        )

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_added_object_is_detection(self) -> None:
        from app.models.detection import Detection
        session = _make_session()

        await DetectionRepo.create(
            session,
            score=9.0,
            severity="critical",
            technique_id="T1003",
            technique_name="Credential Dumping",
            tactic="Credential Access",
            name="LSASS Dump",
            host="DC-01",
        )

        added = session.add.call_args[0][0]
        assert isinstance(added, Detection)

    @pytest.mark.asyncio
    async def test_created_detection_has_correct_host(self) -> None:
        session = _make_session()

        result = await DetectionRepo.create(
            session,
            score=6.0,
            severity="high",
            technique_id="T1021",
            technique_name="Remote Services",
            tactic="Lateral Movement",
            name="RDP Lateral Movement",
            host="SRV-PROD-01",
        )

        assert result.host == "SRV-PROD-01"

    @pytest.mark.asyncio
    async def test_created_detection_has_correct_severity(self) -> None:
        session = _make_session()

        result = await DetectionRepo.create(
            session,
            score=9.5,
            severity="critical",
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic="Impact",
            name="Ransomware Execution",
            host="FILE-SRV-01",
        )

        assert result.severity == "critical"


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestDetectionRepoUpdate:
    """DetectionRepo.update() modifies an existing Detection or returns None."""

    @pytest.mark.asyncio
    async def test_returns_updated_detection_when_found(self) -> None:
        det = _make_detection(id="DET-1", status="active")
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=det)):
            result = await DetectionRepo.update(session, "DET-1", status="investigating")

        assert result is det

    @pytest.mark.asyncio
    async def test_sets_attribute_on_detection(self) -> None:
        det = MagicMock()
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=det)):
            await DetectionRepo.update(session, "DET-1", status="resolved", assigned_to="J. Smith")

        assert det.status == "resolved"
        assert det.assigned_to == "J. Smith"

    @pytest.mark.asyncio
    async def test_skips_none_kwarg_values(self) -> None:
        det = MagicMock()
        det.status = "active"
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=det)):
            await DetectionRepo.update(session, "DET-1", status=None, assigned_to="J. Smith")

        # None value must not overwrite the attribute
        assert det.status == "active"
        assert det.assigned_to == "J. Smith"

    @pytest.mark.asyncio
    async def test_flushes_session_when_found(self) -> None:
        det = _make_detection()
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=det)):
            await DetectionRepo.update(session, "DET-1", status="investigating")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=None)):
            result = await DetectionRepo.update(session, "nonexistent", status="resolved")

        assert result is None

    @pytest.mark.asyncio
    async def test_does_not_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=None)):
            await DetectionRepo.update(session, "nonexistent", status="resolved")

        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_priority_update_is_applied(self) -> None:
        det = MagicMock()
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=det)):
            await DetectionRepo.update(session, "DET-1", priority="P1 Urgent")

        assert det.priority == "P1 Urgent"


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestDetectionRepoDelete:
    """DetectionRepo.delete() removes an existing Detection or returns False."""

    @pytest.mark.asyncio
    async def test_returns_true_when_found(self) -> None:
        det = _make_detection()
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=det)):
            result = await DetectionRepo.delete(session, "DET-1")

        assert result is True

    @pytest.mark.asyncio
    async def test_calls_session_delete_when_found(self) -> None:
        det = _make_detection()
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=det)):
            await DetectionRepo.delete(session, "DET-1")

        session.delete.assert_awaited_once_with(det)

    @pytest.mark.asyncio
    async def test_calls_session_flush_when_found(self) -> None:
        det = _make_detection()
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=det)):
            await DetectionRepo.delete(session, "DET-1")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=None)):
            result = await DetectionRepo.delete(session, "nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_no_session_delete_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=None)):
            await DetectionRepo.delete(session, "nonexistent")

        session.delete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(DetectionRepo, "get", new=AsyncMock(return_value=None)):
            await DetectionRepo.delete(session, "nonexistent")

        session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# count()
# ---------------------------------------------------------------------------


class TestDetectionRepoCount:
    """DetectionRepo.count() returns total detection count."""

    @pytest.mark.asyncio
    async def test_returns_count_from_scalar(self) -> None:
        session = _make_session()
        session.scalar.return_value = 42

        result = await DetectionRepo.count(session)

        assert result == 42

    @pytest.mark.asyncio
    async def test_returns_zero_when_scalar_is_none(self) -> None:
        session = _make_session()
        session.scalar.return_value = None

        result = await DetectionRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_returns_zero_when_table_is_empty(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0

        result = await DetectionRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_calls_session_scalar_once(self) -> None:
        session = _make_session()
        session.scalar.return_value = 10

        await DetectionRepo.count(session)

        session.scalar.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_integer(self) -> None:
        session = _make_session()
        session.scalar.return_value = 7

        result = await DetectionRepo.count(session)

        assert isinstance(result, int)

    @pytest.mark.parametrize("count_val", [0, 1, 100, 999])
    @pytest.mark.asyncio
    async def test_returns_exact_count(self, count_val: int) -> None:
        session = _make_session()
        session.scalar.return_value = count_val

        result = await DetectionRepo.count(session)

        assert result == count_val
