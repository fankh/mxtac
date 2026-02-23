"""Tests for IncidentRepo — async DB operations for the incidents table.

Feature 26.2 — IncidentRepo repository layer

Approach:
  - All session interactions are mocked (no live DB needed)
  - AsyncMock used for awaitable session methods (execute, flush, scalar, delete)
  - MagicMock used for synchronous session methods (add)
  - IncidentRepo.get_by_id is patched internally for methods that call it (update, delete)

Coverage:
  - list(): returns (items, total) from session.execute/scalar
  - list(): no filters — two calls (scalar for count + execute for data)
  - list(): severity filter accepted without error
  - list(): status filter accepted without error
  - list(): assigned_to filter accepted without error
  - list(): search filter accepted without error
  - list(): sort=severity accepted without error
  - list(): sort=status accepted without error
  - list(): default sort (created_at desc) accepted without error
  - list(): all filters combined do not raise
  - list(): empty result returns ([], 0)
  - list(): None total scalar maps to 0
  - get_by_id(): found → returns Incident
  - get_by_id(): not found → returns None
  - get_by_id(): calls session.execute once
  - create(): returns Incident instance
  - create(): calls session.add once
  - create(): calls session.flush once
  - create(): added object is an Incident
  - create(): returned Incident has correct field values
  - update(): found → sets attributes, flushes, returns Incident
  - update(): not found → returns None without flush
  - update(): None kwarg values are skipped
  - update(): flushes session when found
  - update(): does not flush when not found
  - delete(): found → calls session.delete + flush, returns True
  - delete(): not found → returns False
  - delete(): calls session.delete with correct object when found
  - delete(): no session.delete when not found
  - delete(): no flush when not found
  - count(): returns scalar result
  - count(): None scalar maps to 0
  - count(): returns integer
  - get_by_detection(): returns list from session.execute
  - get_by_detection(): returns empty list when none found
  - get_by_detection(): calls session.execute once
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.repositories.incident_repo import IncidentRepo


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


def _make_incident(**kwargs) -> MagicMock:
    """Minimal Incident-like mock."""
    inc = MagicMock()
    inc.id = kwargs.get("id", 1)
    inc.title = kwargs.get("title", "Ransomware Detected on WS-01")
    inc.description = kwargs.get("description", "Critical ransomware activity observed.")
    inc.severity = kwargs.get("severity", "critical")
    inc.status = kwargs.get("status", "new")
    inc.priority = kwargs.get("priority", 1)
    inc.assigned_to = kwargs.get("assigned_to", None)
    inc.created_by = kwargs.get("created_by", "analyst1")
    inc.detection_ids = kwargs.get("detection_ids", [])
    return inc


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


class TestIncidentRepoList:
    """IncidentRepo.list() returns (items, total) with filtering and pagination."""

    @pytest.mark.asyncio
    async def test_returns_tuple_of_list_and_int(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([_make_incident()])

        result = await IncidentRepo.list(session)

        assert isinstance(result, tuple)
        assert isinstance(result[0], list)
        assert isinstance(result[1], int)

    @pytest.mark.asyncio
    async def test_returns_items_and_total(self) -> None:
        inc = _make_incident(id=1)
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([inc])

        items, total = await IncidentRepo.list(session)

        assert items == [inc]
        assert total == 1

    @pytest.mark.asyncio
    async def test_empty_result_returns_empty_list_and_zero(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(session)

        assert items == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_none_scalar_maps_to_zero_total(self) -> None:
        session = _make_session()
        session.scalar.return_value = None
        session.execute.return_value = _scalars_result([])

        _, total = await IncidentRepo.list(session)

        assert total == 0

    @pytest.mark.asyncio
    async def test_calls_execute_for_data(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        await IncidentRepo.list(session)

        session.execute.assert_awaited()

    @pytest.mark.asyncio
    async def test_calls_scalar_for_count(self) -> None:
        session = _make_session()
        session.scalar.return_value = 3
        session.execute.return_value = _scalars_result([])

        await IncidentRepo.list(session)

        session.scalar.assert_awaited()

    @pytest.mark.asyncio
    async def test_returns_multiple_incidents(self) -> None:
        incs = [_make_incident(id=i) for i in range(5)]
        session = _make_session()
        session.scalar.return_value = 5
        session.execute.return_value = _scalars_result(incs)

        items, total = await IncidentRepo.list(session)

        assert len(items) == 5
        assert total == 5

    @pytest.mark.asyncio
    async def test_severity_filter_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(session, severity=["critical", "high"])

        assert items == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_status_filter_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(session, status=["new", "investigating"])

        assert items == []

    @pytest.mark.asyncio
    async def test_assigned_to_filter_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(session, assigned_to="analyst1")

        assert items == []

    @pytest.mark.asyncio
    async def test_search_filter_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(session, search="ransomware")

        assert items == []

    @pytest.mark.asyncio
    async def test_sort_severity_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(session, sort="severity")

        assert items == []

    @pytest.mark.asyncio
    async def test_sort_status_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(session, sort="status")

        assert items == []

    @pytest.mark.asyncio
    async def test_default_sort_created_at_does_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(session, sort="created_at")

        assert items == []

    @pytest.mark.asyncio
    async def test_all_filters_combined_do_not_raise(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(
            session,
            skip=0,
            limit=10,
            severity=["critical"],
            status=["new"],
            assigned_to="analyst1",
            search="lateral movement",
            sort="severity",
        )

        assert items == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_skip_and_limit_accepted(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await IncidentRepo.list(session, skip=10, limit=5)

        assert items == []


# ---------------------------------------------------------------------------
# get_by_id()
# ---------------------------------------------------------------------------


class TestIncidentRepoGetById:
    """IncidentRepo.get_by_id() returns an Incident or None."""

    @pytest.mark.asyncio
    async def test_returns_incident_when_found(self) -> None:
        inc = _make_incident(id=42)
        session = _make_session()
        session.execute.return_value = _scalar_one_result(inc)

        result = await IncidentRepo.get_by_id(session, 42)

        assert result is inc

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await IncidentRepo.get_by_id(session, 999)

        assert result is None

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await IncidentRepo.get_by_id(session, 1)

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


class TestIncidentRepoCreate:
    """IncidentRepo.create() constructs and persists an Incident."""

    @pytest.mark.asyncio
    async def test_returns_incident_instance(self) -> None:
        from app.models.incident import Incident
        session = _make_session()

        result = await IncidentRepo.create(
            session,
            title="Lateral Movement Detected",
            severity="high",
            status="new",
            priority=2,
            created_by="analyst1",
        )

        assert isinstance(result, Incident)

    @pytest.mark.asyncio
    async def test_calls_session_add(self) -> None:
        session = _make_session()

        await IncidentRepo.create(
            session,
            title="Credential Dumping",
            severity="critical",
            status="new",
            priority=1,
            created_by="analyst2",
        )

        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_calls_session_flush(self) -> None:
        session = _make_session()

        await IncidentRepo.create(
            session,
            title="Phishing Campaign",
            severity="medium",
            status="new",
            priority=3,
            created_by="analyst1",
        )

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_added_object_is_incident(self) -> None:
        from app.models.incident import Incident
        session = _make_session()

        await IncidentRepo.create(
            session,
            title="Data Exfiltration",
            severity="critical",
            status="new",
            priority=1,
            created_by="soc-lead",
        )

        added = session.add.call_args[0][0]
        assert isinstance(added, Incident)

    @pytest.mark.asyncio
    async def test_created_incident_has_correct_title(self) -> None:
        session = _make_session()

        result = await IncidentRepo.create(
            session,
            title="Ransomware Execution",
            severity="critical",
            status="new",
            priority=1,
            created_by="analyst1",
        )

        assert result.title == "Ransomware Execution"

    @pytest.mark.asyncio
    async def test_created_incident_has_correct_severity(self) -> None:
        session = _make_session()

        result = await IncidentRepo.create(
            session,
            title="Brute Force Attack",
            severity="high",
            status="new",
            priority=2,
            created_by="analyst3",
        )

        assert result.severity == "high"

    @pytest.mark.asyncio
    async def test_created_incident_has_correct_created_by(self) -> None:
        session = _make_session()

        result = await IncidentRepo.create(
            session,
            title="Insider Threat",
            severity="medium",
            status="new",
            priority=3,
            created_by="sec-admin",
        )

        assert result.created_by == "sec-admin"


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestIncidentRepoUpdate:
    """IncidentRepo.update() modifies an existing Incident or returns None."""

    @pytest.mark.asyncio
    async def test_returns_updated_incident_when_found(self) -> None:
        inc = _make_incident(id=1, status="new")
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=inc)):
            result = await IncidentRepo.update(session, 1, status="investigating")

        assert result is inc

    @pytest.mark.asyncio
    async def test_sets_attribute_on_incident(self) -> None:
        inc = MagicMock()
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=inc)):
            await IncidentRepo.update(session, 1, status="contained", assigned_to="analyst2")

        assert inc.status == "contained"
        assert inc.assigned_to == "analyst2"

    @pytest.mark.asyncio
    async def test_skips_none_kwarg_values(self) -> None:
        inc = MagicMock()
        inc.status = "new"
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=inc)):
            await IncidentRepo.update(session, 1, status=None, assigned_to="analyst2")

        # None value must not overwrite the existing attribute
        assert inc.status == "new"
        assert inc.assigned_to == "analyst2"

    @pytest.mark.asyncio
    async def test_flushes_session_when_found(self) -> None:
        inc = _make_incident()
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=inc)):
            await IncidentRepo.update(session, 1, status="investigating")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await IncidentRepo.update(session, 999, status="resolved")

        assert result is None

    @pytest.mark.asyncio
    async def test_does_not_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await IncidentRepo.update(session, 999, status="resolved")

        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_severity_update_is_applied(self) -> None:
        inc = MagicMock()
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=inc)):
            await IncidentRepo.update(session, 1, severity="low")

        assert inc.severity == "low"

    @pytest.mark.asyncio
    async def test_priority_update_is_applied(self) -> None:
        inc = MagicMock()
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=inc)):
            await IncidentRepo.update(session, 1, priority=1)

        assert inc.priority == 1


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestIncidentRepoDelete:
    """IncidentRepo.delete() removes an existing Incident or returns False."""

    @pytest.mark.asyncio
    async def test_returns_true_when_found(self) -> None:
        inc = _make_incident()
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=inc)):
            result = await IncidentRepo.delete(session, 1)

        assert result is True

    @pytest.mark.asyncio
    async def test_calls_session_delete_when_found(self) -> None:
        inc = _make_incident()
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=inc)):
            await IncidentRepo.delete(session, 1)

        session.delete.assert_awaited_once_with(inc)

    @pytest.mark.asyncio
    async def test_calls_session_flush_when_found(self) -> None:
        inc = _make_incident()
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=inc)):
            await IncidentRepo.delete(session, 1)

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await IncidentRepo.delete(session, 999)

        assert result is False

    @pytest.mark.asyncio
    async def test_no_session_delete_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await IncidentRepo.delete(session, 999)

        session.delete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(IncidentRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await IncidentRepo.delete(session, 999)

        session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# count()
# ---------------------------------------------------------------------------


class TestIncidentRepoCount:
    """IncidentRepo.count() returns total incident count."""

    @pytest.mark.asyncio
    async def test_returns_count_from_scalar(self) -> None:
        session = _make_session()
        session.scalar.return_value = 17

        result = await IncidentRepo.count(session)

        assert result == 17

    @pytest.mark.asyncio
    async def test_returns_zero_when_scalar_is_none(self) -> None:
        session = _make_session()
        session.scalar.return_value = None

        result = await IncidentRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_returns_zero_when_table_is_empty(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0

        result = await IncidentRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_calls_session_scalar_once(self) -> None:
        session = _make_session()
        session.scalar.return_value = 5

        await IncidentRepo.count(session)

        session.scalar.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_integer(self) -> None:
        session = _make_session()
        session.scalar.return_value = 3

        result = await IncidentRepo.count(session)

        assert isinstance(result, int)

    @pytest.mark.parametrize("count_val", [0, 1, 50, 1000])
    @pytest.mark.asyncio
    async def test_returns_exact_count(self, count_val: int) -> None:
        session = _make_session()
        session.scalar.return_value = count_val

        result = await IncidentRepo.count(session)

        assert result == count_val


# ---------------------------------------------------------------------------
# get_by_detection()
# ---------------------------------------------------------------------------


class TestIncidentRepoGetByDetection:
    """IncidentRepo.get_by_detection() returns incidents linked to a detection."""

    @pytest.mark.asyncio
    async def test_returns_list(self) -> None:
        inc = _make_incident(detection_ids=["DET-001"])
        session = _make_session()
        session.execute.return_value = _scalars_result([inc])

        result = await IncidentRepo.get_by_detection(session, "DET-001")

        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_returns_matching_incidents(self) -> None:
        inc = _make_incident(id=1, detection_ids=["DET-001"])
        session = _make_session()
        session.execute.return_value = _scalars_result([inc])

        result = await IncidentRepo.get_by_detection(session, "DET-001")

        assert result == [inc]

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_none_found(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        result = await IncidentRepo.get_by_detection(session, "DET-GHOST")

        assert result == []

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        await IncidentRepo.get_by_detection(session, "DET-001")

        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_multiple_incidents_for_one_detection(self) -> None:
        incs = [_make_incident(id=i, detection_ids=["DET-001"]) for i in range(3)]
        session = _make_session()
        session.execute.return_value = _scalars_result(incs)

        result = await IncidentRepo.get_by_detection(session, "DET-001")

        assert len(result) == 3
