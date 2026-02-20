"""Tests for ConnectorRepo — async DB operations for the connectors table.

Feature 18.4 — Alembic migration 0002 (rules + connectors)

Approach:
  - All session interactions are mocked (no live DB needed)
  - AsyncMock used for awaitable session methods (execute, flush, scalar)
  - MagicMock used for synchronous session methods (add)
  - get_by_id is patched internally for methods that call it (update, update_status, delete)

Coverage:
  - list(): returns all connectors ordered by name, session.execute called once
  - list(): empty result returns empty list
  - get_by_id(): found → returns Connector; not found → returns None
  - create(): Connector added to session, flushed, returned with correct attributes
  - update(): found → sets attributes, flushes, returns Connector
  - update(): not found → returns None without flush
  - update(): None kwarg values are skipped
  - update_status(): found → sets status, last_seen_at, error_message; flushes
  - update_status(): sets last_seen_at to a valid ISO timestamp
  - update_status(): with error_message → sets error_message
  - update_status(): without error_message → sets error_message to None
  - update_status(): not found → returns None
  - delete(): found → deletes, flushes, returns True
  - delete(): not found → returns False without delete/flush
  - count(): returns scalar result; None result → 0
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.repositories.connector_repo import ConnectorRepo


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


def _make_connector(**kwargs) -> MagicMock:
    """Minimal Connector-like mock."""
    conn = MagicMock()
    conn.id = kwargs.get("id", "conn-abc")
    conn.name = kwargs.get("name", "wazuh-prod")
    conn.connector_type = kwargs.get("connector_type", "wazuh")
    conn.status = kwargs.get("status", "inactive")
    conn.enabled = kwargs.get("enabled", True)
    conn.error_message = kwargs.get("error_message", None)
    conn.last_seen_at = kwargs.get("last_seen_at", None)
    return conn


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


class TestConnectorRepoList:
    """ConnectorRepo.list() returns connectors from session.execute."""

    @pytest.mark.asyncio
    async def test_returns_all_connectors(self) -> None:
        c1 = _make_connector(id="c1", name="opencti")
        c2 = _make_connector(id="c2", name="wazuh")
        session = _make_session()
        session.execute.return_value = _scalars_result([c1, c2])

        result = await ConnectorRepo.list(session)

        assert result == [c1, c2]

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        await ConnectorRepo.list(session)

        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_no_connectors(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        result = await ConnectorRepo.list(session)

        assert result == []

    @pytest.mark.asyncio
    async def test_result_is_list_type(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([_make_connector()])

        result = await ConnectorRepo.list(session)

        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_returns_multiple_connectors(self) -> None:
        connectors = [_make_connector(id=f"c{i}") for i in range(4)]
        session = _make_session()
        session.execute.return_value = _scalars_result(connectors)

        result = await ConnectorRepo.list(session)

        assert len(result) == 4


# ---------------------------------------------------------------------------
# get_by_id()
# ---------------------------------------------------------------------------


class TestConnectorRepoGetById:
    """ConnectorRepo.get_by_id() returns a Connector or None."""

    @pytest.mark.asyncio
    async def test_returns_connector_when_found(self) -> None:
        conn = _make_connector(id="conn-1")
        session = _make_session()
        session.execute.return_value = _scalar_one_result(conn)

        result = await ConnectorRepo.get_by_id(session, "conn-1")

        assert result is conn

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await ConnectorRepo.get_by_id(session, "nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await ConnectorRepo.get_by_id(session, "conn-1")

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


class TestConnectorRepoCreate:
    """ConnectorRepo.create() constructs and persists a Connector."""

    @pytest.mark.asyncio
    async def test_returns_connector_instance(self) -> None:
        session = _make_session()

        result = await ConnectorRepo.create(
            session,
            id="conn-new",
            name="zeek-sensor",
            connector_type="zeek",
        )

        assert result is not None

    @pytest.mark.asyncio
    async def test_calls_session_add(self) -> None:
        session = _make_session()

        await ConnectorRepo.create(session, name="test", connector_type="generic")

        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_calls_session_flush(self) -> None:
        session = _make_session()

        await ConnectorRepo.create(session, name="test", connector_type="generic")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_created_connector_has_correct_name(self) -> None:
        session = _make_session()

        result = await ConnectorRepo.create(
            session, name="suricata-ids", connector_type="suricata"
        )

        assert result.name == "suricata-ids"

    @pytest.mark.asyncio
    async def test_created_connector_has_correct_type(self) -> None:
        session = _make_session()

        result = await ConnectorRepo.create(
            session, name="velociraptor-hunt", connector_type="velociraptor"
        )

        assert result.connector_type == "velociraptor"

    @pytest.mark.asyncio
    async def test_add_receives_connector_object(self) -> None:
        from app.models.connector import Connector
        session = _make_session()

        await ConnectorRepo.create(session, name="test", connector_type="generic")

        added = session.add.call_args[0][0]
        assert isinstance(added, Connector)


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestConnectorRepoUpdate:
    """ConnectorRepo.update() modifies an existing Connector or returns None."""

    @pytest.mark.asyncio
    async def test_returns_updated_connector_when_found(self) -> None:
        conn = _make_connector(id="conn-1")
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            result = await ConnectorRepo.update(session, "conn-1", name="Updated Name")

        assert result is conn

    @pytest.mark.asyncio
    async def test_sets_attribute_on_connector(self) -> None:
        conn = MagicMock()
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update(session, "conn-1", name="New Name", status="active")

        assert conn.name == "New Name"
        assert conn.status == "active"

    @pytest.mark.asyncio
    async def test_skips_none_kwarg_values(self) -> None:
        conn = MagicMock()
        conn.name = "Original Name"
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update(session, "conn-1", name=None, status="active")

        # None values must not overwrite the attribute
        assert conn.name == "Original Name"
        assert conn.status == "active"

    @pytest.mark.asyncio
    async def test_flushes_session_when_found(self) -> None:
        conn = _make_connector()
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update(session, "conn-1", status="active")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await ConnectorRepo.update(session, "nonexistent", status="active")

        assert result is None

    @pytest.mark.asyncio
    async def test_does_not_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await ConnectorRepo.update(session, "nonexistent", status="active")

        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_false_value_is_not_skipped(self) -> None:
        """False is not None — it must be set, not skipped."""
        conn = MagicMock()
        conn.enabled = True
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update(session, "conn-1", enabled=False)

        assert conn.enabled is False


# ---------------------------------------------------------------------------
# update_status()
# ---------------------------------------------------------------------------


class TestConnectorRepoUpdateStatus:
    """ConnectorRepo.update_status() sets status, last_seen_at, error_message."""

    @pytest.mark.asyncio
    async def test_returns_connector_when_found(self) -> None:
        conn = _make_connector(id="conn-1")
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            result = await ConnectorRepo.update_status(session, "conn-1", "active")

        assert result is conn

    @pytest.mark.asyncio
    async def test_sets_status(self) -> None:
        conn = _make_connector(status="inactive")
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update_status(session, "conn-1", "active")

        assert conn.status == "active"

    @pytest.mark.asyncio
    async def test_sets_last_seen_at_to_iso_timestamp(self) -> None:
        conn = _make_connector(last_seen_at=None)
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update_status(session, "conn-1", "active")

        # last_seen_at should be a valid ISO 8601 timestamp
        assert conn.last_seen_at is not None
        parsed = datetime.fromisoformat(conn.last_seen_at)
        assert parsed.tzinfo is not None  # timezone-aware

    @pytest.mark.asyncio
    async def test_last_seen_at_is_recent(self) -> None:
        conn = _make_connector()
        session = _make_session()

        before = datetime.now(timezone.utc)
        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update_status(session, "conn-1", "active")
        after = datetime.now(timezone.utc)

        ts = datetime.fromisoformat(conn.last_seen_at)
        assert before <= ts <= after

    @pytest.mark.asyncio
    async def test_sets_error_message_when_provided(self) -> None:
        conn = _make_connector(error_message=None)
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update_status(
                session, "conn-1", "error", error_message="Connection refused"
            )

        assert conn.error_message == "Connection refused"

    @pytest.mark.asyncio
    async def test_sets_error_message_to_none_when_not_provided(self) -> None:
        conn = _make_connector(error_message="Previous error")
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update_status(session, "conn-1", "active")

        assert conn.error_message is None

    @pytest.mark.asyncio
    async def test_flushes_session_when_found(self) -> None:
        conn = _make_connector()
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.update_status(session, "conn-1", "active")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await ConnectorRepo.update_status(session, "nonexistent", "active")

        assert result is None

    @pytest.mark.asyncio
    async def test_does_not_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await ConnectorRepo.update_status(session, "nonexistent", "active")

        session.flush.assert_not_awaited()

    @pytest.mark.parametrize("status", ["active", "inactive", "error", "degraded"])
    @pytest.mark.asyncio
    async def test_accepts_any_status_string(self, status: str) -> None:
        conn = _make_connector()
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            result = await ConnectorRepo.update_status(session, "conn-1", status)

        assert conn.status == status
        assert result is conn


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestConnectorRepoDelete:
    """ConnectorRepo.delete() removes an existing Connector or returns False."""

    @pytest.mark.asyncio
    async def test_returns_true_when_found(self) -> None:
        conn = _make_connector()
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            result = await ConnectorRepo.delete(session, "conn-1")

        assert result is True

    @pytest.mark.asyncio
    async def test_calls_session_delete_when_found(self) -> None:
        conn = _make_connector()
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.delete(session, "conn-1")

        session.delete.assert_awaited_once_with(conn)

    @pytest.mark.asyncio
    async def test_calls_session_flush_when_found(self) -> None:
        conn = _make_connector()
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=conn)):
            await ConnectorRepo.delete(session, "conn-1")

        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=None)):
            result = await ConnectorRepo.delete(session, "nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_no_session_delete_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await ConnectorRepo.delete(session, "nonexistent")

        session.delete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_flush_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(ConnectorRepo, "get_by_id", new=AsyncMock(return_value=None)):
            await ConnectorRepo.delete(session, "nonexistent")

        session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# count()
# ---------------------------------------------------------------------------


class TestConnectorRepoCount:
    """ConnectorRepo.count() returns total connector count."""

    @pytest.mark.asyncio
    async def test_returns_count_from_scalar(self) -> None:
        session = _make_session()
        session.scalar.return_value = 8

        result = await ConnectorRepo.count(session)

        assert result == 8

    @pytest.mark.asyncio
    async def test_returns_zero_when_scalar_is_none(self) -> None:
        """None result from scalar (empty table) maps to 0."""
        session = _make_session()
        session.scalar.return_value = None

        result = await ConnectorRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_returns_zero_when_table_is_empty(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0

        result = await ConnectorRepo.count(session)

        assert result == 0

    @pytest.mark.asyncio
    async def test_calls_session_scalar_once(self) -> None:
        session = _make_session()
        session.scalar.return_value = 3

        await ConnectorRepo.count(session)

        session.scalar.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_integer(self) -> None:
        session = _make_session()
        session.scalar.return_value = 4

        result = await ConnectorRepo.count(session)

        assert isinstance(result, int)

    @pytest.mark.parametrize("count_val", [0, 1, 8, 100])
    @pytest.mark.asyncio
    async def test_returns_exact_count(self, count_val: int) -> None:
        session = _make_session()
        session.scalar.return_value = count_val

        result = await ConnectorRepo.count(session)

        assert result == count_val
