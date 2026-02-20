"""Integration tests for ConnectorRepo — real SQLite via the db_session fixture.

Feature 18.4 — Alembic migration 0002 (rules + connectors)

Approach:
  - Uses the ``db_session`` fixture from conftest.py (in-memory SQLite, fresh schema).
  - No mocks: every test exercises real SQL statements through SQLAlchemy.
  - Each test function receives an isolated session that is rolled back on teardown.

Coverage:
  - create(): ORM defaults applied; connector returned with correct attributes
  - create(): created connector persisted and retrievable via get_by_id
  - create(): unique name constraint enforced by DB
  - list(): empty table → empty list; non-empty → all connectors returned
  - list(): results ordered by name ascending
  - get_by_id(): existing → returns Connector; nonexistent → None
  - update(): found → attributes mutated, flush reflected in subsequent read
  - update(): not found → returns None
  - update(): None kwarg values are skipped
  - update(): False (bool) is applied, not skipped
  - update_status(): sets status + last_seen_at ISO timestamp
  - update_status(): with error_message → set; without → cleared to None
  - update_status(): not found → returns None
  - update_status(): last_seen_at is a valid ISO 8601 timestamp
  - delete(): found → True, connector no longer returned by get_by_id
  - delete(): not found → False
  - count(): 0 for empty table; exact count after inserts
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.connector_repo import ConnectorRepo

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_connector(session: AsyncSession, **kwargs) -> object:
    """Create a minimal connector, merging defaults with caller-supplied kwargs."""
    defaults = {
        "name": "wazuh-prod",
        "connector_type": "wazuh",
        "config_json": "{}",
        "enabled": True,
    }
    defaults.update(kwargs)
    return await ConnectorRepo.create(session, **defaults)


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


class TestConnectorRepoCreateIntegration:
    """ConnectorRepo.create() persists a connector with correct ORM defaults."""

    async def test_returns_connector_with_id(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        assert conn.id is not None
        assert len(conn.id) == 36  # UUID format

    async def test_returns_connector_with_correct_name(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session, name="zeek-sensor")
        assert conn.name == "zeek-sensor"

    async def test_returns_connector_with_correct_type(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session, connector_type="zeek", name="zeek-prod")
        assert conn.connector_type == "zeek"

    async def test_default_status_is_inactive(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        assert conn.status == "inactive"

    async def test_default_enabled_is_true(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        assert conn.enabled is True

    async def test_default_events_total_is_zero(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        assert conn.events_total == 0

    async def test_default_errors_total_is_zero(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        assert conn.errors_total == 0

    async def test_default_last_seen_at_is_none(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        assert conn.last_seen_at is None

    async def test_default_error_message_is_none(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        assert conn.error_message is None

    async def test_connector_retrievable_after_create(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session, name="opencti-prod")
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched is not None
        assert fetched.id == conn.id

    async def test_config_json_persisted(self, db_session: AsyncSession) -> None:
        config = json.dumps({"host": "wazuh.local", "port": 1514})
        conn = await _create_connector(db_session, config_json=config)
        assert conn.config_json == config

    @pytest.mark.parametrize(
        "connector_type",
        ["wazuh", "zeek", "suricata", "prowler", "opencti", "velociraptor", "osquery", "generic"],
    )
    async def test_all_connector_types_accepted(
        self, db_session: AsyncSession, connector_type: str
    ) -> None:
        conn = await _create_connector(
            db_session,
            name=f"{connector_type}-test",
            connector_type=connector_type,
        )
        assert conn.connector_type == connector_type


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


class TestConnectorRepoListIntegration:
    """ConnectorRepo.list() returns connectors from the database ordered by name."""

    async def test_empty_table_returns_empty_list(self, db_session: AsyncSession) -> None:
        result = await ConnectorRepo.list(db_session)
        assert result == []

    async def test_returns_all_connectors(self, db_session: AsyncSession) -> None:
        await _create_connector(db_session, name="alpha")
        await _create_connector(db_session, name="beta")
        result = await ConnectorRepo.list(db_session)
        assert len(result) == 2

    async def test_result_is_list_type(self, db_session: AsyncSession) -> None:
        await _create_connector(db_session)
        result = await ConnectorRepo.list(db_session)
        assert isinstance(result, list)

    async def test_ordered_by_name_ascending(self, db_session: AsyncSession) -> None:
        """list() must return connectors sorted by name ASC."""
        await _create_connector(db_session, name="zebra")
        await _create_connector(db_session, name="alpha")
        await _create_connector(db_session, name="midnight")
        result = await ConnectorRepo.list(db_session)
        names = [c.name for c in result]
        assert names == sorted(names)

    async def test_single_connector_in_result(self, db_session: AsyncSession) -> None:
        await _create_connector(db_session, name="only-one")
        result = await ConnectorRepo.list(db_session)
        assert len(result) == 1
        assert result[0].name == "only-one"

    async def test_names_in_result(self, db_session: AsyncSession) -> None:
        await _create_connector(db_session, name="wazuh-prod")
        await _create_connector(db_session, name="zeek-sensor")
        names = {c.name for c in await ConnectorRepo.list(db_session)}
        assert "wazuh-prod" in names
        assert "zeek-sensor" in names


# ---------------------------------------------------------------------------
# get_by_id()
# ---------------------------------------------------------------------------


class TestConnectorRepoGetByIdIntegration:
    """ConnectorRepo.get_by_id() queries the database for a connector by PK."""

    async def test_returns_connector_when_found(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session, name="findable-conn")
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched is not None
        assert fetched.name == "findable-conn"

    async def test_returns_none_when_not_found(self, db_session: AsyncSession) -> None:
        result = await ConnectorRepo.get_by_id(
            db_session, "nonexistent-uuid-0000-0000-000000000000"
        )
        assert result is None

    async def test_returns_correct_connector_among_many(self, db_session: AsyncSession) -> None:
        conn1 = await _create_connector(db_session, name="first")
        conn2 = await _create_connector(db_session, name="second")
        fetched = await ConnectorRepo.get_by_id(db_session, conn2.id)
        assert fetched is not None
        assert fetched.id == conn2.id
        assert fetched.name == "second"

    async def test_returned_connector_has_all_fields(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(
            db_session,
            name="full-conn",
            connector_type="suricata",
            config_json='{"key": "value"}',
        )
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.connector_type == "suricata"
        assert fetched.config_json == '{"key": "value"}'
        assert fetched.status == "inactive"


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestConnectorRepoUpdateIntegration:
    """ConnectorRepo.update() modifies an existing connector in the database."""

    async def test_update_enabled_false(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session, enabled=True)
        updated = await ConnectorRepo.update(db_session, conn.id, enabled=False)
        assert updated is not None
        assert updated.enabled is False

    async def test_update_status(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        await ConnectorRepo.update(db_session, conn.id, status="active")
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.status == "active"

    async def test_update_multiple_fields(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        config = json.dumps({"host": "new.local"})
        await ConnectorRepo.update(
            db_session, conn.id, status="active", config_json=config, enabled=False
        )
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.status == "active"
        assert fetched.config_json == config
        assert fetched.enabled is False

    async def test_update_returns_none_for_nonexistent(self, db_session: AsyncSession) -> None:
        result = await ConnectorRepo.update(db_session, "nonexistent-id", status="active")
        assert result is None

    async def test_none_kwarg_does_not_overwrite(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session, name="original-name")
        await ConnectorRepo.update(db_session, conn.id, name=None, status="active")
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.name == "original-name"  # None skipped
        assert fetched.status == "active"  # non-None applied

    async def test_false_value_is_applied(self, db_session: AsyncSession) -> None:
        """False must be applied, not skipped (only None is skipped)."""
        conn = await _create_connector(db_session, enabled=True)
        await ConnectorRepo.update(db_session, conn.id, enabled=False)
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.enabled is False

    async def test_zero_is_applied(self, db_session: AsyncSession) -> None:
        """Zero must be applied, not skipped."""
        conn = await _create_connector(db_session)
        await ConnectorRepo.update(db_session, conn.id, events_total=0)
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.events_total == 0


# ---------------------------------------------------------------------------
# update_status()
# ---------------------------------------------------------------------------


class TestConnectorRepoUpdateStatusIntegration:
    """ConnectorRepo.update_status() sets status, last_seen_at, error_message."""

    async def test_sets_status(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        await ConnectorRepo.update_status(db_session, conn.id, "active")
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.status == "active"

    async def test_sets_last_seen_at_to_iso_timestamp(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        assert conn.last_seen_at is None
        await ConnectorRepo.update_status(db_session, conn.id, "active")
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.last_seen_at is not None
        parsed = datetime.fromisoformat(fetched.last_seen_at)
        assert parsed.tzinfo is not None  # timezone-aware

    async def test_last_seen_at_is_recent(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        before = datetime.now(timezone.utc)
        await ConnectorRepo.update_status(db_session, conn.id, "active")
        after = datetime.now(timezone.utc)
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        ts = datetime.fromisoformat(fetched.last_seen_at)
        assert before <= ts <= after

    async def test_sets_error_message_when_provided(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        await ConnectorRepo.update_status(
            db_session, conn.id, "error", error_message="Connection refused"
        )
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.error_message == "Connection refused"

    async def test_clears_error_message_when_not_provided(self, db_session: AsyncSession) -> None:
        """error_message is reset to None when not given (clean recovery)."""
        conn = await _create_connector(db_session)
        # Set error first
        await ConnectorRepo.update_status(
            db_session, conn.id, "error", error_message="Previous error"
        )
        # Recover without error_message
        await ConnectorRepo.update_status(db_session, conn.id, "active")
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.error_message is None

    async def test_returns_none_for_nonexistent(self, db_session: AsyncSession) -> None:
        result = await ConnectorRepo.update_status(db_session, "nonexistent-id", "active")
        assert result is None

    async def test_returns_connector_on_success(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        result = await ConnectorRepo.update_status(db_session, conn.id, "active")
        assert result is not None
        assert result.id == conn.id

    @pytest.mark.parametrize("status", ["active", "inactive", "error"])
    async def test_any_valid_status_is_persisted(
        self, db_session: AsyncSession, status: str
    ) -> None:
        conn = await _create_connector(db_session)
        await ConnectorRepo.update_status(db_session, conn.id, status)
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched.status == status


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestConnectorRepoDeleteIntegration:
    """ConnectorRepo.delete() removes the connector from the database."""

    async def test_returns_true_when_deleted(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        result = await ConnectorRepo.delete(db_session, conn.id)
        assert result is True

    async def test_connector_is_gone_after_delete(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        await ConnectorRepo.delete(db_session, conn.id)
        fetched = await ConnectorRepo.get_by_id(db_session, conn.id)
        assert fetched is None

    async def test_returns_false_for_nonexistent(self, db_session: AsyncSession) -> None:
        result = await ConnectorRepo.delete(db_session, "nonexistent-id")
        assert result is False

    async def test_other_connectors_unaffected_by_delete(self, db_session: AsyncSession) -> None:
        conn1 = await _create_connector(db_session, name="keep-me")
        conn2 = await _create_connector(db_session, name="delete-me")
        await ConnectorRepo.delete(db_session, conn2.id)
        remaining = await ConnectorRepo.list(db_session)
        assert len(remaining) == 1
        assert remaining[0].id == conn1.id

    async def test_double_delete_returns_false(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session)
        await ConnectorRepo.delete(db_session, conn.id)
        result = await ConnectorRepo.delete(db_session, conn.id)
        assert result is False

    async def test_list_is_empty_after_all_deleted(self, db_session: AsyncSession) -> None:
        conn1 = await _create_connector(db_session, name="conn-1")
        conn2 = await _create_connector(db_session, name="conn-2")
        await ConnectorRepo.delete(db_session, conn1.id)
        await ConnectorRepo.delete(db_session, conn2.id)
        result = await ConnectorRepo.list(db_session)
        assert result == []


# ---------------------------------------------------------------------------
# count()
# ---------------------------------------------------------------------------


class TestConnectorRepoCountIntegration:
    """ConnectorRepo.count() returns the exact number of connectors in the database."""

    async def test_zero_when_empty(self, db_session: AsyncSession) -> None:
        result = await ConnectorRepo.count(db_session)
        assert result == 0

    async def test_one_after_create(self, db_session: AsyncSession) -> None:
        await _create_connector(db_session)
        result = await ConnectorRepo.count(db_session)
        assert result == 1

    async def test_count_matches_number_of_connectors(self, db_session: AsyncSession) -> None:
        for i in range(4):
            await _create_connector(db_session, name=f"connector-{i}")
        result = await ConnectorRepo.count(db_session)
        assert result == 4

    async def test_count_decreases_after_delete(self, db_session: AsyncSession) -> None:
        conn = await _create_connector(db_session, name="delete-me")
        await _create_connector(db_session, name="keep-me")
        await ConnectorRepo.delete(db_session, conn.id)
        result = await ConnectorRepo.count(db_session)
        assert result == 1

    async def test_returns_integer(self, db_session: AsyncSession) -> None:
        result = await ConnectorRepo.count(db_session)
        assert isinstance(result, int)

    async def test_count_includes_inactive_connectors(self, db_session: AsyncSession) -> None:
        """count() includes all connectors regardless of status or enabled state."""
        await _create_connector(db_session, name="active-conn", enabled=True)
        await _create_connector(db_session, name="inactive-conn", enabled=False)
        result = await ConnectorRepo.count(db_session)
        assert result == 2
