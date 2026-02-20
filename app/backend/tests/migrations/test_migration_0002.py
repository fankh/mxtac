"""Tests for Alembic migration 0002 — rules + connectors tables

Feature 18.4 — Alembic migration 0002 (rules + connectors)

Approach:
  - Migration metadata tested via direct attribute inspection
  - upgrade() / downgrade() tested by patching alembic.op and inspecting call args
  - ORM model schema verified via SQLAlchemy table inspection (no live DB needed)

Coverage:
  - Revision metadata: revision id, parent (0001), branch labels, dependencies
  - upgrade(): creates rules table before connectors table
  - upgrade(): rules table — all 20 columns with correct types, nullability, defaults
  - upgrade(): connectors table — all 12 columns with correct types, nullability, defaults
  - upgrade(): server defaults for rule_type, status, level, enabled, hit_count, fp_count
  - upgrade(): server defaults for config_json, status, enabled, events_total, errors_total
  - upgrade(): unique constraint on connectors.name, index on connectors.connector_type
  - downgrade(): drops connectors before rules (dependency-safe reverse order)
  - downgrade(): no extra operations (no create, no alter)
  - ORM Rule model table columns match the migration schema
  - ORM Connector model table columns match the migration schema
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest
import sqlalchemy as sa

# ---------------------------------------------------------------------------
# Migration module loader
# ---------------------------------------------------------------------------

_MIGRATION_PATH = (
    Path(__file__).parents[2] / "alembic" / "versions" / "0002_add_rules_connectors.py"
)


def _load_migration() -> ModuleType:
    """Load the migration module directly from disk (bypasses alembic package system)."""
    spec = importlib.util.spec_from_file_location("migration_0002", _MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


_migration = _load_migration()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_upgrade() -> MagicMock:
    """Patch alembic.op, run upgrade(), and return the mock for inspection."""
    mock_op = MagicMock()
    with patch.object(_migration, "op", mock_op):
        _migration.upgrade()
    return mock_op


def _run_downgrade() -> MagicMock:
    """Patch alembic.op, run downgrade(), and return the mock for inspection."""
    mock_op = MagicMock()
    with patch.object(_migration, "op", mock_op):
        _migration.downgrade()
    return mock_op


def _extract_columns(create_table_call) -> dict[str, sa.Column]:
    """Build a name→Column map from a create_table mock call's positional args."""
    return {
        col.name: col
        for col in create_table_call.args[1:]
        if isinstance(col, sa.Column)
    }


def _rules_columns() -> dict[str, sa.Column]:
    mock_op = _run_upgrade()
    rules_call = mock_op.create_table.call_args_list[0]
    return _extract_columns(rules_call)


def _connectors_columns() -> dict[str, sa.Column]:
    mock_op = _run_upgrade()
    connectors_call = mock_op.create_table.call_args_list[1]
    return _extract_columns(connectors_call)


# ---------------------------------------------------------------------------
# Migration metadata
# ---------------------------------------------------------------------------


class TestMigrationMetadata:
    """Module-level migration attributes are set correctly."""

    def test_revision_is_0002(self) -> None:
        assert _migration.revision == "0002"

    def test_down_revision_is_0001(self) -> None:
        """Migration 0002 descends from 0001."""
        assert _migration.down_revision == "0001"

    def test_branch_labels_is_none(self) -> None:
        assert _migration.branch_labels is None

    def test_depends_on_is_none(self) -> None:
        assert _migration.depends_on is None

    def test_module_exposes_upgrade_callable(self) -> None:
        assert callable(_migration.upgrade)

    def test_module_exposes_downgrade_callable(self) -> None:
        assert callable(_migration.downgrade)

    def test_migration_file_exists(self) -> None:
        assert _MIGRATION_PATH.exists()


# ---------------------------------------------------------------------------
# upgrade() — table creation order
# ---------------------------------------------------------------------------


class TestUpgradeTableOrder:
    """upgrade() creates exactly two tables in dependency-safe order."""

    def test_creates_exactly_two_tables(self) -> None:
        mock_op = _run_upgrade()
        assert mock_op.create_table.call_count == 2

    def test_rules_table_created_first(self) -> None:
        mock_op = _run_upgrade()
        first_name = mock_op.create_table.call_args_list[0].args[0]
        assert first_name == "rules"

    def test_connectors_table_created_second(self) -> None:
        mock_op = _run_upgrade()
        second_name = mock_op.create_table.call_args_list[1].args[0]
        assert second_name == "connectors"

    def test_no_drop_table_called_in_upgrade(self) -> None:
        mock_op = _run_upgrade()
        mock_op.drop_table.assert_not_called()

    def test_no_add_column_in_upgrade(self) -> None:
        mock_op = _run_upgrade()
        mock_op.add_column.assert_not_called()


# ---------------------------------------------------------------------------
# upgrade() — rules table schema
# ---------------------------------------------------------------------------


class TestRulesTableSchema:
    """upgrade() creates the rules table with the expected columns."""

    @pytest.fixture(scope="class")
    def cols(self) -> dict[str, sa.Column]:
        return _rules_columns()

    # Presence — all 20 columns
    @pytest.mark.parametrize(
        "col_name",
        [
            "id", "title", "description", "rule_type", "content",
            "status", "level", "enabled",
            "logsource_product", "logsource_category", "logsource_service",
            "technique_ids", "tactic_ids",
            "hit_count", "fp_count", "last_hit_at",
            "created_by", "source",
            "created_at", "updated_at",
        ],
    )
    def test_column_present(self, cols: dict, col_name: str) -> None:
        assert col_name in cols

    def test_total_column_count_is_20(self, cols: dict) -> None:
        assert len(cols) == 20

    # id
    def test_id_type_is_string_36(self, cols: dict) -> None:
        assert isinstance(cols["id"].type, sa.String)
        assert cols["id"].type.length == 36

    def test_id_is_primary_key(self, cols: dict) -> None:
        assert cols["id"].primary_key is True

    def test_id_is_not_nullable(self, cols: dict) -> None:
        assert cols["id"].nullable is False

    # title
    def test_title_type_is_string_500(self, cols: dict) -> None:
        assert isinstance(cols["title"].type, sa.String)
        assert cols["title"].type.length == 500

    def test_title_is_not_nullable(self, cols: dict) -> None:
        assert cols["title"].nullable is False

    # description
    def test_description_type_is_text(self, cols: dict) -> None:
        assert isinstance(cols["description"].type, sa.Text)

    def test_description_is_nullable(self, cols: dict) -> None:
        assert cols["description"].nullable is True

    # rule_type
    def test_rule_type_type_is_string_30(self, cols: dict) -> None:
        assert isinstance(cols["rule_type"].type, sa.String)
        assert cols["rule_type"].type.length == 30

    def test_rule_type_is_not_nullable(self, cols: dict) -> None:
        assert cols["rule_type"].nullable is False

    def test_rule_type_server_default_contains_sigma(self, cols: dict) -> None:
        sd = cols["rule_type"].server_default
        assert sd is not None
        assert "sigma" in str(sd.arg)

    # content
    def test_content_type_is_text(self, cols: dict) -> None:
        assert isinstance(cols["content"].type, sa.Text)

    def test_content_is_not_nullable(self, cols: dict) -> None:
        assert cols["content"].nullable is False

    # status
    def test_status_type_is_string_20(self, cols: dict) -> None:
        assert isinstance(cols["status"].type, sa.String)
        assert cols["status"].type.length == 20

    def test_status_is_not_nullable(self, cols: dict) -> None:
        assert cols["status"].nullable is False

    def test_status_server_default_contains_experimental(self, cols: dict) -> None:
        sd = cols["status"].server_default
        assert sd is not None
        assert "experimental" in str(sd.arg)

    # level
    def test_level_type_is_string_20(self, cols: dict) -> None:
        assert isinstance(cols["level"].type, sa.String)
        assert cols["level"].type.length == 20

    def test_level_is_not_nullable(self, cols: dict) -> None:
        assert cols["level"].nullable is False

    def test_level_server_default_contains_medium(self, cols: dict) -> None:
        sd = cols["level"].server_default
        assert sd is not None
        assert "medium" in str(sd.arg)

    # enabled
    def test_enabled_type_is_boolean(self, cols: dict) -> None:
        assert isinstance(cols["enabled"].type, sa.Boolean)

    def test_enabled_is_not_nullable(self, cols: dict) -> None:
        assert cols["enabled"].nullable is False

    def test_enabled_server_default_is_true(self, cols: dict) -> None:
        sd = cols["enabled"].server_default
        assert sd is not None
        assert "true" in str(sd.arg).lower()

    # logsource fields (all nullable)
    def test_logsource_product_type_is_string_100(self, cols: dict) -> None:
        assert isinstance(cols["logsource_product"].type, sa.String)
        assert cols["logsource_product"].type.length == 100

    def test_logsource_product_is_nullable(self, cols: dict) -> None:
        assert cols["logsource_product"].nullable is True

    def test_logsource_category_type_is_string_100(self, cols: dict) -> None:
        assert isinstance(cols["logsource_category"].type, sa.String)
        assert cols["logsource_category"].type.length == 100

    def test_logsource_category_is_nullable(self, cols: dict) -> None:
        assert cols["logsource_category"].nullable is True

    def test_logsource_service_type_is_string_100(self, cols: dict) -> None:
        assert isinstance(cols["logsource_service"].type, sa.String)
        assert cols["logsource_service"].type.length == 100

    def test_logsource_service_is_nullable(self, cols: dict) -> None:
        assert cols["logsource_service"].nullable is True

    # ATT&CK JSON fields
    def test_technique_ids_type_is_text(self, cols: dict) -> None:
        assert isinstance(cols["technique_ids"].type, sa.Text)

    def test_technique_ids_is_nullable(self, cols: dict) -> None:
        assert cols["technique_ids"].nullable is True

    def test_tactic_ids_type_is_text(self, cols: dict) -> None:
        assert isinstance(cols["tactic_ids"].type, sa.Text)

    def test_tactic_ids_is_nullable(self, cols: dict) -> None:
        assert cols["tactic_ids"].nullable is True

    # Stats
    def test_hit_count_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["hit_count"].type, sa.Integer)

    def test_hit_count_is_not_nullable(self, cols: dict) -> None:
        assert cols["hit_count"].nullable is False

    def test_hit_count_server_default_is_zero(self, cols: dict) -> None:
        sd = cols["hit_count"].server_default
        assert sd is not None
        assert "0" in str(sd.arg)

    def test_fp_count_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["fp_count"].type, sa.Integer)

    def test_fp_count_is_not_nullable(self, cols: dict) -> None:
        assert cols["fp_count"].nullable is False

    def test_fp_count_server_default_is_zero(self, cols: dict) -> None:
        sd = cols["fp_count"].server_default
        assert sd is not None
        assert "0" in str(sd.arg)

    def test_last_hit_at_type_is_string_50(self, cols: dict) -> None:
        assert isinstance(cols["last_hit_at"].type, sa.String)
        assert cols["last_hit_at"].type.length == 50

    def test_last_hit_at_is_nullable(self, cols: dict) -> None:
        assert cols["last_hit_at"].nullable is True

    # Ownership
    def test_created_by_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["created_by"].type, sa.String)
        assert cols["created_by"].type.length == 255

    def test_created_by_is_nullable(self, cols: dict) -> None:
        assert cols["created_by"].nullable is True

    def test_source_type_is_string_100(self, cols: dict) -> None:
        assert isinstance(cols["source"].type, sa.String)
        assert cols["source"].type.length == 100

    def test_source_is_nullable(self, cols: dict) -> None:
        assert cols["source"].nullable is True

    # Timestamps
    def test_created_at_type_is_datetime_with_timezone(self, cols: dict) -> None:
        col_type = cols["created_at"].type
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True

    def test_created_at_has_server_default(self, cols: dict) -> None:
        assert cols["created_at"].server_default is not None

    def test_updated_at_type_is_datetime_with_timezone(self, cols: dict) -> None:
        col_type = cols["updated_at"].type
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True

    def test_updated_at_has_server_default(self, cols: dict) -> None:
        assert cols["updated_at"].server_default is not None

    # Parametrized nullability
    @pytest.mark.parametrize(
        "col_name",
        [
            "description", "logsource_product", "logsource_category",
            "logsource_service", "technique_ids", "tactic_ids",
            "last_hit_at", "created_by", "source",
        ],
    )
    def test_nullable_columns(self, cols: dict, col_name: str) -> None:
        assert cols[col_name].nullable is True

    @pytest.mark.parametrize(
        "col_name",
        ["id", "title", "rule_type", "content", "status", "level", "enabled",
         "hit_count", "fp_count"],
    )
    def test_non_nullable_columns(self, cols: dict, col_name: str) -> None:
        assert cols[col_name].nullable is False


# ---------------------------------------------------------------------------
# upgrade() — connectors table schema
# ---------------------------------------------------------------------------


class TestConnectorsTableSchema:
    """upgrade() creates the connectors table with the expected columns."""

    @pytest.fixture(scope="class")
    def cols(self) -> dict[str, sa.Column]:
        return _connectors_columns()

    # Presence — all 12 columns
    @pytest.mark.parametrize(
        "col_name",
        [
            "id", "name", "connector_type", "config_json",
            "status", "enabled", "last_seen_at", "error_message",
            "events_total", "errors_total", "created_at", "updated_at",
        ],
    )
    def test_column_present(self, cols: dict, col_name: str) -> None:
        assert col_name in cols

    def test_total_column_count_is_12(self, cols: dict) -> None:
        assert len(cols) == 12

    # id
    def test_id_type_is_string_36(self, cols: dict) -> None:
        assert isinstance(cols["id"].type, sa.String)
        assert cols["id"].type.length == 36

    def test_id_is_primary_key(self, cols: dict) -> None:
        assert cols["id"].primary_key is True

    # name
    def test_name_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["name"].type, sa.String)
        assert cols["name"].type.length == 255

    def test_name_is_not_nullable(self, cols: dict) -> None:
        assert cols["name"].nullable is False

    def test_name_has_unique_constraint(self, cols: dict) -> None:
        assert cols["name"].unique is True

    # connector_type
    def test_connector_type_type_is_string_50(self, cols: dict) -> None:
        assert isinstance(cols["connector_type"].type, sa.String)
        assert cols["connector_type"].type.length == 50

    def test_connector_type_is_not_nullable(self, cols: dict) -> None:
        assert cols["connector_type"].nullable is False

    def test_connector_type_is_indexed(self, cols: dict) -> None:
        assert cols["connector_type"].index is True

    # config_json
    def test_config_json_type_is_text(self, cols: dict) -> None:
        assert isinstance(cols["config_json"].type, sa.Text)

    def test_config_json_is_not_nullable(self, cols: dict) -> None:
        assert cols["config_json"].nullable is False

    def test_config_json_server_default_is_empty_object(self, cols: dict) -> None:
        sd = cols["config_json"].server_default
        assert sd is not None
        assert "{}" in str(sd.arg)

    # status
    def test_status_type_is_string_20(self, cols: dict) -> None:
        assert isinstance(cols["status"].type, sa.String)
        assert cols["status"].type.length == 20

    def test_status_is_not_nullable(self, cols: dict) -> None:
        assert cols["status"].nullable is False

    def test_status_server_default_contains_inactive(self, cols: dict) -> None:
        sd = cols["status"].server_default
        assert sd is not None
        assert "inactive" in str(sd.arg)

    # enabled
    def test_enabled_type_is_boolean(self, cols: dict) -> None:
        assert isinstance(cols["enabled"].type, sa.Boolean)

    def test_enabled_is_not_nullable(self, cols: dict) -> None:
        assert cols["enabled"].nullable is False

    def test_enabled_server_default_is_true(self, cols: dict) -> None:
        sd = cols["enabled"].server_default
        assert sd is not None
        assert "true" in str(sd.arg).lower()

    # last_seen_at
    def test_last_seen_at_type_is_string_50(self, cols: dict) -> None:
        assert isinstance(cols["last_seen_at"].type, sa.String)
        assert cols["last_seen_at"].type.length == 50

    def test_last_seen_at_is_nullable(self, cols: dict) -> None:
        assert cols["last_seen_at"].nullable is True

    # error_message
    def test_error_message_type_is_text(self, cols: dict) -> None:
        assert isinstance(cols["error_message"].type, sa.Text)

    def test_error_message_is_nullable(self, cols: dict) -> None:
        assert cols["error_message"].nullable is True

    # Metrics
    def test_events_total_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["events_total"].type, sa.Integer)

    def test_events_total_is_not_nullable(self, cols: dict) -> None:
        assert cols["events_total"].nullable is False

    def test_events_total_server_default_is_zero(self, cols: dict) -> None:
        sd = cols["events_total"].server_default
        assert sd is not None
        assert "0" in str(sd.arg)

    def test_errors_total_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["errors_total"].type, sa.Integer)

    def test_errors_total_is_not_nullable(self, cols: dict) -> None:
        assert cols["errors_total"].nullable is False

    def test_errors_total_server_default_is_zero(self, cols: dict) -> None:
        sd = cols["errors_total"].server_default
        assert sd is not None
        assert "0" in str(sd.arg)

    # Timestamps
    def test_created_at_type_is_datetime_with_timezone(self, cols: dict) -> None:
        col_type = cols["created_at"].type
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True

    def test_created_at_has_server_default(self, cols: dict) -> None:
        assert cols["created_at"].server_default is not None

    def test_updated_at_type_is_datetime_with_timezone(self, cols: dict) -> None:
        col_type = cols["updated_at"].type
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True

    def test_updated_at_has_server_default(self, cols: dict) -> None:
        assert cols["updated_at"].server_default is not None

    # Parametrized nullability
    @pytest.mark.parametrize(
        "col_name",
        ["last_seen_at", "error_message"],
    )
    def test_nullable_columns(self, cols: dict, col_name: str) -> None:
        assert cols[col_name].nullable is True

    @pytest.mark.parametrize(
        "col_name",
        ["id", "name", "connector_type", "config_json", "status",
         "enabled", "events_total", "errors_total"],
    )
    def test_non_nullable_columns(self, cols: dict, col_name: str) -> None:
        assert cols[col_name].nullable is False


# ---------------------------------------------------------------------------
# downgrade()
# ---------------------------------------------------------------------------


class TestDowngrade:
    """downgrade() drops both tables in reverse creation order."""

    def test_drops_exactly_two_tables(self) -> None:
        mock_op = _run_downgrade()
        assert mock_op.drop_table.call_count == 2

    def test_drops_connectors_first(self) -> None:
        """connectors is dropped before rules (safe reverse order)."""
        mock_op = _run_downgrade()
        first_drop = mock_op.drop_table.call_args_list[0].args[0]
        assert first_drop == "connectors"

    def test_drops_rules_second(self) -> None:
        mock_op = _run_downgrade()
        second_drop = mock_op.drop_table.call_args_list[1].args[0]
        assert second_drop == "rules"

    def test_no_create_table_in_downgrade(self) -> None:
        mock_op = _run_downgrade()
        mock_op.create_table.assert_not_called()

    def test_no_add_column_in_downgrade(self) -> None:
        mock_op = _run_downgrade()
        mock_op.add_column.assert_not_called()

    def test_no_create_index_in_downgrade(self) -> None:
        mock_op = _run_downgrade()
        mock_op.create_index.assert_not_called()


# ---------------------------------------------------------------------------
# ORM model — Rule
# ---------------------------------------------------------------------------


class TestRuleOrmModel:
    """ORM Rule model table structure matches the 0002 migration schema."""

    @pytest.fixture(scope="class")
    def table(self):
        from app.models.rule import Rule
        return Rule.__table__

    def test_table_name_is_rules(self, table) -> None:
        assert table.name == "rules"

    def test_has_all_expected_columns(self, table) -> None:
        expected = {
            "id", "title", "description", "rule_type", "content",
            "status", "level", "enabled",
            "logsource_product", "logsource_category", "logsource_service",
            "technique_ids", "tactic_ids",
            "hit_count", "fp_count", "last_hit_at",
            "created_by", "source",
            "created_at", "updated_at",
        }
        actual = {c.name for c in table.columns}
        assert expected == actual

    def test_id_is_primary_key(self, table) -> None:
        assert table.c.id.primary_key is True

    def test_id_string_length_is_36(self, table) -> None:
        assert table.c.id.type.length == 36

    def test_title_string_length_is_500(self, table) -> None:
        assert table.c.title.type.length == 500

    def test_title_is_not_nullable(self, table) -> None:
        assert table.c.title.nullable is False

    def test_description_is_text(self, table) -> None:
        assert isinstance(table.c.description.type, sa.Text)

    def test_description_is_nullable(self, table) -> None:
        assert table.c.description.nullable is True

    def test_rule_type_string_length_is_30(self, table) -> None:
        assert table.c.rule_type.type.length == 30

    def test_rule_type_orm_default_is_sigma(self, table) -> None:
        assert table.c.rule_type.default.arg == "sigma"

    def test_content_is_text(self, table) -> None:
        assert isinstance(table.c.content.type, sa.Text)

    def test_content_is_not_nullable(self, table) -> None:
        assert table.c.content.nullable is False

    def test_status_string_length_is_20(self, table) -> None:
        assert table.c.status.type.length == 20

    def test_status_orm_default_is_experimental(self, table) -> None:
        assert table.c.status.default.arg == "experimental"

    def test_level_string_length_is_20(self, table) -> None:
        assert table.c.level.type.length == 20

    def test_level_orm_default_is_medium(self, table) -> None:
        assert table.c.level.default.arg == "medium"

    def test_enabled_is_boolean(self, table) -> None:
        assert isinstance(table.c.enabled.type, sa.Boolean)

    def test_enabled_orm_default_is_true(self, table) -> None:
        assert table.c.enabled.default.arg is True

    def test_hit_count_is_integer(self, table) -> None:
        assert isinstance(table.c.hit_count.type, sa.Integer)

    def test_hit_count_orm_default_is_zero(self, table) -> None:
        assert table.c.hit_count.default.arg == 0

    def test_fp_count_is_integer(self, table) -> None:
        assert isinstance(table.c.fp_count.type, sa.Integer)

    def test_fp_count_orm_default_is_zero(self, table) -> None:
        assert table.c.fp_count.default.arg == 0

    def test_last_hit_at_is_nullable(self, table) -> None:
        assert table.c.last_hit_at.nullable is True

    def test_created_by_is_nullable(self, table) -> None:
        assert table.c.created_by.nullable is True

    def test_source_is_nullable(self, table) -> None:
        assert table.c.source.nullable is True

    def test_created_at_is_datetime(self, table) -> None:
        assert isinstance(table.c.created_at.type, sa.DateTime)

    def test_updated_at_is_datetime(self, table) -> None:
        assert isinstance(table.c.updated_at.type, sa.DateTime)

    @pytest.mark.parametrize(
        "col_name",
        [
            "description", "logsource_product", "logsource_category",
            "logsource_service", "technique_ids", "tactic_ids",
            "last_hit_at", "created_by", "source",
        ],
    )
    def test_nullable_columns(self, table, col_name: str) -> None:
        assert table.c[col_name].nullable is True

    @pytest.mark.parametrize(
        "col_name",
        ["id", "title", "rule_type", "content", "status", "level",
         "enabled", "hit_count", "fp_count"],
    )
    def test_non_nullable_columns(self, table, col_name: str) -> None:
        assert table.c[col_name].nullable is False

    def test_repr_contains_level(self) -> None:
        from app.models.rule import Rule
        r = Rule(id="rule-1", level="high", title="Suspicious PowerShell Execution")
        assert "high" in repr(r)

    def test_repr_contains_title(self) -> None:
        from app.models.rule import Rule
        r = Rule(id="rule-1", level="critical", title="LSASS Memory Dump Detected")
        assert "LSASS Memory Dump Detected" in repr(r)

    def test_repr_contains_id(self) -> None:
        from app.models.rule import Rule
        r = Rule(id="abc-123", level="medium", title="Test Rule")
        assert "abc-123" in repr(r)

    @pytest.mark.parametrize("level", ["low", "medium", "high", "critical"])
    def test_repr_shows_any_valid_level(self, level: str) -> None:
        from app.models.rule import Rule
        r = Rule(id="rule-x", level=level, title=f"{level} rule")
        assert level in repr(r)


# ---------------------------------------------------------------------------
# ORM model — Connector
# ---------------------------------------------------------------------------


class TestConnectorOrmModel:
    """ORM Connector model table structure matches the 0002 migration schema."""

    @pytest.fixture(scope="class")
    def table(self):
        from app.models.connector import Connector
        return Connector.__table__

    def test_table_name_is_connectors(self, table) -> None:
        assert table.name == "connectors"

    def test_has_all_expected_columns(self, table) -> None:
        expected = {
            "id", "name", "connector_type", "config_json",
            "status", "enabled", "last_seen_at", "error_message",
            "events_total", "errors_total", "created_at", "updated_at",
        }
        actual = {c.name for c in table.columns}
        assert expected == actual

    def test_id_is_primary_key(self, table) -> None:
        assert table.c.id.primary_key is True

    def test_id_string_length_is_36(self, table) -> None:
        assert table.c.id.type.length == 36

    def test_name_string_length_is_255(self, table) -> None:
        assert table.c.name.type.length == 255

    def test_name_is_not_nullable(self, table) -> None:
        assert table.c.name.nullable is False

    def test_name_has_unique_constraint(self, table) -> None:
        assert table.c.name.unique is True

    def test_connector_type_string_length_is_50(self, table) -> None:
        assert table.c.connector_type.type.length == 50

    def test_connector_type_is_not_nullable(self, table) -> None:
        assert table.c.connector_type.nullable is False

    def test_connector_type_is_indexed(self, table) -> None:
        assert table.c.connector_type.index is True

    def test_config_json_is_text(self, table) -> None:
        assert isinstance(table.c.config_json.type, sa.Text)

    def test_config_json_is_not_nullable(self, table) -> None:
        assert table.c.config_json.nullable is False

    def test_config_json_orm_default_is_empty_json(self, table) -> None:
        assert table.c.config_json.default.arg == "{}"

    def test_status_string_length_is_20(self, table) -> None:
        assert table.c.status.type.length == 20

    def test_status_orm_default_is_inactive(self, table) -> None:
        assert table.c.status.default.arg == "inactive"

    def test_enabled_is_boolean(self, table) -> None:
        assert isinstance(table.c.enabled.type, sa.Boolean)

    def test_enabled_orm_default_is_true(self, table) -> None:
        assert table.c.enabled.default.arg is True

    def test_last_seen_at_is_nullable(self, table) -> None:
        assert table.c.last_seen_at.nullable is True

    def test_error_message_is_text(self, table) -> None:
        assert isinstance(table.c.error_message.type, sa.Text)

    def test_error_message_is_nullable(self, table) -> None:
        assert table.c.error_message.nullable is True

    def test_events_total_is_integer(self, table) -> None:
        assert isinstance(table.c.events_total.type, sa.Integer)

    def test_events_total_is_not_nullable(self, table) -> None:
        assert table.c.events_total.nullable is False

    def test_events_total_orm_default_is_zero(self, table) -> None:
        assert table.c.events_total.default.arg == 0

    def test_errors_total_is_integer(self, table) -> None:
        assert isinstance(table.c.errors_total.type, sa.Integer)

    def test_errors_total_is_not_nullable(self, table) -> None:
        assert table.c.errors_total.nullable is False

    def test_errors_total_orm_default_is_zero(self, table) -> None:
        assert table.c.errors_total.default.arg == 0

    def test_created_at_is_datetime(self, table) -> None:
        assert isinstance(table.c.created_at.type, sa.DateTime)

    def test_updated_at_is_datetime(self, table) -> None:
        assert isinstance(table.c.updated_at.type, sa.DateTime)

    def test_repr_contains_name(self) -> None:
        from app.models.connector import Connector
        c = Connector(name="wazuh-prod", connector_type="wazuh", status="active")
        assert "wazuh-prod" in repr(c)

    def test_repr_contains_connector_type(self) -> None:
        from app.models.connector import Connector
        c = Connector(name="zeek-sensor", connector_type="zeek", status="inactive")
        assert "zeek" in repr(c)

    def test_repr_contains_status(self) -> None:
        from app.models.connector import Connector
        c = Connector(name="suricata-ids", connector_type="suricata", status="error")
        assert "error" in repr(c)

    @pytest.mark.parametrize(
        "connector_type",
        ["wazuh", "zeek", "suricata", "prowler", "opencti", "velociraptor", "osquery", "generic"],
    )
    def test_repr_shows_any_valid_connector_type(self, connector_type: str) -> None:
        from app.models.connector import Connector
        c = Connector(name=f"{connector_type}-test", connector_type=connector_type, status="inactive")
        assert connector_type in repr(c)
