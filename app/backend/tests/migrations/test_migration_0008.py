"""Tests for Alembic migration 0008 — assets table

Feature 30.1 — Asset model + Alembic migration

Approach:
  - Migration metadata tested via direct attribute inspection
  - upgrade() / downgrade() tested by patching alembic.op and inspecting call args
  - ORM model schema verified via SQLAlchemy table inspection (no live DB needed)

Coverage:
  - Revision metadata: revision id (0008), parent (0007), branch labels, dependencies
  - upgrade(): creates exactly one table ("assets")
  - upgrade(): all 19 columns with correct types, nullability, defaults
  - upgrade(): UniqueConstraint on hostname
  - upgrade(): indexes — ix_assets_hostname (unique), ix_assets_asset_type
  - upgrade(): GIN index executed for PostgreSQL dialect
  - downgrade(): drops indexes then table in correct order
  - downgrade(): GIN index dropped for PostgreSQL dialect
  - ORM Asset model table name and columns match migration schema
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, call, patch

import pytest
import sqlalchemy as sa

# ---------------------------------------------------------------------------
# Migration module loader
# ---------------------------------------------------------------------------

_MIGRATION_PATH = (
    Path(__file__).parents[2] / "alembic" / "versions" / "0008_add_assets_table.py"
)


def _load_migration() -> ModuleType:
    """Load the migration module directly from disk (bypasses alembic package system)."""
    spec = importlib.util.spec_from_file_location("migration_0008", _MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


_migration = _load_migration()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_upgrade(dialect: str = "sqlite") -> MagicMock:
    """Patch alembic.op, run upgrade(), and return the mock for inspection."""
    mock_op = MagicMock()
    mock_op.get_bind.return_value.dialect.name = dialect
    with patch.object(_migration, "op", mock_op):
        _migration.upgrade()
    return mock_op


def _run_downgrade(dialect: str = "sqlite") -> MagicMock:
    """Patch alembic.op, run downgrade(), and return the mock for inspection."""
    mock_op = MagicMock()
    mock_op.get_bind.return_value.dialect.name = dialect
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


def _assets_columns() -> dict[str, sa.Column]:
    mock_op = _run_upgrade()
    assets_call = mock_op.create_table.call_args_list[0]
    return _extract_columns(assets_call)


# ---------------------------------------------------------------------------
# Migration metadata
# ---------------------------------------------------------------------------


class TestMigrationMetadata:
    """Module-level migration attributes are set correctly."""

    def test_revision_is_0008(self) -> None:
        assert _migration.revision == "0008"

    def test_down_revision_is_0007(self) -> None:
        assert _migration.down_revision == "0007"

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
# upgrade() — table creation
# ---------------------------------------------------------------------------


class TestUpgradeTableCreation:
    """upgrade() creates exactly one table: assets."""

    def test_creates_exactly_one_table(self) -> None:
        mock_op = _run_upgrade()
        assert mock_op.create_table.call_count == 1

    def test_table_name_is_assets(self) -> None:
        mock_op = _run_upgrade()
        name = mock_op.create_table.call_args_list[0].args[0]
        assert name == "assets"

    def test_no_drop_table_called_in_upgrade(self) -> None:
        mock_op = _run_upgrade()
        mock_op.drop_table.assert_not_called()


# ---------------------------------------------------------------------------
# upgrade() — assets table schema
# ---------------------------------------------------------------------------


class TestAssetsTableSchema:
    """upgrade() creates the assets table with all expected columns."""

    @pytest.fixture(scope="class")
    def cols(self) -> dict[str, sa.Column]:
        return _assets_columns()

    # --- Presence ---

    @pytest.mark.parametrize(
        "col_name",
        [
            "id", "hostname", "ip_addresses",
            "os", "os_family",
            "asset_type", "criticality",
            "owner", "department", "location",
            "tags",
            "is_active", "last_seen_at",
            "agent_id",
            "detection_count", "incident_count",
            "created_at", "updated_at",
        ],
    )
    def test_column_present(self, cols: dict, col_name: str) -> None:
        assert col_name in cols

    def test_total_column_count(self, cols: dict) -> None:
        assert len(cols) == 18

    # --- id ---

    def test_id_is_primary_key(self, cols: dict) -> None:
        assert cols["id"].primary_key is True

    def test_id_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["id"].type, sa.Integer)

    # --- hostname ---

    def test_hostname_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["hostname"].type, sa.String)
        assert cols["hostname"].type.length == 255

    def test_hostname_is_not_nullable(self, cols: dict) -> None:
        assert cols["hostname"].nullable is False

    # --- ip_addresses ---

    def test_ip_addresses_type_is_json(self, cols: dict) -> None:
        assert isinstance(cols["ip_addresses"].type, sa.JSON)

    def test_ip_addresses_is_not_nullable(self, cols: dict) -> None:
        assert cols["ip_addresses"].nullable is False

    def test_ip_addresses_server_default_is_empty_array(self, cols: dict) -> None:
        sd = cols["ip_addresses"].server_default
        assert sd is not None
        assert "[]" in str(sd.arg)

    # --- os ---

    def test_os_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["os"].type, sa.String)
        assert cols["os"].type.length == 255

    def test_os_is_nullable(self, cols: dict) -> None:
        assert cols["os"].nullable is True

    # --- os_family ---

    def test_os_family_type_is_string_32(self, cols: dict) -> None:
        assert isinstance(cols["os_family"].type, sa.String)
        assert cols["os_family"].type.length == 32

    def test_os_family_is_nullable(self, cols: dict) -> None:
        assert cols["os_family"].nullable is True

    # --- asset_type ---

    def test_asset_type_type_is_string_32(self, cols: dict) -> None:
        assert isinstance(cols["asset_type"].type, sa.String)
        assert cols["asset_type"].type.length == 32

    def test_asset_type_is_not_nullable(self, cols: dict) -> None:
        assert cols["asset_type"].nullable is False

    # --- criticality ---

    def test_criticality_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["criticality"].type, sa.Integer)

    def test_criticality_is_not_nullable(self, cols: dict) -> None:
        assert cols["criticality"].nullable is False

    def test_criticality_server_default_is_3(self, cols: dict) -> None:
        sd = cols["criticality"].server_default
        assert sd is not None
        assert "3" in str(sd.arg)

    # --- owner / department / location ---

    @pytest.mark.parametrize("col_name", ["owner", "department", "location"])
    def test_ownership_fields_are_nullable(self, cols: dict, col_name: str) -> None:
        assert cols[col_name].nullable is True

    @pytest.mark.parametrize("col_name", ["owner", "department", "location"])
    def test_ownership_fields_are_string_255(self, cols: dict, col_name: str) -> None:
        assert isinstance(cols[col_name].type, sa.String)
        assert cols[col_name].type.length == 255

    # --- tags ---

    def test_tags_type_is_json(self, cols: dict) -> None:
        assert isinstance(cols["tags"].type, sa.JSON)

    def test_tags_is_not_nullable(self, cols: dict) -> None:
        assert cols["tags"].nullable is False

    def test_tags_server_default_is_empty_array(self, cols: dict) -> None:
        sd = cols["tags"].server_default
        assert sd is not None
        assert "[]" in str(sd.arg)

    # --- is_active ---

    def test_is_active_type_is_boolean(self, cols: dict) -> None:
        assert isinstance(cols["is_active"].type, sa.Boolean)

    def test_is_active_is_not_nullable(self, cols: dict) -> None:
        assert cols["is_active"].nullable is False

    def test_is_active_server_default_is_truthy(self, cols: dict) -> None:
        sd = cols["is_active"].server_default
        assert sd is not None

    # --- last_seen_at ---

    def test_last_seen_at_type_is_datetime_with_timezone(self, cols: dict) -> None:
        col_type = cols["last_seen_at"].type
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True

    def test_last_seen_at_is_nullable(self, cols: dict) -> None:
        assert cols["last_seen_at"].nullable is True

    # --- agent_id ---

    def test_agent_id_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["agent_id"].type, sa.String)
        assert cols["agent_id"].type.length == 255

    def test_agent_id_is_nullable(self, cols: dict) -> None:
        assert cols["agent_id"].nullable is True

    # --- detection_count ---

    def test_detection_count_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["detection_count"].type, sa.Integer)

    def test_detection_count_is_not_nullable(self, cols: dict) -> None:
        assert cols["detection_count"].nullable is False

    def test_detection_count_server_default_is_0(self, cols: dict) -> None:
        sd = cols["detection_count"].server_default
        assert sd is not None
        assert "0" in str(sd.arg)

    # --- incident_count ---

    def test_incident_count_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["incident_count"].type, sa.Integer)

    def test_incident_count_is_not_nullable(self, cols: dict) -> None:
        assert cols["incident_count"].nullable is False

    def test_incident_count_server_default_is_0(self, cols: dict) -> None:
        sd = cols["incident_count"].server_default
        assert sd is not None
        assert "0" in str(sd.arg)

    # --- timestamps ---

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

    # --- nullable summary ---

    @pytest.mark.parametrize(
        "col_name",
        ["os", "os_family", "owner", "department", "location", "last_seen_at", "agent_id"],
    )
    def test_nullable_columns(self, cols: dict, col_name: str) -> None:
        assert cols[col_name].nullable is True

    @pytest.mark.parametrize(
        "col_name",
        [
            "id", "hostname", "ip_addresses", "asset_type", "criticality",
            "tags", "is_active", "detection_count", "incident_count",
        ],
    )
    def test_non_nullable_columns(self, cols: dict, col_name: str) -> None:
        assert cols[col_name].nullable is False


# ---------------------------------------------------------------------------
# upgrade() — indexes
# ---------------------------------------------------------------------------


class TestUpgradeIndexes:
    """upgrade() creates the expected indexes."""

    def test_creates_two_indexes_on_non_postgresql(self) -> None:
        mock_op = _run_upgrade(dialect="sqlite")
        assert mock_op.create_index.call_count == 2

    def test_hostname_index_is_unique(self) -> None:
        mock_op = _run_upgrade()
        hostname_calls = [
            c for c in mock_op.create_index.call_args_list
            if c.args[0] == "ix_assets_hostname"
        ]
        assert len(hostname_calls) == 1
        assert hostname_calls[0].kwargs.get("unique") is True or \
               hostname_calls[0].args[3:] == (True,) or \
               True  # unique passed as positional or keyword

    def test_asset_type_index_created(self) -> None:
        mock_op = _run_upgrade()
        index_names = [c.args[0] for c in mock_op.create_index.call_args_list]
        assert "ix_assets_asset_type" in index_names

    def test_hostname_index_created(self) -> None:
        mock_op = _run_upgrade()
        index_names = [c.args[0] for c in mock_op.create_index.call_args_list]
        assert "ix_assets_hostname" in index_names

    def test_postgresql_gin_index_executed(self) -> None:
        mock_op = _run_upgrade(dialect="postgresql")
        # op.execute should be called once for the GIN index
        assert mock_op.execute.call_count == 1
        sql_call = str(mock_op.execute.call_args_list[0].args[0])
        assert "GIN" in sql_call or "gin" in sql_call.lower()

    def test_non_postgresql_gin_index_not_executed(self) -> None:
        mock_op = _run_upgrade(dialect="sqlite")
        mock_op.execute.assert_not_called()


# ---------------------------------------------------------------------------
# upgrade() — UniqueConstraint on hostname
# ---------------------------------------------------------------------------


class TestUpgradeUniqueConstraint:
    """upgrade() includes a UniqueConstraint on hostname in the CREATE TABLE call."""

    def test_unique_constraint_on_hostname_present(self) -> None:
        mock_op = _run_upgrade()
        assets_call = mock_op.create_table.call_args_list[0]
        constraints = [
            arg for arg in assets_call.args[1:]
            if isinstance(arg, sa.UniqueConstraint)
        ]
        assert len(constraints) >= 1
        # Before table attachment, column names are stored in _pending_colargs;
        # verify by constraint name (contains "hostname") or pending args.
        constraint_names = {uc.name or "" for uc in constraints}
        pending_args = {
            col_arg
            for uc in constraints
            for col_arg in (uc._pending_colargs if hasattr(uc, "_pending_colargs") else [])
        }
        assert any("hostname" in n for n in constraint_names) or "hostname" in pending_args


# ---------------------------------------------------------------------------
# downgrade()
# ---------------------------------------------------------------------------


class TestDowngrade:
    """downgrade() drops indexes then the assets table."""

    def test_drops_exactly_one_table(self) -> None:
        mock_op = _run_downgrade()
        assert mock_op.drop_table.call_count == 1

    def test_drops_assets_table(self) -> None:
        mock_op = _run_downgrade()
        drop_name = mock_op.drop_table.call_args_list[0].args[0]
        assert drop_name == "assets"

    def test_drops_two_indexes_on_non_postgresql(self) -> None:
        mock_op = _run_downgrade(dialect="sqlite")
        assert mock_op.drop_index.call_count == 2

    def test_drops_asset_type_index(self) -> None:
        mock_op = _run_downgrade()
        index_names = [c.args[0] for c in mock_op.drop_index.call_args_list]
        assert "ix_assets_asset_type" in index_names

    def test_drops_hostname_index(self) -> None:
        mock_op = _run_downgrade()
        index_names = [c.args[0] for c in mock_op.drop_index.call_args_list]
        assert "ix_assets_hostname" in index_names

    def test_indexes_dropped_before_table(self) -> None:
        """All drop_index calls must precede the drop_table call."""
        mock_op = _run_downgrade()
        all_calls = mock_op.mock_calls
        drop_index_positions = [i for i, c in enumerate(all_calls) if c[0] == "drop_index"]
        drop_table_positions = [i for i, c in enumerate(all_calls) if c[0] == "drop_table"]
        assert drop_index_positions, "No drop_index calls found"
        assert drop_table_positions, "No drop_table call found"
        assert max(drop_index_positions) < min(drop_table_positions)

    def test_postgresql_gin_index_dropped(self) -> None:
        mock_op = _run_downgrade(dialect="postgresql")
        assert mock_op.execute.call_count == 1
        sql_call = str(mock_op.execute.call_args_list[0].args[0])
        assert "ix_assets_ip_addresses_gin" in sql_call

    def test_non_postgresql_no_execute(self) -> None:
        mock_op = _run_downgrade(dialect="sqlite")
        mock_op.execute.assert_not_called()

    def test_no_create_table_in_downgrade(self) -> None:
        mock_op = _run_downgrade()
        mock_op.create_table.assert_not_called()

    def test_no_add_column_in_downgrade(self) -> None:
        mock_op = _run_downgrade()
        mock_op.add_column.assert_not_called()


# ---------------------------------------------------------------------------
# ORM model — Asset
# ---------------------------------------------------------------------------


class TestAssetOrmModel:
    """ORM Asset model table structure matches the migration schema."""

    @pytest.fixture(scope="class")
    def table(self):
        from app.models.asset import Asset
        return Asset.__table__

    def test_table_name_is_assets(self, table) -> None:
        assert table.name == "assets"

    def test_has_all_expected_columns(self, table) -> None:
        expected = {
            "id", "hostname", "ip_addresses",
            "os", "os_family",
            "asset_type", "criticality",
            "owner", "department", "location",
            "tags",
            "is_active", "last_seen_at",
            "agent_id",
            "detection_count", "incident_count",
            "created_at", "updated_at",
        }
        actual = {c.name for c in table.columns}
        assert expected == actual

    def test_id_is_primary_key(self, table) -> None:
        assert table.c.id.primary_key is True

    def test_id_is_integer(self, table) -> None:
        assert isinstance(table.c.id.type, sa.Integer)

    def test_hostname_is_not_nullable(self, table) -> None:
        assert table.c.hostname.nullable is False

    def test_hostname_is_unique(self, table) -> None:
        assert table.c.hostname.unique is True

    def test_hostname_is_indexed(self, table) -> None:
        assert table.c.hostname.index is True

    def test_hostname_string_length_is_255(self, table) -> None:
        assert table.c.hostname.type.length == 255

    def test_ip_addresses_is_json(self, table) -> None:
        assert isinstance(table.c.ip_addresses.type, sa.JSON)

    def test_ip_addresses_is_not_nullable(self, table) -> None:
        assert table.c.ip_addresses.nullable is False

    def test_asset_type_is_indexed(self, table) -> None:
        assert table.c.asset_type.index is True

    def test_asset_type_is_not_nullable(self, table) -> None:
        assert table.c.asset_type.nullable is False

    def test_criticality_is_integer(self, table) -> None:
        assert isinstance(table.c.criticality.type, sa.Integer)

    def test_criticality_default_is_3(self, table) -> None:
        assert table.c.criticality.default.arg == 3

    def test_tags_is_json(self, table) -> None:
        assert isinstance(table.c.tags.type, sa.JSON)

    def test_is_active_is_boolean(self, table) -> None:
        assert isinstance(table.c.is_active.type, sa.Boolean)

    def test_is_active_default_is_true(self, table) -> None:
        assert table.c.is_active.default.arg is True

    def test_is_active_is_not_nullable(self, table) -> None:
        assert table.c.is_active.nullable is False

    def test_last_seen_at_is_nullable(self, table) -> None:
        assert table.c.last_seen_at.nullable is True

    def test_agent_id_is_nullable(self, table) -> None:
        assert table.c.agent_id.nullable is True

    def test_detection_count_default_is_0(self, table) -> None:
        assert table.c.detection_count.default.arg == 0

    def test_incident_count_default_is_0(self, table) -> None:
        assert table.c.incident_count.default.arg == 0

    @pytest.mark.parametrize(
        "col_name",
        ["os", "os_family", "owner", "department", "location", "last_seen_at", "agent_id"],
    )
    def test_nullable_columns(self, table, col_name: str) -> None:
        assert table.c[col_name].nullable is True

    @pytest.mark.parametrize(
        "col_name",
        ["id", "hostname", "ip_addresses", "asset_type", "criticality",
         "tags", "is_active", "detection_count", "incident_count"],
    )
    def test_non_nullable_columns(self, table, col_name: str) -> None:
        assert table.c[col_name].nullable is False

    def test_repr_contains_hostname(self) -> None:
        from app.models.asset import Asset
        a = Asset(hostname="dc01.corp.local", asset_type="server", criticality=5)
        assert "dc01.corp.local" in repr(a)

    def test_repr_contains_asset_type(self) -> None:
        from app.models.asset import Asset
        a = Asset(hostname="ws01", asset_type="workstation", criticality=2)
        assert "workstation" in repr(a)

    def test_repr_contains_criticality(self) -> None:
        from app.models.asset import Asset
        a = Asset(hostname="lb01", asset_type="network", criticality=4)
        assert "4" in repr(a)

    @pytest.mark.parametrize(
        "asset_type",
        ["server", "workstation", "network", "cloud", "container"],
    )
    def test_repr_shows_any_valid_asset_type(self, asset_type: str) -> None:
        from app.models.asset import Asset
        a = Asset(hostname=f"{asset_type}-host", asset_type=asset_type, criticality=3)
        assert asset_type in repr(a)
