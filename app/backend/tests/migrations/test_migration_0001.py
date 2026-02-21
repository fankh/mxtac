"""Tests for Alembic migration 0001 — users + detections tables

Feature 18.3 — Alembic migration 0001 (initial schema)

Approach:
  - Migration metadata tested via direct attribute inspection
  - upgrade() / downgrade() tested by patching alembic.op and inspecting call args
  - ORM model schema verified via SQLAlchemy table inspection (no live DB needed)

Coverage:
  - Revision metadata: revision id, parent, branch labels, dependencies
  - upgrade(): creates users table before detections table
  - upgrade(): users table — all 8 columns with correct types, nullability, defaults
  - upgrade(): detections table — all 24 columns with correct types, nullability, defaults
  - upgrade(): server defaults for role, is_active, status, occurrence_count
  - upgrade(): indexes on email, severity, technique_id, tactic, status, host, time
  - downgrade(): drops detections before users (dependency-safe reverse order)
  - downgrade(): no extra operations (no create, no alter)
  - ORM User model table columns match the migration schema
  - ORM Detection model table columns match the migration schema
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
    Path(__file__).parents[2] / "alembic" / "versions" / "0001_initial_schema.py"
)


def _load_migration() -> ModuleType:
    """Load the migration module directly from disk (bypasses alembic package system)."""
    spec = importlib.util.spec_from_file_location("migration_0001", _MIGRATION_PATH)
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


def _users_columns() -> dict[str, sa.Column]:
    mock_op = _run_upgrade()
    users_call = mock_op.create_table.call_args_list[0]
    return _extract_columns(users_call)


def _detections_columns() -> dict[str, sa.Column]:
    mock_op = _run_upgrade()
    detections_call = mock_op.create_table.call_args_list[1]
    return _extract_columns(detections_call)


# ---------------------------------------------------------------------------
# Migration metadata
# ---------------------------------------------------------------------------


class TestMigrationMetadata:
    """Module-level migration attributes are set correctly."""

    def test_revision_is_0001(self) -> None:
        assert _migration.revision == "0001"

    def test_down_revision_is_none(self) -> None:
        """First migration has no parent."""
        assert _migration.down_revision is None

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

    def test_users_table_created_first(self) -> None:
        mock_op = _run_upgrade()
        first_name = mock_op.create_table.call_args_list[0].args[0]
        assert first_name == "users"

    def test_detections_table_created_second(self) -> None:
        mock_op = _run_upgrade()
        second_name = mock_op.create_table.call_args_list[1].args[0]
        assert second_name == "detections"

    def test_no_drop_table_called_in_upgrade(self) -> None:
        mock_op = _run_upgrade()
        mock_op.drop_table.assert_not_called()


# ---------------------------------------------------------------------------
# upgrade() — users table schema
# ---------------------------------------------------------------------------


class TestUsersTableSchema:
    """upgrade() creates the users table with the expected columns."""

    @pytest.fixture(scope="class")
    def cols(self) -> dict[str, sa.Column]:
        return _users_columns()

    # Presence
    @pytest.mark.parametrize(
        "col_name",
        ["id", "email", "hashed_password", "full_name", "role", "is_active", "created_at", "updated_at"],
    )
    def test_column_present(self, cols: dict, col_name: str) -> None:
        assert col_name in cols

    def test_total_column_count_is_eight(self, cols: dict) -> None:
        assert len(cols) == 8

    # id
    def test_id_type_is_string_36(self, cols: dict) -> None:
        assert isinstance(cols["id"].type, sa.String)
        assert cols["id"].type.length == 36

    def test_id_is_primary_key(self, cols: dict) -> None:
        assert cols["id"].primary_key is True

    # email
    def test_email_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["email"].type, sa.String)
        assert cols["email"].type.length == 255

    def test_email_is_not_nullable(self, cols: dict) -> None:
        assert cols["email"].nullable is False

    def test_email_has_unique_constraint(self, cols: dict) -> None:
        assert cols["email"].unique is True

    def test_email_is_indexed(self, cols: dict) -> None:
        assert cols["email"].index is True

    # hashed_password
    def test_hashed_password_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["hashed_password"].type, sa.String)
        assert cols["hashed_password"].type.length == 255

    def test_hashed_password_is_not_nullable(self, cols: dict) -> None:
        assert cols["hashed_password"].nullable is False

    # full_name
    def test_full_name_is_nullable(self, cols: dict) -> None:
        assert cols["full_name"].nullable is True

    def test_full_name_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["full_name"].type, sa.String)
        assert cols["full_name"].type.length == 255

    # role
    def test_role_type_is_string_50(self, cols: dict) -> None:
        assert isinstance(cols["role"].type, sa.String)
        assert cols["role"].type.length == 50

    def test_role_is_not_nullable(self, cols: dict) -> None:
        assert cols["role"].nullable is False

    def test_role_server_default_contains_analyst(self, cols: dict) -> None:
        sd = cols["role"].server_default
        assert sd is not None
        assert "analyst" in str(sd.arg)

    # is_active
    def test_is_active_type_is_boolean(self, cols: dict) -> None:
        assert isinstance(cols["is_active"].type, sa.Boolean)

    def test_is_active_is_not_nullable(self, cols: dict) -> None:
        assert cols["is_active"].nullable is False

    def test_is_active_server_default_is_true(self, cols: dict) -> None:
        sd = cols["is_active"].server_default
        assert sd is not None
        assert "true" in str(sd.arg).lower()

    # created_at
    def test_created_at_type_is_datetime_with_timezone(self, cols: dict) -> None:
        col_type = cols["created_at"].type
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True

    def test_created_at_has_server_default(self, cols: dict) -> None:
        assert cols["created_at"].server_default is not None

    # updated_at
    def test_updated_at_type_is_datetime_with_timezone(self, cols: dict) -> None:
        col_type = cols["updated_at"].type
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True

    def test_updated_at_has_server_default(self, cols: dict) -> None:
        assert cols["updated_at"].server_default is not None


# ---------------------------------------------------------------------------
# upgrade() — detections table schema
# ---------------------------------------------------------------------------


class TestDetectionsTableSchema:
    """upgrade() creates the detections table with the expected columns."""

    @pytest.fixture(scope="class")
    def cols(self) -> dict[str, sa.Column]:
        return _detections_columns()

    # Presence — all 24 columns
    @pytest.mark.parametrize(
        "col_name",
        [
            "id", "score", "severity", "technique_id", "technique_name",
            "tactic", "tactic_id", "name", "description", "status",
            "priority", "host", "user", "process", "log_source",
            "event_id", "rule_name", "occurrence_count", "cvss_v3",
            "confidence", "assigned_to", "time", "created_at", "updated_at",
        ],
    )
    def test_column_present(self, cols: dict, col_name: str) -> None:
        assert col_name in cols

    def test_total_column_count_is_24(self, cols: dict) -> None:
        assert len(cols) == 24

    # id
    def test_id_is_primary_key(self, cols: dict) -> None:
        assert cols["id"].primary_key is True

    def test_id_type_is_string_36(self, cols: dict) -> None:
        assert isinstance(cols["id"].type, sa.String)
        assert cols["id"].type.length == 36

    # score
    def test_score_type_is_float(self, cols: dict) -> None:
        assert isinstance(cols["score"].type, sa.Float)

    def test_score_is_not_nullable(self, cols: dict) -> None:
        assert cols["score"].nullable is False

    # severity
    def test_severity_type_is_string_20(self, cols: dict) -> None:
        assert isinstance(cols["severity"].type, sa.String)
        assert cols["severity"].type.length == 20

    def test_severity_is_not_nullable(self, cols: dict) -> None:
        assert cols["severity"].nullable is False

    def test_severity_is_indexed(self, cols: dict) -> None:
        assert cols["severity"].index is True

    # technique_id
    def test_technique_id_type_is_string_20(self, cols: dict) -> None:
        assert isinstance(cols["technique_id"].type, sa.String)
        assert cols["technique_id"].type.length == 20

    def test_technique_id_is_not_nullable(self, cols: dict) -> None:
        assert cols["technique_id"].nullable is False

    def test_technique_id_is_indexed(self, cols: dict) -> None:
        assert cols["technique_id"].index is True

    # technique_name
    def test_technique_name_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["technique_name"].type, sa.String)
        assert cols["technique_name"].type.length == 255

    def test_technique_name_is_not_nullable(self, cols: dict) -> None:
        assert cols["technique_name"].nullable is False

    # tactic
    def test_tactic_type_is_string_100(self, cols: dict) -> None:
        assert isinstance(cols["tactic"].type, sa.String)
        assert cols["tactic"].type.length == 100

    def test_tactic_is_not_nullable(self, cols: dict) -> None:
        assert cols["tactic"].nullable is False

    def test_tactic_is_indexed(self, cols: dict) -> None:
        assert cols["tactic"].index is True

    # tactic_id
    def test_tactic_id_type_is_string_20(self, cols: dict) -> None:
        assert isinstance(cols["tactic_id"].type, sa.String)
        assert cols["tactic_id"].type.length == 20

    def test_tactic_id_is_nullable(self, cols: dict) -> None:
        assert cols["tactic_id"].nullable is True

    # name
    def test_name_type_is_string_500(self, cols: dict) -> None:
        assert isinstance(cols["name"].type, sa.String)
        assert cols["name"].type.length == 500

    def test_name_is_not_nullable(self, cols: dict) -> None:
        assert cols["name"].nullable is False

    # description
    def test_description_type_is_text(self, cols: dict) -> None:
        assert isinstance(cols["description"].type, sa.Text)

    def test_description_is_nullable(self, cols: dict) -> None:
        assert cols["description"].nullable is True

    # status
    def test_status_type_is_string_30(self, cols: dict) -> None:
        assert isinstance(cols["status"].type, sa.String)
        assert cols["status"].type.length == 30

    def test_status_is_not_nullable(self, cols: dict) -> None:
        assert cols["status"].nullable is False

    def test_status_server_default_is_active(self, cols: dict) -> None:
        sd = cols["status"].server_default
        assert sd is not None
        assert "active" in str(sd.arg)

    def test_status_is_indexed(self, cols: dict) -> None:
        assert cols["status"].index is True

    # priority
    def test_priority_type_is_string_20(self, cols: dict) -> None:
        assert isinstance(cols["priority"].type, sa.String)
        assert cols["priority"].type.length == 20

    def test_priority_is_nullable(self, cols: dict) -> None:
        assert cols["priority"].nullable is True

    # host
    def test_host_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["host"].type, sa.String)
        assert cols["host"].type.length == 255

    def test_host_is_not_nullable(self, cols: dict) -> None:
        assert cols["host"].nullable is False

    def test_host_is_indexed(self, cols: dict) -> None:
        assert cols["host"].index is True

    # user (nullable actor identity)
    def test_user_is_nullable(self, cols: dict) -> None:
        assert cols["user"].nullable is True

    # process
    def test_process_type_is_string_500(self, cols: dict) -> None:
        assert isinstance(cols["process"].type, sa.String)
        assert cols["process"].type.length == 500

    def test_process_is_nullable(self, cols: dict) -> None:
        assert cols["process"].nullable is True

    # log_source
    def test_log_source_type_is_string_100(self, cols: dict) -> None:
        assert isinstance(cols["log_source"].type, sa.String)
        assert cols["log_source"].type.length == 100

    def test_log_source_is_nullable(self, cols: dict) -> None:
        assert cols["log_source"].nullable is True

    # event_id
    def test_event_id_type_is_string_50(self, cols: dict) -> None:
        assert isinstance(cols["event_id"].type, sa.String)
        assert cols["event_id"].type.length == 50

    def test_event_id_is_nullable(self, cols: dict) -> None:
        assert cols["event_id"].nullable is True

    # rule_name
    def test_rule_name_type_is_string_500(self, cols: dict) -> None:
        assert isinstance(cols["rule_name"].type, sa.String)
        assert cols["rule_name"].type.length == 500

    def test_rule_name_is_nullable(self, cols: dict) -> None:
        assert cols["rule_name"].nullable is True

    # occurrence_count
    def test_occurrence_count_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["occurrence_count"].type, sa.Integer)

    def test_occurrence_count_is_not_nullable(self, cols: dict) -> None:
        assert cols["occurrence_count"].nullable is False

    def test_occurrence_count_server_default_is_1(self, cols: dict) -> None:
        sd = cols["occurrence_count"].server_default
        assert sd is not None
        assert "1" in str(sd.arg)

    # cvss_v3
    def test_cvss_v3_type_is_float(self, cols: dict) -> None:
        assert isinstance(cols["cvss_v3"].type, sa.Float)

    def test_cvss_v3_is_nullable(self, cols: dict) -> None:
        assert cols["cvss_v3"].nullable is True

    # confidence
    def test_confidence_type_is_integer(self, cols: dict) -> None:
        assert isinstance(cols["confidence"].type, sa.Integer)

    def test_confidence_is_nullable(self, cols: dict) -> None:
        assert cols["confidence"].nullable is True

    # assigned_to
    def test_assigned_to_type_is_string_255(self, cols: dict) -> None:
        assert isinstance(cols["assigned_to"].type, sa.String)
        assert cols["assigned_to"].type.length == 255

    def test_assigned_to_is_nullable(self, cols: dict) -> None:
        assert cols["assigned_to"].nullable is True

    # time (event timestamp)
    def test_time_type_is_datetime_with_timezone(self, cols: dict) -> None:
        col_type = cols["time"].type
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True

    def test_time_is_not_nullable(self, cols: dict) -> None:
        assert cols["time"].nullable is False

    def test_time_is_indexed(self, cols: dict) -> None:
        assert cols["time"].index is True

    # timestamps
    def test_created_at_has_server_default(self, cols: dict) -> None:
        assert cols["created_at"].server_default is not None

    def test_updated_at_has_server_default(self, cols: dict) -> None:
        assert cols["updated_at"].server_default is not None

    # Parametrized index checks
    @pytest.mark.parametrize(
        "col_name",
        ["severity", "technique_id", "tactic", "status", "host", "time"],
    )
    def test_indexed_columns(self, cols: dict, col_name: str) -> None:
        assert cols[col_name].index is True

    # Parametrized nullability checks
    @pytest.mark.parametrize(
        "col_name",
        [
            "tactic_id", "description", "priority", "user", "process",
            "log_source", "event_id", "rule_name", "cvss_v3",
            "confidence", "assigned_to",
        ],
    )
    def test_nullable_columns(self, cols: dict, col_name: str) -> None:
        assert cols[col_name].nullable is True

    @pytest.mark.parametrize(
        "col_name",
        [
            "id", "score", "severity", "technique_id", "technique_name",
            "tactic", "name", "status", "host", "occurrence_count", "time",
        ],
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

    def test_drops_detections_first(self) -> None:
        """detections is dropped before users (safe reverse order)."""
        mock_op = _run_downgrade()
        first_drop = mock_op.drop_table.call_args_list[0].args[0]
        assert first_drop == "detections"

    def test_drops_users_second(self) -> None:
        mock_op = _run_downgrade()
        second_drop = mock_op.drop_table.call_args_list[1].args[0]
        assert second_drop == "users"

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
# ORM model — User
# ---------------------------------------------------------------------------


class TestUserOrmModel:
    """ORM User model table structure matches the 0001 migration schema."""

    @pytest.fixture(scope="class")
    def table(self):
        from app.models.user import User
        return User.__table__

    def test_table_name_is_users(self, table) -> None:
        assert table.name == "users"

    def test_has_all_expected_columns(self, table) -> None:
        expected = {
            "id", "email", "hashed_password", "full_name", "role", "is_active",
            "created_at", "updated_at",
            # MFA fields added in feature 32.1
            "mfa_secret", "mfa_enabled", "mfa_backup_codes",
        }
        actual = {c.name for c in table.columns}
        assert expected == actual

    def test_id_is_primary_key(self, table) -> None:
        assert table.c.id.primary_key is True

    def test_id_string_length_is_36(self, table) -> None:
        assert table.c.id.type.length == 36

    def test_email_is_not_nullable(self, table) -> None:
        assert table.c.email.nullable is False

    def test_email_has_unique_constraint(self, table) -> None:
        assert table.c.email.unique is True

    def test_email_is_indexed(self, table) -> None:
        assert table.c.email.index is True

    def test_email_string_length_is_255(self, table) -> None:
        assert table.c.email.type.length == 255

    def test_hashed_password_is_not_nullable(self, table) -> None:
        assert table.c.hashed_password.nullable is False

    def test_full_name_is_nullable(self, table) -> None:
        assert table.c.full_name.nullable is True

    def test_role_is_not_nullable(self, table) -> None:
        assert table.c.role.nullable is False

    def test_role_string_length_is_50(self, table) -> None:
        assert table.c.role.type.length == 50

    def test_role_orm_default_is_analyst(self, table) -> None:
        assert table.c.role.default.arg == "analyst"

    def test_is_active_is_boolean(self, table) -> None:
        assert isinstance(table.c.is_active.type, sa.Boolean)

    def test_is_active_is_not_nullable(self, table) -> None:
        assert table.c.is_active.nullable is False

    def test_is_active_orm_default_is_true(self, table) -> None:
        assert table.c.is_active.default.arg is True

    def test_created_at_is_datetime(self, table) -> None:
        assert isinstance(table.c.created_at.type, sa.DateTime)

    def test_updated_at_is_datetime(self, table) -> None:
        assert isinstance(table.c.updated_at.type, sa.DateTime)

    def test_repr_contains_email(self) -> None:
        from app.models.user import User
        u = User(email="test@example.com", hashed_password="h", role="analyst")
        assert "test@example.com" in repr(u)

    def test_repr_contains_role(self) -> None:
        from app.models.user import User
        u = User(email="admin@example.com", hashed_password="h", role="admin")
        assert "admin" in repr(u)

    @pytest.mark.parametrize("role", ["admin", "analyst", "hunter", "engineer"])
    def test_repr_shows_any_valid_role(self, role: str) -> None:
        from app.models.user import User
        u = User(email=f"{role}@test.local", hashed_password="h", role=role)
        assert role in repr(u)


# ---------------------------------------------------------------------------
# ORM model — Detection
# ---------------------------------------------------------------------------


class TestDetectionOrmModel:
    """ORM Detection model table structure matches the 0001 migration schema."""

    @pytest.fixture(scope="class")
    def table(self):
        from app.models.detection import Detection
        return Detection.__table__

    def test_table_name_is_detections(self, table) -> None:
        assert table.name == "detections"

    def test_has_all_expected_columns(self, table) -> None:
        expected = {
            "id", "score", "severity", "technique_id", "technique_name",
            "tactic", "tactic_id", "name", "description", "status",
            "priority", "host", "user", "process", "log_source",
            "event_id", "rule_name", "occurrence_count", "cvss_v3",
            "confidence", "assigned_to", "time", "created_at", "updated_at",
        }
        actual = {c.name for c in table.columns}
        assert expected == actual

    def test_id_is_primary_key(self, table) -> None:
        assert table.c.id.primary_key is True

    def test_id_string_length_is_36(self, table) -> None:
        assert table.c.id.type.length == 36

    def test_score_is_float(self, table) -> None:
        assert isinstance(table.c.score.type, sa.Float)

    def test_score_is_not_nullable(self, table) -> None:
        assert table.c.score.nullable is False

    def test_severity_is_indexed(self, table) -> None:
        assert table.c.severity.index is True

    def test_technique_id_is_indexed(self, table) -> None:
        assert table.c.technique_id.index is True

    def test_tactic_is_indexed(self, table) -> None:
        assert table.c.tactic.index is True

    def test_status_is_indexed(self, table) -> None:
        assert table.c.status.index is True

    def test_host_is_indexed(self, table) -> None:
        assert table.c.host.index is True

    def test_time_is_indexed(self, table) -> None:
        assert table.c.time.index is True

    def test_status_orm_default_is_active(self, table) -> None:
        assert table.c.status.default.arg == "active"

    def test_occurrence_count_orm_default_is_1(self, table) -> None:
        assert table.c.occurrence_count.default.arg == 1

    def test_tactic_id_is_nullable(self, table) -> None:
        assert table.c.tactic_id.nullable is True

    def test_description_is_text_type(self, table) -> None:
        assert isinstance(table.c.description.type, sa.Text)

    def test_time_is_datetime_with_timezone(self, table) -> None:
        col_type = table.c.time.type
        assert isinstance(col_type, sa.DateTime)
        assert col_type.timezone is True

    def test_time_is_not_nullable(self, table) -> None:
        assert table.c.time.nullable is False

    @pytest.mark.parametrize(
        "col_name",
        ["severity", "technique_id", "tactic", "status", "host", "time"],
    )
    def test_indexed_columns(self, table, col_name: str) -> None:
        assert table.c[col_name].index is True

    @pytest.mark.parametrize(
        "col_name",
        [
            "tactic_id", "description", "priority", "user", "process",
            "log_source", "event_id", "rule_name", "cvss_v3",
            "confidence", "assigned_to",
        ],
    )
    def test_nullable_columns(self, table, col_name: str) -> None:
        assert table.c[col_name].nullable is True

    @pytest.mark.parametrize(
        "col_name",
        [
            "id", "score", "severity", "technique_id", "technique_name",
            "tactic", "name", "status", "host", "occurrence_count", "time",
        ],
    )
    def test_non_nullable_columns(self, table, col_name: str) -> None:
        assert table.c[col_name].nullable is False

    def test_repr_contains_severity(self) -> None:
        import uuid
        from datetime import datetime, timezone
        from app.models.detection import Detection
        d = Detection(
            id=str(uuid.uuid4()),
            score=8.5,
            severity="critical",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="execution",
            name="Suspicious Script Execution",
            status="active",
            host="dc01.corp.local",
            time=datetime.now(timezone.utc),
        )
        assert "critical" in repr(d)

    def test_repr_contains_technique_id(self) -> None:
        import uuid
        from datetime import datetime, timezone
        from app.models.detection import Detection
        d = Detection(
            id=str(uuid.uuid4()),
            score=7.0,
            severity="high",
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            tactic="credential-access",
            name="LSASS Memory Dump",
            status="active",
            host="ws01",
            time=datetime.now(timezone.utc),
        )
        assert "T1003" in repr(d)
