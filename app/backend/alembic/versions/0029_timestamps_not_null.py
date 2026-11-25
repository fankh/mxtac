"""Make created_at / updated_at NOT NULL on the core tables.

Migrations 0001-0006 created these columns as nullable, while the models
(``TimestampMixin``) declare them ``NOT NULL``.  Both columns have a
``now()`` server default, so a NULL only appears when a row explicitly wrote
one; such rows get the current time before the constraint is added.

Batch mode lets the change run on SQLite (table copy) as well as PostgreSQL
(plain ``ALTER COLUMN``).

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-25
"""

import sqlalchemy as sa

from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels = None
depends_on = None

_TABLES = ("users", "detections", "rules", "connectors", "incidents", "events")
_COLUMNS = ("created_at", "updated_at")


def _set_nullable(nullable: bool) -> None:
    for table in _TABLES:
        with op.batch_alter_table(table) as batch:
            for column in _COLUMNS:
                batch.alter_column(
                    column,
                    existing_type=sa.DateTime(timezone=True),
                    existing_server_default=sa.func.now(),
                    nullable=nullable,
                )


def upgrade() -> None:
    for table in _TABLES:
        for column in _COLUMNS:
            op.execute(
                f"UPDATE {table} SET {column} = CURRENT_TIMESTAMP WHERE {column} IS NULL"
            )
    _set_nullable(False)


def downgrade() -> None:
    _set_nullable(True)
