"""Add coverage_snapshots table for daily ATT&CK coverage trend (Feature 16.6)

Revision ID: 0013
Revises: 0012
Create Date: 2026-02-21
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "coverage_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("snapshot_date", sa.Date, nullable=False),
        sa.Column("coverage_pct", sa.Float, nullable=False),
        sa.Column("covered_count", sa.Integer, nullable=False),
        sa.Column("total_count", sa.Integer, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("snapshot_date", name="uq_coverage_snapshots_date"),
    )
    op.create_index("ix_coverage_snapshots_date", "coverage_snapshots", ["snapshot_date"])


def downgrade() -> None:
    op.drop_index("ix_coverage_snapshots_date", table_name="coverage_snapshots")
    op.drop_table("coverage_snapshots")
