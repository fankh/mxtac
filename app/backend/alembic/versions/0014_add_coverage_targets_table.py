"""Add coverage_targets table for configurable coverage threshold (Feature 16.7)

Revision ID: 0014
Revises: 0013
Create Date: 2026-02-21
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "coverage_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_pct", sa.Float, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("label", sa.String(255), nullable=True),
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
    )


def downgrade() -> None:
    op.drop_table("coverage_targets")
