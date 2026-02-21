"""Add saved_queries table for named hunt query persistence (Feature 11.7)

Revision ID: 0012
Revises: 0011
Create Date: 2026-02-21
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saved_queries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("query", sa.Text, nullable=True),
        sa.Column("filters", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("time_from", sa.String(50), nullable=False, server_default="now-24h"),
        sa.Column("time_to", sa.String(50), nullable=False, server_default="now"),
        sa.Column("created_by", sa.String(255), nullable=False),
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
    op.create_index("ix_saved_queries_created_by", "saved_queries", ["created_by"])


def downgrade() -> None:
    op.drop_index("ix_saved_queries_created_by", table_name="saved_queries")
    op.drop_table("saved_queries")
