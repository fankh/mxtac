"""Add reports table — feature 31.2 / 31.4.

Revision ID: 0025
Revises: 0024
Create Date: 2026-02-27
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: Union[str, None] = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("template_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="generating"),
        sa.Column("format", sa.String(10), nullable=False, server_default="json"),
        sa.Column("params_json", sa.JSON(), nullable=False),
        sa.Column("content_json", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(254), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_reports_template_type", "reports", ["template_type"])
    op.create_index("ix_reports_status", "reports", ["status"])
    op.create_index("ix_reports_created_by", "reports", ["created_by"])


def downgrade() -> None:
    op.drop_index("ix_reports_created_by", table_name="reports")
    op.drop_index("ix_reports_status", table_name="reports")
    op.drop_index("ix_reports_template_type", table_name="reports")
    op.drop_table("reports")
