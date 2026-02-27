"""Add scheduled_reports table — feature 31.4.

Stores cron-based automated report schedule configurations.

Revision ID: 0026
Revises: 0025
Create Date: 2026-02-27
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: Union[str, None] = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scheduled_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("template_type", sa.String(50), nullable=False),
        # 5-field cron expression (UTC), e.g. "0 8 * * 1"
        sa.Column("schedule", sa.String(100), nullable=False),
        sa.Column("params_json", sa.JSON(), nullable=False),
        sa.Column("format", sa.String(10), nullable=False, server_default="json"),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        # Optional: forward report notification to this channel after generation
        sa.Column("notification_channel_id", sa.Integer(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
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
    op.create_index(
        "ix_scheduled_reports_template_type",
        "scheduled_reports",
        ["template_type"],
    )
    op.create_index(
        "ix_scheduled_reports_next_run_at",
        "scheduled_reports",
        ["next_run_at"],
    )
    op.create_index(
        "ix_scheduled_reports_created_by",
        "scheduled_reports",
        ["created_by"],
    )


def downgrade() -> None:
    op.drop_index("ix_scheduled_reports_created_by", table_name="scheduled_reports")
    op.drop_index("ix_scheduled_reports_next_run_at", table_name="scheduled_reports")
    op.drop_index("ix_scheduled_reports_template_type", table_name="scheduled_reports")
    op.drop_table("scheduled_reports")
