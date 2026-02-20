"""Add notification_channels table

Revision ID: 0005
Revises: 0004
Create Date: 2026-02-20
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("channel_type", sa.String(50), nullable=False),
        sa.Column("config_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("min_severity", sa.String(20), nullable=False, server_default="low"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_notification_channels_channel_type", "notification_channels", ["channel_type"])


def downgrade() -> None:
    op.drop_index("ix_notification_channels_channel_type", table_name="notification_channels")
    op.drop_table("notification_channels")
