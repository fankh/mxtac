"""Add rules and connectors tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-19
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("rule_type", sa.String(30), nullable=False, server_default="sigma"),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="experimental"),
        sa.Column("level", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("logsource_product", sa.String(100), nullable=True),
        sa.Column("logsource_category", sa.String(100), nullable=True),
        sa.Column("logsource_service", sa.String(100), nullable=True),
        sa.Column("technique_ids", sa.Text, nullable=True),
        sa.Column("tactic_ids", sa.Text, nullable=True),
        sa.Column("hit_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("fp_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_hit_at", sa.String(50), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("source", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "connectors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("connector_type", sa.String(50), nullable=False, index=True),
        sa.Column("config_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(20), nullable=False, server_default="inactive"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_seen_at", sa.String(50), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("events_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("errors_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("connectors")
    op.drop_table("rules")
