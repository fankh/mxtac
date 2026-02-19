"""Initial schema: users and detections tables

Revision ID: 0001
Revises:
Create Date: 2026-02-19
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("role", sa.String(50), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "detections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("score", sa.Float, nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("technique_id", sa.String(20), nullable=False, index=True),
        sa.Column("technique_name", sa.String(255), nullable=False),
        sa.Column("tactic", sa.String(100), nullable=False, index=True),
        sa.Column("tactic_id", sa.String(20), nullable=True),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="active", index=True),
        sa.Column("priority", sa.String(20), nullable=True),
        sa.Column("host", sa.String(255), nullable=False, index=True),
        sa.Column("user", sa.String(255), nullable=True),
        sa.Column("process", sa.String(500), nullable=True),
        sa.Column("log_source", sa.String(100), nullable=True),
        sa.Column("event_id", sa.String(50), nullable=True),
        sa.Column("rule_name", sa.String(500), nullable=True),
        sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("cvss_v3", sa.Float, nullable=True),
        sa.Column("confidence", sa.Integer, nullable=True),
        sa.Column("assigned_to", sa.String(255), nullable=True),
        sa.Column("time", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("detections")
    op.drop_table("users")
