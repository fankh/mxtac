"""Add incidents table

Revision ID: 0003
Revises: 0002
Create Date: 2026-02-20
"""
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="new", index=True),
        sa.Column("priority", sa.Integer, nullable=False, server_default="3"),
        sa.Column("assigned_to", sa.String(255), nullable=True, index=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("detection_ids", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("technique_ids", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("tactic_ids", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("hosts", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("ttd_seconds", sa.Integer, nullable=True),
        sa.Column("ttr_seconds", sa.Integer, nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("incidents")
