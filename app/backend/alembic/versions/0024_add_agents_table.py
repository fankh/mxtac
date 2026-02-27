"""Add agents table (TASK-4.5 — Agent Registry & Management API)

Revision ID: 0024
Revises: 0023
Create Date: 2026-02-27
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("agent_type", sa.String(20), nullable=False),
        sa.Column("version", sa.String(50), nullable=False, server_default="unknown"),
        sa.Column("status", sa.String(20), nullable=False, server_default="offline"),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
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
    op.create_index("ix_agents_hostname", "agents", ["hostname"], unique=True)
    op.create_index("ix_agents_agent_type", "agents", ["agent_type"])
    op.create_index("ix_agents_status", "agents", ["status"])


def downgrade() -> None:
    op.drop_index("ix_agents_status", table_name="agents")
    op.drop_index("ix_agents_agent_type", table_name="agents")
    op.drop_index("ix_agents_hostname", table_name="agents")
    op.drop_table("agents")
