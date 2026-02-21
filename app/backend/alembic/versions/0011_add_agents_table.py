"""Add agents table for agent registry and management (TASK-4.5)

Revision ID: 0011
Revises: 0010
Create Date: 2026-02-21
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
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
        sa.Column("config_json", sa.Text, nullable=False, server_default="{}"),
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
        sa.UniqueConstraint("hostname", name="uq_agents_hostname"),
    )
    op.create_index("ix_agents_hostname", "agents", ["hostname"])
    op.create_index("ix_agents_agent_type", "agents", ["agent_type"])
    op.create_index("ix_agents_status", "agents", ["status"])


def downgrade() -> None:
    op.drop_index("ix_agents_status", table_name="agents")
    op.drop_index("ix_agents_agent_type", table_name="agents")
    op.drop_index("ix_agents_hostname", table_name="agents")
    op.drop_table("agents")
