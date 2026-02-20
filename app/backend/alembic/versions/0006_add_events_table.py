"""Add events table for PostgreSQL-backed event search (feature 11.1)

Revision ID: 0006
Revises: 0005
Create Date: 2026-02-20
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_uid", sa.String(64), nullable=True),
        sa.Column("time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("class_name", sa.String(64), nullable=True),
        sa.Column("class_uid", sa.Integer, nullable=True),
        sa.Column("severity_id", sa.Integer, nullable=True),
        sa.Column("src_ip", sa.String(45), nullable=True),
        sa.Column("dst_ip", sa.String(45), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("process_hash", sa.String(128), nullable=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("source", sa.String(32), nullable=True),
        sa.Column("raw", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_events_time", "events", ["time"])
    op.create_index("ix_events_event_uid", "events", ["event_uid"])
    op.create_index("ix_events_severity_id", "events", ["severity_id"])
    op.create_index("ix_events_src_ip", "events", ["src_ip"])
    op.create_index("ix_events_dst_ip", "events", ["dst_ip"])
    op.create_index("ix_events_hostname", "events", ["hostname"])
    op.create_index("ix_events_username", "events", ["username"])
    op.create_index("ix_events_process_hash", "events", ["process_hash"])
    op.create_index("ix_events_source", "events", ["source"])


def downgrade() -> None:
    op.drop_index("ix_events_source", table_name="events")
    op.drop_index("ix_events_process_hash", table_name="events")
    op.drop_index("ix_events_username", table_name="events")
    op.drop_index("ix_events_hostname", table_name="events")
    op.drop_index("ix_events_dst_ip", table_name="events")
    op.drop_index("ix_events_src_ip", table_name="events")
    op.drop_index("ix_events_severity_id", table_name="events")
    op.drop_index("ix_events_event_uid", table_name="events")
    op.drop_index("ix_events_time", table_name="events")
    op.drop_table("events")
