"""Add routing_rules column to notification_channels (feature 27.6)

Revision ID: 0020
Revises: 0019
Create Date: 2026-02-22
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "notification_channels",
        sa.Column(
            "routing_rules",
            sa.Text(),
            nullable=True,
            server_default="[]",
        ),
    )


def downgrade() -> None:
    op.drop_column("notification_channels", "routing_rules")
