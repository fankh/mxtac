"""Add last_login_at and inactive_locked_at to users table (feature 1.7)

Revision ID: 0015
Revises: 0014
Create Date: 2026-02-22
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("inactive_locked_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "inactive_locked_at")
    op.drop_column("users", "last_login_at")
