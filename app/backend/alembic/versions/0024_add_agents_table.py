"""Agents table already created in migration 0011 — this is a no-op placeholder.

The agents table was first introduced in revision 0011. A previous retry
attempt generated a duplicate migration here. The agents table DDL lives in
0011; this revision exists only to maintain the revision chain integrity.

Revision ID: 0024
Revises: 0023
Create Date: 2026-02-27
"""

from typing import Union

from alembic import op

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Agents table already created in revision 0011. Nothing to do.
    pass


def downgrade() -> None:
    # Nothing to undo — agents table lifecycle is managed in revision 0011.
    pass
