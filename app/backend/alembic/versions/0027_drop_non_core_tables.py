"""Drop the tables of features removed from the community core.

The lean core keeps auth, users, detections, rules, coverage, hunt/search,
incidents and the Wazuh / Zeek / Suricata / syslog sources.  The tables that
belonged to SSO, threat intelligence, assets, notifications, endpoint agents,
API keys, permission sets, suppression rules and reports are dropped here.

This migration is one-way: the dropped data cannot be restored by a downgrade.

Revision ID: 0027
Revises: 0026
Create Date: 2026-11-24
"""

from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels = None
depends_on = None

# Child tables come before the tables their foreign keys point to.
_DROPPED_TABLES = (
    "oidc_user_links",
    "oidc_providers",
    "saml_user_links",
    "saml_providers",
    "api_keys",
    "permission_sets",
    "iocs",
    "assets",
    "notification_channels",
    "agents",
    "suppression_rules",
    "scheduled_reports",
    "reports",
)


def upgrade() -> None:
    for table in _DROPPED_TABLES:
        op.execute(f"DROP TABLE IF EXISTS {table}")


def downgrade() -> None:
    raise NotImplementedError(
        "Migration 0027 drops the tables of features that were removed from the "
        "community core and cannot be downgraded. Restore the database from a "
        "backup taken before the upgrade to get those tables back."
    )
