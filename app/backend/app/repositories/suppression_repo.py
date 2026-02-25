"""Repository for alert suppression rules.

Provides CRUD operations and the core ``match`` query used by AlertManager
to determine whether an incoming alert should be suppressed.
"""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from math import ceil
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.validators import escape_like
from ..models.suppression_rule import SuppressionRule


class SuppressionRepo:
    """Data-access layer for SuppressionRule entities."""

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    @staticmethod
    async def list(
        session: AsyncSession,
        page: int = 1,
        page_size: int = 25,
        is_active: bool | None = None,
        search: str | None = None,
    ) -> tuple[list[SuppressionRule], int]:
        """Return paginated suppression rules.

        Args:
            page: 1-based page number.
            page_size: Results per page (1-100).
            is_active: If set, filter by active/inactive status.
            search: Substring match on name or reason.
        """
        q = select(SuppressionRule)
        if is_active is not None:
            q = q.where(SuppressionRule.is_active == is_active)
        if search:
            pattern = f"%{escape_like(search)}%"
            q = q.where(
                SuppressionRule.name.ilike(pattern, escape="\\")
                | SuppressionRule.reason.ilike(pattern, escape="\\")
            )
        q = q.order_by(SuppressionRule.id.desc())

        count_q = select(func.count()).select_from(q.subquery())
        total = (await session.execute(count_q)).scalar_one()

        offset = (page - 1) * page_size
        items = (await session.execute(q.offset(offset).limit(page_size))).scalars().all()
        return list(items), total

    @staticmethod
    async def get(session: AsyncSession, rule_id: int) -> SuppressionRule | None:
        return await session.get(SuppressionRule, rule_id)

    @staticmethod
    async def create(session: AsyncSession, **kwargs: Any) -> SuppressionRule:
        rule = SuppressionRule(**kwargs)
        session.add(rule)
        await session.flush()
        await session.refresh(rule)
        return rule

    @staticmethod
    async def update(
        session: AsyncSession, rule_id: int, **kwargs: Any
    ) -> SuppressionRule | None:
        rule = await session.get(SuppressionRule, rule_id)
        if rule is None:
            return None
        for key, value in kwargs.items():
            setattr(rule, key, value)
        await session.flush()
        await session.refresh(rule)
        return rule

    @staticmethod
    async def delete(session: AsyncSession, rule_id: int) -> bool:
        rule = await session.get(SuppressionRule, rule_id)
        if rule is None:
            return False
        await session.delete(rule)
        await session.flush()
        return True

    # ------------------------------------------------------------------
    # Suppression check
    # ------------------------------------------------------------------

    @staticmethod
    async def match(
        session: AsyncSession,
        *,
        rule_id_val: str,
        host_val: str,
        technique_id_val: str,
        tactic_val: str,
        severity_val: str,
    ) -> SuppressionRule | None:
        """Return the first active, non-expired suppression rule that matches all
        non-null fields against the incoming alert, or None if none match.

        Matching semantics:
        - rule_id   — exact match (case-sensitive)
        - host      — fnmatch wildcard (e.g. "win-*", "srv-dc01")
        - technique_id — exact match (case-sensitive)
        - tactic    — case-insensitive exact match
        - severity  — case-insensitive exact match

        All non-null fields must match (AND logic).  NULL fields on the rule
        are treated as wildcards (match anything).

        Returns:
            The first matching SuppressionRule, or None.
        """
        now = datetime.now(timezone.utc)

        # Fetch all active, non-expired candidates from DB.
        # We apply coarse DB filters (is_active, expires_at) and then apply
        # fine-grained Python matching for host (fnmatch) and case-insensitive
        # fields.  The table is typically small so the in-memory scan is fine.
        q = (
            select(SuppressionRule)
            .where(SuppressionRule.is_active == True)  # noqa: E712
            .where(
                (SuppressionRule.expires_at == None)  # noqa: E711
                | (SuppressionRule.expires_at > now)
            )
        )
        candidates = (await session.execute(q)).scalars().all()

        for rule in candidates:
            if not _rule_matches(rule, rule_id_val, host_val, technique_id_val, tactic_val, severity_val):
                continue
            # Record the hit — update count and timestamp
            await session.execute(
                update(SuppressionRule)
                .where(SuppressionRule.id == rule.id)
                .values(
                    hit_count=SuppressionRule.hit_count + 1,
                    last_hit_at=now,
                )
            )
            return rule

        return None


# ------------------------------------------------------------------
# Private helpers
# ------------------------------------------------------------------


def _rule_matches(
    rule: SuppressionRule,
    rule_id_val: str,
    host_val: str,
    technique_id_val: str,
    tactic_val: str,
    severity_val: str,
) -> bool:
    """Return True if every non-null field on *rule* matches the alert values."""
    if rule.rule_id is not None and rule.rule_id != rule_id_val:
        return False
    if rule.host is not None and not fnmatch.fnmatch(host_val.lower(), rule.host.lower()):
        return False
    if rule.technique_id is not None and rule.technique_id != technique_id_val:
        return False
    if rule.tactic is not None and rule.tactic.lower() != tactic_val.lower():
        return False
    if rule.severity is not None and rule.severity.lower() != severity_val.lower():
        return False
    return True
