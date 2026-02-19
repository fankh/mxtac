"""Rule repository — async DB operations for the rules table."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.rule import Rule


class RuleRepo:

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        enabled: bool | None = None,
        level: str | None = None,
    ) -> list[Rule]:
        q = select(Rule)
        if enabled is not None:
            q = q.where(Rule.enabled == enabled)
        if level:
            q = q.where(Rule.level == level)
        q = q.order_by(Rule.created_at.desc())
        result = await session.execute(q)
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(session: AsyncSession, rule_id: str) -> Rule | None:
        result = await session.execute(select(Rule).where(Rule.id == rule_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> Rule:
        rule = Rule(**kwargs)
        session.add(rule)
        await session.flush()
        return rule

    @staticmethod
    async def update(session: AsyncSession, rule_id: str, **kwargs) -> Rule | None:
        rule = await RuleRepo.get_by_id(session, rule_id)
        if not rule:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(rule, k, v)
        await session.flush()
        return rule

    @staticmethod
    async def enable(session: AsyncSession, rule_id: str) -> Rule | None:
        return await RuleRepo.update(session, rule_id, enabled=True)

    @staticmethod
    async def disable(session: AsyncSession, rule_id: str) -> Rule | None:
        return await RuleRepo.update(session, rule_id, enabled=False)

    @staticmethod
    async def delete(session: AsyncSession, rule_id: str) -> bool:
        rule = await RuleRepo.get_by_id(session, rule_id)
        if not rule:
            return False
        await session.delete(rule)
        await session.flush()
        return True

    @staticmethod
    async def count(session: AsyncSession) -> int:
        result = await session.scalar(select(func.count()).select_from(Rule))
        return result or 0
