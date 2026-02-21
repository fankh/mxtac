"""Agent repository — async DB operations for the agents table."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.agent import Agent


class AgentRepo:

    @staticmethod
    async def list(session: AsyncSession) -> list[Agent]:
        result = await session.execute(
            select(Agent).order_by(Agent.hostname)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(session: AsyncSession, agent_id: str) -> Agent | None:
        result = await session.execute(
            select(Agent).where(Agent.id == agent_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_hostname(session: AsyncSession, hostname: str) -> Agent | None:
        result = await session.execute(
            select(Agent).where(Agent.hostname == hostname)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> Agent:
        agent = Agent(**kwargs)
        session.add(agent)
        await session.flush()
        return agent

    @staticmethod
    async def update(session: AsyncSession, agent_id: str, **kwargs) -> Agent | None:
        agent = await AgentRepo.get_by_id(session, agent_id)
        if not agent:
            return None
        for k, v in kwargs.items():
            setattr(agent, k, v)
        await session.flush()
        return agent

    @staticmethod
    async def update_heartbeat(session: AsyncSession, agent_id: str) -> Agent | None:
        """Record a heartbeat: set last_heartbeat=now and status=online."""
        agent = await AgentRepo.get_by_id(session, agent_id)
        if not agent:
            return None
        agent.last_heartbeat = datetime.now(timezone.utc)
        agent.status = "online"
        await session.flush()
        return agent

    @staticmethod
    async def delete(session: AsyncSession, agent_id: str) -> bool:
        agent = await AgentRepo.get_by_id(session, agent_id)
        if not agent:
            return False
        await session.delete(agent)
        await session.flush()
        return True

    @staticmethod
    async def degrade_stale_agents(session: AsyncSession) -> tuple[int, int]:
        """Auto-degrade agents that have stopped sending heartbeats.

        Rules:
        - No heartbeat for >= 2 min and status=online  → degraded
        - No heartbeat for >= 10 min (any non-offline)  → offline

        Returns (newly_degraded_count, newly_offline_count).
        """
        now = datetime.now(timezone.utc)
        degraded_cutoff = now - timedelta(minutes=2)
        offline_cutoff = now - timedelta(minutes=10)

        # Fetch all agents that are still considered active
        result = await session.execute(
            select(Agent).where(Agent.status.in_(["online", "degraded"]))
        )
        active_agents = list(result.scalars().all())

        degraded_count = 0
        offline_count = 0

        for agent in active_agents:
            if agent.last_heartbeat is None:
                # Never sent a heartbeat — mark offline immediately
                agent.status = "offline"
                offline_count += 1
                continue

            # Normalise to UTC-aware for safe comparison regardless of DB backend
            hb = agent.last_heartbeat
            if hb.tzinfo is None:
                hb = hb.replace(tzinfo=timezone.utc)

            if hb < offline_cutoff:
                agent.status = "offline"
                offline_count += 1
            elif hb < degraded_cutoff and agent.status == "online":
                agent.status = "degraded"
                degraded_count += 1
            # else: recently seen or already degraded within the 2-10 min window

        if active_agents:
            await session.flush()

        return degraded_count, offline_count
