"""Audit log repository — async DB operations for the audit_logs table."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.audit_log import AuditLog
from ..models.base import new_uuid


class AuditLogRepo:

    @staticmethod
    async def create(
        session: AsyncSession,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str = "",
        details: dict | None = None,
        request_ip: str | None = None,
        request_method: str | None = None,
        request_path: str | None = None,
        user_agent: str | None = None,
        timestamp: datetime | None = None,
    ) -> AuditLog:
        """Insert a new audit log entry and flush to the session."""
        kwargs: dict = {
            "id": new_uuid(),
            "actor": actor,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id or None,
            "details": details or {},
            "request_ip": request_ip,
            "request_method": request_method,
            "request_path": request_path,
            "user_agent": user_agent,
        }
        if timestamp is not None:
            kwargs["timestamp"] = timestamp

        entry = AuditLog(**kwargs)
        session.add(entry)
        await session.flush()
        return entry

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        skip: int = 0,
        limit: int = 50,
        actor: str | None = None,
        action: str | None = None,
        resource_type: str | None = None,
        from_ts: datetime | None = None,
        to_ts: datetime | None = None,
    ) -> tuple[list[AuditLog], int]:
        """Return (items, total) with optional filtering and offset/limit pagination.

        Results are sorted newest-first.
        """
        q = select(AuditLog)

        if actor is not None:
            q = q.where(AuditLog.actor == actor)
        if action is not None:
            q = q.where(AuditLog.action == action)
        if resource_type is not None:
            q = q.where(AuditLog.resource_type == resource_type)
        if from_ts is not None:
            q = q.where(AuditLog.timestamp >= from_ts)
        if to_ts is not None:
            q = q.where(AuditLog.timestamp <= to_ts)

        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        q = q.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit)
        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def get_by_id(session: AsyncSession, entry_id: str) -> AuditLog | None:
        result = await session.execute(
            select(AuditLog).where(AuditLog.id == entry_id)
        )
        return result.scalar_one_or_none()
