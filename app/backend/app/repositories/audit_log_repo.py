"""Audit log repository — async DB operations for the audit_logs table."""

from __future__ import annotations

from datetime import datetime

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
