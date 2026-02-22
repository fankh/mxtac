"""Data-access layer for Permission Sets (Feature 3.9)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.permission_set import PermissionSet
from ..models.base import new_uuid


class PermissionSetRepo:

    @staticmethod
    async def create(
        db: AsyncSession,
        name: str,
        permissions: list[str],
        created_by: str,
        description: str | None = None,
    ) -> PermissionSet:
        ps = PermissionSet(
            id=new_uuid(),
            name=name,
            description=description,
            permissions=permissions,
            created_by=created_by,
        )
        db.add(ps)
        await db.flush()
        return ps

    @staticmethod
    async def get_by_id(db: AsyncSession, set_id: str) -> PermissionSet | None:
        result = await db.execute(
            select(PermissionSet).where(PermissionSet.id == set_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_name(db: AsyncSession, name: str) -> PermissionSet | None:
        result = await db.execute(
            select(PermissionSet).where(PermissionSet.name == name)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def list_active(db: AsyncSession) -> list[PermissionSet]:
        """Return all active permission sets, ordered alphabetically by name."""
        result = await db.execute(
            select(PermissionSet)
            .where(PermissionSet.is_active == True)  # noqa: E712
            .order_by(PermissionSet.name)
        )
        return list(result.scalars().all())

    @staticmethod
    async def update(
        db: AsyncSession,
        set_id: str,
        name: str | None = None,
        description: str | None = None,
        permissions: list[str] | None = None,
    ) -> PermissionSet | None:
        result = await db.execute(
            select(PermissionSet).where(PermissionSet.id == set_id)
        )
        ps = result.scalar_one_or_none()
        if ps is None:
            return None
        if name is not None:
            ps.name = name
        if description is not None:
            ps.description = description
        if permissions is not None:
            ps.permissions = permissions
        await db.flush()
        return ps

    @staticmethod
    async def delete(db: AsyncSession, set_id: str) -> bool:
        """Soft-delete (deactivate) a permission set.  Returns True if found."""
        result = await db.execute(
            select(PermissionSet).where(PermissionSet.id == set_id)
        )
        ps = result.scalar_one_or_none()
        if ps is None:
            return False
        ps.is_active = False
        await db.flush()
        return True
