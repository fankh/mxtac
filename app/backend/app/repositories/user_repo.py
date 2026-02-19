"""User repository — async DB operations for the users table."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.user import User


class UserRepo:

    @staticmethod
    async def list(session: AsyncSession) -> list[User]:
        result = await session.execute(select(User).order_by(User.email))
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(session: AsyncSession, user_id: str) -> User | None:
        result = await session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_email(session: AsyncSession, email: str) -> User | None:
        result = await session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> User:
        user = User(**kwargs)
        session.add(user)
        await session.flush()
        return user

    @staticmethod
    async def update(session: AsyncSession, user_id: str, **kwargs) -> User | None:
        user = await UserRepo.get_by_id(session, user_id)
        if not user:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(user, k, v)
        await session.flush()
        return user

    @staticmethod
    async def delete(session: AsyncSession, user_id: str) -> bool:
        user = await UserRepo.get_by_id(session, user_id)
        if not user:
            return False
        await session.delete(user)
        await session.flush()
        return True

    @staticmethod
    async def count(session: AsyncSession) -> int:
        result = await session.scalar(select(func.count()).select_from(User))
        return result or 0
