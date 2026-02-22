"""Repository for OIDC provider and user-link data access (feature 1.9)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.oidc_provider import OIDCProvider, OIDCUserLink


class OIDCProviderRepo:
    """Data-access helpers for the oidc_providers table."""

    @staticmethod
    async def list_active(db: AsyncSession) -> list[OIDCProvider]:
        result = await db.execute(
            select(OIDCProvider).where(OIDCProvider.is_active == True).order_by(OIDCProvider.name)
        )
        return list(result.scalars().all())

    @staticmethod
    async def list_all(db: AsyncSession) -> list[OIDCProvider]:
        result = await db.execute(select(OIDCProvider).order_by(OIDCProvider.name))
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(db: AsyncSession, provider_id: str) -> OIDCProvider | None:
        result = await db.execute(
            select(OIDCProvider).where(OIDCProvider.id == provider_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_name(db: AsyncSession, name: str) -> OIDCProvider | None:
        result = await db.execute(
            select(OIDCProvider).where(OIDCProvider.name == name)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(db: AsyncSession, **kwargs) -> OIDCProvider:
        provider = OIDCProvider(**kwargs)
        db.add(provider)
        await db.flush()
        await db.refresh(provider)
        return provider

    @staticmethod
    async def update(db: AsyncSession, provider_id: str, **kwargs) -> OIDCProvider | None:
        provider = await OIDCProviderRepo.get_by_id(db, provider_id)
        if not provider:
            return None
        for key, value in kwargs.items():
            if value is not None:
                setattr(provider, key, value)
        await db.flush()
        await db.refresh(provider)
        return provider

    @staticmethod
    async def deactivate(db: AsyncSession, provider_id: str) -> bool:
        provider = await OIDCProviderRepo.get_by_id(db, provider_id)
        if not provider:
            return False
        provider.is_active = False
        await db.flush()
        return True


class OIDCUserLinkRepo:
    """Data-access helpers for the oidc_user_links table."""

    @staticmethod
    async def get_by_subject(
        db: AsyncSession, provider_id: str, subject: str
    ) -> OIDCUserLink | None:
        result = await db.execute(
            select(OIDCUserLink).where(
                OIDCUserLink.provider_id == provider_id,
                OIDCUserLink.subject == subject,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(
        db: AsyncSession, user_id: str, provider_id: str, subject: str
    ) -> OIDCUserLink:
        link = OIDCUserLink(user_id=user_id, provider_id=provider_id, subject=subject)
        db.add(link)
        await db.flush()
        await db.refresh(link)
        return link
