"""Repository for SAML provider and user-link data access (feature 1.10)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.saml_provider import SAMLProvider, SAMLUserLink


class SAMLProviderRepo:
    """Data-access helpers for the saml_providers table."""

    @staticmethod
    async def list_active(db: AsyncSession) -> list[SAMLProvider]:
        result = await db.execute(
            select(SAMLProvider).where(SAMLProvider.is_active == True).order_by(SAMLProvider.name)
        )
        return list(result.scalars().all())

    @staticmethod
    async def list_all(db: AsyncSession) -> list[SAMLProvider]:
        result = await db.execute(select(SAMLProvider).order_by(SAMLProvider.name))
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(db: AsyncSession, provider_id: str) -> SAMLProvider | None:
        result = await db.execute(
            select(SAMLProvider).where(SAMLProvider.id == provider_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_name(db: AsyncSession, name: str) -> SAMLProvider | None:
        result = await db.execute(
            select(SAMLProvider).where(SAMLProvider.name == name)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(db: AsyncSession, **kwargs) -> SAMLProvider:
        provider = SAMLProvider(**kwargs)
        db.add(provider)
        await db.flush()
        await db.refresh(provider)
        return provider

    @staticmethod
    async def update(db: AsyncSession, provider_id: str, **kwargs) -> SAMLProvider | None:
        provider = await SAMLProviderRepo.get_by_id(db, provider_id)
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
        provider = await SAMLProviderRepo.get_by_id(db, provider_id)
        if not provider:
            return False
        provider.is_active = False
        await db.flush()
        return True


class SAMLUserLinkRepo:
    """Data-access helpers for the saml_user_links table."""

    @staticmethod
    async def get_by_name_id(
        db: AsyncSession, provider_id: str, name_id: str
    ) -> SAMLUserLink | None:
        result = await db.execute(
            select(SAMLUserLink).where(
                SAMLUserLink.provider_id == provider_id,
                SAMLUserLink.name_id == name_id,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(
        db: AsyncSession, user_id: str, provider_id: str, name_id: str
    ) -> SAMLUserLink:
        link = SAMLUserLink(user_id=user_id, provider_id=provider_id, name_id=name_id)
        db.add(link)
        await db.flush()
        await db.refresh(link)
        return link
