from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def _build_engine():
    url = settings.database_url
    if _is_sqlite(url):
        # SQLite does not support connection pool settings (pool_size, max_overflow).
        # check_same_thread=False is required for async use across coroutines.
        return create_async_engine(
            url,
            echo=settings.debug,
            connect_args={"check_same_thread": False},
        )
    return create_async_engine(
        url,
        echo=settings.debug,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


engine = _build_engine()

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a DB session, auto-closes on exit."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
