import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings

logger = logging.getLogger(__name__)

engine = create_async_engine(
    settings.scheduler_db_url,
    echo=False,
    connect_args={"check_same_thread": False},
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Create all tables if they don't exist."""
    from .models import Base

    # Ensure the data directory exists
    db_path = settings.db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await _ensure_columns()


async def _ensure_columns():
    """Add new columns to existing tables (safe for SQLite)."""
    migrations = [
        ("tasks", "test_status", "VARCHAR(20)"),
        ("tasks", "test_output", "TEXT"),
        ("tasks", "verification_status", "VARCHAR(20)"),
        ("tasks", "verification_output", "TEXT"),
    ]
    async with engine.begin() as conn:
        for table, column, col_type in migrations:
            try:
                await conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                )
                logger.info(f"Added column {table}.{column}")
            except Exception:
                pass  # Column already exists


async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session
