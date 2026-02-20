"""Shared pytest fixtures for the MxTac backend test suite.

Provides:
- ``db_session``      — isolated in-memory SQLite AsyncSession
- ``client``          — httpx AsyncClient with get_db overridden to SQLite
- ``viewer_headers``  — JWT auth headers for the viewer role
- ``analyst_headers`` — JWT auth headers for the analyst role
- ``hunter_headers``  — JWT auth headers for the hunter role
- ``engineer_headers``— JWT auth headers for the engineer role
- ``admin_headers``   — JWT auth headers for the admin role
- ``auth_headers``    — backward-compat alias for analyst_headers
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import timedelta
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.core.rate_limit as _rl_module
from app.core.database import get_db
from app.core.security import create_access_token
from app.main import app
from app.models import Base

# ---------------------------------------------------------------------------
# Rate limiter reset — clear in-memory counters and force in-memory fallback
# between tests so that accumulated request counts (from Valkey or in-memory)
# do not cause spurious 429 responses.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_rate_limiter() -> None:
    """Reset the rate limiter before every test.

    Clears the in-memory counter dict AND patches the Valkey client within
    the rate-limit module so that the in-memory fallback is always used.
    This prevents Valkey state from leaking across test runs.
    """
    _rl_module._rate_limiter._mem.clear()
    with patch(
        "app.core.rate_limit.get_valkey_client",
        side_effect=Exception("Valkey disabled in tests"),
    ):
        yield


# ---------------------------------------------------------------------------
# SQLite in-memory engine + session
# ---------------------------------------------------------------------------

_SQLITE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Isolated in-memory SQLite session; schema created fresh, rolled back after test."""
    engine = create_async_engine(_SQLITE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
        await session.rollback()
    await engine.dispose()


# ---------------------------------------------------------------------------
# Async HTTP test client with DB override
# ---------------------------------------------------------------------------


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Async test client; get_db dependency overridden with the in-memory SQLite session."""

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Auth header helpers — create JWT directly (no DB login required)
# ---------------------------------------------------------------------------


def _make_auth_headers(email: str, role: str) -> dict[str, str]:
    token = create_access_token(
        {"sub": email, "role": role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers() -> dict[str, str]:
    return _make_auth_headers("viewer@mxtac.local", "viewer")


@pytest.fixture
def analyst_headers() -> dict[str, str]:
    return _make_auth_headers("analyst@mxtac.local", "analyst")


@pytest.fixture
def hunter_headers() -> dict[str, str]:
    return _make_auth_headers("hunter@mxtac.local", "hunter")


@pytest.fixture
def engineer_headers() -> dict[str, str]:
    return _make_auth_headers("engineer@mxtac.local", "engineer")


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return _make_auth_headers("admin@mxtac.local", "admin")


@pytest.fixture
def auth_headers(analyst_headers: dict[str, str]) -> dict[str, str]:
    """Backward-compatible alias — defaults to analyst role."""
    return analyst_headers
