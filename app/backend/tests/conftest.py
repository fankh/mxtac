"""Shared pytest fixtures for the MxTac backend test suite."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
async def client() -> AsyncClient:
    """Async HTTP test client wired to the FastAPI app (no real network calls)."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def auth_headers(client: AsyncClient) -> dict[str, str]:
    """Login with the demo account and return Authorization headers."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@mxtac.local", "password": "mxtac2026"},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
