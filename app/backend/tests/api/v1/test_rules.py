"""Tests for PATCH /api/v1/rules — Feature 28.6: RBAC: viewer cannot PATCH rules.

Coverage:
  - viewer role → PATCH /rules/{id} → 403 Forbidden
  - engineer role → PATCH /rules/{id} for non-existent rule → 404 (not blocked)
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from httpx import AsyncClient

from app.core.security import create_access_token

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _token_headers(role: str, email: str | None = None) -> dict[str, str]:
    """Create a valid JWT for *role* without hitting the DB."""
    sub = email or f"{role}@mxtac.local"
    token = create_access_token(
        {"sub": sub, "role": role},
        expires_delta=timedelta(hours=1),
    )
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Feature 28.6 — RBAC: viewer cannot PATCH rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_cannot_patch_rule(client: AsyncClient) -> None:
    """PATCH /rules/{id} with viewer role → 403 Forbidden."""
    resp = await client.patch(
        "/api/v1/rules/any-rule-id",
        headers=_token_headers("viewer"),
        json={"enabled": False},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_analyst_cannot_patch_rule(client: AsyncClient) -> None:
    """PATCH /rules/{id} with analyst role → 403 Forbidden.

    rules:write requires engineer or admin; analyst lacks it.
    """
    resp = await client.patch(
        "/api/v1/rules/any-rule-id",
        headers=_token_headers("analyst"),
        json={"enabled": False},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_hunter_cannot_patch_rule(client: AsyncClient) -> None:
    """PATCH /rules/{id} with hunter role → 403 Forbidden.

    Hunter can read rules but cannot write them.
    """
    resp = await client.patch(
        "/api/v1/rules/any-rule-id",
        headers=_token_headers("hunter"),
        json={"enabled": False},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_engineer_can_reach_patch_rule_endpoint(client: AsyncClient) -> None:
    """PATCH /rules/{id} with engineer role is not blocked by RBAC.

    The rule does not exist, so we expect 404 — not 403.
    This confirms engineer has rules:write permission.
    """
    resp = await client.patch(
        "/api/v1/rules/nonexistent-rule-id",
        headers=_token_headers("engineer"),
        json={"enabled": False},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_can_reach_patch_rule_endpoint(client: AsyncClient) -> None:
    """PATCH /rules/{id} with admin role is not blocked by RBAC → 404."""
    resp = await client.patch(
        "/api/v1/rules/nonexistent-rule-id",
        headers=_token_headers("admin"),
        json={"enabled": False},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unauthenticated_cannot_patch_rule(client: AsyncClient) -> None:
    """PATCH /rules/{id} without Authorization header → 401 or 403."""
    resp = await client.patch(
        "/api/v1/rules/any-rule-id",
        json={"enabled": False},
    )
    assert resp.status_code in (401, 403)
