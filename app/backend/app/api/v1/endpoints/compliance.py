"""Compliance framework coverage endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....services.compliance_mapper import ComplianceMapper

router = APIRouter(prefix="/compliance", tags=["compliance"])

_VALID_FRAMEWORKS = ("nist", "pci-dss")


@router.get(
    "/{framework}",
    summary="Get compliance framework coverage matrix",
)
async def get_compliance_coverage(
    framework: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("reports:read")),
) -> dict:
    """
    Return coverage matrix for a compliance framework.

    - **framework**: `nist` (NIST 800-53) or `pci-dss` (PCI-DSS v4.0)
    - Coverage is calculated from active (enabled) Sigma rules' technique IDs.
    - A control is marked `covered` when at least one mapped ATT&CK technique
      appears in an active rule.
    - Requires analyst+ role (reports:read).
    """
    if framework not in _VALID_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid framework {framework!r}. Valid: {', '.join(_VALID_FRAMEWORKS)}",
        )

    mapper = ComplianceMapper(db)
    return await mapper.get_compliance_status(framework)
