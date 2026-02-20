"""ATT&CK Coverage endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.rule_repo import RuleRepo
from ....schemas.overview import CoverageSummary
from ....services.mock_data import COVERAGE_SUMMARY

router = APIRouter(prefix="/coverage", tags=["coverage"])


@router.get("", response_model=CoverageSummary)
async def get_coverage(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """Overall ATT&CK coverage percentage and technique count.

    Coverage is calculated from active (enabled) Sigma rules: counts the distinct
    ATT&CK technique IDs referenced by all enabled rules versus the total techniques
    tracked in the 9-tactic heatmap scope (ATT&CK v14, 105 techniques).
    Falls back to mock data when no enabled rules with technique mappings exist.
    """
    summary = await RuleRepo.get_coverage_summary(db)
    if summary is None:
        return COVERAGE_SUMMARY
    return CoverageSummary(**summary)
