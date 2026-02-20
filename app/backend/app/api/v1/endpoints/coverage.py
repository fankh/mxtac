"""ATT&CK Coverage endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.rule_repo import RuleRepo
from ....schemas.overview import CoverageSummary, CoverageGaps
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


@router.get("/gaps", response_model=CoverageGaps)
async def get_coverage_gaps(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """ATT&CK techniques not covered by any enabled Sigma rule.

    Returns coverage gap metrics and an actionable list of technique IDs that
    appear in the rule library (enabled or disabled) but are not covered by any
    currently *enabled* rule.

    - ``gap_count``             = total_count (105) - covered_count
    - ``uncovered_techniques``  = technique IDs in any rule but NOT in enabled rules;
                                  re-enabling those rules would close the gap
    """
    gaps = await RuleRepo.get_coverage_gaps(db)
    return CoverageGaps(**gaps)
