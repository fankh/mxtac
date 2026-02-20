"""ATT&CK Coverage endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.detection_repo import DetectionRepo
from ....schemas.overview import CoverageSummary
from ....services.mock_data import COVERAGE_SUMMARY

router = APIRouter(prefix="/coverage", tags=["coverage"])


@router.get("", response_model=CoverageSummary)
async def get_coverage(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """Overall ATT&CK coverage percentage and technique count.

    Returns the number of distinct ATT&CK techniques observed in detections
    versus the total techniques tracked in the 9-tactic heatmap scope (v14).
    Falls back to mock data when no detections exist in the database.
    """
    summary = await DetectionRepo.get_coverage_summary(db)
    if summary is None:
        return COVERAGE_SUMMARY
    return CoverageSummary(**summary)
