"""ATT&CK Coverage endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
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


@router.get("/navigator")
async def get_navigator_layer(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
) -> JSONResponse:
    """Export ATT&CK Navigator-compatible layer JSON.

    Produces a Navigator v4.5 layer where each technique's score equals the
    number of enabled Sigma rules that reference it.  Only techniques covered
    by at least one enabled rule appear in the layer.  The JSON can be imported
    directly into the MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/).
    """
    technique_counts = await RuleRepo.get_navigator_techniques(db)

    techniques = [
        {
            "techniqueID": tid,
            "score": count,
            "color": "",
            "comment": f"{count} rule{'s' if count != 1 else ''} covering this technique",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": False,
        }
        for tid, count in sorted(technique_counts.items())
    ]

    max_score = max(technique_counts.values()) if technique_counts else 1

    layer = {
        "name": "MxTac Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"ATT&CK coverage exported from MxTac on "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}. "
            f"Score = number of enabled Sigma rules covering the technique."
        ),
        "filters": {
            "platforms": ["Linux", "macOS", "Windows", "Network", "Cloud"],
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ffaf66", "#ff6666"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }

    return JSONResponse(content=layer)
