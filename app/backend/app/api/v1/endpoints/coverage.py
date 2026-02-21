"""ATT&CK Coverage endpoints."""

from datetime import date, datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.coverage_snapshot_repo import CoverageSnapshotRepo
from ....repositories.coverage_target_repo import CoverageTargetRepo
from ....repositories.rule_repo import RuleRepo
from ....schemas.overview import (
    CoverageByDataSource,
    CoverageGaps,
    CoverageSummary,
    CoverageTrend,
    CoverageTrendPoint,
    CoverageTargetRead,
    CoverageTargetUpdate,
)
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


@router.get("/by-datasource", response_model=CoverageByDataSource)
async def get_coverage_by_datasource(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """ATT&CK coverage breakdown by data source connector.

    Groups enabled Sigma rules by their Sigma logsource (product/category/service)
    and calculates distinct ATT&CK technique coverage per connector type
    (Wazuh, Zeek, Suricata).  The aggregate total reflects all unique techniques
    covered by any enabled rule across all sources combined.

    Coverage is zero for a source when no enabled rules map to that connector.
    """
    data = await RuleRepo.get_coverage_by_datasource(db)
    return CoverageByDataSource(**data)


@router.get("/trend", response_model=CoverageTrend)
async def get_coverage_trend(
    days: Annotated[int, Query(ge=1, le=365, description="Number of calendar days to include")] = 30,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """ATT&CK coverage trend — daily snapshots over the last N days.

    Automatically captures today's coverage as a snapshot (upsert) before
    returning the historical trend, so the chart always includes the latest
    state without requiring a separate scheduled job.

    Returns points ordered ascending by date (oldest first) so the frontend
    can render a left-to-right trend line directly.

    - ``days``  query parameter (1–365, default 30)
    - Points with no stored snapshot are omitted (sparse series).
    """
    # Auto-capture today's snapshot from the live rule state
    summary = await RuleRepo.get_coverage_summary(db)
    if summary is not None:
        await CoverageSnapshotRepo.upsert(
            db,
            snapshot_date=date.today(),
            coverage_pct=summary["coverage_pct"],
            covered_count=summary["covered_count"],
            total_count=summary["total_count"],
        )

    snapshots = await CoverageSnapshotRepo.get_trend(db, days=days)

    points = [
        CoverageTrendPoint(
            date=s.snapshot_date.isoformat(),
            coverage_pct=s.coverage_pct,
            covered_count=s.covered_count,
            total_count=s.total_count,
        )
        for s in snapshots
    ]

    return CoverageTrend(points=points, days=days)


async def _get_current_pct(db: AsyncSession) -> float:
    """Return the live coverage percentage from enabled rules (0.0 when no rules)."""
    summary = await RuleRepo.get_coverage_summary(db)
    if summary is None:
        return COVERAGE_SUMMARY.coverage_pct
    return summary["coverage_pct"]


@router.get("/target", response_model=CoverageTargetRead)
async def get_coverage_target(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """Return the configured coverage target and current alert status.

    - ``target_pct``         — the operator-configured threshold (0–100)
    - ``enabled``            — whether alerting is active
    - ``label``              — optional label (e.g. "Q1 2026 Goal")
    - ``current_pct``        — live coverage percentage
    - ``is_below_threshold`` — True when enabled=True AND current_pct < target_pct

    If no target has been configured yet, returns a default disabled target at
    80 % so the response always has a valid schema.
    """
    target = await CoverageTargetRepo.get(db)
    current_pct = await _get_current_pct(db)

    if target is None:
        return CoverageTargetRead(
            target_pct=80.0,
            enabled=False,
            label=None,
            current_pct=current_pct,
            is_below_threshold=False,
        )

    return CoverageTargetRead(
        target_pct=target.target_pct,
        enabled=target.enabled,
        label=target.label,
        current_pct=current_pct,
        is_below_threshold=target.enabled and current_pct < target.target_pct,
    )


@router.put("/target", response_model=CoverageTargetRead)
async def upsert_coverage_target(
    body: CoverageTargetUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:write")),
):
    """Create or update the coverage target threshold.

    Sets the percentage that the live ATT&CK coverage must meet or exceed.
    When ``enabled=True``, the ``is_below_threshold`` field on the GET response
    will be ``True`` whenever coverage drops below ``target_pct``, signalling
    that attention is required.

    ``target_pct`` is clamped to [0, 100] server-side.
    """
    target = await CoverageTargetRepo.upsert(
        db,
        target_pct=body.target_pct,
        enabled=body.enabled,
        label=body.label,
    )
    current_pct = await _get_current_pct(db)

    return CoverageTargetRead(
        target_pct=target.target_pct,
        enabled=target.enabled,
        label=target.label,
        current_pct=current_pct,
        is_below_threshold=target.enabled and current_pct < target.target_pct,
    )
