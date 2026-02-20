from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.incident_repo import IncidentRepo
from ....schemas.overview import KpiMetrics, TimelinePoint, TacticBar, HeatRow, IntegrationStatus
from ....services.mock_data import KPI, TIMELINE, TACTICS, HEATMAP, INTEGRATIONS, TACTIC_LABELS
from ....schemas.detection import Detection
from ....services.mock_data import DETECTIONS

router = APIRouter(prefix="/overview", tags=["overview"])


@router.get("/kpis", response_model=KpiMetrics)
async def get_kpis(
    range: str = Query("7d", description="Time range: 24h | 7d | 30d"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """KPI metrics for the Security Overview dashboard header cards."""
    now = datetime.now(timezone.utc)
    raw = await IncidentRepo.get_metrics(
        db, from_date=now - timedelta(days=30), to_date=now
    )
    kpi_dict = KPI.model_dump()
    kpi_dict["open_incidents_count"] = raw["open_count"]
    kpi_dict["mttr_minutes"] = (
        round(raw["avg_ttr"] / 60, 2) if raw["avg_ttr"] is not None else None
    )
    if raw["avg_ttd"] is not None:
        kpi_dict["mttd_minutes"] = round(raw["avg_ttd"] / 60, 2)
    return KpiMetrics(**kpi_dict)


@router.get("/timeline", response_model=list[TimelinePoint])
async def get_timeline(
    range: str = Query("7d"),
    _: dict = Depends(require_permission("detections:read")),
):
    """Detection counts per day broken down by severity."""
    return TIMELINE


@router.get("/tactics", response_model=list[TacticBar])
async def get_tactics(
    range: str = Query("7d"),
    _: dict = Depends(require_permission("detections:read")),
):
    """Top ATT&CK tactic breakdown with counts and trend percentage."""
    return TACTICS


@router.get("/coverage/heatmap", response_model=list[HeatRow])
async def get_heatmap(
    _: dict = Depends(require_permission("detections:read")),
):
    """ATT&CK technique coverage heatmap — 4 rows × 9 tactic columns."""
    return HEATMAP


@router.get("/coverage/tactic-labels", response_model=list[str])
async def get_tactic_labels(
    _: dict = Depends(require_permission("detections:read")),
):
    """Ordered tactic abbreviation labels for heatmap columns."""
    return TACTIC_LABELS


@router.get("/integrations", response_model=list[IntegrationStatus])
async def get_integrations(
    _: dict = Depends(require_permission("detections:read")),
):
    """Integration status for all configured connectors."""
    return INTEGRATIONS


@router.get("/recent-detections", response_model=list[Detection])
async def get_recent_detections(
    limit: int = Query(6, le=20),
    _: dict = Depends(require_permission("detections:read")),
):
    """Recent critical/high detections for the overview table."""
    critical_high = [d for d in DETECTIONS if d.severity in ("critical", "high")]
    return sorted(critical_high, key=lambda d: d.time, reverse=True)[:limit]
