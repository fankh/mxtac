from fastapi import APIRouter, Query
from ....schemas.overview import KpiMetrics, TimelinePoint, TacticBar, HeatRow, IntegrationStatus
from ....services.mock_data import KPI, TIMELINE, TACTICS, HEATMAP, INTEGRATIONS, TACTIC_LABELS
from ....schemas.detection import Detection
from ....services.mock_data import DETECTIONS

router = APIRouter(prefix="/overview", tags=["overview"])


@router.get("/kpis", response_model=KpiMetrics)
async def get_kpis(range: str = Query("7d", description="Time range: 24h | 7d | 30d")):
    """KPI metrics for the Security Overview dashboard header cards."""
    return KPI


@router.get("/timeline", response_model=list[TimelinePoint])
async def get_timeline(range: str = Query("7d")):
    """Detection counts per day broken down by severity."""
    return TIMELINE


@router.get("/tactics", response_model=list[TacticBar])
async def get_tactics(range: str = Query("7d")):
    """Top ATT&CK tactic breakdown with counts and trend percentage."""
    return TACTICS


@router.get("/coverage/heatmap", response_model=list[HeatRow])
async def get_heatmap():
    """ATT&CK technique coverage heatmap — 4 rows × 9 tactic columns."""
    return HEATMAP


@router.get("/coverage/tactic-labels", response_model=list[str])
async def get_tactic_labels():
    """Ordered tactic abbreviation labels for heatmap columns."""
    return TACTIC_LABELS


@router.get("/integrations", response_model=list[IntegrationStatus])
async def get_integrations():
    """Integration status for all configured connectors."""
    return INTEGRATIONS


@router.get("/recent-detections", response_model=list[Detection])
async def get_recent_detections(limit: int = Query(6, le=20)):
    """Recent critical/high detections for the overview table."""
    critical_high = [d for d in DETECTIONS if d.severity in ("critical", "high")]
    return sorted(critical_high, key=lambda d: d.time, reverse=True)[:limit]
