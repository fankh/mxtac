from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....models.connector import Connector
from ....repositories.connector_repo import ConnectorRepo
from ....repositories.detection_repo import DetectionRepo
from ....repositories.incident_repo import IncidentRepo
from ....schemas.overview import KpiMetrics, TimelinePoint, TacticBar, HeatRow, IntegrationStatus
from ....services.mock_data import KPI, TACTICS, HEATMAP, INTEGRATIONS, TACTIC_LABELS
from ....schemas.detection import Detection
from ....services.mock_data import DETECTIONS

router = APIRouter(prefix="/overview", tags=["overview"])

_RANGE_DAYS: dict[str, int] = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}


def _parse_range_days(range_str: str) -> int:
    return _RANGE_DAYS.get(range_str, 7)


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
    range: str = Query("7d", description="Time range: 24h | 7d | 30d | 90d"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """Detection counts per day broken down by severity."""
    days = _parse_range_days(range)
    now = datetime.now(timezone.utc)
    from_date = now - timedelta(days=days)

    db_rows = await DetectionRepo.get_timeline(db, from_date=from_date, to_date=now)
    by_day = {row["day"]: row for row in db_rows}

    # Walk forward from from_date to today, filling zeros for days with no detections.
    # Use a while-loop to avoid shadowing the built-in range() with the `range` parameter.
    result: list[TimelinePoint] = []
    day = from_date.date()
    end_day = now.date()
    while day <= end_day:
        row = by_day.get(str(day))
        result.append(
            TimelinePoint(
                date=f"{day.strftime('%b')} {day.day}",
                critical=row["critical"] if row else 0,
                high=row["high"] if row else 0,
                medium=row["medium"] if row else 0,
                total=row["total"] if row else 0,
            )
        )
        day += timedelta(days=1)
    return result


@router.get("/tactics", response_model=list[TacticBar])
async def get_tactics(
    range: str = Query("7d", description="Time range: 24h | 7d | 30d | 90d"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """Top ATT&CK tactic breakdown with counts and trend percentage."""
    days = _parse_range_days(range)
    now = datetime.now(timezone.utc)
    from_date = now - timedelta(days=days)
    prev_from_date = from_date - timedelta(days=days)

    rows = await DetectionRepo.get_tactics(
        db, from_date=from_date, to_date=now, prev_from_date=prev_from_date
    )
    if not rows:
        return TACTICS  # fallback to mock data when DB has no detections
    return [TacticBar(**r) for r in rows]


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


def _connector_to_integration_status(conn: Connector) -> IntegrationStatus:
    """Map a Connector ORM object to the IntegrationStatus response schema."""
    if not conn.enabled:
        return IntegrationStatus(
            id=conn.id,
            name=conn.name,
            status="disabled",
            metric="Not configured",
        )
    if conn.status in ("active", "connected"):
        return IntegrationStatus(
            id=conn.id,
            name=conn.name,
            status="connected",
            metric=f"{conn.events_total:,} events total",
        )
    if conn.status in ("error", "warning"):
        return IntegrationStatus(
            id=conn.id,
            name=conn.name,
            status="warning",
            metric=conn.error_message or "Connection error",
            detail=conn.error_message,
        )
    # inactive or unknown
    return IntegrationStatus(
        id=conn.id,
        name=conn.name,
        status="disabled",
        metric="Inactive",
    )


@router.get("/integrations", response_model=list[IntegrationStatus])
async def get_integrations(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """Integration status for all configured connectors."""
    connectors = await ConnectorRepo.list(db)
    if not connectors:
        return INTEGRATIONS  # fallback to mock data when no connectors are registered
    return [_connector_to_integration_status(c) for c in connectors]


@router.get("/recent-detections", response_model=list[Detection])
async def get_recent_detections(
    limit: int = Query(6, le=20),
    _: dict = Depends(require_permission("detections:read")),
):
    """Recent critical/high detections for the overview table."""
    critical_high = [d for d in DETECTIONS if d.severity in ("critical", "high")]
    return sorted(critical_high, key=lambda d: d.time, reverse=True)[:limit]
