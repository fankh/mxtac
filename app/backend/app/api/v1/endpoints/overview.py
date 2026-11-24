from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....models.connector import Connector
from ....repositories.connector_repo import ConnectorRepo
from ....repositories.coverage_snapshot_repo import CoverageSnapshotRepo
from ....repositories.detection_repo import TACTIC_LABELS, DetectionRepo
from ....repositories.incident_repo import IncidentRepo
from ....repositories.rule_repo import RuleRepo
from ....schemas.detection import Detection
from ....schemas.overview import KpiMetrics, TimelinePoint, TacticBar, HeatRow, IntegrationStatus

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
    days = _parse_range_days(range)
    from_date = now - timedelta(days=days)
    prev_from_date = from_date - timedelta(days=days)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = (now - timedelta(days=now.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    det_counts = await DetectionRepo.get_kpi_counts(
        db,
        from_date=from_date,
        to_date=now,
        prev_from_date=prev_from_date,
        today_start=today_start,
    )
    inc_metrics = await IncidentRepo.get_metrics(db, from_date=from_date, to_date=now)
    prev_inc_metrics = await IncidentRepo.get_metrics(
        db, from_date=prev_from_date, to_date=from_date
    )
    conn_counts = await ConnectorRepo.get_status_counts(db)
    rule_counts = await RuleRepo.get_kpi_counts(db, week_start=week_start)

    # ATT&CK coverage — same source and scope as GET /coverage (enabled rules).
    coverage = await RuleRepo.get_coverage_summary(db)
    # Delta = techniques gained/lost since the last snapshot before this period.
    baseline = await CoverageSnapshotRepo.get_latest_on_or_before(db, from_date.date())
    coverage_delta = coverage["covered_count"] - baseline.covered_count if baseline else 0

    # Detection delta %: compare current period vs previous period
    total_current = det_counts["total_current"]
    total_prev = det_counts["total_prev"]
    if total_prev > 0:
        delta_pct = round((total_current - total_prev) / total_prev * 100, 1)
    elif total_current > 0:
        delta_pct = 100.0
    else:
        delta_pct = 0.0

    # MTTD — None when the period has no incident time-to-detect data
    avg_ttd = inc_metrics["avg_ttd"]
    prev_avg_ttd = prev_inc_metrics["avg_ttd"]
    mttd_minutes = round(avg_ttd / 60, 2) if avg_ttd is not None else None
    mttd_delta_minutes = (
        round((avg_ttd - prev_avg_ttd) / 60, 2)
        if avg_ttd is not None and prev_avg_ttd is not None
        else None
    )

    return KpiMetrics(
        total_detections=total_current,
        total_detections_delta_pct=delta_pct,
        critical_alerts=det_counts["critical"],
        critical_alerts_new_today=det_counts["critical_today"],
        attack_coverage_pct=coverage["coverage_pct"],
        attack_covered=coverage["covered_count"],
        attack_total=coverage["total_count"],
        attack_coverage_delta=coverage_delta,
        mttd_minutes=mttd_minutes,
        mttd_delta_minutes=mttd_delta_minutes,
        integrations_active=conn_counts["active"],
        integrations_total=conn_counts["total"],
        sigma_rules_active=rule_counts["active"],
        sigma_rules_critical=rule_counts["critical"],
        sigma_rules_high=rule_counts["high"],
        sigma_rules_deployed_this_week=rule_counts["deployed_this_week"],
        open_incidents_count=inc_metrics["open_count"],
        mttr_minutes=(
            round(inc_metrics["avg_ttr"] / 60, 2)
            if inc_metrics["avg_ttr"] is not None
            else None
        ),
    )


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
    """Top ATT&CK tactic breakdown with counts and trend percentage (empty when no detections)."""
    days = _parse_range_days(range)
    now = datetime.now(timezone.utc)
    from_date = now - timedelta(days=days)
    prev_from_date = from_date - timedelta(days=days)

    rows = await DetectionRepo.get_tactics(
        db, from_date=from_date, to_date=now, prev_from_date=prev_from_date
    )
    return [TacticBar(**r) for r in rows]


@router.get("/coverage/heatmap", response_model=list[HeatRow])
async def get_heatmap(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """ATT&CK technique coverage heatmap — 4 rows × 9 tactic columns.

    The grid is always complete; cells have ``covered == 0`` when no detections exist.
    """
    rows = await DetectionRepo.get_heatmap(db)
    return [HeatRow(**r) for r in rows]


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
    """Integration status for all configured connectors (empty when none are registered)."""
    connectors = await ConnectorRepo.list(db)
    return [_connector_to_integration_status(c) for c in connectors]


@router.get("/recent-detections", response_model=list[Detection])
async def get_recent_detections(
    limit: int = Query(6, le=20),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
):
    """Recent critical/high detections for the overview table (empty when none exist)."""
    items, _total = await DetectionRepo.list(
        db,
        severity=["critical", "high"],
        sort="time",
        order="desc",
        page_size=limit,
    )
    return [
        {
            "id": d.id,
            "score": d.score,
            "severity": d.severity,
            "technique_id": d.technique_id,
            "technique_name": d.technique_name,
            "name": d.name,
            "host": d.host,
            "tactic": d.tactic,
            "status": d.status,
            "time": d.time,
            "user": d.user,
            "process": d.process,
            "rule_name": d.rule_name,
            "log_source": d.log_source,
            "event_id": d.event_id,
            "occurrence_count": d.occurrence_count,
            "description": d.description,
            "cvss_v3": d.cvss_v3,
            "confidence": d.confidence,
            "tactic_id": d.tactic_id,
            "related_technique_ids": [],
            "assigned_to": d.assigned_to,
            "priority": d.priority,
        }
        for d in items
    ]
