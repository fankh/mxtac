"""Incident management endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.detection_repo import DetectionRepo
from ....repositories.incident_repo import IncidentRepo, SortField
from ....schemas.common import Pagination, PaginatedResponse
from ....schemas.incident import Incident, IncidentCreate, IncidentDetail, IncidentMetrics, IncidentNote, IncidentUpdate, NoteCreate
from ....services.audit import get_audit_logger

router = APIRouter(prefix="/incidents", tags=["incidents"])

# Valid forward-only status progression
_STATUS_PROGRESSION = ["new", "investigating", "contained", "resolved", "closed"]


def _incident_to_schema(inc) -> dict:
    """Convert ORM Incident to schema dict."""
    return {
        "id": inc.id,
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "status": inc.status,
        "priority": inc.priority,
        "assigned_to": inc.assigned_to,
        "created_by": inc.created_by,
        "detection_ids": inc.detection_ids,
        "technique_ids": inc.technique_ids,
        "tactic_ids": inc.tactic_ids,
        "hosts": inc.hosts,
        "ttd_seconds": inc.ttd_seconds,
        "ttr_seconds": inc.ttr_seconds,
        "closed_at": inc.closed_at,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
    }


def _detection_to_schema(det) -> dict:
    """Convert ORM Detection to schema dict."""
    return {
        "id": det.id,
        "score": det.score,
        "severity": det.severity,
        "technique_id": det.technique_id,
        "technique_name": det.technique_name,
        "name": det.name,
        "host": det.host,
        "tactic": det.tactic,
        "status": det.status,
        "time": det.time,
        "user": det.user,
        "process": det.process,
        "rule_name": det.rule_name,
        "log_source": det.log_source,
        "event_id": det.event_id,
        "occurrence_count": det.occurrence_count,
        "description": det.description,
        "cvss_v3": det.cvss_v3,
        "confidence": det.confidence,
        "tactic_id": det.tactic_id,
        "related_technique_ids": getattr(det, "related_technique_ids", None) or [],
        "assigned_to": det.assigned_to,
        "priority": det.priority,
    }


@router.get("", response_model=PaginatedResponse[Incident])
async def list_incidents(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: list[Literal["critical", "high", "medium", "low"]] | None = Query(None),
    status: list[Literal["new", "investigating", "contained", "resolved", "closed"]] | None = Query(None),
    assigned_to: str | None = Query(None, max_length=254, description="Filter by assignee email"),
    search: str | None = Query(None, max_length=255, description="Search in title and description"),
    sort: SortField = Query("created_at", description="Sort field: created_at, severity, or status"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("incidents:read")),
) -> PaginatedResponse:
    """
    List incidents with pagination and optional filters.

    - Requires viewer+ role (incidents:read).
    - Default sort: created_at desc (newest first).
    - Severity sort: critical → high → medium → low.
    - Status sort: new → investigating → contained → resolved → closed.
    """
    skip = (page - 1) * page_size
    items, total = await IncidentRepo.list(
        db,
        skip=skip,
        limit=page_size,
        severity=severity,
        status=status,
        assigned_to=assigned_to,
        search=search,
        sort=sort,
    )
    return PaginatedResponse(
        items=[_incident_to_schema(inc) for inc in items],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=max(1, ceil(total / page_size)),
        ),
    )


@router.post("", response_model=Incident, status_code=201)
async def create_incident(
    body: IncidentCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("incidents:write")),
) -> dict:
    """
    Create a new incident, optionally linking existing detections.

    - Requires analyst+ role (detections:write).
    - created_by is auto-populated from the JWT.
    - technique_ids, tactic_ids, and hosts are auto-extracted from linked detections.
    """
    # Resolve linked detections and extract entities
    technique_ids: list[str] = []
    tactic_ids: list[str] = []
    hosts: list[str] = []

    for det_id in body.detection_ids:
        det = await DetectionRepo.get(db, det_id)
        if det is None:
            raise HTTPException(
                status_code=404,
                detail=f"Detection {det_id!r} not found",
            )
        if det.technique_id and det.technique_id not in technique_ids:
            technique_ids.append(det.technique_id)
        if det.tactic_id and det.tactic_id not in tactic_ids:
            tactic_ids.append(det.tactic_id)
        if det.host and det.host not in hosts:
            hosts.append(det.host)

    incident = await IncidentRepo.create(
        db,
        title=body.title,
        description=body.description,
        severity=body.severity,
        detection_ids=body.detection_ids,
        assigned_to=body.assigned_to,
        created_by=current_user["email"],
        technique_ids=technique_ids,
        tactic_ids=tactic_ids,
        hosts=hosts,
    )

    await get_audit_logger().log(
        actor=current_user["email"],
        action="create",
        resource_type="incident",
        resource_id=str(incident.id),
        details={
            "title": incident.title,
            "severity": incident.severity,
            "detection_ids": incident.detection_ids,
        },
        request=request,
    )

    return _incident_to_schema(incident)


@router.get("/metrics", response_model=IncidentMetrics)
async def get_incident_metrics(
    from_date: datetime | None = Query(None, description="Start date (ISO 8601). Defaults to 30 days ago."),
    to_date: datetime | None = Query(None, description="End date (ISO 8601). Defaults to now."),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("incidents:read")),
) -> dict:
    """
    Incident SLA metrics — MTTD, MTTR, open count, and severity breakdown.

    - from_date / to_date default to the last 30 days.
    - mttr_seconds is null when no closed incidents exist in the range.
    - mttd_seconds is null when no incidents with TTD data exist in the range.
    - incidents_this_week / incidents_this_month are calendar-based (not bounded by from_date/to_date).
    - Requires viewer+ role (incidents:read).
    """
    now = datetime.now(timezone.utc)
    resolved_to = to_date if to_date is not None else now
    resolved_from = from_date if from_date is not None else now - timedelta(days=30)

    raw = await IncidentRepo.get_metrics(db, from_date=resolved_from, to_date=resolved_to)

    sc = raw["status_counts"]
    sev = raw["severity_counts"]
    return {
        "total_incidents": {
            "new": sc.get("new", 0),
            "investigating": sc.get("investigating", 0),
            "contained": sc.get("contained", 0),
            "resolved": sc.get("resolved", 0),
            "closed": sc.get("closed", 0),
        },
        "mttr_seconds": raw["avg_ttr"],
        "mttd_seconds": raw["avg_ttd"],
        "open_incidents_count": raw["open_count"],
        "incidents_by_severity": {
            "critical": sev.get("critical", 0),
            "high": sev.get("high", 0),
            "medium": sev.get("medium", 0),
            "low": sev.get("low", 0),
        },
        "incidents_this_week": raw["week_count"],
        "incidents_this_month": raw["month_count"],
        "from_date": resolved_from,
        "to_date": resolved_to,
    }


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("incidents:read")),
) -> dict:
    """
    Get full incident detail including linked detections and timeline.

    - Requires viewer+ role (incidents:read).
    - Returns 404 if the incident does not exist.
    - `detections`: full detection objects for each detection_id.
    - `notes`: timeline entries stored on the incident.
    - `duration_seconds`: elapsed seconds from created_at to closed_at (or now if open).
    """
    incident = await IncidentRepo.get_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    # Fetch linked detections (skip any that were deleted)
    detections = []
    for det_id in incident.detection_ids:
        det = await DetectionRepo.get(db, det_id)
        if det is not None:
            detections.append(_detection_to_schema(det))

    # Compute duration
    created = incident.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    end_time = incident.closed_at or datetime.now(timezone.utc)
    if end_time.tzinfo is None:
        end_time = end_time.replace(tzinfo=timezone.utc)
    duration_seconds = max(0, int((end_time - created).total_seconds()))

    # Parse notes — stored as list of dicts in JSON column
    raw_notes = incident.notes or []
    notes = [IncidentNote(**n) for n in raw_notes]

    return {
        **_incident_to_schema(incident),
        "detections": detections,
        "notes": [n.model_dump() for n in notes],
        "duration_seconds": duration_seconds,
    }


@router.patch("/{incident_id}", response_model=Incident)
async def update_incident(
    incident_id: int,
    body: IncidentUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("incidents:write")),
) -> dict:
    """
    Partially update an incident.

    - Requires analyst+ role (incidents:write).
    - Only explicitly provided fields are updated.
    - Status must progress forward: new → investigating → contained → resolved → closed.
    - Transitioning to 'resolved' or 'closed' sets closed_at and calculates ttr_seconds.
    - Providing detection_ids replaces the current set and re-syncs technique_ids/tactic_ids/hosts.
    - assigned_to may be set to null to unassign.
    """
    incident = await IncidentRepo.get_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    provided = body.model_fields_set
    changes: dict = {}
    old_status: str | None = None

    # --- Status transition validation ---
    if "status" in provided and body.status is not None:
        old_status = incident.status
        new_status = body.status
        if new_status != old_status:
            old_idx = _STATUS_PROGRESSION.index(old_status)
            new_idx = _STATUS_PROGRESSION.index(new_status)
            if new_idx < old_idx:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"Invalid status transition: {old_status!r} → {new_status!r}. "
                        "Status can only progress forward "
                        "(new → investigating → contained → resolved → closed)."
                    ),
                )
            changes["status"] = new_status

            # Auto-create a timeline note for the status change
            status_note = {
                "id": str(uuid.uuid4()),
                "author": current_user["email"],
                "content": f"Status changed from {old_status} to {new_status} by {current_user['email']}",
                "note_type": "status_change",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            changes["notes"] = list(incident.notes or []) + [status_note]

            # Auto-set closed_at and ttr_seconds on first close
            if new_status in ("resolved", "closed") and incident.closed_at is None:
                now = datetime.now(timezone.utc)
                changes["closed_at"] = now
                created = incident.created_at
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                changes["ttr_seconds"] = max(0, int((now - created).total_seconds()))

    # --- Scalar fields that cannot be cleared (skip explicit None) ---
    for field in ("title", "severity"):
        if field in provided and getattr(body, field) is not None:
            changes[field] = getattr(body, field)

    # --- Scalar fields that may be cleared ---
    for field in ("description", "priority"):
        if field in provided:
            changes[field] = getattr(body, field)

    # --- Assignee (explicit None = unassign) ---
    if "assigned_to" in provided:
        changes["assigned_to"] = body.assigned_to

    # --- Detection IDs: replace set and re-sync derived entity lists ---
    if "detection_ids" in provided and body.detection_ids is not None:
        technique_ids: list[str] = []
        tactic_ids: list[str] = []
        hosts: list[str] = []
        for det_id in body.detection_ids:
            det = await DetectionRepo.get(db, det_id)
            if det is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Detection {det_id!r} not found",
                )
            if det.technique_id and det.technique_id not in technique_ids:
                technique_ids.append(det.technique_id)
            if det.tactic_id and det.tactic_id not in tactic_ids:
                tactic_ids.append(det.tactic_id)
            if det.host and det.host not in hosts:
                hosts.append(det.host)
        changes["detection_ids"] = body.detection_ids
        changes["technique_ids"] = technique_ids
        changes["tactic_ids"] = tactic_ids
        changes["hosts"] = hosts

    # Apply all collected changes
    for k, v in changes.items():
        setattr(incident, k, v)
    await db.flush()

    # --- Audit log (only when something actually changed) ---
    if changes:
        audit_details: dict = {}
        if old_status is not None and "status" in changes:
            audit_details["status"] = {"from": old_status, "to": changes["status"]}
        for field in ("title", "severity", "priority", "assigned_to", "description"):
            if field in changes:
                audit_details[field] = changes[field]
        if "detection_ids" in changes:
            audit_details["detection_ids"] = changes["detection_ids"]

        await get_audit_logger().log(
            actor=current_user["email"],
            action="update",
            resource_type="incident",
            resource_id=str(incident.id),
            details=audit_details,
            request=request,
        )

    return _incident_to_schema(incident)


@router.post("/{incident_id}/notes", response_model=IncidentNote, status_code=201)
async def add_note(
    incident_id: int,
    body: NoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("incidents:write")),
) -> dict:
    """
    Add a timestamped note to an incident's timeline.

    - Requires analyst+ role (incidents:write).
    - author is auto-populated from the JWT.
    - note_type: comment | status_change | evidence (default: comment).
    """
    incident = await IncidentRepo.get_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    now = datetime.now(timezone.utc)
    note = {
        "id": str(uuid.uuid4()),
        "author": current_user["email"],
        "content": body.content,
        "note_type": body.note_type,
        "created_at": now.isoformat(),
    }

    # Assign new list so SQLAlchemy detects the JSON column change
    incident.notes = list(incident.notes or []) + [note]
    await db.flush()

    return note


@router.delete("/{incident_id}", status_code=204)
async def delete_incident(
    incident_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_permission("incidents:delete")),
) -> Response:
    """
    Soft-delete an incident by setting its status to 'closed'.

    - Requires admin role (incidents:delete).
    - Sets status → 'closed', records closed_at, and calculates ttr_seconds if not already set.
    - Adds a timeline note recording the deletion.
    - Audit-logs the action as 'delete'.
    - Returns 204 No Content.
    - Returns 404 if the incident does not exist.
    """
    incident = await IncidentRepo.get_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    now = datetime.now(timezone.utc)
    old_status = incident.status

    incident.status = "closed"

    if incident.closed_at is None:
        incident.closed_at = now
        created = incident.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        incident.ttr_seconds = max(0, int((now - created).total_seconds()))

    deletion_note = {
        "id": str(uuid.uuid4()),
        "author": current_user["email"],
        "content": f"Incident closed by {current_user['email']}",
        "note_type": "status_change",
        "created_at": now.isoformat(),
    }
    incident.notes = list(incident.notes or []) + [deletion_note]

    await db.flush()

    await get_audit_logger().log(
        actor=current_user["email"],
        action="delete",
        resource_type="incident",
        resource_id=str(incident_id),
        details={"title": incident.title, "status_before": old_status},
        request=request,
    )

    return Response(status_code=204)


@router.get("/{incident_id}/notes", response_model=list[IncidentNote])
async def list_notes(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("incidents:read")),
) -> list[dict]:
    """
    List all notes for an incident in chronological order (oldest first).

    - Requires viewer+ role (incidents:read).
    - Returns 404 if the incident does not exist.
    """
    incident = await IncidentRepo.get_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    raw_notes = incident.notes or []
    return sorted(raw_notes, key=lambda n: n.get("created_at", ""))
