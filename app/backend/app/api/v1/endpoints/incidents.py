"""Incident management endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from math import ceil
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.detection_repo import DetectionRepo
from ....repositories.incident_repo import IncidentRepo, SortField
from ....schemas.common import Pagination, PaginatedResponse
from ....schemas.incident import Incident, IncidentCreate, IncidentDetail, IncidentNote, IncidentUpdate
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
    assigned_to: str | None = Query(None, description="Filter by assignee email"),
    search: str | None = Query(None, description="Search in title and description"),
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
