"""Alert suppression rules API (feature 9.11).

Endpoints:
  GET    /suppression-rules          — list rules (paginated)
  POST   /suppression-rules          — create rule
  GET    /suppression-rules/{id}     — get single rule
  PATCH  /suppression-rules/{id}     — update rule
  DELETE /suppression-rules/{id}     — delete rule
"""

from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....core.security import get_current_user
from ....repositories.suppression_repo import SuppressionRepo
from ....schemas.common import PaginatedResponse, Pagination
from ....schemas.suppression import (
    SuppressionRule,
    SuppressionRuleCreate,
    SuppressionRuleUpdate,
)

router = APIRouter(prefix="/suppression-rules", tags=["suppression-rules"])


def _to_schema(rule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "reason": rule.reason,
        "rule_id": rule.rule_id,
        "host": rule.host,
        "technique_id": rule.technique_id,
        "tactic": rule.tactic,
        "severity": rule.severity,
        "is_active": rule.is_active,
        "expires_at": rule.expires_at,
        "created_by": rule.created_by,
        "hit_count": rule.hit_count,
        "last_hit_at": rule.last_hit_at,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


@router.get("", response_model=PaginatedResponse[SuppressionRule])
async def list_suppression_rules(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    is_active: bool | None = Query(None),
    search: str | None = Query(None, max_length=255),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("suppression_rules:read")),
):
    items, total = await SuppressionRepo.list(
        db,
        page=page,
        page_size=page_size,
        is_active=is_active,
        search=search,
    )
    return PaginatedResponse(
        items=[_to_schema(r) for r in items],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=max(1, ceil(total / page_size)),
        ),
    )


@router.post("", response_model=SuppressionRule, status_code=201)
async def create_suppression_rule(
    body: SuppressionRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    _: dict = Depends(require_permission("suppression_rules:write")),
):
    rule = await SuppressionRepo.create(
        db,
        name=body.name,
        reason=body.reason,
        rule_id=body.rule_id,
        host=body.host,
        technique_id=body.technique_id,
        tactic=body.tactic,
        severity=body.severity,
        is_active=body.is_active,
        expires_at=body.expires_at,
        created_by=current_user.get("sub", "unknown"),
    )
    await db.commit()
    return _to_schema(rule)


@router.get("/{rule_id}", response_model=SuppressionRule)
async def get_suppression_rule(
    rule_id: int = Path(..., description="Suppression rule ID"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("suppression_rules:read")),
):
    rule = await SuppressionRepo.get(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Suppression rule {rule_id} not found")
    return _to_schema(rule)


@router.patch("/{rule_id}", response_model=SuppressionRule)
async def update_suppression_rule(
    rule_id: int = Path(..., description="Suppression rule ID"),
    body: SuppressionRuleUpdate = ...,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("suppression_rules:write")),
):
    updates = body.model_dump(exclude_none=True)
    if not updates:
        rule = await SuppressionRepo.get(db, rule_id)
        if rule is None:
            raise HTTPException(status_code=404, detail=f"Suppression rule {rule_id} not found")
        return _to_schema(rule)

    rule = await SuppressionRepo.update(db, rule_id, **updates)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Suppression rule {rule_id} not found")
    await db.commit()
    return _to_schema(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_suppression_rule(
    rule_id: int = Path(..., description="Suppression rule ID"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("suppression_rules:write")),
):
    deleted = await SuppressionRepo.delete(db, rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Suppression rule {rule_id} not found")
    await db.commit()
