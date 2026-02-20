"""Sigma Rules CRUD + import + test endpoints."""

from __future__ import annotations

import json
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....engine.sigma_engine import SigmaEngine, _Condition
from ....repositories.rule_repo import RuleRepo

router = APIRouter(prefix="/rules", tags=["rules"])

# ── Schemas ──────────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    title: str
    content: str          # YAML text
    enabled: bool = True

class RuleUpdate(BaseModel):
    enabled: bool | None = None
    content: str | None = None

class RuleResponse(BaseModel):
    id: str
    title: str
    level: str
    status: str
    enabled: bool
    technique_ids: list[str]
    tactic_ids: list[str]
    logsource: dict
    hit_count: int = 0
    fp_count: int = 0


class RuleDetailResponse(RuleResponse):
    """Extended response for GET /rules/{id} — includes raw YAML and metadata."""
    content: str
    description: str = ""
    source: str | None = None
    created_by: str | None = None

class RuleTestRequest(BaseModel):
    content: str          # YAML to test
    sample_event: dict    # event to test against

class RuleTestResponse(BaseModel):
    matched: bool
    errors: list[str]

class RuleImportRequest(BaseModel):
    yaml_content: str     # single or multi-doc YAML

# ── Sigma engine (compilation + testing only, not for storage) ────────────────

_engine = SigmaEngine()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_to_response(rule: Any) -> dict:
    """Convert ORM Rule → RuleResponse-compatible dict."""
    try:
        technique_ids = json.loads(rule.technique_ids) if rule.technique_ids else []
    except (json.JSONDecodeError, TypeError):
        technique_ids = []
    try:
        tactic_ids = json.loads(rule.tactic_ids) if rule.tactic_ids else []
    except (json.JSONDecodeError, TypeError):
        tactic_ids = []
    logsource: dict = {}
    if rule.logsource_product:
        logsource["product"] = rule.logsource_product
    if rule.logsource_category:
        logsource["category"] = rule.logsource_category
    if rule.logsource_service:
        logsource["service"] = rule.logsource_service
    return {
        "id": rule.id,
        "title": rule.title,
        "level": rule.level,
        "status": rule.status,
        "enabled": rule.enabled,
        "technique_ids": technique_ids,
        "tactic_ids": tactic_ids,
        "logsource": logsource,
        "hit_count": rule.hit_count,
        "fp_count": rule.fp_count,
    }


def _rule_to_detail_response(rule: Any) -> dict:
    """Convert ORM Rule → RuleDetailResponse-compatible dict (superset of RuleResponse)."""
    base = _rule_to_response(rule)
    base.update({
        "content": rule.content or "",
        "description": rule.description or "",
        "source": rule.source,
        "created_by": rule.created_by,
    })
    return base


async def _parse_and_persist(
    yaml_text: str,
    db: AsyncSession,
    *,
    enabled: bool = True,
) -> list:
    """Parse Sigma YAML (single or multi-doc), validate, and persist each to DB.

    Returns the list of created ORM Rule objects.
    """
    created = []
    for doc in yaml.safe_load_all(yaml_text):
        if not isinstance(doc, dict):
            continue
        rule_yaml = yaml.dump(doc)
        sigma_rule = _engine.load_rule_yaml(rule_yaml)
        if not sigma_rule:
            continue
        logsource = sigma_rule.logsource or {}
        db_rule = await RuleRepo.create(
            db,
            id=sigma_rule.id,
            title=sigma_rule.title,
            description=sigma_rule.description or "",
            content=rule_yaml,
            status=sigma_rule.status,
            level=sigma_rule.level,
            enabled=enabled,
            logsource_product=logsource.get("product"),
            logsource_category=logsource.get("category"),
            logsource_service=logsource.get("service"),
            technique_ids=json.dumps(sigma_rule.technique_ids),
            tactic_ids=json.dumps(sigma_rule.tactic_ids),
            source="custom",
        )
        created.append(db_rule)
    return created


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=list[RuleResponse])
async def list_rules(
    enabled: bool | None = None,
    level: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:read")),
):
    """List all Sigma rules. Supports filtering by enabled/level."""
    rules = await RuleRepo.list(db, enabled=enabled, level=level)
    return [_rule_to_response(r) for r in rules]


@router.get("/stats/summary", response_model=dict)
async def rules_summary(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:read")),
):
    rules = await RuleRepo.list(db)
    by_level: dict[str, int] = {}
    for r in rules:
        by_level[r.level] = by_level.get(r.level, 0) + 1
    return {
        "total": len(rules),
        "enabled": sum(1 for r in rules if r.enabled),
        "by_level": by_level,
    }


@router.post("/test", response_model=RuleTestResponse)
async def test_rule_yaml(
    body: RuleTestRequest,
    _: dict = Depends(require_permission("rules:read")),
):
    """Test arbitrary Sigma YAML against a sample event (no save)."""
    try:
        doc = yaml.safe_load(body.content)
        detection = doc.get("detection", {})
        cond = _Condition(detection)
        matched = cond.matches(body.sample_event)
        return {"matched": matched, "errors": []}
    except Exception as exc:
        return {"matched": False, "errors": [str(exc)]}


@router.post("/import", response_model=dict)
async def import_rules(
    body: RuleImportRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:write")),
):
    """Bulk import Sigma rules from YAML (single or multi-document)."""
    try:
        created = await _parse_and_persist(body.yaml_content, db)
        total = await RuleRepo.count(db)
        return {"imported": len(created), "total_rules": total}
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Import failed: {exc}")


@router.get("/{rule_id}", response_model=RuleDetailResponse)
async def get_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:read")),
):
    """Fetch a single Sigma rule by ID, including raw YAML content and metadata."""
    rule = await RuleRepo.get_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _rule_to_detail_response(rule)


@router.post("", response_model=RuleResponse, status_code=201)
async def create_rule(
    body: RuleCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:write")),
):
    """Create a custom Sigma rule from raw YAML."""
    created = await _parse_and_persist(body.content, db, enabled=body.enabled)
    if not created:
        raise HTTPException(status_code=422, detail="Invalid Sigma YAML")
    return _rule_to_response(created[0])


@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:write")),
):
    rule = await RuleRepo.get_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    update_kwargs: dict = {}
    if body.enabled is not None:
        update_kwargs["enabled"] = body.enabled
    if body.content is not None:
        sigma_rule = _engine.load_rule_yaml(body.content)
        if sigma_rule:
            logsource = sigma_rule.logsource or {}
            update_kwargs.update({
                "content": body.content,
                "title": sigma_rule.title,
                "level": sigma_rule.level,
                "status": sigma_rule.status,
                "logsource_product": logsource.get("product"),
                "logsource_category": logsource.get("category"),
                "logsource_service": logsource.get("service"),
                "technique_ids": json.dumps(sigma_rule.technique_ids),
                "tactic_ids": json.dumps(sigma_rule.tactic_ids),
            })

    updated = await RuleRepo.update(db, rule_id, **update_kwargs)
    return _rule_to_response(updated)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:write")),
):
    deleted = await RuleRepo.delete(db, rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")


@router.post("/{rule_id}/test", response_model=RuleTestResponse)
async def test_rule(
    rule_id: str,
    body: RuleTestRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:read")),
):
    """Test an existing rule against a sample event."""
    rule = await RuleRepo.get_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    try:
        doc = yaml.safe_load(rule.content)
        detection = doc.get("detection", {})
        cond = _Condition(detection)
        matched = cond.matches(body.sample_event)
        return {"matched": matched, "errors": []}
    except Exception as exc:
        return {"matched": False, "errors": [str(exc)]}
