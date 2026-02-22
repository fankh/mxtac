"""Sigma Rules CRUD + import + test endpoints."""

from __future__ import annotations

import json
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....core.valkey import publish_rule_reload
from ....engine.sigma_engine import SigmaEngine, _Condition
from ....repositories.rule_repo import RuleRepo

router = APIRouter(prefix="/rules", tags=["rules"])

# ── Schemas ──────────────────────────────────────────────────────────────────

_MAX_YAML_BYTES = 1_000_000   # 1 MB per single rule


class RuleCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    content: str = Field(..., max_length=_MAX_YAML_BYTES)   # YAML text
    enabled: bool = True

class RuleUpdate(BaseModel):
    enabled: bool | None = None
    content: str | None = Field(default=None, max_length=_MAX_YAML_BYTES)

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
    content: str = Field(..., max_length=_MAX_YAML_BYTES)   # YAML to test
    sample_event: dict    # event to test against

class RuleEventTestRequest(BaseModel):
    """Request body for POST /rules/{rule_id}/test — only sample event, content comes from DB."""
    sample_event: dict

class RuleTestResponse(BaseModel):
    matched: bool
    errors: list[str]

_MAX_IMPORT_YAML_BYTES = 10_000_000   # 10 MB for bulk import


class RuleImportRequest(BaseModel):
    yaml_content: str = Field(..., max_length=_MAX_IMPORT_YAML_BYTES)   # single or multi-doc YAML

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
    engine: Any = None,
) -> list:
    """Parse Sigma YAML (single or multi-doc), validate, and persist each to DB.

    Syncs each persisted rule into `engine` (app.state.sigma_engine) when provided.
    Returns the list of created ORM Rule objects.
    """
    created = []
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError:
        return []
    for doc in docs:
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
        if engine is not None:
            sigma_rule.enabled = enabled
            engine.upsert_rule(sigma_rule)
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
    """Validate Sigma YAML structure and test it against a sample event (no save).

    Validation phases:
      1. YAML syntax — must parse without errors
      2. Structure    — must be a mapping with 'title' and 'detection' fields
      3. Detection    — 'detection' block must contain a 'condition' key
      4. Compilation  — must load successfully via SigmaEngine
      5. Evaluation   — detection condition evaluated against the sample event
    """
    # Phase 1: YAML syntax
    try:
        doc = yaml.safe_load(body.content)
    except yaml.YAMLError as exc:
        return {"matched": False, "errors": [f"YAML parse error: {exc}"]}

    if not isinstance(doc, dict):
        return {"matched": False, "errors": ["YAML must be a mapping (dict)"]}

    # Phase 2: Required Sigma fields
    validation_errors: list[str] = []
    if "title" not in doc:
        validation_errors.append("Missing required field: 'title'")
    if "detection" not in doc:
        validation_errors.append("Missing required field: 'detection'")
    if validation_errors:
        return {"matched": False, "errors": validation_errors}

    # Phase 3: Detection block structure
    detection = doc.get("detection", {})
    if not isinstance(detection, dict):
        return {"matched": False, "errors": ["'detection' must be a mapping"]}
    if "condition" not in detection:
        return {"matched": False, "errors": ["'detection' block is missing 'condition'"]}

    # Phase 4 + 5: Compile via engine and evaluate
    try:
        sigma_rule = _engine.load_rule_yaml(body.content)
        if sigma_rule is None:
            return {"matched": False, "errors": ["Failed to compile Sigma rule — check rule structure"]}
        matched = sigma_rule._matcher.matches(body.sample_event)
        return {"matched": matched, "errors": []}
    except Exception as exc:
        return {"matched": False, "errors": [f"Evaluation error: {exc}"]}


@router.post("/import", response_model=dict)
async def import_rules(
    request: Request,
    body: RuleImportRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:write")),
):
    """Bulk import Sigma rules from YAML (single or multi-document)."""
    try:
        engine = getattr(request.app.state, "sigma_engine", None)
        created = await _parse_and_persist(body.yaml_content, db, engine=engine)
        total = await RuleRepo.count(db)
        if created:
            await publish_rule_reload()
        return {"imported": len(created), "total_rules": total}
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Import failed: {exc}")


@router.post("/reload", response_model=dict)
async def reload_rules(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:write")),
):
    """Hot-reload all Sigma rules from DB into the in-process engine.

    Clears the current engine state and reloads every enabled/disabled rule
    from the database.  Use this after bulk DB operations or to recover from
    engine state drift without restarting the server.

    Returns the number of rules loaded and the total rule count in DB.
    """
    engine = getattr(request.app.state, "sigma_engine", None)
    if engine is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="Sigma engine not initialized")
    reloaded = await engine.reload_from_db(db)
    total = await RuleRepo.count(db)
    return {"reloaded": reloaded, "total_rules": total}


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
    request: Request,
    body: RuleCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:write")),
):
    """Create a custom Sigma rule from raw YAML."""
    engine = getattr(request.app.state, "sigma_engine", None)
    created = await _parse_and_persist(body.content, db, enabled=body.enabled, engine=engine)
    if not created:
        raise HTTPException(status_code=422, detail="Invalid Sigma YAML")
    await publish_rule_reload()
    return _rule_to_response(created[0])


@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    request: Request,
    rule_id: str,
    body: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:write")),
):
    rule = await RuleRepo.get_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    update_kwargs: dict = {}
    sigma_rule = None
    if body.enabled is not None:
        update_kwargs["enabled"] = body.enabled
    if body.content is not None:
        sigma_rule = _engine.load_rule_yaml(body.content)
        if not sigma_rule:
            raise HTTPException(status_code=422, detail="Invalid Sigma YAML")
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

    if not update_kwargs:
        return _rule_to_response(rule)

    updated = await RuleRepo.update(db, rule_id, **update_kwargs)

    # Sync the in-process Sigma engine so evaluation reflects DB state
    engine = getattr(request.app.state, "sigma_engine", None)
    if engine is not None:
        if sigma_rule is not None:
            # Content changed: rebuild index entry with correct enabled state
            sigma_rule.enabled = update_kwargs.get("enabled", rule.enabled)
            engine.remove_rule(rule_id)
            engine.add_rule(sigma_rule)
        elif body.enabled is not None:
            # Only enabled flag changed: update in-place
            existing = engine._rules.get(rule_id)
            if existing is not None:
                existing.enabled = body.enabled

    await publish_rule_reload()
    return _rule_to_response(updated)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    request: Request,
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:write")),
):
    deleted = await RuleRepo.delete(db, rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")
    engine = getattr(request.app.state, "sigma_engine", None)
    if engine is not None:
        engine.remove_rule(rule_id)
    await publish_rule_reload()


@router.post("/{rule_id}/mark_fp", response_model=dict, status_code=200)
async def mark_false_positive(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:write")),
):
    """Mark a rule match as a false positive — atomically increments fp_count.

    Called by analysts when reviewing an alert triggered by this rule and
    determining it is a false positive.  Requires detections:write permission
    (analyst, hunter, engineer, admin).
    """
    rule = await RuleRepo.get_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await RuleRepo.increment_fp(db, rule_id)
    return {"rule_id": rule_id, "status": "marked"}


@router.post("/{rule_id}/test", response_model=RuleTestResponse)
async def test_rule(
    rule_id: str,
    body: RuleEventTestRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("rules:read")),
):
    """Test an existing stored rule against a sample event.

    The rule content is loaded from the database; only a sample event is required.
    """
    rule = await RuleRepo.get_by_id(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    try:
        sigma_rule = _engine.load_rule_yaml(rule.content)
        if sigma_rule is None:
            return {"matched": False, "errors": ["Stored rule failed to compile"]}
        matched = sigma_rule._matcher.matches(body.sample_event)
        return {"matched": matched, "errors": []}
    except Exception as exc:
        return {"matched": False, "errors": [f"Evaluation error: {exc}"]}
