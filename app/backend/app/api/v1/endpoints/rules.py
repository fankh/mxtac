"""Sigma Rules CRUD + import + test endpoints."""

from __future__ import annotations

import json
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ....core.security import get_current_user
from ....engine.sigma_engine import SigmaEngine, SigmaRule
from ....services.mock_data import DETECTIONS   # reuse for now

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

class RuleTestRequest(BaseModel):
    content: str          # YAML to test
    sample_event: dict    # event to test against

class RuleTestResponse(BaseModel):
    matched: bool
    errors: list[str]

class RuleImportRequest(BaseModel):
    yaml_content: str     # single or multi-doc YAML

# ── In-memory rule store (replace with DB in production) ──────────────────────

_engine = SigmaEngine()
_rule_store: dict[str, dict] = {}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_into_engine(yaml_text: str) -> list[SigmaRule]:
    """Parse YAML (single or multi-doc) and return loaded rules."""
    loaded = []
    for doc in yaml.safe_load_all(yaml_text):
        if isinstance(doc, dict):
            rule = _engine.load_rule_yaml(yaml.dump(doc))
            if rule:
                _engine.add_rule(rule)
                _rule_store[rule.id] = {
                    "id": rule.id,
                    "title": rule.title,
                    "level": rule.level,
                    "status": rule.status,
                    "enabled": rule.enabled,
                    "technique_ids": rule.technique_ids,
                    "tactic_ids":    rule.tactic_ids,
                    "logsource":     rule.logsource,
                    "content":       yaml.dump(doc),
                    "hit_count": 0,
                    "fp_count":  0,
                }
                loaded.append(rule)
    return loaded

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=list[RuleResponse])
async def list_rules(
    enabled: bool | None = None,
    level: str | None = None,
    _: str = Depends(get_current_user),
):
    """List all Sigma rules. Supports filtering by enabled/level."""
    rules = list(_rule_store.values())
    if enabled is not None:
        rules = [r for r in rules if r["enabled"] == enabled]
    if level:
        rules = [r for r in rules if r["level"] == level]
    return rules


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: str, _: str = Depends(get_current_user)):
    rule = _rule_store.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.post("", response_model=RuleResponse, status_code=201)
async def create_rule(body: RuleCreate, _: str = Depends(get_current_user)):
    """Create a custom Sigma rule from raw YAML."""
    loaded = _load_into_engine(body.content)
    if not loaded:
        raise HTTPException(status_code=422, detail="Invalid Sigma YAML")
    rule = loaded[0]
    result = _rule_store[rule.id]
    result["enabled"] = body.enabled
    return result


@router.patch("/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: str, body: RuleUpdate, _: str = Depends(get_current_user)):
    rule = _rule_store.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if body.enabled is not None:
        rule["enabled"] = body.enabled
        if rule_id in _engine._rules:
            _engine._rules[rule_id].enabled = body.enabled
    if body.content is not None:
        loaded = _load_into_engine(body.content)
        if loaded:
            rule["content"] = body.content
    return rule


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: str, _: str = Depends(get_current_user)):
    if rule_id not in _rule_store:
        raise HTTPException(status_code=404, detail="Rule not found")
    del _rule_store[rule_id]
    _engine._rules.pop(rule_id, None)


@router.post("/{rule_id}/test", response_model=RuleTestResponse)
async def test_rule(rule_id: str, body: RuleTestRequest, _: str = Depends(get_current_user)):
    """Test an existing rule against a sample event."""
    rule_obj = _engine._rules.get(rule_id)
    if not rule_obj:
        raise HTTPException(status_code=404, detail="Rule not found")
    try:
        matched = rule_obj._matcher.matches(body.sample_event)
        return {"matched": matched, "errors": []}
    except Exception as exc:
        return {"matched": False, "errors": [str(exc)]}


@router.post("/test", response_model=RuleTestResponse)
async def test_rule_yaml(body: RuleTestRequest, _: str = Depends(get_current_user)):
    """Test arbitrary Sigma YAML against a sample event (no save)."""
    errors = []
    try:
        from ....engine.sigma_engine import _Condition
        doc = yaml.safe_load(body.content)
        detection = doc.get("detection", {})
        cond = _Condition(detection)
        matched = cond.matches(body.sample_event)
        return {"matched": matched, "errors": []}
    except Exception as exc:
        return {"matched": False, "errors": [str(exc)]}


@router.post("/import", response_model=dict)
async def import_rules(body: RuleImportRequest, _: str = Depends(get_current_user)):
    """Bulk import Sigma rules from YAML (single or multi-document)."""
    try:
        loaded = _load_into_engine(body.yaml_content)
        return {"imported": len(loaded), "total_rules": len(_rule_store)}
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Import failed: {exc}")


@router.get("/stats/summary", response_model=dict)
async def rules_summary(_: str = Depends(get_current_user)):
    rules = list(_rule_store.values())
    by_level: dict[str, int] = {}
    for r in rules:
        by_level[r["level"]] = by_level.get(r["level"], 0) + 1
    return {
        "total":   len(rules),
        "enabled": sum(1 for r in rules if r["enabled"]),
        "by_level": by_level,
    }
