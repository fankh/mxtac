"""Notification channel management endpoints."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.notification_channel_repo import NotificationChannelRepo
from ....services.notification_dispatcher import (
    NotificationDispatcher,
    _RULE_FIELDS,
    _RULE_OPERATORS,
    _matches_routing_rules,
)

router = APIRouter(prefix="/notifications/channels", tags=["notifications"])

CHANNEL_TYPES = ["email", "slack", "webhook", "msteams"]
SEVERITY_LEVELS = ["critical", "high", "medium", "low"]

# Required config keys per channel type (at least one must be present and non-empty)
_REQUIRED_CONFIG_KEYS: dict[str, list[str]] = {
    "email":   ["to_addresses"],
    "slack":   ["webhook_url"],
    "webhook": ["url"],
    "msteams": ["webhook_url"],
}


# ── Schemas ───────────────────────────────────────────────────────────────────


class RoutingRule(BaseModel):
    """A single alert routing condition.

    Fields: severity, tactic, technique_id, host, rule_name
    Operators: eq, ne, in, contains, regex
    """

    field: str
    operator: str
    value: Any


class ChannelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    channel_type: str
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    min_severity: str = "low"
    routing_rules: list[RoutingRule] = Field(default_factory=list)


class ChannelUpdate(BaseModel):
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    min_severity: str | None = None
    routing_rules: list[RoutingRule] | None = None


class ChannelResponse(BaseModel):
    id: int
    name: str
    channel_type: str
    config: dict[str, Any]
    enabled: bool
    min_severity: str
    routing_rules: list[dict[str, Any]]
    created_at: datetime
    updated_at: datetime


# ── Helpers ───────────────────────────────────────────────────────────────────


def _channel_to_response(ch) -> dict:
    try:
        config = json.loads(ch.config_json or "{}")
    except json.JSONDecodeError:
        config = {}
    try:
        routing_rules = json.loads(ch.routing_rules or "[]")
        if not isinstance(routing_rules, list):
            routing_rules = []
    except json.JSONDecodeError:
        routing_rules = []
    return {
        "id": ch.id,
        "name": ch.name,
        "channel_type": ch.channel_type,
        "config": config,
        "enabled": ch.enabled,
        "min_severity": ch.min_severity,
        "routing_rules": routing_rules,
        "created_at": ch.created_at,
        "updated_at": ch.updated_at,
    }


def _validate_config(channel_type: str, config: dict[str, Any]) -> None:
    """Raise 422 if required config keys are missing or empty."""
    required = _REQUIRED_CONFIG_KEYS.get(channel_type, [])
    missing = [k for k in required if not config.get(k)]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required config keys for '{channel_type}': {missing}",
        )


def _validate_routing_rules(rules: list[RoutingRule]) -> None:
    """Raise 422 if any routing rule has an invalid field or operator."""
    valid_fields = sorted(_RULE_FIELDS)
    valid_operators = sorted(_RULE_OPERATORS)
    for i, rule in enumerate(rules):
        if rule.field not in _RULE_FIELDS:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"routing_rules[{i}]: invalid field '{rule.field}'. "
                    f"Must be one of: {valid_fields}"
                ),
            )
        if rule.operator not in _RULE_OPERATORS:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"routing_rules[{i}]: invalid operator '{rule.operator}'. "
                    f"Must be one of: {valid_operators}"
                ),
            )
        if rule.operator == "in" and not isinstance(rule.value, list):
            raise HTTPException(
                status_code=422,
                detail=(
                    f"routing_rules[{i}]: operator 'in' requires a list value, "
                    f"got {type(rule.value).__name__}"
                ),
            )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("", response_model=list[ChannelResponse])
async def list_channels(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("notifications:read")),
) -> list[dict]:
    """List all notification channels (paginated)."""
    items, _total = await NotificationChannelRepo.list(db, page=page, page_size=page_size)
    return [_channel_to_response(ch) for ch in items]


@router.get("/{channel_id}", response_model=ChannelResponse)
async def get_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("notifications:read")),
) -> dict:
    """Get a single notification channel by ID."""
    ch = await NotificationChannelRepo.get_by_id(db, channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    return _channel_to_response(ch)


@router.post("", response_model=ChannelResponse, status_code=201)
async def create_channel(
    body: ChannelCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("notifications:write")),
) -> dict:
    """Create a new notification channel.

    Validates that channel_type is one of: email, slack, webhook, msteams.
    Validates required config keys per channel type.
    Validates routing_rules field names and operators if provided.
    """
    if body.channel_type not in CHANNEL_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid channel_type. Must be one of: {CHANNEL_TYPES}",
        )
    if body.min_severity not in SEVERITY_LEVELS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid min_severity. Must be one of: {SEVERITY_LEVELS}",
        )
    _validate_config(body.channel_type, body.config)
    _validate_routing_rules(body.routing_rules)
    ch = await NotificationChannelRepo.create(
        db,
        name=body.name,
        channel_type=body.channel_type,
        config_json=json.dumps(body.config),
        enabled=body.enabled,
        min_severity=body.min_severity,
        routing_rules=json.dumps([r.model_dump() for r in body.routing_rules]),
    )
    return _channel_to_response(ch)


@router.patch("/{channel_id}", response_model=ChannelResponse)
async def update_channel(
    channel_id: int,
    body: ChannelUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("notifications:write")),
) -> dict:
    """Update a notification channel (enable/disable, config, min_severity, routing_rules)."""
    if body.min_severity is not None and body.min_severity not in SEVERITY_LEVELS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid min_severity. Must be one of: {SEVERITY_LEVELS}",
        )
    if body.routing_rules is not None:
        _validate_routing_rules(body.routing_rules)
    updates: dict[str, Any] = {}
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.min_severity is not None:
        updates["min_severity"] = body.min_severity
    if body.config is not None:
        updates["config_json"] = json.dumps(body.config)
    if body.routing_rules is not None:
        updates["routing_rules"] = json.dumps([r.model_dump() for r in body.routing_rules])
    ch = await NotificationChannelRepo.update(db, channel_id, **updates)
    if not ch:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    return _channel_to_response(ch)


@router.delete("/{channel_id}", status_code=204)
async def delete_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("notifications:write")),
):
    """Delete a notification channel."""
    deleted = await NotificationChannelRepo.delete(db, channel_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Notification channel not found")


@router.post("/{channel_id}/test", response_model=dict)
async def test_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("notifications:write")),
) -> dict:
    """Send a dummy test alert through the specified notification channel.

    Returns ``{"channel_id": int, "sent": bool, "message": str}``.
    """
    ch = await NotificationChannelRepo.get_by_id(db, channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Notification channel not found")

    dummy_alert: dict[str, Any] = {
        "rule_id": "test-rule-001",
        "rule_title": "MxTac Test Notification",
        "level": "medium",
        "host": "test-host.local",
        "tactic_ids": ["TA0001"],
        "technique_ids": ["T1059"],
        "score": 50,
        "time": datetime.now(timezone.utc).isoformat(),
    }

    dispatcher = NotificationDispatcher()
    try:
        await dispatcher._dispatch_one(ch, dummy_alert)
        sent = True
        message = f"Test notification sent via {ch.channel_type} channel '{ch.name}'"
    except Exception as exc:
        sent = False
        message = str(exc)
    finally:
        await dispatcher.close()

    return {"channel_id": channel_id, "sent": sent, "message": message}


@router.get("/{channel_id}/test-rule", response_model=dict)
async def test_routing_rule(
    channel_id: int,
    severity: str = Query("high", description="Alert severity level"),
    tactic: str = Query("lateral-movement", description="Alert tactic ID"),
    technique_id: str = Query("T1059", description="Alert technique ID"),
    host: str = Query("test-host.local", description="Alert host"),
    rule_name: str = Query("Test Rule", description="Alert rule name / title"),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("notifications:read")),
) -> dict:
    """Test the channel's routing rules against a sample alert.

    Evaluates the channel's ``routing_rules`` against the provided alert fields
    without sending an actual notification.

    Returns::

        {
            "channel_id": int,
            "matched": bool,          # True → alert would be routed to this channel
            "routing_rules": list,    # the channel's current rules (may be empty)
            "sample_alert": dict,     # the constructed sample alert
        }

    If ``routing_rules`` is empty the channel receives all alerts (above min_severity),
    so ``matched`` will always be ``True`` in that case.
    """
    ch = await NotificationChannelRepo.get_by_id(db, channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Notification channel not found")

    try:
        rules: list[dict] = json.loads(ch.routing_rules or "[]")
        if not isinstance(rules, list):
            rules = []
    except json.JSONDecodeError:
        rules = []

    sample_alert: dict[str, Any] = {
        "rule_id": "test-rule-001",
        "rule_title": rule_name,
        "level": severity,
        "host": host,
        "tactic_ids": [tactic],
        "technique_ids": [technique_id],
        "score": 50,
        "time": datetime.now(timezone.utc).isoformat(),
    }

    matched = _matches_routing_rules(rules, sample_alert)

    return {
        "channel_id": channel_id,
        "matched": matched,
        "routing_rules": rules,
        "sample_alert": sample_alert,
    }
