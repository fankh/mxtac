"""
Role-Based Access Control (RBAC) middleware for MxTac.

Five roles in ascending privilege order:
  viewer < analyst < hunter < engineer < admin

Usage in endpoints:
    @router.get("/rules")
    async def list_rules(user=Depends(require_permission("rules:read"))):
        ...
"""

from __future__ import annotations

from typing import Callable

from fastapi import Depends

from .exceptions import ForbiddenError
from .security import get_current_user

# ── Role hierarchy (lowest to highest) ────────────────────────────────────────

ROLES = ("viewer", "analyst", "hunter", "engineer", "admin")

# ── Permission matrix ─────────────────────────────────────────────────────────
# Maps each permission string to the set of roles that are granted access.

PERMISSIONS: dict[str, set[str]] = {
    "detections:read":   {"viewer", "analyst", "hunter", "engineer", "admin"},
    "detections:write":  {"analyst", "hunter", "engineer", "admin"},
    "detections:delete": {"admin"},
    "incidents:read":    {"viewer", "analyst", "hunter", "engineer", "admin"},
    "incidents:write":  {"analyst", "hunter", "engineer", "admin"},
    "incidents:delete": {"admin"},
    "rules:read":       {"hunter", "engineer", "admin"},
    "rules:write":      {"engineer", "admin"},
    "connectors:read":  {"engineer", "admin"},
    "connectors:write": {"engineer", "admin"},
    "users:read":       {"admin"},
    "users:write":      {"admin"},
    "events:search":    {"hunter", "engineer", "admin"},
    "threat_intel:read":  {"hunter", "engineer", "admin"},
    "threat_intel:write": {"engineer", "admin"},
    "assets:read":        {"analyst", "hunter", "engineer", "admin"},
    "assets:write":       {"engineer", "admin"},
    "audit_logs:read":    {"admin"},
    "agents:read":        {"engineer", "admin"},
    "agents:write":       {"engineer", "admin"},
    "hunt_queries:read":  {"hunter", "engineer", "admin"},
    "hunt_queries:write": {"hunter", "engineer", "admin"},
    "reports:read":       {"analyst", "hunter", "engineer", "admin"},
    "reports:write":      {"analyst", "hunter", "engineer", "admin"},
    "reports:delete":     {"analyst", "hunter", "engineer", "admin"},
    "notifications:read":  {"engineer", "admin"},
    "notifications:write": {"engineer", "admin"},
    "suppression_rules:read":  {"analyst", "hunter", "engineer", "admin"},
    "suppression_rules:write": {"engineer", "admin"},
}

# ── Role → permissions (inverse map) ──────────────────────────────────────────
# Derived from PERMISSIONS: maps each role to the frozenset of permissions it
# is granted.  Kept in sync automatically — edit PERMISSIONS above, not here.

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    role: frozenset(perm for perm, allowed in PERMISSIONS.items() if role in allowed)
    for role in ROLES
}


def permissions_for_role(role: str) -> frozenset[str]:
    """Return the frozenset of permissions granted to *role*.

    Parameters
    ----------
    role:
        A role string.  If the role is not in :data:`ROLES`, an empty
        frozenset is returned rather than raising an error.
    """
    return ROLE_PERMISSIONS.get(role, frozenset())


def require_permission(permission: str) -> Callable:
    """Return a FastAPI dependency that enforces *permission* for the current user.

    The dependency resolves to the authenticated user dict on success, or raises
    ``ForbiddenError`` if the user's role is not in the allowed set.

    Parameters
    ----------
    permission:
        A string key present in :data:`PERMISSIONS`, e.g. ``"rules:write"``.

    Raises
    ------
    ForbiddenError
        If the user's role lacks the requested permission.
    ValueError
        At import-time if *permission* is not defined in the matrix (developer
        safeguard; does not run at request-time).
    """
    if permission not in PERMISSIONS:
        raise ValueError(
            f"Unknown permission '{permission}'. "
            f"Valid permissions: {', '.join(sorted(PERMISSIONS))}"
        )

    allowed_roles = PERMISSIONS[permission]

    async def _check(current_user: dict = Depends(get_current_user)) -> dict:
        role = current_user.get("role", "viewer")
        if role not in allowed_roles:
            raise ForbiddenError(
                f"Role '{role}' does not have '{permission}' permission"
            )
        return current_user

    return _check
