"""Tests for app/core/rbac.py

Feature 3.1: Roles: viewer / analyst / hunter / engineer / admin
Feature 3.2: Permission map — role → allowed actions

Coverage:
  ROLES constant:
    - Tuple contains exactly 5 roles in ascending privilege order
    - All expected role names are present
  PERMISSIONS matrix:
    - All 12 permissions are defined
    - Each permission maps to the correct set of allowed roles
    - Viewer-only permissions return empty denied sets for viewer
    - Admin-only permissions deny all other roles
  ROLE_PERMISSIONS map (Feature 3.2):
    - Dict with exactly 5 keys (one per role)
    - Each value is a frozenset of valid permission strings
    - Correct permission sets for each role
    - Monotonically increasing: each role is a superset of roles below it
    - Consistent with PERMISSIONS (inverse relationship)
  permissions_for_role() (Feature 3.2):
    - Returns correct frozenset for each known role
    - Returns empty frozenset for unknown roles
    - Return type is always frozenset
  require_permission():
    - Raises ValueError at call-time for unknown permission (developer safeguard)
    - Returns a callable for valid permissions
  _check (inner dependency):
    - Allowed role → returns user dict unchanged
    - Disallowed role → raises ForbiddenError
    - Missing 'role' key in user dict → defaults to 'viewer'
    - ForbiddenError message names both the role and the permission
  User model (role field):
    - Default role is 'analyst'
    - Role field can be set to each of the five valid roles
    - __repr__ includes role
  Integration (HTTP via test client):
    - viewer/analyst blocked from rules:read endpoint → 403
    - hunter passes rules:read endpoint → not 403
    - viewer blocked from detections:write endpoint → 403
    - analyst passes detections:write endpoint → not 403
    - all roles pass detections:read endpoint → not 403
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock, patch

from app.core.exceptions import ForbiddenError
from app.core.rbac import PERMISSIONS, ROLE_PERMISSIONS, ROLES, permissions_for_role, require_permission

# ---------------------------------------------------------------------------
# Constants under test
# ---------------------------------------------------------------------------

_ALL_ROLES = ("viewer", "analyst", "hunter", "engineer", "admin")

# ---------------------------------------------------------------------------
# ROLES constant
# ---------------------------------------------------------------------------


class TestRolesConstant:
    """ROLES tuple has the correct membership and order."""

    def test_roles_is_tuple(self) -> None:
        assert isinstance(ROLES, tuple)

    def test_roles_has_five_entries(self) -> None:
        assert len(ROLES) == 5

    def test_viewer_is_first(self) -> None:
        assert ROLES[0] == "viewer"

    def test_analyst_is_second(self) -> None:
        assert ROLES[1] == "analyst"

    def test_hunter_is_third(self) -> None:
        assert ROLES[2] == "hunter"

    def test_engineer_is_fourth(self) -> None:
        assert ROLES[3] == "engineer"

    def test_admin_is_last(self) -> None:
        assert ROLES[4] == "admin"

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_all_roles_present(self, role: str) -> None:
        assert role in ROLES

    def test_no_duplicate_roles(self) -> None:
        assert len(ROLES) == len(set(ROLES))


# ---------------------------------------------------------------------------
# PERMISSIONS matrix — structure
# ---------------------------------------------------------------------------


class TestPermissionsMatrix:
    """PERMISSIONS dict has the correct keys and each value is a set of strings."""

    _EXPECTED_PERMISSIONS = {
        "detections:read",
        "detections:write",
        "incidents:read",
        "incidents:write",
        "incidents:delete",
        "rules:read",
        "rules:write",
        "connectors:read",
        "connectors:write",
        "users:read",
        "users:write",
        "events:search",
    }

    def test_permissions_is_dict(self) -> None:
        assert isinstance(PERMISSIONS, dict)

    def test_permissions_has_eleven_entries(self) -> None:
        assert len(PERMISSIONS) == 12

    @pytest.mark.parametrize("perm", list(_EXPECTED_PERMISSIONS))
    def test_expected_permission_exists(self, perm: str) -> None:
        assert perm in PERMISSIONS

    @pytest.mark.parametrize("perm", list(_EXPECTED_PERMISSIONS))
    def test_permission_value_is_set(self, perm: str) -> None:
        assert isinstance(PERMISSIONS[perm], set)

    @pytest.mark.parametrize("perm", list(_EXPECTED_PERMISSIONS))
    def test_permission_roles_are_valid_strings(self, perm: str) -> None:
        for role in PERMISSIONS[perm]:
            assert role in _ALL_ROLES, f"Unknown role '{role}' in '{perm}'"


# ---------------------------------------------------------------------------
# PERMISSIONS matrix — correctness for each permission
# ---------------------------------------------------------------------------


class TestPermissionsCorrectness:
    """Each permission grants access to exactly the documented role set."""

    # --- detections:read — all five roles ---

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_detections_read_allows_all_roles(self, role: str) -> None:
        assert role in PERMISSIONS["detections:read"]

    # --- detections:write — analyst and above (not viewer) ---

    def test_detections_write_denies_viewer(self) -> None:
        assert "viewer" not in PERMISSIONS["detections:write"]

    @pytest.mark.parametrize("role", ["analyst", "hunter", "engineer", "admin"])
    def test_detections_write_allows_analyst_and_above(self, role: str) -> None:
        assert role in PERMISSIONS["detections:write"]

    # --- incidents:read — all five roles ---

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_incidents_read_allows_all_roles(self, role: str) -> None:
        assert role in PERMISSIONS["incidents:read"]

    # --- incidents:write — analyst and above (not viewer) ---

    def test_incidents_write_denies_viewer(self) -> None:
        assert "viewer" not in PERMISSIONS["incidents:write"]

    @pytest.mark.parametrize("role", ["analyst", "hunter", "engineer", "admin"])
    def test_incidents_write_allows_analyst_and_above(self, role: str) -> None:
        assert role in PERMISSIONS["incidents:write"]

    # --- rules:read — hunter and above (not viewer, analyst) ---

    @pytest.mark.parametrize("role", ["viewer", "analyst"])
    def test_rules_read_denies_viewer_and_analyst(self, role: str) -> None:
        assert role not in PERMISSIONS["rules:read"]

    @pytest.mark.parametrize("role", ["hunter", "engineer", "admin"])
    def test_rules_read_allows_hunter_and_above(self, role: str) -> None:
        assert role in PERMISSIONS["rules:read"]

    # --- rules:write — engineer and above (not viewer, analyst, hunter) ---

    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter"])
    def test_rules_write_denies_below_engineer(self, role: str) -> None:
        assert role not in PERMISSIONS["rules:write"]

    @pytest.mark.parametrize("role", ["engineer", "admin"])
    def test_rules_write_allows_engineer_and_admin(self, role: str) -> None:
        assert role in PERMISSIONS["rules:write"]

    # --- connectors:read — engineer and above ---

    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter"])
    def test_connectors_read_denies_below_engineer(self, role: str) -> None:
        assert role not in PERMISSIONS["connectors:read"]

    @pytest.mark.parametrize("role", ["engineer", "admin"])
    def test_connectors_read_allows_engineer_and_admin(self, role: str) -> None:
        assert role in PERMISSIONS["connectors:read"]

    # --- connectors:write — engineer and above ---

    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter"])
    def test_connectors_write_denies_below_engineer(self, role: str) -> None:
        assert role not in PERMISSIONS["connectors:write"]

    @pytest.mark.parametrize("role", ["engineer", "admin"])
    def test_connectors_write_allows_engineer_and_admin(self, role: str) -> None:
        assert role in PERMISSIONS["connectors:write"]

    # --- users:read — admin only ---

    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter", "engineer"])
    def test_users_read_denies_non_admin(self, role: str) -> None:
        assert role not in PERMISSIONS["users:read"]

    def test_users_read_allows_admin(self) -> None:
        assert "admin" in PERMISSIONS["users:read"]

    def test_users_read_allows_only_admin(self) -> None:
        assert PERMISSIONS["users:read"] == {"admin"}

    # --- users:write — admin only ---

    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter", "engineer"])
    def test_users_write_denies_non_admin(self, role: str) -> None:
        assert role not in PERMISSIONS["users:write"]

    def test_users_write_allows_admin(self) -> None:
        assert "admin" in PERMISSIONS["users:write"]

    def test_users_write_allows_only_admin(self) -> None:
        assert PERMISSIONS["users:write"] == {"admin"}

    # --- events:search — hunter and above (not viewer, analyst) ---

    @pytest.mark.parametrize("role", ["viewer", "analyst"])
    def test_events_search_denies_viewer_and_analyst(self, role: str) -> None:
        assert role not in PERMISSIONS["events:search"]

    @pytest.mark.parametrize("role", ["hunter", "engineer", "admin"])
    def test_events_search_allows_hunter_and_above(self, role: str) -> None:
        assert role in PERMISSIONS["events:search"]


# ---------------------------------------------------------------------------
# ROLE_PERMISSIONS map (Feature 3.2) — structure
# ---------------------------------------------------------------------------


class TestRolePermissionsStructure:
    """ROLE_PERMISSIONS is a dict with one frozenset per role."""

    def test_role_permissions_is_dict(self) -> None:
        assert isinstance(ROLE_PERMISSIONS, dict)

    def test_role_permissions_has_five_keys(self) -> None:
        assert len(ROLE_PERMISSIONS) == 5

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_all_roles_are_keys(self, role: str) -> None:
        assert role in ROLE_PERMISSIONS

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_each_value_is_frozenset(self, role: str) -> None:
        assert isinstance(ROLE_PERMISSIONS[role], frozenset)

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_each_permission_in_role_is_valid(self, role: str) -> None:
        for perm in ROLE_PERMISSIONS[role]:
            assert perm in PERMISSIONS, f"Unknown permission '{perm}' in ROLE_PERMISSIONS['{role}']"


# ---------------------------------------------------------------------------
# ROLE_PERMISSIONS map — correctness for each role
# ---------------------------------------------------------------------------

_VIEWER_PERMS = frozenset({"detections:read", "incidents:read"})
_ANALYST_PERMS = _VIEWER_PERMS | {"detections:write", "incidents:write"}
_HUNTER_PERMS = _ANALYST_PERMS | {"rules:read", "events:search"}
_ENGINEER_PERMS = _HUNTER_PERMS | {"rules:write", "connectors:read", "connectors:write"}
_ADMIN_PERMS = _ENGINEER_PERMS | {"users:read", "users:write", "incidents:delete"}


class TestRolePermissionsCorrectness:
    """Each role has exactly the documented permission set."""

    def test_viewer_permissions(self) -> None:
        assert ROLE_PERMISSIONS["viewer"] == _VIEWER_PERMS

    def test_analyst_permissions(self) -> None:
        assert ROLE_PERMISSIONS["analyst"] == _ANALYST_PERMS

    def test_hunter_permissions(self) -> None:
        assert ROLE_PERMISSIONS["hunter"] == _HUNTER_PERMS

    def test_engineer_permissions(self) -> None:
        assert ROLE_PERMISSIONS["engineer"] == _ENGINEER_PERMS

    def test_admin_permissions(self) -> None:
        assert ROLE_PERMISSIONS["admin"] == _ADMIN_PERMS

    def test_admin_has_all_eleven_permissions(self) -> None:
        assert len(ROLE_PERMISSIONS["admin"]) == 12

    def test_viewer_has_two_permissions(self) -> None:
        assert len(ROLE_PERMISSIONS["viewer"]) == 2

    def test_analyst_has_four_permissions(self) -> None:
        assert len(ROLE_PERMISSIONS["analyst"]) == 4

    def test_hunter_has_six_permissions(self) -> None:
        assert len(ROLE_PERMISSIONS["hunter"]) == 6

    def test_engineer_has_nine_permissions(self) -> None:
        assert len(ROLE_PERMISSIONS["engineer"]) == 9

    # --- Specific inclusions ---

    @pytest.mark.parametrize("perm", ["detections:read", "incidents:read"])
    def test_viewer_has_read_only_permissions(self, perm: str) -> None:
        assert perm in ROLE_PERMISSIONS["viewer"]

    def test_viewer_cannot_write_detections(self) -> None:
        assert "detections:write" not in ROLE_PERMISSIONS["viewer"]

    def test_viewer_cannot_write_incidents(self) -> None:
        assert "incidents:write" not in ROLE_PERMISSIONS["viewer"]

    def test_analyst_can_write_detections(self) -> None:
        assert "detections:write" in ROLE_PERMISSIONS["analyst"]

    def test_analyst_cannot_read_rules(self) -> None:
        assert "rules:read" not in ROLE_PERMISSIONS["analyst"]

    def test_hunter_can_read_rules(self) -> None:
        assert "rules:read" in ROLE_PERMISSIONS["hunter"]

    def test_hunter_cannot_write_rules(self) -> None:
        assert "rules:write" not in ROLE_PERMISSIONS["hunter"]

    def test_hunter_can_search_events(self) -> None:
        assert "events:search" in ROLE_PERMISSIONS["hunter"]

    def test_engineer_can_write_rules(self) -> None:
        assert "rules:write" in ROLE_PERMISSIONS["engineer"]

    def test_engineer_can_read_connectors(self) -> None:
        assert "connectors:read" in ROLE_PERMISSIONS["engineer"]

    def test_engineer_cannot_read_users(self) -> None:
        assert "users:read" not in ROLE_PERMISSIONS["engineer"]

    def test_admin_can_read_users(self) -> None:
        assert "users:read" in ROLE_PERMISSIONS["admin"]

    def test_admin_can_write_users(self) -> None:
        assert "users:write" in ROLE_PERMISSIONS["admin"]


class TestRolePermissionsMonotonicity:
    """Higher privilege roles have a strict superset of lower roles' permissions."""

    def test_analyst_is_superset_of_viewer(self) -> None:
        assert ROLE_PERMISSIONS["viewer"] < ROLE_PERMISSIONS["analyst"]

    def test_hunter_is_superset_of_analyst(self) -> None:
        assert ROLE_PERMISSIONS["analyst"] < ROLE_PERMISSIONS["hunter"]

    def test_engineer_is_superset_of_hunter(self) -> None:
        assert ROLE_PERMISSIONS["hunter"] < ROLE_PERMISSIONS["engineer"]

    def test_admin_is_superset_of_engineer(self) -> None:
        assert ROLE_PERMISSIONS["engineer"] < ROLE_PERMISSIONS["admin"]


class TestRolePermissionsConsistency:
    """ROLE_PERMISSIONS and PERMISSIONS are consistent inverses of each other."""

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_role_perms_match_permissions_inverse(self, role: str) -> None:
        """For every permission, role is in the allowed set iff it's in ROLE_PERMISSIONS."""
        for perm, allowed_roles in PERMISSIONS.items():
            if role in allowed_roles:
                assert perm in ROLE_PERMISSIONS[role], (
                    f"'{perm}' should be in ROLE_PERMISSIONS['{role}']"
                )
            else:
                assert perm not in ROLE_PERMISSIONS[role], (
                    f"'{perm}' should NOT be in ROLE_PERMISSIONS['{role}']"
                )


# ---------------------------------------------------------------------------
# permissions_for_role() helper (Feature 3.2)
# ---------------------------------------------------------------------------


class TestPermissionsForRole:
    """permissions_for_role() returns the correct frozenset."""

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_returns_frozenset_for_known_roles(self, role: str) -> None:
        result = permissions_for_role(role)
        assert isinstance(result, frozenset)

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_matches_role_permissions_dict(self, role: str) -> None:
        assert permissions_for_role(role) == ROLE_PERMISSIONS[role]

    def test_viewer_result(self) -> None:
        assert permissions_for_role("viewer") == _VIEWER_PERMS

    def test_analyst_result(self) -> None:
        assert permissions_for_role("analyst") == _ANALYST_PERMS

    def test_hunter_result(self) -> None:
        assert permissions_for_role("hunter") == _HUNTER_PERMS

    def test_engineer_result(self) -> None:
        assert permissions_for_role("engineer") == _ENGINEER_PERMS

    def test_admin_result(self) -> None:
        assert permissions_for_role("admin") == _ADMIN_PERMS

    def test_unknown_role_returns_empty_frozenset(self) -> None:
        assert permissions_for_role("superuser") == frozenset()

    def test_empty_string_returns_empty_frozenset(self) -> None:
        assert permissions_for_role("") == frozenset()

    def test_unknown_role_return_type_is_frozenset(self) -> None:
        result = permissions_for_role("nonexistent")
        assert isinstance(result, frozenset)

    def test_result_is_immutable(self) -> None:
        """The returned frozenset cannot be mutated."""
        result = permissions_for_role("admin")
        with pytest.raises(AttributeError):
            result.add("new:permission")  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# require_permission() — validation
# ---------------------------------------------------------------------------


class TestRequirePermissionValidation:
    """require_permission raises ValueError immediately for unknown permissions."""

    def test_unknown_permission_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            require_permission("unknown:permission")

    def test_error_message_names_the_permission(self) -> None:
        with pytest.raises(ValueError, match="unknown:perm"):
            require_permission("unknown:perm")

    def test_error_message_lists_valid_permissions(self) -> None:
        with pytest.raises(ValueError, match="rules:read"):
            require_permission("bogus:action")

    def test_empty_string_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            require_permission("")

    def test_partial_match_raises_value_error(self) -> None:
        """'rules' alone is not a valid permission key."""
        with pytest.raises(ValueError):
            require_permission("rules")

    def test_valid_permission_returns_callable(self) -> None:
        checker = require_permission("rules:read")
        assert callable(checker)

    @pytest.mark.parametrize("perm", [
        "detections:read", "detections:write",
        "incidents:read", "incidents:write", "incidents:delete",
        "rules:read", "rules:write",
        "connectors:read", "connectors:write",
        "users:read", "users:write",
        "events:search",
    ])
    def test_all_known_permissions_return_callable(self, perm: str) -> None:
        checker = require_permission(perm)
        assert callable(checker)


# ---------------------------------------------------------------------------
# require_permission() — _check inner dependency (unit)
# ---------------------------------------------------------------------------

# We call _check directly, bypassing FastAPI's DI by passing current_user explicitly.


class TestRequirePermissionAllowed:
    """_check returns the user dict when the role has the requested permission."""

    async def test_admin_can_use_users_write(self) -> None:
        checker = require_permission("users:write")
        user = {"email": "admin@mxtac.local", "role": "admin"}
        result = await checker(current_user=user)
        assert result is user

    async def test_admin_can_use_users_read(self) -> None:
        checker = require_permission("users:read")
        user = {"email": "admin@mxtac.local", "role": "admin"}
        result = await checker(current_user=user)
        assert result is user

    async def test_engineer_can_use_rules_write(self) -> None:
        checker = require_permission("rules:write")
        user = {"email": "eng@mxtac.local", "role": "engineer"}
        result = await checker(current_user=user)
        assert result is user

    async def test_engineer_can_use_connectors_read(self) -> None:
        checker = require_permission("connectors:read")
        user = {"email": "eng@mxtac.local", "role": "engineer"}
        result = await checker(current_user=user)
        assert result is user

    async def test_hunter_can_use_rules_read(self) -> None:
        checker = require_permission("rules:read")
        user = {"email": "h@mxtac.local", "role": "hunter"}
        result = await checker(current_user=user)
        assert result is user

    async def test_hunter_can_use_events_search(self) -> None:
        checker = require_permission("events:search")
        user = {"email": "h@mxtac.local", "role": "hunter"}
        result = await checker(current_user=user)
        assert result is user

    async def test_analyst_can_use_detections_write(self) -> None:
        checker = require_permission("detections:write")
        user = {"email": "a@mxtac.local", "role": "analyst"}
        result = await checker(current_user=user)
        assert result is user

    async def test_analyst_can_use_incidents_write(self) -> None:
        checker = require_permission("incidents:write")
        user = {"email": "a@mxtac.local", "role": "analyst"}
        result = await checker(current_user=user)
        assert result is user

    async def test_viewer_can_use_detections_read(self) -> None:
        checker = require_permission("detections:read")
        user = {"email": "v@mxtac.local", "role": "viewer"}
        result = await checker(current_user=user)
        assert result is user

    async def test_viewer_can_use_incidents_read(self) -> None:
        checker = require_permission("incidents:read")
        user = {"email": "v@mxtac.local", "role": "viewer"}
        result = await checker(current_user=user)
        assert result is user

    @pytest.mark.parametrize("role", _ALL_ROLES)
    async def test_all_roles_can_read_detections(self, role: str) -> None:
        checker = require_permission("detections:read")
        user = {"email": f"{role}@mxtac.local", "role": role}
        result = await checker(current_user=user)
        assert result["role"] == role

    @pytest.mark.parametrize("role", _ALL_ROLES)
    async def test_all_roles_can_read_incidents(self, role: str) -> None:
        checker = require_permission("incidents:read")
        user = {"email": f"{role}@mxtac.local", "role": role}
        result = await checker(current_user=user)
        assert result["role"] == role


class TestRequirePermissionForbidden:
    """_check raises ForbiddenError when the role lacks the requested permission."""

    async def test_viewer_cannot_use_detections_write(self) -> None:
        checker = require_permission("detections:write")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "v@mxtac.local", "role": "viewer"})

    async def test_viewer_cannot_use_incidents_write(self) -> None:
        checker = require_permission("incidents:write")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "v@mxtac.local", "role": "viewer"})

    async def test_viewer_cannot_use_rules_read(self) -> None:
        checker = require_permission("rules:read")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "v@mxtac.local", "role": "viewer"})

    async def test_analyst_cannot_use_rules_read(self) -> None:
        checker = require_permission("rules:read")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "a@mxtac.local", "role": "analyst"})

    async def test_viewer_cannot_use_rules_write(self) -> None:
        checker = require_permission("rules:write")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "v@mxtac.local", "role": "viewer"})

    async def test_analyst_cannot_use_rules_write(self) -> None:
        checker = require_permission("rules:write")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "a@mxtac.local", "role": "analyst"})

    async def test_hunter_cannot_use_rules_write(self) -> None:
        checker = require_permission("rules:write")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "h@mxtac.local", "role": "hunter"})

    async def test_viewer_cannot_use_connectors_read(self) -> None:
        checker = require_permission("connectors:read")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "v@mxtac.local", "role": "viewer"})

    async def test_hunter_cannot_use_connectors_read(self) -> None:
        checker = require_permission("connectors:read")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "h@mxtac.local", "role": "hunter"})

    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter", "engineer"])
    async def test_non_admin_cannot_use_users_read(self, role: str) -> None:
        checker = require_permission("users:read")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": f"{role}@mxtac.local", "role": role})

    @pytest.mark.parametrize("role", ["viewer", "analyst", "hunter", "engineer"])
    async def test_non_admin_cannot_use_users_write(self, role: str) -> None:
        checker = require_permission("users:write")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": f"{role}@mxtac.local", "role": role})

    async def test_viewer_cannot_use_events_search(self) -> None:
        checker = require_permission("events:search")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "v@mxtac.local", "role": "viewer"})

    async def test_analyst_cannot_use_events_search(self) -> None:
        checker = require_permission("events:search")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "a@mxtac.local", "role": "analyst"})


class TestRequirePermissionForbiddenMessage:
    """ForbiddenError message names both the denied role and the permission."""

    async def test_error_message_includes_role(self) -> None:
        checker = require_permission("rules:write")
        with pytest.raises(ForbiddenError, match="viewer"):
            await checker(current_user={"email": "v@mxtac.local", "role": "viewer"})

    async def test_error_message_includes_permission(self) -> None:
        checker = require_permission("rules:write")
        with pytest.raises(ForbiddenError, match="rules:write"):
            await checker(current_user={"email": "v@mxtac.local", "role": "viewer"})

    async def test_error_message_hunter_and_users_read(self) -> None:
        checker = require_permission("users:read")
        with pytest.raises(ForbiddenError, match="hunter"):
            await checker(current_user={"email": "h@mxtac.local", "role": "hunter"})

    async def test_forbidden_error_http_status_is_403(self) -> None:
        """ForbiddenError carries the 403 status code attribute."""
        checker = require_permission("rules:write")
        with pytest.raises(ForbiddenError) as exc_info:
            await checker(current_user={"email": "v@mxtac.local", "role": "viewer"})
        assert exc_info.value.status_code == 403


class TestRequirePermissionMissingRole:
    """When the user dict has no 'role' key, the dependency defaults to 'viewer'."""

    async def test_missing_role_key_defaults_to_viewer_and_is_denied(self) -> None:
        """User dict without 'role' acts as viewer — denied from rules:read."""
        checker = require_permission("rules:read")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "ghost@mxtac.local"})

    async def test_missing_role_key_defaults_to_viewer_and_is_allowed(self) -> None:
        """User dict without 'role' acts as viewer — allowed for detections:read."""
        checker = require_permission("detections:read")
        result = await checker(current_user={"email": "ghost@mxtac.local"})
        assert result["email"] == "ghost@mxtac.local"

    async def test_none_role_value_is_denied_for_restricted_permission(self) -> None:
        """role=None is not in any allowed set — treated as unknown role."""
        checker = require_permission("rules:write")
        with pytest.raises(ForbiddenError):
            await checker(current_user={"email": "x@mxtac.local", "role": None})


# ---------------------------------------------------------------------------
# User model — role field
# ---------------------------------------------------------------------------


class TestUserModelRole:
    """User.role field defaults to 'analyst' (column default), accepts all five roles, appears in repr."""

    def test_column_default_role_is_analyst(self) -> None:
        """The SQLAlchemy column default for role is 'analyst'.

        SQLAlchemy `default=` is an insert-time default, not a Python attribute
        default.  We verify the column metadata rather than the object attribute.
        """
        from app.models.user import User
        col = User.__table__.c.role
        assert col.default is not None
        assert col.default.arg == "analyst"

    def test_column_default_is_active_is_true(self) -> None:
        """The SQLAlchemy column default for is_active is True."""
        from app.models.user import User
        col = User.__table__.c.is_active
        assert col.default is not None
        assert col.default.arg is True

    @pytest.mark.asyncio
    async def test_default_role_applied_on_db_insert(self, db_session) -> None:
        """After a DB insert with no explicit role, role resolves to 'analyst'."""
        from app.models.user import User
        u = User(email="noroleset@mxtac.local", hashed_password="$2b$12$hash")
        db_session.add(u)
        await db_session.flush()
        await db_session.refresh(u)
        assert u.role == "analyst"

    @pytest.mark.asyncio
    async def test_is_active_applied_on_db_insert(self, db_session) -> None:
        """After a DB insert with no explicit is_active, it resolves to True."""
        from app.models.user import User
        u = User(email="noactive@mxtac.local", hashed_password="$2b$12$hash")
        db_session.add(u)
        await db_session.flush()
        await db_session.refresh(u)
        assert u.is_active is True

    @pytest.mark.parametrize("role", _ALL_ROLES)
    def test_role_field_accepts_all_valid_roles(self, role: str) -> None:
        from app.models.user import User
        u = User(
            email=f"{role}@mxtac.local",
            hashed_password="$2b$12$hash",
            role=role,
        )
        assert u.role == role

    def test_repr_includes_role(self) -> None:
        from app.models.user import User
        u = User(
            email="hunter@mxtac.local",
            hashed_password="$2b$12$hash",
            role="hunter",
        )
        assert "hunter" in repr(u)

    def test_repr_includes_email(self) -> None:
        from app.models.user import User
        u = User(
            email="admin@mxtac.local",
            hashed_password="$2b$12$hash",
            role="admin",
        )
        assert "admin@mxtac.local" in repr(u)

    def test_role_is_mutable(self) -> None:
        """Role can be changed after construction."""
        from app.models.user import User
        u = User(email="u@mxtac.local", hashed_password="$2b$12$hash", role="viewer")
        u.role = "engineer"
        assert u.role == "engineer"


# ---------------------------------------------------------------------------
# Integration — HTTP enforcement via test client
# ---------------------------------------------------------------------------

MOCK_IS_BLACKLISTED = "app.core.security.is_token_blacklisted"


class TestRbacIntegrationRulesRead:
    """GET /api/v1/rules enforces rules:read — hunter+ allowed, viewer/analyst denied."""

    async def test_unauthenticated_rules_read_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/rules")
        assert resp.status_code == 401

    async def test_viewer_rules_read_returns_403(self, client: AsyncClient, viewer_headers: dict) -> None:
        resp = await client.get("/api/v1/rules", headers=viewer_headers)
        assert resp.status_code == 403

    async def test_analyst_rules_read_returns_403(self, client: AsyncClient, analyst_headers: dict) -> None:
        resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert resp.status_code == 403

    async def test_hunter_rules_read_is_not_403(self, client: AsyncClient, hunter_headers: dict) -> None:
        resp = await client.get("/api/v1/rules", headers=hunter_headers)
        assert resp.status_code != 403

    async def test_engineer_rules_read_is_not_403(self, client: AsyncClient, engineer_headers: dict) -> None:
        resp = await client.get("/api/v1/rules", headers=engineer_headers)
        assert resp.status_code != 403

    async def test_admin_rules_read_is_not_403(self, client: AsyncClient, admin_headers: dict) -> None:
        resp = await client.get("/api/v1/rules", headers=admin_headers)
        assert resp.status_code != 403


class TestRbacIntegrationDetectionsRead:
    """GET /api/v1/detections enforces detections:read — all roles allowed."""

    async def test_unauthenticated_detections_read_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/detections")
        assert resp.status_code == 401

    @pytest.mark.parametrize("headers_fixture", [
        "viewer_headers", "analyst_headers", "hunter_headers",
        "engineer_headers", "admin_headers",
    ])
    async def test_all_roles_pass_detections_read(
        self, request, client: AsyncClient, headers_fixture: str
    ) -> None:
        headers = request.getfixturevalue(headers_fixture)
        resp = await client.get("/api/v1/detections", headers=headers)
        assert resp.status_code != 403, (
            f"Role '{headers_fixture.replace('_headers', '')}' was wrongly denied detections:read"
        )


class TestRbacIntegrationDetectionsWrite:
    """PATCH /api/v1/detections/{id} enforces detections:write — viewer denied, analyst+ allowed."""

    _PATCH_URL = "/api/v1/detections/DET-2026-00001"
    _PATCH_BODY = {"status": "investigating"}

    async def test_viewer_detections_write_returns_403(self, client: AsyncClient, viewer_headers: dict) -> None:
        resp = await client.patch(self._PATCH_URL, headers=viewer_headers, json=self._PATCH_BODY)
        assert resp.status_code == 403

    async def test_analyst_detections_write_is_not_403(self, client: AsyncClient, analyst_headers: dict) -> None:
        """Analyst has detections:write — RBAC passes even if resource is 404."""
        resp = await client.patch(self._PATCH_URL, headers=analyst_headers, json=self._PATCH_BODY)
        assert resp.status_code != 403

    async def test_admin_detections_write_is_not_403(self, client: AsyncClient, admin_headers: dict) -> None:
        resp = await client.patch(self._PATCH_URL, headers=admin_headers, json=self._PATCH_BODY)
        assert resp.status_code != 403


class TestRbacIntegrationUsersEndpoints:
    """Users endpoints enforce users:read (admin only)."""

    async def test_unauthenticated_list_users_returns_401_or_403(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/users")
        assert resp.status_code in (401, 403)

    async def test_viewer_list_users_returns_403(self, client: AsyncClient, viewer_headers: dict) -> None:
        """Users endpoint enforces users:read — viewer is denied."""
        resp = await client.get("/api/v1/users", headers=viewer_headers)
        assert resp.status_code == 403

    async def test_engineer_list_users_returns_403(self, client: AsyncClient, engineer_headers: dict) -> None:
        """Users endpoint enforces users:read — engineer is denied."""
        resp = await client.get("/api/v1/users", headers=engineer_headers)
        assert resp.status_code == 403

    async def test_admin_can_list_users(self, client: AsyncClient, admin_headers: dict) -> None:
        resp = await client.get("/api/v1/users", headers=admin_headers)
        assert resp.status_code == 200


class TestRbacIntegrationForbiddenResponseShape:
    """403 responses from require_permission have the expected JSON structure."""

    async def test_forbidden_response_has_detail_key(self, client: AsyncClient, viewer_headers: dict) -> None:
        resp = await client.get("/api/v1/rules", headers=viewer_headers)
        assert resp.status_code == 403
        assert "detail" in resp.json()

    async def test_forbidden_response_mentions_role(self, client: AsyncClient, analyst_headers: dict) -> None:
        resp = await client.get("/api/v1/rules", headers=analyst_headers)
        assert resp.status_code == 403
        body = resp.json()
        assert "analyst" in body.get("detail", "")

    async def test_forbidden_response_mentions_permission(self, client: AsyncClient, viewer_headers: dict) -> None:
        resp = await client.get("/api/v1/rules", headers=viewer_headers)
        assert resp.status_code == 403
        body = resp.json()
        assert "rules:read" in body.get("detail", "")
