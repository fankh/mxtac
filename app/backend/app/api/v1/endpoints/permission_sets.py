"""Permission Set management endpoints (Feature 3.9).

Permission Sets are named, reusable collections of RBAC permission strings.
They allow admins and engineers to define consistent access profiles that can
be applied to multiple API keys.

Routes:
  POST   /auth/permission-sets        — Create a permission set (engineer+)
  GET    /auth/permission-sets        — List active permission sets (authenticated)
  GET    /auth/permission-sets/{id}   — Get a permission set by ID (authenticated)
  PUT    /auth/permission-sets/{id}   — Update a permission set (engineer+)
  DELETE /auth/permission-sets/{id}   — Soft-delete a permission set (admin only)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....core.security import get_current_user
from ....repositories.permission_set_repo import PermissionSetRepo
from ....repositories.user_repo import UserRepo
from ....schemas.permission_set import (
    PermissionSetCreate,
    PermissionSetResponse,
    PermissionSetUpdate,
)

router = APIRouter(prefix="/auth/permission-sets", tags=["permission-sets"])


def _to_response(ps) -> PermissionSetResponse:
    return PermissionSetResponse(
        id=ps.id,
        name=ps.name,
        description=ps.description,
        permissions=ps.permissions,
        is_active=ps.is_active,
        created_by=ps.created_by,
        created_at=ps.created_at,
        updated_at=ps.updated_at,
    )


@router.post("", response_model=PermissionSetResponse, status_code=201)
async def create_permission_set(
    body: PermissionSetCreate,
    current_user: dict = Depends(require_permission("connectors:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a named permission set.

    Requires at least the ``connectors:write`` permission (engineer or admin).
    All permissions in the set must be valid scope strings.  The caller cannot
    include permissions that exceed their own role's permissions.
    """
    from ....core.rbac import permissions_for_role

    user_permissions = permissions_for_role(current_user["role"])
    forbidden = [p for p in body.permissions if p not in user_permissions]
    if forbidden:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permissions exceed your role permissions: {forbidden}",
        )

    # Resolve creator's DB user record for the created_by field
    user = await UserRepo.get_by_email(db, current_user["email"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Check for name collision
    existing = await PermissionSetRepo.get_by_name(db, body.name)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Permission set '{body.name}' already exists",
        )

    ps = await PermissionSetRepo.create(
        db,
        name=body.name,
        permissions=body.permissions,
        created_by=str(user.id),
        description=body.description,
    )
    return _to_response(ps)


@router.get("", response_model=list[PermissionSetResponse])
async def list_permission_sets(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all active permission sets."""
    sets = await PermissionSetRepo.list_active(db)
    return [_to_response(ps) for ps in sets]


@router.get("/{set_id}", response_model=PermissionSetResponse)
async def get_permission_set(
    set_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return a single permission set by ID."""
    ps = await PermissionSetRepo.get_by_id(db, set_id)
    if ps is None or not ps.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission set not found",
        )
    return _to_response(ps)


@router.put("/{set_id}", response_model=PermissionSetResponse)
async def update_permission_set(
    set_id: str,
    body: PermissionSetUpdate,
    current_user: dict = Depends(require_permission("connectors:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update a permission set's name, description, or permissions.

    Requires at least the ``connectors:write`` permission (engineer or admin).
    Updated permissions must not exceed the caller's role permissions.
    """
    ps = await PermissionSetRepo.get_by_id(db, set_id)
    if ps is None or not ps.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission set not found",
        )

    if body.permissions is not None:
        from ....core.rbac import permissions_for_role
        user_permissions = permissions_for_role(current_user["role"])
        forbidden = [p for p in body.permissions if p not in user_permissions]
        if forbidden:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permissions exceed your role permissions: {forbidden}",
            )

    # Check name collision if renaming
    if body.name is not None and body.name != ps.name:
        existing = await PermissionSetRepo.get_by_name(db, body.name)
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Permission set '{body.name}' already exists",
            )

    updated = await PermissionSetRepo.update(
        db,
        set_id=set_id,
        name=body.name,
        description=body.description,
        permissions=body.permissions,
    )
    return _to_response(updated)


@router.delete("/{set_id}", status_code=204)
async def delete_permission_set(
    set_id: str,
    current_user: dict = Depends(require_permission("users:write")),
    db: AsyncSession = Depends(get_db),
):
    """Soft-delete a permission set (admin only).

    Deactivates the set; existing API keys whose scopes were snapshotted from
    this set are unaffected.
    """
    deleted = await PermissionSetRepo.delete(db, set_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission set not found",
        )
