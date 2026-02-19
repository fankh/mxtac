"""User management endpoints (admin only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.security import get_current_user, hash_password

router = APIRouter(prefix="/users", tags=["users"])

ROLES = ["viewer", "analyst", "hunter", "engineer", "admin"]


class UserCreate(BaseModel):
    email: str
    full_name: str | None = None
    role: str = "analyst"
    password: str


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: str | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str | None
    role: str
    is_active: bool


def _user_to_response(u) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "is_active": u.is_active,
    }


@router.get("", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    from ....repositories.user_repo import UserRepo
    users = await UserRepo.list(db)
    return [_user_to_response(u) for u in users]


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    from ....repositories.user_repo import UserRepo
    user = await UserRepo.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


@router.post("", response_model=UserResponse, status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    from ....repositories.user_repo import UserRepo
    if body.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role. Must be one of: {ROLES}")
    existing = await UserRepo.get_by_email(db, body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user = await UserRepo.create(
        db,
        email=body.email,
        full_name=body.full_name,
        role=body.role,
        hashed_password=hash_password(body.password),
    )
    return _user_to_response(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    from ....repositories.user_repo import UserRepo
    if body.role is not None and body.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role: {body.role}")
    user = await UserRepo.update(db, user_id, **body.model_dump(exclude_none=True))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    from ....repositories.user_repo import UserRepo
    deleted = await UserRepo.delete(db, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
