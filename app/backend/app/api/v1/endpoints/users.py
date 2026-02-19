"""User management endpoints (admin only)."""

from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from ....core.security import get_current_user

router = APIRouter(prefix="/users", tags=["users"])

ROLES = ["viewer", "analyst", "hunter", "engineer", "admin"]

# ── Schemas ──────────────────────────────────────────────────────────────────

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

# ── In-memory user store (replace with DB) ───────────────────────────────────

_users: dict[str, dict] = {
    "usr-001": {
        "id": "usr-001",
        "email": "analyst@mxtac.local",
        "full_name": "Default Analyst",
        "role": "analyst",
        "is_active": True,
    },
    "usr-002": {
        "id": "usr-002",
        "email": "admin@mxtac.local",
        "full_name": "Admin",
        "role": "admin",
        "is_active": True,
    },
}

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=list[UserResponse])
async def list_users(_: str = Depends(get_current_user)):
    return list(_users.values())


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, _: str = Depends(get_current_user)):
    user = _users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("", response_model=UserResponse, status_code=201)
async def create_user(body: UserCreate, _: str = Depends(get_current_user)):
    if body.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role. Must be one of: {ROLES}")
    if any(u["email"] == body.email for u in _users.values()):
        raise HTTPException(status_code=409, detail="Email already registered")
    user_id = str(uuid4())
    user = {
        "id": user_id,
        "email": body.email,
        "full_name": body.full_name,
        "role": body.role,
        "is_active": True,
    }
    _users[user_id] = user
    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(user_id: str, body: UserUpdate, _: str = Depends(get_current_user)):
    user = _users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.full_name is not None:
        user["full_name"] = body.full_name
    if body.role is not None:
        if body.role not in ROLES:
            raise HTTPException(status_code=422, detail=f"Invalid role: {body.role}")
        user["role"] = body.role
    if body.is_active is not None:
        user["is_active"] = body.is_active
    return user


@router.delete("/{user_id}", status_code=204)
async def delete_user(user_id: str, _: str = Depends(get_current_user)):
    if user_id not in _users:
        raise HTTPException(status_code=404, detail="User not found")
    del _users[user_id]
