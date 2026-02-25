"""User management endpoints (admin only)."""

from __future__ import annotations

import email.mime.multipart
import email.mime.text
import re
from uuid import uuid4

import aiosmtplib
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.config import settings
from ....core.database import get_db
from ....core.logging import get_logger
from ....core.rbac import require_permission
from ....core.security import create_invite_token, hash_password
from ....core.validators import EMAIL_MAX_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, validate_password_complexity, validate_password_no_consecutive

logger = get_logger(__name__)

router = APIRouter(prefix="/users", tags=["users"])

ROLES = ["viewer", "analyst", "hunter", "engineer", "admin"]

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", re.IGNORECASE)


class UserCreate(BaseModel):
    email: str = Field(..., max_length=EMAIL_MAX_LENGTH)
    full_name: str | None = Field(default=None, max_length=255)
    role: str = "analyst"
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    must_change_password: bool = True

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("value is not a valid email address")
        return v

    @field_validator("password")
    @classmethod
    def validate_password_policy(cls, v: str) -> str:
        validate_password_complexity(v)
        return validate_password_no_consecutive(v)


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=255)
    role: str | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str | None
    role: str
    is_active: bool
    mfa_enabled: bool
    must_change_password: bool


def _user_to_response(u) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "is_active": u.is_active,
        "mfa_enabled": u.mfa_enabled,
        "must_change_password": u.must_change_password,
    }


@router.get("", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("users:read")),
):
    from ....repositories.user_repo import UserRepo
    users = await UserRepo.list(db)
    return [_user_to_response(u) for u in users]


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("users:read")),
):
    from ....repositories.user_repo import UserRepo
    user = await UserRepo.get_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


@router.post("", response_model=UserResponse, status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("users:write")),
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
        must_change_password=body.must_change_password,
    )
    return _user_to_response(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("users:write")),
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
    _: dict = Depends(require_permission("users:write")),
):
    from ....repositories.user_repo import UserRepo
    deleted = await UserRepo.delete(db, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")


# ---------------------------------------------------------------------------
# POST /users/invite — send email invite (feature 4.6)
# ---------------------------------------------------------------------------


class InviteCreate(BaseModel):
    email: str = Field(..., max_length=EMAIL_MAX_LENGTH)
    full_name: str | None = Field(default=None, max_length=255)
    role: str = "analyst"

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("value is not a valid email address")
        return v


class InviteResponse(BaseModel):
    email: str
    role: str
    invite_token: str
    email_sent: bool


async def _send_invite_email(to_email: str, role: str, invite_token: str) -> bool:
    """Send an invite email via SMTP.

    Uses global smtp_* settings from config.  Mirrors the pattern used by
    NotificationDispatcher._send_email: STARTTLS by default, implicit TLS
    when use_tls=True.  Returns True on success, False on any SMTP error.
    """
    base_url = settings.cors_origins[0] if settings.cors_origins else "http://localhost:5173"
    invite_link = f"{base_url}/accept-invite?token={invite_token}"

    text_body = (
        f"You have been invited to join MxTac Security Platform with the role: {role}.\n\n"
        f"Click the link below to set your password and activate your account:\n"
        f"{invite_link}\n\n"
        f"This link expires in 48 hours.\n\n"
        f"If you did not expect this invitation, please ignore this email."
    )

    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = "You have been invited to MxTac"
    msg["From"] = settings.smtp_from_address
    msg["To"] = to_email
    msg.attach(email.mime.text.MIMEText(text_body, "plain", "utf-8"))

    use_tls = settings.smtp_port == 465
    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            use_tls=use_tls,
            start_tls=(not use_tls),
            username=settings.smtp_username or None,
            password=settings.smtp_password or None,
        )
        logger.info("Invite email sent to=%s role=%s", to_email, role)
        return True
    except Exception as exc:
        logger.warning("Invite email to %s failed: %s", to_email, exc)
        return False


@router.post("/invite", response_model=InviteResponse, status_code=200)
async def invite_user(
    body: InviteCreate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("users:write")),
):
    """Create a new user account and send an email invite with a setup link.

    The invited user receives a 48-hour invite token they use to set their
    password.  The user record is created immediately with a random placeholder
    password and must_change_password=True.
    """
    from ....repositories.user_repo import UserRepo

    if body.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role. Must be one of: {ROLES}")

    existing = await UserRepo.get_by_email(db, body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    # Random placeholder — the real password is set when the invite is accepted.
    placeholder_hash = hash_password(str(uuid4()))
    user = await UserRepo.create(
        db,
        email=body.email,
        full_name=body.full_name,
        role=body.role,
        hashed_password=placeholder_hash,
        must_change_password=True,
    )

    token = create_invite_token(user.id)
    email_sent = await _send_invite_email(body.email, body.role, token)

    return InviteResponse(
        email=body.email,
        role=body.role,
        invite_token=token,
        email_sent=email_sent,
    )
