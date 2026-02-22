import re
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator, model_validator

from ..core.rbac import PERMISSIONS
from ..core.validators import EMAIL_MAX_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, validate_password_complexity, validate_password_no_consecutive

_VALID_SCOPES: frozenset[str] = frozenset(PERMISSIONS.keys())

# Accepts any user@domain.tld format — including RFC 6762 .local names used
# by internal service accounts (e.g. analyst@mxtac.local).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", re.IGNORECASE)


class LoginRequest(BaseModel):
    email: str = Field(..., max_length=EMAIL_MAX_LENGTH)
    password: str = Field(..., max_length=PASSWORD_MAX_LENGTH)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("value is not a valid email address")
        return v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutResponse(BaseModel):
    message: str


class MfaSetupResponse(BaseModel):
    secret: str
    qr_code_uri: str
    backup_codes: list[str]


class MfaVerifyRequest(BaseModel):
    # TOTP codes are 6 digits; backup codes up to 16 alphanumeric chars
    code: str = Field(..., min_length=6, max_length=16, pattern=r"^[A-Za-z0-9]+$")


class MfaVerifyResponse(BaseModel):
    message: str


# Feature 32.2 — MFA login flow
class MfaLoginResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str


class MfaVerifyLoginRequest(BaseModel):
    mfa_token: str = Field(..., max_length=512)
    code: str = Field(..., min_length=6, max_length=16, pattern=r"^[A-Za-z0-9]+$")


# Feature 32.3 — MFA management
class MeResponse(BaseModel):
    email: str
    role: str
    full_name: str | None = None
    mfa_enabled: bool


class MfaDisableRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=20)

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        if not v.isdigit() or int(v) < 1:
            raise ValueError("user_id must be a positive integer")
        return v


# Feature 1.8 — First-login forced password change
class PasswordChangeRequiredResponse(BaseModel):
    password_change_required: bool = True
    password_change_token: str


class ChangePasswordRequest(BaseModel):
    password_change_token: str = Field(..., max_length=512)
    new_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    confirm_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("new_password")
    @classmethod
    def validate_new_password_policy(cls, v: str) -> str:
        validate_password_complexity(v)
        return validate_password_no_consecutive(v)

    @model_validator(mode="after")
    def passwords_match(self) -> "ChangePasswordRequest":
        if self.new_password != self.confirm_password:
            raise ValueError("passwords do not match")
        return self


# ---------------------------------------------------------------------------
# Feature 1.11 — Scoped API key management
# ---------------------------------------------------------------------------


class APIKeyCreate(BaseModel):
    label: str = Field(..., min_length=1, max_length=255)
    scopes: list[str] = Field(..., min_length=1)
    expires_at: datetime | None = None

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: list[str]) -> list[str]:
        invalid = [s for s in v if s not in _VALID_SCOPES]
        if invalid:
            raise ValueError(f"Invalid scope(s): {', '.join(sorted(invalid))}")
        # Deduplicate while preserving order
        return list(dict.fromkeys(v))

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, v: datetime | None) -> datetime | None:
        if v is not None:
            # Ensure timezone-aware comparison
            if v.tzinfo is None:
                raise ValueError("expires_at must include timezone information")
            if v <= datetime.now(timezone.utc):
                raise ValueError("expires_at must be in the future")
        return v


class APIKeyResponse(BaseModel):
    id: str
    label: str | None
    scopes: list[str]
    is_active: bool
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None


class APIKeyCreateResponse(APIKeyResponse):
    """Extends APIKeyResponse with the raw key — returned once on creation only."""
    key: str
