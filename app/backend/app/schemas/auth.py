import re

from pydantic import BaseModel, Field, field_validator

from ..core.validators import EMAIL_MAX_LENGTH, PASSWORD_MAX_LENGTH

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
