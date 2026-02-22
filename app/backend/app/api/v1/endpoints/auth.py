import base64
import hashlib
import hmac
import secrets
import string
from datetime import datetime, timezone

import pyotp
from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.config import settings
from ....core.database import get_db
from ....core.security import (
    create_access_token,
    create_mfa_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    verify_password,
)
from ....core.valkey import (
    blacklist_token,
    clear_login_attempts,
    increment_login_attempts,
    increment_mfa_attempts,
    is_account_locked,
)
from ....repositories.user_repo import UserRepo
from ....core.rbac import require_permission
from ....schemas.auth import (
    LoginRequest,
    LogoutResponse,
    MeResponse,
    MfaDisableRequest,
    MfaLoginResponse,
    MfaSetupResponse,
    MfaVerifyLoginRequest,
    MfaVerifyRequest,
    MfaVerifyResponse,
    RefreshRequest,
    TokenResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# MFA helpers
# ---------------------------------------------------------------------------


def _get_fernet() -> Fernet:
    """Derive a Fernet symmetric key from the application secret key."""
    key_bytes = hashlib.sha256(settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def _encrypt_secret(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def _decrypt_secret(ciphertext: str) -> str:
    return _get_fernet().decrypt(ciphertext.encode()).decode()


def _generate_backup_codes() -> list[str]:
    charset = string.ascii_uppercase + string.digits
    return ["".join(secrets.choice(charset) for _ in range(8)) for _ in range(8)]


def _hash_backup_code(code: str) -> str:
    """Hash a backup code with HMAC-SHA256 keyed on the application secret."""
    return hmac.new(settings.secret_key.encode(), code.encode(), hashlib.sha256).hexdigest()


@router.post("/login")
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    # 1. Check account lockout before doing any further work.
    if await is_account_locked(body.email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked. Try again in 30 minutes.",
        )

    user = await UserRepo.get_by_email(db, body.email)
    if not user or not verify_password(body.password, user.hashed_password):
        # Increment failed attempts counter regardless of whether the user exists
        # (consistent behaviour prevents email enumeration via timing).
        await increment_login_attempts(body.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Successful authentication — reset the failed-attempt counter.
    await clear_login_attempts(body.email)

    if user.mfa_enabled:
        mfa_token = create_mfa_token(str(user.id))
        return MfaLoginResponse(mfa_token=mfa_token)
    token = create_access_token({"sub": user.email, "role": user.role})
    refresh = create_refresh_token({"sub": user.email})
    return TokenResponse(
        access_token=token,
        refresh_token=refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/mfa/verify", response_model=TokenResponse)
async def mfa_verify_login(body: MfaVerifyLoginRequest, db: AsyncSession = Depends(get_db)):
    """Verify TOTP code (or backup code) after password authentication.

    Accepts the mfa_token issued by POST /auth/login when mfa_enabled=True.
    Rate-limited to 5 attempts per mfa_token. On success, returns full
    access + refresh tokens.
    """
    # 1. Validate mfa_token JWT
    payload = decode_token(body.mfa_token)
    if payload.get("purpose") != "mfa":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token")

    user_id = payload.get("sub")
    jti = payload.get("jti", "")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token")

    # 2. Rate limit: max 5 attempts per mfa_token
    attempts = await increment_mfa_attempts(jti)
    if attempts > 5:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many MFA attempts",
        )

    # 3. Look up user
    user = await UserRepo.get_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token")
    if not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA not configured")

    # 4. Verify TOTP (±1 window for clock skew) or backup code
    secret = _decrypt_secret(user.mfa_secret)
    code = body.code.strip()

    if pyotp.TOTP(secret).verify(code, valid_window=1):
        pass  # valid TOTP
    else:
        code_hash = _hash_backup_code(code.upper())
        if user.mfa_backup_codes and code_hash in user.mfa_backup_codes:
            # Consume the backup code — remove it so it can't be reused
            user.mfa_backup_codes = [c for c in user.mfa_backup_codes if c != code_hash]
            await db.flush()
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    # 5. Issue full access + refresh tokens
    token = create_access_token({"sub": user.email, "role": user.role})
    refresh = create_refresh_token({"sub": user.email})
    return TokenResponse(
        access_token=token,
        refresh_token=refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = await UserRepo.get_by_email(db, email)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    token = create_access_token({"sub": user.email, "role": user.role})
    new_refresh = create_refresh_token({"sub": user.email})
    return TokenResponse(
        access_token=token,
        refresh_token=new_refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )

    parts = authorization.split()
    token = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else authorization

    # Raises 401 if the token is invalid or expired
    payload = decode_token(token)

    jti = payload.get("jti")
    if jti:
        exp = payload.get("exp", 0)
        now = int(datetime.now(timezone.utc).timestamp())
        ttl = exp - now
        await blacklist_token(jti, ttl)

    return LogoutResponse(message="Logged out")


# ---------------------------------------------------------------------------
# Feature 32.1 — TOTP MFA setup
# ---------------------------------------------------------------------------


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def mfa_setup(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a TOTP secret and QR code URI for the authenticated user.

    Stores the encrypted secret and hashed backup codes in the DB but does NOT
    enable MFA yet — the user must confirm via POST /auth/mfa/verify-setup.
    """
    user = await UserRepo.get_by_email(db, current_user["email"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    secret = pyotp.random_base32()
    qr_code_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name="MxTac"
    )

    backup_codes = _generate_backup_codes()
    hashed_codes = [_hash_backup_code(code) for code in backup_codes]

    user.mfa_secret = _encrypt_secret(secret)
    user.mfa_backup_codes = hashed_codes
    await db.flush()

    return MfaSetupResponse(secret=secret, qr_code_uri=qr_code_uri, backup_codes=backup_codes)


@router.post("/mfa/verify-setup", response_model=MfaVerifyResponse)
async def mfa_verify_setup(
    body: MfaVerifyRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify a TOTP code and activate MFA for the authenticated user.

    Returns 400 if MFA setup has not been initiated or the code is invalid.
    """
    user = await UserRepo.get_by_email(db, current_user["email"])
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA setup not initiated")

    secret = _decrypt_secret(user.mfa_secret)
    if not pyotp.TOTP(secret).verify(body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")

    user.mfa_enabled = True
    await db.flush()

    return MfaVerifyResponse(message="MFA enabled")


# ---------------------------------------------------------------------------
# Feature 32.3 — MFA management
# ---------------------------------------------------------------------------


@router.get("/me", response_model=MeResponse)
async def get_me(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the authenticated user's profile including MFA status."""
    user = await UserRepo.get_by_email(db, current_user["email"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return MeResponse(
        email=user.email,
        role=user.role,
        full_name=user.full_name,
        mfa_enabled=user.mfa_enabled,
    )


@router.post("/mfa/disable", response_model=MfaVerifyResponse)
async def mfa_disable(
    body: MfaDisableRequest,
    current_user: dict = Depends(require_permission("users:write")),
    db: AsyncSession = Depends(get_db),
):
    """Disable MFA for a given user (admin only).

    Clears the TOTP secret and all backup codes for the target user.
    Requires the caller to have the 'users:write' permission (admin role).
    """
    user = await UserRepo.get_by_id(db, body.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_backup_codes = None
    await db.flush()

    return MfaVerifyResponse(message="MFA disabled")
