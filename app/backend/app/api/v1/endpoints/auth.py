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
    create_refresh_token,
    decode_token,
    get_current_user,
    verify_password,
)
from ....core.valkey import blacklist_token
from ....repositories.user_repo import UserRepo
from ....schemas.auth import (
    LoginRequest,
    LogoutResponse,
    MfaSetupResponse,
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


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = await UserRepo.get_by_email(db, body.email)
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )
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
