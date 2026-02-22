import base64
import hashlib
import hmac
import secrets
import string
from datetime import datetime, timedelta, timezone

import pyotp
from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.config import settings
from ....core.database import get_db
from ....core.security import (
    create_access_token,
    create_mfa_token,
    create_password_change_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
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
from ....repositories.api_key_repo import APIKeyRepo
from ....repositories.permission_set_repo import PermissionSetRepo
from ....core.rbac import require_permission, permissions_for_role
from ....schemas.auth import (
    APIKeyCreate,
    APIKeyCreateResponse,
    APIKeyResponse,
    ChangePasswordRequest,
    LoginRequest,
    LogoutResponse,
    MeResponse,
    MfaDisableRequest,
    MfaLoginResponse,
    MfaSetupResponse,
    MfaVerifyLoginRequest,
    MfaVerifyRequest,
    MfaVerifyResponse,
    PasswordChangeRequiredResponse,
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

    # Feature 1.7 — Inactive account lock: lock accounts that have not logged in
    # for account_inactivity_days days. Only fires when the setting is enabled (>0)
    # and the user has previously logged in. Accounts that are already inactive
    # are handled by the is_active check below.
    if settings.account_inactivity_days > 0 and user.is_active and user.last_login_at is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=settings.account_inactivity_days)
        if user.last_login_at < cutoff:
            now = datetime.now(timezone.utc)
            user.is_active = False
            user.inactive_locked_at = now
            await db.flush()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account locked due to inactivity. Contact your administrator.",
            )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Successful authentication — reset the failed-attempt counter.
    await clear_login_attempts(body.email)

    # Record the successful login timestamp (feature 1.7).
    user.last_login_at = datetime.now(timezone.utc)
    await db.flush()

    # Feature 1.8 — Forced password change on first login.
    # Issued before the MFA check so that new accounts without MFA are handled
    # cleanly.  If MFA is also enabled the user will be required to go through
    # MFA again after the password change.
    if user.must_change_password:
        pc_token = create_password_change_token(str(user.id))
        return PasswordChangeRequiredResponse(password_change_token=pc_token)

    # Feature 2.3 — Password expiry: require a change if the password is older
    # than password_expiry_days.  Only applies when the setting is enabled (>0)
    # and password_changed_at has been recorded (None means clock not yet started).
    if (
        settings.password_expiry_days > 0
        and user.password_changed_at is not None
    ):
        cutoff = datetime.now(timezone.utc) - timedelta(days=settings.password_expiry_days)
        if user.password_changed_at < cutoff:
            pc_token = create_password_change_token(str(user.id))
            return PasswordChangeRequiredResponse(password_change_token=pc_token)

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


# ---------------------------------------------------------------------------
# Feature 1.8 — First-login forced password change
# ---------------------------------------------------------------------------


@router.post("/change-password")
async def change_password(body: ChangePasswordRequest, db: AsyncSession = Depends(get_db)):
    """Complete a forced first-login password change.

    Accepts the ``password_change_token`` issued by POST /auth/login when
    ``must_change_password=True``.  On success clears the flag and returns
    full access + refresh tokens (or an MFA token if MFA is also enabled).
    """
    payload = decode_token(body.password_change_token)
    if payload.get("purpose") != "password_change":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password change token",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password change token",
        )

    user = await UserRepo.get_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password change token",
        )

    # Feature 2.4 — Password history: cannot reuse last 2 passwords.
    # "Last 2" = current password + 1 previous (stored in password_history).
    history = list(user.password_history or [])
    candidates = [user.hashed_password] + history
    for old_hash in candidates:
        if verify_password(body.new_password, old_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot reuse one of your last 2 passwords",
            )

    # Rotate history: move current hash in; keep the 1 most-recent previous entry.
    user.password_history = [user.hashed_password]

    user.hashed_password = hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = datetime.now(timezone.utc)
    await db.flush()

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


# ---------------------------------------------------------------------------
# Feature 1.11 — Scoped API key management
# Feature 3.9 — Scoped API keys (per-permission set)
# ---------------------------------------------------------------------------

_API_KEY_BYTES = 32  # 256-bit entropy


def _generate_api_key() -> str:
    """Return a cryptographically random API key with a recognisable prefix."""
    return "mxtac_" + secrets.token_urlsafe(_API_KEY_BYTES)


@router.post("/api-keys", response_model=APIKeyCreateResponse, status_code=201)
async def create_api_key(
    body: APIKeyCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a scoped API key for the authenticated user.

    The raw key is returned **once** in this response — store it securely,
    it cannot be retrieved again.

    Requested scopes must be a subset of the permissions granted to the
    caller's role.  Admins may assign any valid scope.

    Feature 3.9: Alternatively, supply ``permission_set_id`` to derive scopes
    from a named PermissionSet.  The effective scopes are snapshotted at
    creation time; later changes to the PermissionSet do not affect the key.
    """
    user_permissions = permissions_for_role(current_user["role"])

    # Feature 3.9: resolve scopes from permission set if provided
    permission_set_id: str | None = None
    if body.permission_set_id is not None:
        ps = await PermissionSetRepo.get_by_id(db, body.permission_set_id)
        if ps is None or not ps.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission set not found",
            )
        effective_scopes: list[str] = ps.permissions
        permission_set_id = ps.id
    else:
        effective_scopes = body.scopes  # type: ignore[assignment]  # validated by schema

    # Scope escalation check: requested scopes must be within the caller's role
    forbidden = [s for s in effective_scopes if s not in user_permissions]
    if forbidden:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scopes exceed your role permissions: {forbidden}",
        )

    user = await UserRepo.get_by_email(db, current_user["email"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    raw_key = _generate_api_key()
    api_key = await APIKeyRepo.create(
        db,
        raw_key=raw_key,
        label=body.label,
        owner_id=str(user.id),
        scopes=effective_scopes,
        expires_at=body.expires_at,
        permission_set_id=permission_set_id,
    )
    return APIKeyCreateResponse(
        id=api_key.id,
        label=api_key.label,
        scopes=api_key.scopes or [],
        permission_set_id=api_key.permission_set_id,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        key=raw_key,
    )


@router.get("/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all active API keys belonging to the authenticated user."""
    user = await UserRepo.get_by_email(db, current_user["email"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    keys = await APIKeyRepo.list_by_owner(db, str(user.id))
    return [
        APIKeyResponse(
            id=k.id,
            label=k.label,
            scopes=k.scopes or [],
            permission_set_id=k.permission_set_id,
            is_active=k.is_active,
            created_at=k.created_at,
            expires_at=k.expires_at,
            last_used_at=k.last_used_at,
        )
        for k in keys
    ]


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke (deactivate) an API key.

    Users can revoke only their own keys.  Admins can revoke any key.
    Returns 404 when the key is not found or belongs to a different owner.
    """
    user = await UserRepo.get_by_email(db, current_user["email"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    owner_filter = None if current_user["role"] == "admin" else str(user.id)
    revoked = await APIKeyRepo.revoke(db, key_id, owner_id=owner_filter)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
