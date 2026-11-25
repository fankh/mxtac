import base64
import hashlib
import hmac
import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pyotp
from cryptography.fernet import Fernet
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.config import settings
from ....core.database import get_db
from ....core.rbac import require_permission
from ....core.security import (
    REFRESH_COOKIE_NAME,
    REFRESH_COOKIE_PATH,
    SESSION_ENDED_DETAIL,
    create_access_token,
    create_mfa_token,
    create_password_change_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    session_revocation_id,
    token_version_matches,
    verify_password,
)
from ....core.valkey import (
    blacklist_token,
    clear_login_attempts,
    consume_token,
    increment_login_attempts,
    increment_mfa_attempts,
    is_account_locked,
    is_token_blacklisted,
)
from ....models.user import User
from ....repositories.user_repo import UserRepo
from ....schemas.auth import (
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
    SelfPasswordChangeRequest,
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


def _refresh_cookie_attributes() -> dict[str, Any]:
    """Attributes of the refresh cookie.

    Deleting a cookie only works with the same path, so both the set and the
    delete use these.
    """
    return {
        "key": REFRESH_COOKIE_NAME,
        "path": REFRESH_COOKIE_PATH,
        "httponly": True,
        "secure": settings.refresh_cookie_secure,
        "samesite": "strict",
    }


def _refresh_lifetime_seconds() -> int:
    return settings.refresh_token_expire_days * 86400


def _issue_tokens(response: Response, user: User, sid: str | None = None) -> TokenResponse:
    """Full session for *user*: the access token and the account identity in
    the body, the refresh token as an HttpOnly cookie on *response*.

    *sid* identifies the session.  A sign-in starts a new one; a refresh keeps
    the one of the token it replaces, so that logout and reuse detection can
    end every token that descends from the same sign-in.
    """
    claims = {
        "sub": user.email,
        "sid": sid or str(uuid4()),
        "tv": user.token_version or 0,
    }
    response.set_cookie(
        value=create_refresh_token(claims),
        max_age=_refresh_lifetime_seconds(),
        **_refresh_cookie_attributes(),
    )
    return TokenResponse(
        access_token=create_access_token({**claims, "role": user.role}),
        expires_in=settings.access_token_expire_minutes * 60,
        email=user.email,
        role=user.role,
    )


def _refresh_refused(detail: str = "Invalid refresh token") -> JSONResponse:
    """401 for POST /auth/refresh that also removes the cookie from the browser."""
    refused = JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": detail})
    refused.delete_cookie(**_refresh_cookie_attributes())
    return refused


@router.post("/login", response_model=None)
async def login(body: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)) -> TokenResponse | PasswordChangeRequiredResponse | MfaLoginResponse:
    """Sign in with email and password.

    Answers with a session (access token in the body, refresh token as an
    HttpOnly cookie), or with the one-time token of the step the account has
    to complete first: a password change or an MFA code.
    """
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
        cutoff = datetime.now(UTC) - timedelta(days=settings.account_inactivity_days)
        if user.last_login_at < cutoff:
            now = datetime.now(UTC)
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
    user.last_login_at = datetime.now(UTC)
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
        cutoff = datetime.now(UTC) - timedelta(days=settings.password_expiry_days)
        if user.password_changed_at < cutoff:
            pc_token = create_password_change_token(str(user.id))
            return PasswordChangeRequiredResponse(password_change_token=pc_token)

    if user.mfa_enabled:
        mfa_token = create_mfa_token(str(user.id))
        return MfaLoginResponse(mfa_token=mfa_token)
    return _issue_tokens(response, user)


@router.post("/mfa/verify", response_model=TokenResponse)
async def mfa_verify_login(
    body: MfaVerifyLoginRequest, response: Response, db: AsyncSession = Depends(get_db)
) -> TokenResponse:
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
    return _issue_tokens(response, user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_COOKIE_NAME),
) -> TokenResponse | JSONResponse:
    """Exchange the refresh cookie for a new access token and a new refresh cookie.

    The refresh token is single use: it is put on the revocation list as it is
    exchanged.  Presenting it a second time means the token was copied, so the
    whole session (every refresh token that descends from the same sign-in) is
    ended.  Every refusal also deletes the cookie.
    """
    if not refresh_token:
        return _refresh_refused("Refresh token required")
    try:
        payload = decode_token(refresh_token)
    except HTTPException:
        return _refresh_refused()
    email = payload.get("sub")
    jti = payload.get("jti")
    if payload.get("type") != "refresh" or not email or not jti:
        return _refresh_refused()

    sid = payload.get("sid")
    if sid and await is_token_blacklisted(session_revocation_id(sid)):
        return _refresh_refused(SESSION_ENDED_DETAIL)

    remaining = payload.get("exp", 0) - int(datetime.now(UTC).timestamp())
    if not await consume_token(jti, remaining):
        # Reuse of a rotated token: end the session it belongs to.
        if sid:
            await blacklist_token(session_revocation_id(sid), _refresh_lifetime_seconds())
        return _refresh_refused(SESSION_ENDED_DETAIL)

    user = await UserRepo.get_by_email(db, email)
    if not user or not user.is_active:
        return _refresh_refused("User not found or inactive")
    if not token_version_matches(payload, user.token_version):
        return _refresh_refused(SESSION_ENDED_DETAIL)
    return _issue_tokens(response, user, sid=sid)


@router.post("/logout", response_model=LogoutResponse)
async def logout(response: Response, authorization: str = Header(None)) -> LogoutResponse:
    """End the session of the presented access token.

    Revokes the access token and the session it belongs to, so the refresh
    token of that session stops working as well, and deletes the refresh cookie.
    """
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
        now = int(datetime.now(UTC).timestamp())
        ttl = exp - now
        await blacklist_token(jti, ttl)

    sid = payload.get("sid")
    if sid:
        await blacklist_token(session_revocation_id(sid), _refresh_lifetime_seconds())
    response.delete_cookie(**_refresh_cookie_attributes())

    return LogoutResponse(message="Logged out")


# ---------------------------------------------------------------------------
# Feature 32.1 — TOTP MFA setup
# ---------------------------------------------------------------------------


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def mfa_setup(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MfaSetupResponse:
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
    current_user: dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MfaVerifyResponse:
    """Verify a TOTP code and activate MFA for the authenticated user.

    Returns 400 if MFA setup has not been initiated or the code is invalid.
    """
    user = await UserRepo.get_by_email(db, current_user["email"])
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA setup not initiated")

    secret = _decrypt_secret(user.mfa_secret)
    # Same tolerance as at sign-in: one time step in each direction.  Without
    # it a code typed near the end of its 30 seconds is refused.
    if not pyotp.TOTP(secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")

    user.mfa_enabled = True
    await db.flush()

    return MfaVerifyResponse(message="MFA enabled")


# ---------------------------------------------------------------------------
# Feature 32.3 — MFA management
# ---------------------------------------------------------------------------


@router.get("/me", response_model=MeResponse)
async def get_me(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MeResponse:
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
    current_user: dict[str, Any] = Depends(require_permission("users:write")),
    db: AsyncSession = Depends(get_db),
) -> MfaVerifyResponse:
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


async def _set_new_password(db: AsyncSession, user: User, new_password: str) -> None:
    """Replace the password of *user*, enforcing the history rule.

    Shared by the forced change (POST /auth/change-password) and the
    self-service change (POST /auth/password).  Complexity and length are
    validated by the request schemas before this is reached.
    """
    # Feature 2.4 — Password history: cannot reuse last 2 passwords.
    # "Last 2" = current password + 1 previous (stored in password_history).
    history = list(user.password_history or [])
    candidates = [user.hashed_password] + history
    for old_hash in candidates:
        if verify_password(new_password, old_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot reuse one of your last 2 passwords",
            )

    # Rotate history: move current hash in; keep the 1 most-recent previous entry.
    user.password_history = [user.hashed_password]

    user.hashed_password = hash_password(new_password)
    user.must_change_password = False
    user.password_changed_at = datetime.now(UTC)
    # End every session of the account: tokens carry the version they were
    # issued under and are refused once it has moved on.
    user.token_version = (user.token_version or 0) + 1
    await db.flush()


@router.post("/change-password", response_model=None)
async def change_password(
    body: ChangePasswordRequest, response: Response, db: AsyncSession = Depends(get_db)
) -> TokenResponse | MfaLoginResponse:
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

    await _set_new_password(db, user, body.new_password)

    if user.mfa_enabled:
        mfa_token = create_mfa_token(str(user.id))
        return MfaLoginResponse(mfa_token=mfa_token)

    return _issue_tokens(response, user)


# ---------------------------------------------------------------------------
# Self-service password change for a signed-in user
# ---------------------------------------------------------------------------


@router.post("/password", response_model=TokenResponse)
async def change_own_password(
    body: SelfPasswordChangeRequest,
    response: Response,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Change the password of the signed-in user.

    Requires the current password.  Wrong current passwords count towards the
    same lockout counter as failed logins (5 attempts, 30 minutes), so a
    stolen session cannot be used to guess the password without limit.  The
    new password is subject to the same policy and history rules as the
    forced first-login change.

    The change ends every session of the account, including the one that made
    the request.  The answer is a new session (access token in the body,
    refresh cookie) so that the caller stays signed in; all other browsers and
    API clients of the account have to sign in again.
    """
    email = current_user["email"]
    user = await UserRepo.get_by_email(db, email)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    if await is_account_locked(email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked. Try again in 30 minutes.",
        )

    if not verify_password(body.current_password, user.hashed_password):
        await increment_login_attempts(email)
        # 400, not 401: the session itself is valid and must not be dropped.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    await clear_login_attempts(email)
    await _set_new_password(db, user, body.new_password)
    return _issue_tokens(response, user)
