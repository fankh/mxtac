from datetime import datetime, timedelta, timezone
from uuid import uuid4

import bcrypt as _bcrypt
from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.user import User
from .config import settings
from .database import get_db
from .valkey import is_token_blacklisted

ALGORITHM = "HS256"

# The refresh token travels only in this cookie, which browsers send to the
# refresh route and nowhere else.
REFRESH_COOKIE_NAME = "mxtac_refresh"
REFRESH_COOKIE_PATH = f"{settings.api_prefix}/auth/refresh"


def session_revocation_id(sid: str) -> str:
    """Revocation-list entry that ends the session *sid* (see POST /auth/logout)."""
    return f"sid:{sid}"


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode["exp"] = expire
    to_encode.setdefault("jti", str(uuid4()))
    # Include the current key version so tokens can be mass-invalidated by
    # bumping jwt_key_version in config (e.g. after a secret rotation).
    to_encode["kvr"] = settings.jwt_key_version
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def create_mfa_token(user_id: str) -> str:
    """Create a short-lived MFA verification token (5-minute TTL).

    Claims: sub=user_id, purpose="mfa", jti, kvr, exp.
    Used between password-auth success and TOTP verification.
    """
    to_encode = {
        "sub": user_id,
        "purpose": "mfa",
        "jti": str(uuid4()),
        "kvr": settings.jwt_key_version,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def create_password_change_token(user_id: str) -> str:
    """Create a short-lived password-change token (15-minute TTL).

    Claims: sub=user_id, purpose="password_change", jti, kvr, exp.
    Used for first-login forced password change flow (feature 1.8).
    """
    to_encode = {
        "sub": user_id,
        "purpose": "password_change",
        "jti": str(uuid4()),
        "kvr": settings.jwt_key_version,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "jti": str(uuid4()),
        "kvr": settings.jwt_key_version,
    })
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(10)).decode()


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    # Reject tokens that were issued before the current key rotation epoch.
    # Operators bump jwt_key_version to invalidate all outstanding tokens after
    # a secret rotation or a suspected compromise.
    if payload.get("kvr") != settings.jwt_key_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    return payload


SESSION_ENDED_DETAIL = "Session has ended. Sign in again."


def token_version_matches(payload: dict, token_version: int | None) -> bool:
    """True when the token was issued under the account's current token version.

    Tokens issued before the claim existed count as version 0.
    """
    return payload.get("tv", 0) == (token_version or 0)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


async def current_role(db: AsyncSession, payload: dict) -> str:
    """Return the role the token's user holds *now* (one indexed lookup by email).

    The role and active flag are read from the database on every request, not
    from the token, so deactivating a user or changing a role takes effect
    immediately instead of at token expiry.  The same row carries the token
    version: a token issued before the last password change is refused.
    """
    row = (
        await db.execute(
            select(User.role, User.is_active, User.token_version).where(
                User.email == payload["sub"]
            )
        )
    ).first()
    if row is None or not row.is_active:
        raise _unauthorized("Account is disabled or no longer exists")
    if not token_version_matches(payload, row.token_version):
        raise _unauthorized(SESSION_ENDED_DETAIL)
    return row.role


async def authenticate_access_token(token: str, db: AsyncSession) -> dict:
    """Validate an access token and return ``{"email", "role"}`` for its user.

    Rejects refresh tokens and single-purpose tokens (MFA, password
    change), revoked tokens, and tokens of deactivated or deleted users.
    """
    payload = decode_token(token)
    if payload.get("type") is not None or payload.get("purpose") is not None:
        raise _unauthorized("Not an access token")

    sub = payload.get("sub")
    if not sub:
        raise _unauthorized("Invalid token payload")

    jti = payload.get("jti")
    if jti and await is_token_blacklisted(jti):
        raise _unauthorized("Token has been revoked")

    return {"email": sub, "role": await current_role(db, payload)}


async def get_current_user(
    authorization: str = Header(None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """FastAPI dependency — extract and validate JWT from Authorization header."""
    if not authorization:
        raise _unauthorized("Authorization header required")
    # Support "Bearer <token>" format
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        token = parts[1]
    else:
        token = authorization

    return await authenticate_access_token(token, db)
