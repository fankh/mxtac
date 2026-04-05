from datetime import datetime, timedelta
from uuid import uuid4

import bcrypt as _bcrypt
from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt

from .config import settings
from .valkey import is_token_blacklisted

ALGORITHM = "HS256"


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
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
        "exp": datetime.utcnow() + timedelta(minutes=5),
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
        "exp": datetime.utcnow() + timedelta(minutes=15),
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def create_invite_token(user_id: str) -> str:
    """Create an invite token (48-hour TTL) for a newly invited user.

    Claims: sub=user_id, purpose="invite", jti, kvr, exp.
    Sent via email so the recipient can set their password and activate the account.
    """
    to_encode = {
        "sub": user_id,
        "purpose": "invite",
        "jti": str(uuid4()),
        "kvr": settings.jwt_key_version,
        "exp": datetime.utcnow() + timedelta(hours=48),
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
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


async def get_current_user(authorization: str = Header(None)) -> dict:
    """FastAPI dependency — extract and validate JWT from Authorization header."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )
    # Support "Bearer <token>" format
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        token = parts[1]
    else:
        token = authorization

    payload = decode_token(token)
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    jti = payload.get("jti")
    if jti and await is_token_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    return {"email": sub, "role": payload.get("role", "viewer")}
