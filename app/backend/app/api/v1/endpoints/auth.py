from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.security import create_access_token, create_refresh_token, verify_password, decode_token
from ....repositories.user_repo import UserRepo
from ....schemas.auth import LoginRequest, TokenResponse, RefreshRequest

router = APIRouter(prefix="/auth", tags=["auth"])


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
        expires_in=3600,
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
    return TokenResponse(
        access_token=token,
        refresh_token=body.refresh_token,
        expires_in=3600,
    )


@router.post("/logout")
async def logout():
    return {"message": "Logged out"}
