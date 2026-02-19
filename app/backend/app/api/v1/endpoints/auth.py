from fastapi import APIRouter, HTTPException, status
from ....schemas.auth import LoginRequest, TokenResponse, RefreshRequest
from ....core.security import create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])

# Hard-coded demo user — replace with DB lookup in production
DEMO_USER = {"email": "analyst@mxtac.local", "password": "mxtac2026"}


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    if body.email != DEMO_USER["email"] or body.password != DEMO_USER["password"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token({"sub": body.email, "role": "analyst"})
    return TokenResponse(
        access_token=token,
        refresh_token=create_access_token({"sub": body.email, "type": "refresh"}),
        expires_in=3600,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest):
    # Simplified: re-issue for demo
    token = create_access_token({"sub": "analyst@mxtac.local", "role": "analyst"})
    return TokenResponse(
        access_token=token,
        refresh_token=body.refresh_token,
        expires_in=3600,
    )


@router.post("/logout")
async def logout():
    return {"message": "Logged out"}
