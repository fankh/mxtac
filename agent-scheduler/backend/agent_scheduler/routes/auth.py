from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..auth import hash_password
from ..config import settings

router = APIRouter(prefix="/api/auth")


@router.get("/check")
async def check_auth():
    return {"auth_enabled": bool(settings.auth_password)}


class LoginRequest(BaseModel):
    password: str


@router.post("/login")
async def login(req: LoginRequest):
    if not settings.auth_password:
        raise HTTPException(status_code=400, detail="Auth is not enabled")

    if req.password != settings.auth_password:
        raise HTTPException(status_code=401, detail="Invalid password")

    return {"token": hash_password(req.password)}
