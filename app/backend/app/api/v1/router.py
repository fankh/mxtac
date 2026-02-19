from fastapi import APIRouter
from .endpoints import auth, overview, detections

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(overview.router)
api_router.include_router(detections.router)
