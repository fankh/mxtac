from fastapi import APIRouter
from .endpoints import admin, auth, connectors, detections, events, overview, rules, users, websocket

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(overview.router)
api_router.include_router(detections.router)
api_router.include_router(rules.router)
api_router.include_router(connectors.router)
api_router.include_router(users.router)
api_router.include_router(events.router)
api_router.include_router(websocket.router)
api_router.include_router(admin.router)
