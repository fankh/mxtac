from fastapi import APIRouter
from .endpoints import auth, connectors, coverage, detections, events, incidents, overview, rules, saved_queries, users, websocket, webhook_ingest

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(overview.router)
api_router.include_router(coverage.router)
api_router.include_router(detections.router)
api_router.include_router(incidents.router)
api_router.include_router(rules.router)
api_router.include_router(connectors.router)
api_router.include_router(users.router)
api_router.include_router(events.router)
api_router.include_router(saved_queries.router)
api_router.include_router(websocket.router)
api_router.include_router(webhook_ingest.router)
