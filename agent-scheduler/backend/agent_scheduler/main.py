import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .agents import get_enabled_agents
from .auth import require_auth
from .config import settings
from .database import init_db
from .routes import api, auth, sse
from .scheduler import retry_agent, scheduler, watchdog_agent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing database...")
    await init_db()
    logger.info("Database initialized")

    # Start enabled new agents
    enabled_agents = get_enabled_agents()
    for agent in enabled_agents:
        logger.info("Starting %s...", agent.NAME)
        await agent.start()

    if settings.scheduler_auto_start:
        logger.info("Auto-starting scheduler...")
        await scheduler.start()
        await retry_agent.start()
        await watchdog_agent.start()

    yield

    # Shutdown
    await watchdog_agent.stop()
    await retry_agent.stop()
    if scheduler.is_running:
        logger.info("Stopping scheduler...")
        await scheduler.stop()

    # Stop new agents
    for agent in reversed(enabled_agents):
        logger.info("Stopping %s...", agent.NAME)
        await agent.stop()


app = FastAPI(
    title=f"{settings.project_name} Agent Scheduler",
    description=f"AI Agent Task Scheduler for {settings.project_name}",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS for frontend (dynamic based on frontend_port)
_frontend_port = settings.frontend_port
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        f"http://localhost:{_frontend_port}",
        f"http://127.0.0.1:{_frontend_port}",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(auth.router)  # Unprotected — login/check
app.include_router(api.router, dependencies=[Depends(require_auth)])
app.include_router(sse.router, dependencies=[Depends(require_auth)])


@app.get("/health")
async def health():
    return {"status": "ok"}
