import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import require_auth
from .config import settings
from .database import init_db
from .routes import api, auth, sse
from .scheduler import retry_agent, scheduler

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

    if settings.scheduler_auto_start:
        logger.info("Auto-starting scheduler...")
        await scheduler.start()
        await retry_agent.start()

    yield

    # Shutdown
    await retry_agent.stop()
    if scheduler.is_running:
        logger.info("Stopping scheduler...")
        await scheduler.stop()


app = FastAPI(
    title="Agent Scheduler",
    description="AI Agent Task Scheduler for MxTac",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:13001", "http://127.0.0.1:13001"],
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
