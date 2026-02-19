from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.v1.router import api_router
from .core.config import settings
from .core.exceptions import register_exception_handlers
from .core.logging import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app)
app.include_router(api_router, prefix=settings.api_prefix)


@app.on_event("startup")
async def on_startup() -> None:
    logger.info("MxTac API starting — version=%s debug=%s", settings.version, settings.debug)


@app.get("/health", tags=["ops"])
async def health() -> dict:
    return {"status": "ok", "version": settings.version}
