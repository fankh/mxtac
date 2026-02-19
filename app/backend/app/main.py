import asyncio
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from prometheus_fastapi_instrumentator import Instrumentator

from .api.v1.router import api_router
from .core.config import settings
from .core.database import AsyncSessionLocal
from .core.exceptions import register_exception_handlers
from .core.logging import configure_logging, get_logger
from .db.seed import seed_database
from .pipeline.queue import get_queue, Topic
from .services.opensearch_client import get_opensearch

configure_logging()
logger = get_logger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Prometheus metrics instrumentation
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

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

    # 1. Seed database (idempotent)
    try:
        async with AsyncSessionLocal() as session:
            await seed_database(session)
    except Exception:
        logger.exception("Database seed failed — tables may not exist yet, run alembic upgrade")

    # 2. Init message queue
    queue = get_queue()
    await queue.start()

    # 3. Connect OpenSearch
    os_client = get_opensearch()
    await os_client.connect()

    # 4. Load Sigma rules
    try:
        from .engine.sigma_engine import SigmaEngine
        engine = SigmaEngine()
        rules_dir = Path(__file__).parent.parent / "sigma_rules"
        if rules_dir.exists():
            n = await engine.load_rules_from_dir(rules_dir)
            logger.info("Loaded %d Sigma rules", n)
        else:
            logger.info("No sigma_rules/ directory found, skipping rule loading")
        app.state.sigma_engine = engine
    except Exception:
        logger.exception("Sigma engine init failed")

    # 5. Start normalizer pipeline
    try:
        from .services.normalizers.pipeline import NormalizerPipeline
        normalizer = NormalizerPipeline(queue)
        asyncio.create_task(normalizer.start())
        logger.info("Normalizer pipeline started")
    except Exception:
        logger.exception("Normalizer pipeline start failed")

    # 6. Start Sigma evaluation consumer
    try:
        from .services.sigma_consumer import sigma_consumer
        asyncio.create_task(sigma_consumer(queue, app.state.sigma_engine))
        logger.info("Sigma consumer started")
    except Exception:
        logger.exception("Sigma consumer start failed")

    # 7. Start alert manager consumer
    try:
        from .services.alert_manager import AlertManager
        alert_mgr = AlertManager(queue)
        asyncio.create_task(alert_mgr_consumer(queue, alert_mgr))
        logger.info("Alert manager consumer started")
    except Exception:
        logger.exception("Alert manager start failed")

    # 8. Start WebSocket broadcaster
    try:
        from .services.ws_broadcaster import websocket_broadcaster
        asyncio.create_task(websocket_broadcaster(queue))
        logger.info("WebSocket broadcaster started")
    except Exception:
        logger.exception("WebSocket broadcaster start failed")

    # 9. Start connectors from DB
    try:
        from .connectors.registry import start_connectors_from_db
        async with AsyncSessionLocal() as session:
            connectors = await start_connectors_from_db(session, queue)
        for conn in connectors:
            asyncio.create_task(conn.start())
        logger.info("Started %d connectors", len(connectors))
    except Exception:
        logger.exception("Connector start failed")

    logger.info("MxTac API startup complete")


async def alert_mgr_consumer(queue, alert_mgr) -> None:
    """Subscribe to mxtac.alerts and forward to AlertManager."""
    await queue.subscribe(Topic.ALERTS, "alert-manager", alert_mgr.process)


@app.get("/health", tags=["ops"])
async def health() -> dict:
    return {"status": "ok", "version": settings.version}


@app.get("/ready", tags=["ops"])
async def readiness() -> JSONResponse:
    """Readiness probe — checks PostgreSQL, Valkey, and OpenSearch."""
    checks: dict[str, str] = {}

    # Check PostgreSQL
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as e:
        checks["postgres"] = f"error: {e}"

    # Check Valkey
    try:
        import valkey.asyncio as aioredis
        client = aioredis.from_url(settings.valkey_url)
        await client.ping()
        await client.aclose()
        checks["valkey"] = "ok"
    except Exception as e:
        checks["valkey"] = f"error: {e}"

    # Check OpenSearch
    try:
        from opensearchpy import AsyncOpenSearch
        os_client = AsyncOpenSearch(
            hosts=[settings.opensearch_url],
            http_compress=True,
            use_ssl=settings.opensearch_use_ssl,
            verify_certs=False,
            ssl_show_warn=False,
        )
        await os_client.ping()
        await os_client.close()
        checks["opensearch"] = "ok"
    except Exception as e:
        checks["opensearch"] = f"error: {e}"

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ready" if all_ok else "degraded", "checks": checks},
    )
