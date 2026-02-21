import asyncio
import glob as _glob
import os
import re
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from prometheus_fastapi_instrumentator import Instrumentator

from .api.v1.router import api_router
from .core import metrics as _metrics  # noqa: F401 — registers all mxtac_ metrics
from .core.access_log import AccessLogMiddleware
from .core.config import settings, redact_dsn, _DEV_SECRET, _DEFAULT_PG_URL
from .core.rate_limit import RateLimitMiddleware
from .core.security_headers import SecurityHeadersMiddleware
from .core.database import AsyncSessionLocal
from .core.exceptions import register_exception_handlers
from .core.logging import configure_logging, get_logger
from .db.seed import seed_database
from .pipeline.queue import get_queue, Topic
from .services.duckdb_store import get_duckdb
from .services.opensearch_client import get_opensearch

configure_logging()
logger = get_logger(__name__)


# ── Startup security validation ────────────────────────────────────────────────

# Production environment indicators — any of these env vars being set suggests
# the process is running in a non-development environment.
_PRODUCTION_INDICATORS = (
    "KUBERNETES_SERVICE_HOST",  # Kubernetes pod
    "DYNO",                     # Heroku
    "AWS_EXECUTION_ENV",        # AWS Lambda / ECS
    "GOOGLE_CLOUD_PROJECT",     # GCP
    "WEBSITE_INSTANCE_ID",      # Azure App Service
)


def _check_startup_config() -> None:
    """Log WARNING-level messages for insecure configuration at startup.

    This supplements the hard-fail in Settings._post_init (which refuses to
    start when DEBUG=False + default SECRET_KEY).  Here we emit softer warnings
    for configurations that are risky but not immediately fatal.
    """
    # Warn when DEBUG is True but we appear to be in a production environment.
    if settings.debug:
        detected = [k for k in _PRODUCTION_INDICATORS if os.environ.get(k)]
        if detected:
            logger.warning(
                "SECURITY WARNING: DEBUG=True detected in a likely production "
                "environment (indicators: %s). Set DEBUG=False before deploying.",
                ", ".join(detected),
            )

    # Warn if the database URL still uses the default dev credentials.
    if settings.database_url == _DEFAULT_PG_URL:
        logger.warning(
            "SECURITY WARNING: DATABASE_URL is set to the development default "
            "(mxtac:mxtac@localhost). Use strong, unique credentials in production."
        )

    # Warn if OpenSearch password is empty while a non-localhost host is configured.
    if not settings.opensearch_password and settings.opensearch_host not in ("localhost", "127.0.0.1"):
        logger.warning(
            "SECURITY WARNING: opensearch_password is empty but opensearch_host "
            "is set to %r. Configure authentication for remote OpenSearch.",
            settings.opensearch_host,
        )


# ── /ready helper: sanitise service error strings ─────────────────────────────

# Redact passwords embedded in DSN-style connection strings that might appear
# in exception messages (e.g. asyncpg includes the DSN in connection errors).
_DSN_PASSWORD_RE = re.compile(r"(://[^:@]*:)([^@]+)(@)")


def _sanitize_check_error(msg: str) -> str:
    """Strip credentials from service error strings before including in /ready."""
    return _DSN_PASSWORD_RE.sub(r"\1***\3", msg)


# ── Backup status check ────────────────────────────────────────────────────────

def _check_backup_status() -> str:
    """Return a status string describing the most recent database backup.

    Returns:
        "ok"                       — a backup exists and is within the stale window
        "warn: no backups found"   — backup_dir exists but contains no .sql.gz files
        "warn: backup directory not found" — backup_dir does not exist
        "warn: last backup Xh ago (threshold: Yh)" — most recent backup is stale
    """
    backup_dir = settings.backup_dir
    if not backup_dir or not os.path.isdir(backup_dir):
        return "warn: backup directory not found"

    pattern = os.path.join(backup_dir, "mxtac_backup_*.sql.gz")
    files = _glob.glob(pattern)
    if not files:
        return "warn: no backups found"

    # Most recent backup by mtime
    latest = max(files, key=os.path.getmtime)
    age_hours = (time.time() - os.path.getmtime(latest)) / 3600
    if age_hours > settings.backup_stale_hours:
        return (
            f"warn: last backup {age_hours:.0f}h ago "
            f"(threshold: {settings.backup_stale_hours}h)"
        )
    return "ok"


# ── Body size limit middleware ─────────────────────────────────────────────────

_MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB


class ContentSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds *max_bytes* with HTTP 413.

    Relies on the Content-Length header sent by compliant HTTP clients.
    Field-level max_length constraints on Pydantic models provide an
    additional defence layer for chunked transfers without Content-Length.
    """

    def __init__(self, app, max_bytes: int = _MAX_BODY_SIZE) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                size = int(content_length)
            except ValueError:
                size = 0
            if size > self.max_bytes:
                return Response(
                    status_code=413,
                    content='{"detail": "Request body too large. Maximum allowed size is 10 MB."}',
                    media_type="application/json",
                )
        return await call_next(request)


async def _rule_reload_subscriber() -> None:
    """Subscribe to the Valkey rule-reload channel and hot-reload the SigmaEngine.

    Each API replica runs this background task.  When any replica modifies a
    rule (create / update / delete / import), it publishes a signal to
    RULE_RELOAD_CHANNEL.  This task receives that signal and reloads the
    local SigmaEngine from the database so all replicas stay consistent
    without manual POST /rules/reload calls.

    Exits silently when Valkey is unavailable.
    """
    from .core.valkey import RULE_RELOAD_CHANNEL
    from .core.database import AsyncSessionLocal
    import valkey.asyncio as aioredis

    sub_client = aioredis.from_url(settings.valkey_url, decode_responses=True)
    try:
        pubsub = sub_client.pubsub()
        await pubsub.subscribe(RULE_RELOAD_CHANNEL)
        logger.info("Rule reload subscriber listening on channel %s", RULE_RELOAD_CHANNEL)
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            engine = getattr(app.state, "sigma_engine", None)
            if engine is None:
                continue
            try:
                async with AsyncSessionLocal() as session:
                    n = await engine.reload_from_db(session)
                    logger.info("SigmaEngine reloaded from peer signal: %d rules", n)
            except Exception:
                logger.exception("SigmaEngine reload from peer signal failed")
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.debug("Rule reload subscriber exiting — Valkey may not be reachable")
    finally:
        try:
            await sub_client.aclose()
        except Exception:
            pass


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Prometheus metrics instrumentation
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# Request access log — method, path, status, latency (feature 21.11)
app.add_middleware(AccessLogMiddleware)

# Body size limit — reject oversized requests early (feature 33.3)
app.add_middleware(ContentSizeLimitMiddleware)

# Rate limiting — per-IP, per-endpoint-group (feature 33.1)
# Added before CORSMiddleware so 429 responses still carry CORS headers.
app.add_middleware(RateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers — applied after CORS so headers are present on all responses
# including CORS preflight responses (feature 33.2).
app.add_middleware(SecurityHeadersMiddleware)

register_exception_handlers(app)
app.include_router(api_router, prefix=settings.api_prefix)


@app.on_event("startup")
async def on_startup() -> None:
    logger.info("MxTac API starting — version=%s debug=%s", settings.version, settings.debug)

    # Emit warnings for insecure-but-non-fatal configuration choices.
    _check_startup_config()

    # Pre-initialise state so the shutdown handler always has valid references
    app.state.connectors = {}
    app.state.alert_mgr = None
    app.state.alert_file_writer = None
    app.state.alert_webhook_sender = None
    app.state.alert_email_sender = None
    app.state.duckdb_store = None

    # 0. Auto-migrate when running in SQLite single-binary mode (feature 20.8)
    if settings.sqlite_mode or settings.database_url.startswith("sqlite"):
        from .db.migrate import auto_migrate
        await auto_migrate()

    # 1. Seed database (idempotent)
    try:
        async with AsyncSessionLocal() as session:
            await seed_database(session)
    except Exception:
        logger.exception("Database seed failed — tables may not exist yet, run alembic upgrade")

    # 2. Init message queue
    queue = get_queue()
    await queue.start()
    app.state.queue = queue

    # 3. Connect OpenSearch, apply ILM policies, and create index templates
    os_client = get_opensearch()
    await os_client.connect()
    await os_client.ensure_ilm_policy()        # 90-day retention for events/alerts
    await os_client.ensure_audit_ilm_policy()  # 3-year retention for audit logs (feature 21.14)
    await os_client.ensure_indices()
    app.state.os_client = os_client

    # 3.1. Connect DuckDB embedded event store (feature 20.9)
    if settings.duckdb_enabled:
        duckdb_store = get_duckdb()
        await duckdb_store.connect()
        app.state.duckdb_store = duckdb_store
        logger.info(
            "DuckDB event store enabled path=%r available=%s",
            settings.duckdb_path,
            duckdb_store.is_available,
        )
    else:
        logger.info("DuckDB event store disabled (set DUCKDB_ENABLED=true to enable)")

    # 4. Load Sigma rules
    try:
        from .engine.sigma_engine import SigmaEngine
        engine = SigmaEngine()
        rules_dir = Path(__file__).parent.parent / "sigma_rules"
        if rules_dir.exists():
            n = await engine.load_rules_from_dir(rules_dir)
            logger.info("Loaded %d Sigma rules from disk", n)
        else:
            logger.info("No sigma_rules/ directory found, skipping disk rule loading")
        # Load persisted rules from DB (overrides disk rules with same ID)
        async with AsyncSessionLocal() as session:
            n_db = await engine.load_rules_from_db(session)
            logger.info("Loaded %d Sigma rules from DB", n_db)
        app.state.sigma_engine = engine
    except Exception:
        logger.exception("Sigma engine init failed")
        app.state.sigma_engine = None

    # 5. Wire normalizer pipeline — subscribes to raw topics, publishes to mxtac.normalized
    try:
        from .services.normalizers.pipeline import NormalizerPipeline
        normalizer = NormalizerPipeline(queue)
        await normalizer.start()
        logger.info("Normalizer pipeline started")
    except Exception:
        logger.exception("Normalizer pipeline start failed")

    # 5.1. Wire event persister — triple-write to PostgreSQL + DuckDB + OpenSearch
    try:
        from .services.event_persister import event_persister
        await event_persister(
            queue,
            app.state.os_client,
            duckdb_store=getattr(app.state, "duckdb_store", None),
        )
        logger.info("Event persister started")
    except Exception:
        logger.exception("Event persister start failed")

    # 6. Wire Sigma evaluation consumer — subscribes to mxtac.normalized, publishes alerts
    try:
        from .services.sigma_consumer import sigma_consumer
        await sigma_consumer(queue, app.state.sigma_engine)
        logger.info("Sigma consumer started")
    except Exception:
        logger.exception("Sigma consumer start failed")

    # 7. Wire alert manager — subscribes to mxtac.alerts, deduplicates, scores, enriches
    try:
        from .services.alert_manager import AlertManager
        alert_mgr = AlertManager(queue)
        await queue.subscribe(Topic.ALERTS, "alert-manager", alert_mgr.process)
        app.state.alert_mgr = alert_mgr
        logger.info("Alert manager consumer started")
    except Exception:
        logger.exception("Alert manager start failed")

    # 8. Wire WebSocket broadcaster — subscribes to mxtac.enriched, broadcasts to WS clients
    try:
        from .services.ws_broadcaster import websocket_broadcaster
        await websocket_broadcaster(queue)
        logger.info("WebSocket broadcaster started")
    except Exception:
        logger.exception("WebSocket broadcaster start failed")

    # 8.5. Wire alert file writer — appends enriched alerts as JSON Lines to file
    if settings.alert_file_output_enabled:
        try:
            from .services.alert_file_writer import alert_file_writer
            afw = await alert_file_writer(
                queue,
                path=settings.alert_file_output_path,
                max_bytes=settings.alert_file_max_bytes,
                backup_count=settings.alert_file_backup_count,
            )
            app.state.alert_file_writer = afw
            logger.info("Alert file writer started → %s", settings.alert_file_output_path)
        except Exception:
            logger.exception("Alert file writer start failed")

    # 8.6. Wire alert webhook output — POST enriched alerts to configured URLs
    if settings.alert_webhook_output_enabled and settings.alert_webhook_urls:
        try:
            from .services.webhook_output import alert_webhook_output
            aws = await alert_webhook_output(
                queue,
                urls=settings.alert_webhook_urls,
                timeout=settings.alert_webhook_timeout,
                retry_count=settings.alert_webhook_retry_count,
            )
            app.state.alert_webhook_sender = aws
            logger.info(
                "Alert webhook output started → %d URL(s)", len(settings.alert_webhook_urls)
            )
        except Exception:
            logger.exception("Alert webhook output start failed")

    # 8.7. Wire alert syslog output — emit enriched alerts to a syslog destination
    if settings.alert_syslog_output_enabled:
        try:
            from .services.alert_syslog_output import alert_syslog_output
            ash = await alert_syslog_output(
                queue,
                host=settings.alert_syslog_host,
                port=settings.alert_syslog_port,
                protocol=settings.alert_syslog_protocol,
                facility=settings.alert_syslog_facility,
                tag=settings.alert_syslog_tag,
            )
            app.state.alert_syslog_handler = ash
            logger.info(
                "Alert syslog output started → %s:%d (%s) facility=%s",
                settings.alert_syslog_host,
                settings.alert_syslog_port,
                settings.alert_syslog_protocol,
                settings.alert_syslog_facility,
            )
        except Exception:
            logger.exception("Alert syslog output start failed")

    # 8.8. Wire alert email output — send high-severity alerts via SMTP
    if settings.alert_email_output_enabled and settings.alert_email_to:
        try:
            from .services.alert_email_output import alert_email_output
            aem = await alert_email_output(
                queue,
                smtp_host=settings.alert_email_smtp_host,
                smtp_port=settings.alert_email_smtp_port,
                username=settings.alert_email_smtp_username,
                password=settings.alert_email_smtp_password,
                use_tls=settings.alert_email_smtp_use_tls,
                use_starttls=settings.alert_email_smtp_use_starttls,
                from_addr=settings.alert_email_from,
                to_addrs=settings.alert_email_to,
                min_level=settings.alert_email_min_level,
            )
            app.state.alert_email_sender = aem
            logger.info(
                "Alert email output started → smtp://%s:%d to=%s min_level=%s",
                settings.alert_email_smtp_host,
                settings.alert_email_smtp_port,
                settings.alert_email_to,
                settings.alert_email_min_level,
            )
        except Exception:
            logger.exception("Alert email output start failed")

    # 9. Start connectors from DB — publish raw events into the pipeline
    try:
        from .connectors.registry import start_connectors_from_db
        async with AsyncSessionLocal() as session:
            connectors = await start_connectors_from_db(session, queue)
        for conn in connectors.values():
            asyncio.create_task(conn.start(), name=f"connector-start-{conn.config.name}")
        app.state.connectors = connectors
        logger.info("Started %d connectors", len(connectors))
    except Exception:
        logger.exception("Connector start failed")

    # 10. Subscribe to peer rule-change notifications — keep SigmaEngine in sync across replicas
    asyncio.create_task(_rule_reload_subscriber(), name="rule-reload-subscriber")
    logger.info("Rule reload subscriber started")

    # 11. Start agent status monitor — auto-degrade agents that stop heartbeating
    try:
        from .services.agent_monitor import agent_status_monitor
        asyncio.create_task(agent_status_monitor(), name="agent-status-monitor")
        logger.info("Agent status monitor started")
    except Exception:
        logger.exception("Agent status monitor start failed")

    # 12. Start STIX/TAXII feed pollers — poll configured threat intel feeds (feature 29.5)
    if settings.threat_intel_feeds:
        try:
            from .services.stix_feed import stix_feed_poller
            asyncio.create_task(
                stix_feed_poller(settings.threat_intel_feeds),
                name="stix-feed-poller",
            )
            logger.info(
                "STIX feed poller started: %d feed(s)", len(settings.threat_intel_feeds)
            )
        except Exception:
            logger.exception("STIX feed poller start failed")
    else:
        logger.info(
            "STIX feed poller: no feeds configured (set THREAT_INTEL_FEEDS to enable)"
        )

    # 13. Start IOC expiry task — deactivate expired and stale IOCs hourly (feature 29.8)
    try:
        from .services.ioc_expiry import ioc_expiry_task
        asyncio.create_task(ioc_expiry_task(), name="ioc-expiry-task")
        logger.info("IOC expiry task started")
    except Exception:
        logger.exception("IOC expiry task start failed")

    logger.info("MxTac API startup complete")


@app.on_event("shutdown")
async def on_shutdown() -> None:
    logger.info("MxTac API shutting down")

    # Stop connectors (cancels each connector's poll loop)
    for conn in getattr(app.state, "connectors", {}).values():
        try:
            await conn.stop()
        except Exception:
            logger.exception("Connector stop failed name=%s", conn.config.name)

    # Stop message queue (cancels all consumer tasks)
    try:
        queue = getattr(app.state, "queue", None)
        if queue is not None:
            await queue.stop()
    except Exception:
        logger.exception("Queue stop failed")

    # Close AlertManager (releases Valkey connection)
    try:
        alert_mgr = getattr(app.state, "alert_mgr", None)
        if alert_mgr is not None:
            await alert_mgr.close()
    except Exception:
        logger.exception("AlertManager close failed")

    # Close alert file writer (flush + close file handle)
    try:
        afw = getattr(app.state, "alert_file_writer", None)
        if afw is not None:
            await afw.close()
    except Exception:
        logger.exception("AlertFileWriter close failed")

    # Close alert webhook sender (release HTTP connection pool)
    try:
        aws = getattr(app.state, "alert_webhook_sender", None)
        if aws is not None:
            await aws.close()
    except Exception:
        logger.exception("AlertWebhookSender close failed")

    # Close alert syslog handler (release syslog socket)
    try:
        ash = getattr(app.state, "alert_syslog_handler", None)
        if ash is not None:
            await ash.close()
    except Exception:
        logger.exception("AlertSyslogHandler close failed")

    # Close alert email sender (no-op, present for interface symmetry)
    try:
        aem = getattr(app.state, "alert_email_sender", None)
        if aem is not None:
            await aem.close()
    except Exception:
        logger.exception("AlertEmailSender close failed")

    # Close OpenSearch client
    try:
        os_client = getattr(app.state, "os_client", None)
        if os_client is not None:
            await os_client.close()
    except Exception:
        logger.exception("OpenSearch close failed")

    # Close DuckDB event store
    try:
        duckdb_store = getattr(app.state, "duckdb_store", None)
        if duckdb_store is not None:
            await duckdb_store.close()
    except Exception:
        logger.exception("DuckDB close failed")

    logger.info("MxTac API shutdown complete")


@app.get("/health", tags=["ops"])
async def health() -> dict:
    return {"status": "ok", "version": settings.version}


_READY_CHECK_TIMEOUT = 3.0  # seconds per service check


@app.get("/ready", tags=["ops"])
async def readiness() -> JSONResponse:
    """Readiness probe — checks DB, Valkey, and OpenSearch.

    Each service check is bounded by ``_READY_CHECK_TIMEOUT`` seconds so that
    a hung dependency cannot stall the HAProxy health-check cycle.  A timeout
    is reported as ``"error: timeout"`` and causes a 503 response, which
    HAProxy interprets as the backend being unavailable.

    In SQLite single-binary mode (``sqlite_mode=True`` or a sqlite:// URL),
    only the database check is required for the probe to return 200.  Valkey
    and OpenSearch checks are still performed and included in the response for
    visibility, but failures do not make the probe return 503.
    """
    checks: dict[str, str] = {}
    _sqlite = settings.sqlite_mode or settings.database_url.startswith("sqlite")

    # Check database (PostgreSQL or SQLite)
    async def _check_db() -> None:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))

    try:
        await asyncio.wait_for(_check_db(), timeout=_READY_CHECK_TIMEOUT)
        checks["db"] = "ok"
    except asyncio.TimeoutError:
        checks["db"] = "error: timeout"
    except Exception as e:
        checks["db"] = _sanitize_check_error(f"error: {e}")

    # Check Valkey
    async def _check_valkey() -> None:
        import valkey.asyncio as aioredis
        client = aioredis.from_url(settings.valkey_url)
        try:
            await client.ping()
        finally:
            await client.aclose()

    try:
        await asyncio.wait_for(_check_valkey(), timeout=_READY_CHECK_TIMEOUT)
        checks["valkey"] = "ok"
    except asyncio.TimeoutError:
        checks["valkey"] = "error: timeout"
    except Exception as e:
        checks["valkey"] = _sanitize_check_error(f"error: {e}")

    # Check OpenSearch
    async def _check_opensearch() -> None:
        from opensearchpy import AsyncOpenSearch
        os_client = AsyncOpenSearch(
            hosts=[settings.opensearch_url],
            http_compress=True,
            use_ssl=settings.opensearch_use_ssl,
            verify_certs=False,
            ssl_show_warn=False,
        )
        try:
            await os_client.ping()
        finally:
            await os_client.close()

    try:
        await asyncio.wait_for(_check_opensearch(), timeout=_READY_CHECK_TIMEOUT)
        checks["opensearch"] = "ok"
    except asyncio.TimeoutError:
        checks["opensearch"] = "error: timeout"
    except Exception as e:
        checks["opensearch"] = _sanitize_check_error(f"error: {e}")

    # Check backup status — informational only, does NOT affect 200/503 outcome.
    # A "warn:" value here means no recent backup exists, but the service is
    # still serving requests so we do not degrade the readiness signal.
    try:
        checks["backup"] = _check_backup_status()
    except Exception as e:
        checks["backup"] = f"warn: {e}"

    # Determine overall readiness from required service checks only.
    # The "backup" key is excluded because it is advisory, not critical.
    _required = {k: v for k, v in checks.items() if k != "backup"}

    # In SQLite/single-binary mode only the DB check is required; external
    # services (Valkey, OpenSearch) are optional and their failures are
    # informational only.
    if _sqlite:
        all_ok = _required.get("db") == "ok"
    else:
        all_ok = all(v == "ok" for v in _required.values())

    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ready" if all_ok else "degraded", "checks": checks},
    )
