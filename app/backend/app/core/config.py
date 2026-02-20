import logging

from pydantic import model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

_DEV_SECRET = "dev-secret-change-in-production"
_DEFAULT_PG_URL = "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"


class Settings(BaseSettings):
    app_name: str = "MxTac API"
    version: str = "2.0.0"
    debug: bool = True
    api_prefix: str = "/api/v1"

    # Auth
    secret_key: str = "dev-secret-change-in-production"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # Database
    database_url: str = _DEFAULT_PG_URL

    # SQLite single-binary mode — no external DB required (feature 20.8)
    # When True and DATABASE_URL is not explicitly overridden, the app uses a
    # local SQLite file instead of PostgreSQL.  Valkey and OpenSearch become
    # optional: the /ready probe only requires the DB check to pass.
    sqlite_mode: bool = False
    # Path for the SQLite database file (used only when sqlite_mode=True and
    # DATABASE_URL has not been explicitly set to a sqlite:// URL).
    sqlite_path: str = "./mxtac.db"

    @model_validator(mode="after")
    def _apply_sqlite_mode(self) -> "Settings":
        """Auto-configure SQLite URL when sqlite_mode is enabled."""
        if self.sqlite_mode and not self.database_url.startswith("sqlite"):
            self.database_url = f"sqlite+aiosqlite:///{self.sqlite_path}"
        return self

    # Valkey (Redis-compatible)
    valkey_url: str = "redis://localhost:6379/0"

    # Queue
    queue_backend: str = "memory"  # "memory" | "redis" | "kafka"
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_consumer_group: str = "mxtac"

    # OpenSearch
    opensearch_host: str = "localhost"
    opensearch_port: int = 9200
    opensearch_username: str = ""
    opensearch_password: str = ""
    opensearch_use_ssl: bool = False

    # Alert file output (JSON Lines)
    alert_file_output_enabled: bool = False
    alert_file_output_path: str = "/var/log/mxtac/alerts.jsonl"
    alert_file_max_bytes: int = 100 * 1024 * 1024  # 100 MB per file
    alert_file_backup_count: int = 5  # keep up to 5 rotated files

    # Alert webhook output — POST JSON to one or more URLs
    alert_webhook_output_enabled: bool = False
    alert_webhook_urls: list[str] = []  # e.g. ["https://hooks.example.com/mxtac"]
    alert_webhook_timeout: int = 5  # seconds per request
    alert_webhook_retry_count: int = 3  # retries on timeout / 5xx

    # Rate limiting
    rate_limit_per_minute: int = 300

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    @property
    def opensearch_url(self) -> str:
        scheme = "https" if self.opensearch_use_ssl else "http"
        return f"{scheme}://{self.opensearch_host}:{self.opensearch_port}"

    class Config:
        env_file = ".env"


settings = Settings()

if settings.secret_key == _DEV_SECRET and not settings.debug:
    logger.warning(
        "SECURITY WARNING: SECRET_KEY is set to the development default. "
        "Set a strong, unique SECRET_KEY in production via the SECRET_KEY environment variable."
    )
