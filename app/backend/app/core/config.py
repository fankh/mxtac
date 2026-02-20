import logging

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

_DEV_SECRET = "dev-secret-change-in-production"


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
    database_url: str = "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"

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
