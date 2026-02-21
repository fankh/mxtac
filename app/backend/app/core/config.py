import logging
import re

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

_DEV_SECRET = "dev-secret-change-in-production"
_DEFAULT_PG_URL = "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"

# Regex that matches a password token inside a DSN URL, e.g.:
#   postgresql+asyncpg://user:PASSWORD@host/db
#   redis://:PASSWORD@host:port/0
_DSN_PASSWORD_RE = re.compile(r"(://[^:@]*:)([^@]+)(@)")


def redact_dsn(dsn: str) -> str:
    """Replace the password portion of a DSN URL with '***'."""
    return _DSN_PASSWORD_RE.sub(r"\1***\3", dsn)


class ThreatIntelFeedConfig(BaseModel):
    """Configuration for a single STIX/TAXII 2.1 threat intelligence feed."""

    name: str
    taxii_url: str
    collection_id: str
    api_key: str = Field(default="", repr=False)
    poll_interval: int = 21600  # seconds; default: 6 hours


class Settings(BaseSettings):
    app_name: str = "MxTac API"
    version: str = "2.0.0"
    debug: bool = True
    api_prefix: str = "/api/v1"

    # Auth — secret_key is excluded from repr so it never appears in log output
    secret_key: str = Field(
        default="dev-secret-change-in-production",
        repr=False,
        json_schema_extra={"x-sensitive": True, "format": "password"},
    )
    # Bump this integer to invalidate all currently-issued JWTs (e.g. after a
    # secret rotation).  Every token stores this version in the "kvr" claim;
    # verification rejects tokens whose kvr does not match the current value.
    jwt_key_version: int = 1
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7

    # Database — excluded from repr to prevent password leakage in logs
    database_url: str = Field(
        default=_DEFAULT_PG_URL,
        repr=False,
        json_schema_extra={"x-sensitive": True},
    )

    # SQLite single-binary mode — no external DB required (feature 20.8)
    # When True and DATABASE_URL is not explicitly overridden, the app uses a
    # local SQLite file instead of PostgreSQL.  Valkey and OpenSearch become
    # optional: the /ready probe only requires the DB check to pass.
    sqlite_mode: bool = False
    # Path for the SQLite database file (used only when sqlite_mode=True and
    # DATABASE_URL has not been explicitly set to a sqlite:// URL).
    sqlite_path: str = "./mxtac.db"

    # DuckDB embedded event store — no OpenSearch required (feature 20.9)
    # When True, normalised events are mirrored to a local DuckDB file and
    # analytics queries (search, aggregate) prefer DuckDB over raw PostgreSQL
    # scans when OpenSearch is unavailable.  Both sqlite_mode and duckdb_enabled
    # may be active simultaneously since DuckDB uses a separate file.
    duckdb_enabled: bool = False
    # Path for the DuckDB analytics database file.
    duckdb_path: str = "./mxtac-events.duckdb"

    # Valkey (Redis-compatible)
    valkey_url: str = Field(
        default="redis://localhost:6379/0",
        repr=False,
        json_schema_extra={"x-sensitive": True},
    )

    # Queue
    queue_backend: str = "memory"  # "memory" | "redis" | "kafka"
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_consumer_group: str = "mxtac"

    # OpenSearch
    opensearch_host: str = "localhost"
    opensearch_port: int = 9200
    opensearch_username: str = ""
    opensearch_password: str = Field(
        default="",
        repr=False,
        json_schema_extra={"x-sensitive": True, "format": "password"},
    )
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

    # Alert syslog output — emit enriched alerts to a syslog destination
    alert_syslog_output_enabled: bool = False
    alert_syslog_host: str = "localhost"  # hostname, IP, or /dev/log for Unix socket
    alert_syslog_port: int = 514  # standard syslog port (ignored for Unix socket)
    alert_syslog_protocol: str = "udp"  # "udp" | "tcp"
    alert_syslog_facility: str = "local0"  # syslog facility (local0–local7 recommended)
    alert_syslog_tag: str = "mxtac-alert"  # syslog application tag (ident)

    # Alert email output — send enriched alerts via SMTP (high-severity only)
    alert_email_output_enabled: bool = False
    alert_email_smtp_host: str = "localhost"
    alert_email_smtp_port: int = 587
    alert_email_smtp_username: str = ""
    alert_email_smtp_password: str = Field(
        default="",
        repr=False,
        json_schema_extra={"x-sensitive": True, "format": "password"},
    )
    alert_email_smtp_use_tls: bool = False       # implicit TLS (SMTP_SSL, port 465)
    alert_email_smtp_use_starttls: bool = True   # STARTTLS upgrade (port 587)
    alert_email_from: str = "mxtac-alerts@localhost"
    alert_email_to: list[str] = []               # recipient list
    alert_email_min_level: str = "high"          # minimum severity to email

    # Threat intelligence feeds — STIX/TAXII 2.1 (feature 29.5)
    # Set via THREAT_INTEL_FEEDS env var as a JSON array, e.g.:
    #   [{"name":"AlienVault","taxii_url":"https://...","collection_id":"...","api_key":"..."}]
    threat_intel_feeds: list[ThreatIntelFeedConfig] = []

    # Rate limiting
    rate_limit_per_minute: int = 300

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    @model_validator(mode="after")
    def _post_init(self) -> "Settings":
        """Enforce production security requirements and auto-configure SQLite mode."""
        # Refuse to start in production when the secret key is the dev default.
        # This prevents silent exposure of a well-known key in real deployments.
        if not self.debug and self.secret_key == _DEV_SECRET:
            raise ValueError(
                "FATAL: SECRET_KEY is set to the development default. "
                "Set a strong, unique SECRET_KEY via the SECRET_KEY environment "
                "variable before running in production (DEBUG=False)."
            )

        # Auto-configure SQLite URL when sqlite_mode is enabled.
        if self.sqlite_mode and not self.database_url.startswith("sqlite"):
            self.database_url = f"sqlite+aiosqlite:///{self.sqlite_path}"

        return self

    @property
    def opensearch_url(self) -> str:
        scheme = "https" if self.opensearch_use_ssl else "http"
        return f"{scheme}://{self.opensearch_host}:{self.opensearch_port}"

    class Config:
        env_file = ".env"


settings = Settings()
