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

    # Notification dispatcher SMTP defaults — used by DB-backed email channels
    # when a channel's config_json omits individual SMTP fields.
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = Field(
        default="",
        repr=False,
        json_schema_extra={"x-sensitive": True, "format": "password"},
    )
    smtp_from_address: str = "mxtac-alerts@localhost"

    # Threat intelligence feeds — STIX/TAXII 2.1 (feature 29.5)
    # Set via THREAT_INTEL_FEEDS env var as a JSON array, e.g.:
    #   [{"name":"AlienVault","taxii_url":"https://...","collection_id":"...","api_key":"..."}]
    threat_intel_feeds: list[ThreatIntelFeedConfig] = []

    # IOC expiry — feature 29.8
    # Number of days without a hit before an IOC is auto-deactivated.
    # Set to 0 to disable stale-hit expiry (only expires_at-based expiry runs).
    ioc_no_hit_expiry_days: int = 90

    # Database backup status — feature 38.1
    # Directory where backup-db.sh writes .sql.gz files.  The /ready endpoint
    # checks this directory and emits a warning when no backup has been created
    # within backup_stale_hours.  The warning does NOT cause a 503.
    backup_dir: str = "./backups"
    backup_stale_hours: int = 48

    # OpenSearch index lifecycle management retention — feature 38.2
    # Controls how long each index type is kept before deletion.
    # hot_days (configured in opensearch_client.py) determines when indices
    # transition from hot to warm (with force_merge); these settings control
    # the total retention before deletion.
    opensearch_events_retention_days: int = 90    # events: hot 7d → warm → delete
    opensearch_alerts_retention_days: int = 365   # alerts: hot 30d → warm → delete
    opensearch_audit_retention_days: int = 1095   # audit: hot 90d → warm → delete (3 years)

    # OpenSearch snapshot management — feature 38.3
    # Filesystem path where snapshots are stored (must be accessible by OpenSearch nodes).
    opensearch_snapshot_repo: str = "/backups/opensearch"
    # Number of days to retain snapshots; older ones are auto-deleted by the daily task.
    opensearch_snapshot_retention_days: int = 30

    # PostgreSQL data retention — feature 38.4
    # Controls how long records are kept in PostgreSQL before hard deletion.
    # OpenSearch ILM (feature 38.2) handles event/alert index cleanup independently.
    retention_events_days: int = 90      # informational — OpenSearch ILM controls events
    retention_alerts_days: int = 365     # detections deleted after this many days
    retention_incidents_days: int = 730  # resolved/closed incidents deleted after 2 years
    retention_audit_days: int = 1095     # informational — OpenSearch ISM controls audit (3 years)
    retention_iocs_days: int = 180       # expired IOCs hard-deleted after 180 days

    # Inactive account lock — feature 1.7
    # Accounts that have not logged in for this many days are auto-locked.
    # Set to 0 to disable login-time inactivity checking (background task still respects this).
    account_inactivity_days: int = 90

    # Password expiry — feature 2.3
    # Passwords older than this many days are expired at login; user must change them.
    # Set to 0 to disable time-based password expiry.
    password_expiry_days: int = 90

    # GeoIP enrichment — feature 9.8
    # Path to a MaxMind GeoLite2-City.mmdb or GeoIP2-City.mmdb database file.
    # When None or the file is absent, GeoIP enrichment is silently disabled
    # (fail-open: the pipeline continues without geo data).
    geoip_db_path: str | None = None
    # How long to cache GeoIP results in Valkey (seconds). Default: 24 hours.
    geoip_cache_ttl: int = 86400

    # Alert-to-incident auto-correlation — feature 26.8
    # Group related alerts into incidents automatically after enrichment.
    # Correlation key: (host, tactic) within correlation_window_seconds.
    # Set auto_create_incident_enabled=False to disable entirely.
    auto_create_incident_enabled: bool = True
    auto_create_incident_min_severity: str = "high"  # "low" | "medium" | "high" | "critical"
    correlation_window_seconds: int = 3600  # 1-hour window

    # Alert escalation — feature 27.7
    # Background task (every 5 min) escalates active critical/high detections
    # that have not been acknowledged after escalation_timeout_minutes.
    # Set escalation_channel_id to the NotificationChannel.id that should
    # receive escalation messages.  Leave None to disable escalation.
    escalation_timeout_minutes: int = 30
    escalation_channel_id: int | None = None

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
