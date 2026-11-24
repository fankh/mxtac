import logging
import re

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings

from .validators import validate_password_policy

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

    # Opt-in demo content: when True, the first-run seeder also inserts sample
    # (invented) detections, connectors, rules and incidents.  Never enable on
    # a real deployment — the rows are indistinguishable from real findings.
    seed_demo_data: bool = False

    # Bootstrap password for the first account (admin@mxtac.local), used only
    # when the users table is empty at startup.  Leave unset to have a random
    # one generated and written once to the startup log.  Either way the
    # account must change it at first sign-in.  Must satisfy the password
    # policy; a weak value stops the application from starting.
    initial_admin_password: str | None = Field(
        default=None,
        repr=False,
        json_schema_extra={"x-sensitive": True, "format": "password"},
    )

    # Valkey (Redis-compatible)
    valkey_url: str = Field(
        default="redis://localhost:6379/0",
        repr=False,
        json_schema_extra={"x-sensitive": True},
    )

    # Queue
    queue_backend: str = "memory"  # "memory" | "redis"

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

    # Syslog receiver — inbound UDP/TCP listener (feature 35.4)
    # Listens on a non-privileged port (default 1514); map 514→1514 in Docker.
    syslog_enabled: bool = False
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 1514
    syslog_protocol: str = "udp"  # "udp" | "tcp" | "both"
    syslog_max_message_size: int = 65535

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

    # Inactive account lock — feature 1.7
    # Accounts that have not logged in for this many days are locked at the next login attempt.
    # Set to 0 to disable the inactivity check.
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

    # Rate limiting — requests per minute per client IP for read (GET / HEAD)
    # requests.  Login, export and write requests have fixed, lower limits
    # (see core/rate_limit.py).
    rate_limit_per_minute: int = 300

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    @model_validator(mode="after")
    def _post_init(self) -> "Settings":
        """Enforce production security requirements and auto-configure SQLite mode."""
        # Warn (or hard-fail) when the well-known dev key is in use.
        if self.secret_key == _DEV_SECRET:
            if not self.debug:
                # Production mode with the dev default is a critical security risk.
                # Log the warning first so it appears in the service logs even when
                # the process manager captures stderr before re-raising.
                logger.warning(
                    "SECURITY: SECRET_KEY is set to the development default in "
                    "production mode (DEBUG=False). This is a critical security "
                    "risk — set a strong, unique SECRET_KEY environment variable."
                )
                raise ValueError(
                    "FATAL: SECRET_KEY is set to the development default. "
                    "Set a strong, unique SECRET_KEY via the SECRET_KEY environment "
                    "variable before running in production (DEBUG=False)."
                )
            else:
                # Dev mode: warn but allow startup so local workflows are not blocked.
                logger.warning(
                    "SECRET_KEY is set to the development default. "
                    "Set a unique SECRET_KEY before deploying to production."
                )

        # A blank INITIAL_ADMIN_PASSWORD means "not set"; a weak one is fatal so
        # that a guessable bootstrap password is never silently accepted.
        if not self.initial_admin_password:
            self.initial_admin_password = None
        else:
            try:
                validate_password_policy(self.initial_admin_password)
            except ValueError as exc:
                raise ValueError(
                    f"FATAL: INITIAL_ADMIN_PASSWORD does not meet the password policy: {exc}. "
                    "Set a stronger value, or unset it to have a random password "
                    "generated and written to the startup log."
                ) from None

        # Auto-configure SQLite URL when sqlite_mode is enabled.
        if self.sqlite_mode and not self.database_url.startswith("sqlite"):
            self.database_url = f"sqlite+aiosqlite:///{self.sqlite_path}"

        return self

    @property
    def opensearch_url(self) -> str:
        scheme = "https" if self.opensearch_use_ssl else "http"
        return f"{scheme}://{self.opensearch_host}:{self.opensearch_port}"

    @property
    def opensearch_http_auth(self) -> tuple[str, str] | None:
        """Basic-auth credentials for OpenSearch, or None when no username is set."""
        if not self.opensearch_username:
            return None
        return (self.opensearch_username, self.opensearch_password)

    class Config:
        env_file = ".env"
        # Validation errors must not echo the offending input: it can hold
        # secrets (SECRET_KEY, DSNs, a rejected INITIAL_ADMIN_PASSWORD).
        hide_input_in_errors = True


settings = Settings()
