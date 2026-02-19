from pydantic_settings import BaseSettings


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
