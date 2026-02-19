from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "MxTac API"
    version: str = "2.0.0"
    debug: bool = True
    api_prefix: str = "/api/v1"

    # Auth
    secret_key: str = "dev-secret-change-in-production"
    access_token_expire_minutes: int = 60

    # Database
    database_url: str = "postgresql+asyncpg://mxtac:mxtac@localhost:5432/mxtac"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    class Config:
        env_file = ".env"


settings = Settings()
