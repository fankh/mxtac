from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    scheduler_db_url: str = "sqlite+aiosqlite:///./data/scheduler.db"

    # Server
    scheduler_host: str = "0.0.0.0"
    scheduler_port: int = 13002

    # Scheduler
    scheduler_max_concurrent: int = 2
    scheduler_spawn_delay: int = 30  # seconds between spawns
    scheduler_task_timeout: int = 1800  # 30 minutes
    scheduler_retry_max: int = 3
    scheduler_retry_backoff: int = 60  # base backoff in seconds
    scheduler_auto_start: bool = False

    # Claude CLI
    claude_model: str = "sonnet"
    claude_cli_path: str = "claude"

    # Auth
    auth_password: str = ""  # Empty = auth disabled

    # MxTac
    mxtac_project_root: str = "/home/khchoi/development/new-research/mitre-attack/mxtac"

    @property
    def db_path(self) -> Path:
        """Extract the file path from the SQLite URL."""
        url = self.scheduler_db_url
        if url.startswith("sqlite+aiosqlite:///"):
            return Path(url.replace("sqlite+aiosqlite:///", ""))
        return Path("./data/scheduler.db")


settings = Settings()
