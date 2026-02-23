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
    scheduler_retry_max: int = 5
    scheduler_retry_backoff: int = 60  # base backoff in seconds
    scheduler_auto_start: bool = False
    scheduler_quality_retry_max: int = 10  # max quality-failure retries
    scheduler_test_command: str = ""  # empty = disabled
    scheduler_test_timeout: int = 300  # 5 minutes

    # GitHub
    github_repo_url: str = "https://github.com/fankh/mxtac"

    # Claude CLI
    claude_model: str = "sonnet"
    claude_cli_path: str = "claude"

    # Auth
    auth_password: str = ""  # Empty = auth disabled

    # MxTac
    mxtac_project_root: str = "/home/khchoi/development/new-research/mitre-attack/mxtac"

    # --- New Agent Settings ---

    # TaskCreatorAgent (P0)
    agent_task_creator_enabled: bool = True
    agent_task_creator_interval: int = 300  # 5 minutes
    agent_task_creator_max_tasks_per_cycle: int = 20
    agent_task_creator_use_claude: bool = True

    # VerifierAgent (P0)
    agent_verifier_enabled: bool = True
    agent_verifier_interval: int = 180  # 3 minutes
    agent_verifier_max_per_cycle: int = 3
    agent_verifier_use_claude: bool = True
    agent_verifier_fail_action: str = "reset"  # "mark" or "reset"

    # TestAgent (P1)
    agent_test_enabled: bool = False
    agent_test_interval: int = 300  # 5 minutes
    agent_test_fail_action: str = "reset"  # "mark" or "reset"
    agent_test_full_suite_every: int = 6  # run full suite every Nth cycle
    agent_test_timeout: int = 300

    # LintAgent (P1)
    agent_lint_enabled: bool = False
    agent_lint_interval: int = 600  # 10 minutes
    agent_lint_error_threshold: int = 50

    # IntegrationAgent (P2)
    agent_integration_enabled: bool = False
    agent_integration_interval: int = 900  # 15 minutes
    agent_integration_smoke_url: str = ""

    # SecurityAuditAgent (P2)
    agent_security_enabled: bool = False
    agent_security_interval: int = 1800  # 30 minutes
    agent_security_bandit_skip: str = ""

    @property
    def db_path(self) -> Path:
        """Extract the file path from the SQLite URL."""
        url = self.scheduler_db_url
        if url.startswith("sqlite+aiosqlite:///"):
            return Path(url.replace("sqlite+aiosqlite:///", ""))
        return Path("./data/scheduler.db")


settings = Settings()
