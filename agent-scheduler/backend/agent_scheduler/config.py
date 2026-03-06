import datetime
import os
from pathlib import Path
from zoneinfo import ZoneInfo

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.environ.get("ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Project identity
    project_name: str = ""
    project_root: str = ""

    # Database
    scheduler_db_url: str = "sqlite+aiosqlite:///./data/scheduler.db"

    # Server
    scheduler_host: str = "0.0.0.0"
    scheduler_port: int = 13002
    frontend_port: int = 13001  # for CORS origins

    # Scheduler
    scheduler_timezone: str = "UTC"
    scheduler_max_concurrent: int = 2
    scheduler_spawn_delay: int = 3  # seconds between spawns
    scheduler_task_timeout: int = 1800  # 30 minutes
    scheduler_retry_max: int = 5
    scheduler_retry_backoff: int = 60  # base backoff in seconds
    scheduler_auto_start: bool = True
    scheduler_quality_retry_max: int = 3  # max quality-failure retries
    scheduler_max_total_runs: int = 20  # hard cap on total runs per task
    scheduler_test_command: str = ""  # empty = disabled
    scheduler_test_timeout: int = 300  # 5 minutes

    # GitHub
    github_repo_url: str = ""

    # Claude API
    anthropic_api_key: str = ""
    claude_model: str = "claude-sonnet-4-20250514"
    claude_max_tokens: int = 16384
    max_tool_iterations: int = 75

    # Auth
    auth_password: str = ""  # Empty = auth disabled

    # Auto-split
    scheduler_auto_split_enabled: bool = True
    scheduler_max_target_files: int = 2

    # --- New Agent Settings ---

    # TaskCreatorAgent (P0)
    agent_task_creator_enabled: bool = True
    agent_task_creator_interval: int = 300  # 5 minutes
    agent_task_creator_max_tasks_per_cycle: int = 20
    agent_task_creator_use_claude: bool = True
    agent_task_creator_quality_sample_size: int = 3  # files per quality scan cycle
    agent_task_creator_yaml_dir: str = "tasks"  # YAML task directory (relative to project_root)
    # Markdown docs scanned for task discovery (relative to project_root)
    agent_task_creator_checklist_path: str = "docs/FEATURE-CHECKLIST.md"
    agent_task_creator_plan_path: str = "docs/IMPLEMENTATION-PLAN.md"
    agent_task_creator_api_spec_path: str = "docs/API-SPECIFICATION.md"
    agent_task_creator_security_doc_path: str = "docs/SECURITY-IMPLEMENTATION.md"

    # VerifierAgent (P0)
    agent_verifier_enabled: bool = True
    agent_verifier_interval: int = 180  # 3 minutes
    agent_verifier_max_per_cycle: int = 3
    agent_verifier_use_claude: bool = False
    agent_verifier_fail_action: str = "reset"  # "mark" or "reset"

    # TestAgent (P1)
    agent_test_enabled: bool = True
    agent_test_interval: int = 300  # 5 minutes
    agent_test_fail_action: str = "reset"  # "mark" or "reset"
    agent_test_full_suite_every: int = 6  # run full suite every Nth cycle
    agent_test_timeout: int = 300

    # LintAgent (P1)
    agent_lint_enabled: bool = True
    agent_lint_interval: int = 600  # 10 minutes
    agent_lint_error_threshold: int = 50

    # IntegrationAgent (P2)
    agent_integration_enabled: bool = True
    agent_integration_interval: int = 900  # 15 minutes
    agent_integration_smoke_url: str = ""

    # SecurityAuditAgent (P2)
    agent_security_enabled: bool = True
    agent_security_interval: int = 1800  # 30 minutes
    agent_security_bandit_skip: str = ""

    @property
    def db_path(self) -> Path:
        """Extract the file path from the SQLite URL."""
        url = self.scheduler_db_url
        if url.startswith("sqlite+aiosqlite:///"):
            return Path(url.replace("sqlite+aiosqlite:///", ""))
        return Path("./data/scheduler.db")

    @property
    def tz(self) -> ZoneInfo:
        """Return the configured timezone as a ZoneInfo object."""
        return ZoneInfo(self.scheduler_timezone)


settings = Settings()


def now() -> datetime.datetime:
    """Return the current timezone-aware datetime in the configured timezone."""
    return datetime.datetime.now(settings.tz)
