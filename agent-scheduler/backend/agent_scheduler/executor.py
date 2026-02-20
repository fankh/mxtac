import asyncio
import logging
import os
import time
from dataclasses import dataclass

from .config import settings
from .context import build_prompt

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    pid: int | None
    duration_seconds: float
    timed_out: bool = False


class Executor:
    def __init__(self):
        self._semaphore = asyncio.Semaphore(settings.scheduler_max_concurrent)
        self._last_spawn_time: float = 0
        self._spawn_lock = asyncio.Lock()
        self._running_processes: dict[int, asyncio.subprocess.Process] = {}

    async def _wait_for_rate_limit(self):
        """Enforce minimum delay between spawns."""
        async with self._spawn_lock:
            now = time.monotonic()
            elapsed = now - self._last_spawn_time
            if elapsed < settings.scheduler_spawn_delay:
                wait_time = settings.scheduler_spawn_delay - elapsed
                logger.info(f"Rate limiting: waiting {wait_time:.1f}s before next spawn")
                await asyncio.sleep(wait_time)
            self._last_spawn_time = time.monotonic()

    def _build_env(self) -> dict[str, str]:
        """Build clean environment for subprocess, removing nesting guard vars."""
        env = os.environ.copy()
        # Remove Claude Code nesting guard environment variables
        env.pop("CLAUDECODE", None)
        env.pop("CLAUDE_CODE_SESSION", None)
        env.pop("CLAUDE_CODE_ENTRYPOINT", None)
        return env

    def _build_command(self, prompt: str, model: str | None = None) -> list[str]:
        """Build the claude CLI command."""
        m = model or settings.claude_model
        return [
            settings.claude_cli_path,
            "--print",
            "--model", m,
            "--output-format", "text",
            "--dangerously-skip-permissions",
            prompt,
        ]

    async def execute(
        self,
        prompt: str,
        working_directory: str | None = None,
        model: str | None = None,
        task_db_id: int | None = None,
        task_id: str = "",
        attempt: int = 1,
        max_retries: int = 3,
    ) -> ExecutionResult:
        """Execute a Claude CLI command with semaphore gating and rate limiting."""
        async with self._semaphore:
            await self._wait_for_rate_limit()

            full_prompt = build_prompt(prompt, task_id, attempt, max_retries)
            cmd = self._build_command(full_prompt, model)
            env = self._build_env()
            cwd = working_directory or settings.mxtac_project_root

            logger.info(f"Spawning Claude CLI for task {task_db_id} in {cwd}")
            start_time = time.monotonic()

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    env=env,
                )

                pid = process.pid
                if task_db_id is not None:
                    self._running_processes[task_db_id] = process

                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        process.communicate(),
                        timeout=settings.scheduler_task_timeout,
                    )
                    duration = time.monotonic() - start_time
                    stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
                    stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

                    return ExecutionResult(
                        exit_code=process.returncode or 0,
                        stdout=stdout,
                        stderr=stderr,
                        pid=pid,
                        duration_seconds=duration,
                    )

                except asyncio.TimeoutError:
                    duration = time.monotonic() - start_time
                    logger.warning(f"Task {task_db_id} timed out after {duration:.1f}s")
                    process.kill()
                    await process.wait()
                    return ExecutionResult(
                        exit_code=-1,
                        stdout="",
                        stderr=f"Process timed out after {settings.scheduler_task_timeout}s",
                        pid=pid,
                        duration_seconds=duration,
                        timed_out=True,
                    )

            except Exception as e:
                duration = time.monotonic() - start_time
                logger.exception(f"Failed to execute task {task_db_id}: {e}")
                return ExecutionResult(
                    exit_code=-1,
                    stdout="",
                    stderr=str(e),
                    pid=None,
                    duration_seconds=duration,
                )
            finally:
                if task_db_id is not None:
                    self._running_processes.pop(task_db_id, None)

    async def cancel(self, task_db_id: int) -> bool:
        """Cancel a running process by task DB ID."""
        process = self._running_processes.get(task_db_id)
        if process is None:
            return False
        try:
            process.kill()
            await process.wait()
            return True
        except ProcessLookupError:
            return False

    @property
    def running_count(self) -> int:
        return len(self._running_processes)


# Module-level singleton
executor = Executor()
