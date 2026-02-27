import asyncio
import logging
import time
from dataclasses import dataclass, field

import anthropic

from .config import settings
from .context import build_api_messages

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    pid: int | None
    duration_seconds: float
    timed_out: bool = False
    usage: dict = field(default_factory=dict)


class Executor:
    def __init__(self):
        self._semaphore = asyncio.Semaphore(settings.scheduler_max_concurrent)
        self._last_spawn_time: float = 0
        self._spawn_lock = asyncio.Lock()
        self._running_tasks: dict[int, asyncio.Task] = {}
        self._client: anthropic.AsyncAnthropic | None = None

    def _get_client(self) -> anthropic.AsyncAnthropic:
        """Lazy-init the async Anthropic client."""
        if self._client is None:
            kwargs = {}
            if settings.anthropic_api_key:
                kwargs["api_key"] = settings.anthropic_api_key
            # Falls back to ANTHROPIC_API_KEY env var if not set in config
            self._client = anthropic.AsyncAnthropic(**kwargs)
        return self._client

    async def _wait_for_rate_limit(self):
        """Enforce minimum delay between spawns."""
        async with self._spawn_lock:
            now = time.monotonic()
            elapsed = now - self._last_spawn_time
            if elapsed < settings.scheduler_spawn_delay:
                wait_time = settings.scheduler_spawn_delay - elapsed
                logger.info(f"Rate limiting: waiting {wait_time:.1f}s before next API call")
                await asyncio.sleep(wait_time)
            self._last_spawn_time = time.monotonic()

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
        """Execute a Claude API call with semaphore gating and rate limiting."""
        async with self._semaphore:
            await self._wait_for_rate_limit()

            system_prompt, user_message = build_api_messages(
                prompt, task_id, attempt, max_retries,
            )
            m = model or settings.claude_model

            logger.info(
                f"Calling Claude API for task {task_db_id} "
                f"(model={m}, max_tokens={settings.claude_max_tokens})"
            )
            start_time = time.monotonic()

            # Wrap the API call in an asyncio.Task so we can cancel it
            api_coro = self._call_api(system_prompt, user_message, m)
            task = asyncio.ensure_future(api_coro)

            if task_db_id is not None:
                self._running_tasks[task_db_id] = task

            try:
                try:
                    result_text, usage_info = await asyncio.wait_for(
                        task,
                        timeout=settings.scheduler_task_timeout,
                    )
                    duration = time.monotonic() - start_time
                    logger.info(
                        f"Task {task_db_id} API call finished: "
                        f"duration={duration:.1f}s, "
                        f"tokens={usage_info}"
                    )
                    return ExecutionResult(
                        exit_code=0,
                        stdout=result_text,
                        stderr="",
                        pid=None,
                        duration_seconds=duration,
                        usage=usage_info,
                    )

                except asyncio.TimeoutError:
                    duration = time.monotonic() - start_time
                    logger.warning(f"Task {task_db_id} timed out after {duration:.1f}s")
                    task.cancel()
                    return ExecutionResult(
                        exit_code=-1,
                        stdout="",
                        stderr=f"API call timed out after {settings.scheduler_task_timeout}s",
                        pid=None,
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
                    self._running_tasks.pop(task_db_id, None)

    async def _call_api(
        self, system_prompt: str, user_message: str, model: str
    ) -> tuple[str, dict]:
        """Make the actual Anthropic API call. Returns (response_text, usage_dict)."""
        client = self._get_client()
        response = await client.messages.create(
            model=model,
            max_tokens=settings.claude_max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )

        # Extract text from content blocks
        text_parts = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)

        result_text = "\n".join(text_parts)
        usage_info = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }
        return result_text, usage_info

    async def cancel(self, task_db_id: int) -> bool:
        """Cancel a running API call by task DB ID."""
        task = self._running_tasks.get(task_db_id)
        if task is None:
            return False
        task.cancel()
        return True

    @property
    def running_count(self) -> int:
        return len(self._running_tasks)


# Module-level singleton
executor = Executor()
