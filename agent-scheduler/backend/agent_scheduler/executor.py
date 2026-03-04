import asyncio
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import anthropic
import httpx

from .config import settings
from .context import build_api_messages

__all__ = ["Executor", "ExecutionResult", "BudgetExhaustedError", "executor"]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool definitions for the Claude Messages API
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS = [
    {
        "name": "read_file",
        "description": "Read the contents of a file. Returns the file content as text. Use this to inspect existing code before making changes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file to read.",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Create or overwrite a file with the given content. Parent directories are created automatically.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file to write.",
                },
                "content": {
                    "type": "string",
                    "description": "The full content to write to the file.",
                },
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "list_directory",
        "description": "List the contents of a directory. Returns file and subdirectory names.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the directory to list. Defaults to working directory if omitted.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "run_command",
        "description": "Execute a shell command and return its stdout, stderr, and exit code. Use for running tests, builds, git commands, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute.",
                },
            },
            "required": ["command"],
        },
    },
]


# ---------------------------------------------------------------------------
# Path security
# ---------------------------------------------------------------------------

def _resolve_safe_path(path_str: str, working_directory: str) -> Path:
    """Resolve a path against working_directory, rejecting traversal outside it."""
    wd = Path(working_directory).resolve()
    # Handle absolute paths — still must be under working_directory
    candidate = Path(path_str)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (wd / candidate).resolve()

    # Security: ensure the resolved path is within the working directory
    if not (resolved == wd or str(resolved).startswith(str(wd) + os.sep)):
        raise ValueError(
            f"Path '{path_str}' resolves to '{resolved}' which is outside "
            f"the working directory '{wd}'"
        )
    return resolved


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

def _execute_tool(name: str, tool_input: dict, working_directory: str) -> str:
    """Execute a single tool call synchronously. Returns the result string."""
    try:
        if name == "read_file":
            path = _resolve_safe_path(tool_input["path"], working_directory)
            if not path.exists():
                return f"Error: File not found: {path}"
            if not path.is_file():
                return f"Error: Not a file: {path}"
            content = path.read_text(encoding="utf-8", errors="replace")
            # Truncate very large files
            if len(content) > 100_000:
                content = content[:100_000] + "\n\n... [truncated at 100K chars]"
            return content

        elif name == "write_file":
            path = _resolve_safe_path(tool_input["path"], working_directory)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(tool_input["content"], encoding="utf-8")
            return f"Successfully wrote {len(tool_input['content'])} chars to {path}"

        elif name == "list_directory":
            dir_path_str = tool_input.get("path", ".")
            dir_path = _resolve_safe_path(dir_path_str, working_directory)
            if not dir_path.exists():
                return f"Error: Directory not found: {dir_path}"
            if not dir_path.is_dir():
                return f"Error: Not a directory: {dir_path}"
            entries = sorted(dir_path.iterdir())
            lines = []
            for entry in entries[:500]:  # Cap at 500 entries
                suffix = "/" if entry.is_dir() else ""
                lines.append(f"{entry.name}{suffix}")
            result = "\n".join(lines)
            if len(entries) > 500:
                result += f"\n... and {len(entries) - 500} more entries"
            return result

        elif name == "run_command":
            result = subprocess.run(
                tool_input["command"],
                shell=True,
                cwd=working_directory,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output_parts = []
            if result.stdout:
                output_parts.append(f"stdout:\n{result.stdout}")
            if result.stderr:
                output_parts.append(f"stderr:\n{result.stderr}")
            output_parts.append(f"exit_code: {result.returncode}")
            output = "\n".join(output_parts)
            # Truncate if too large
            if len(output) > 100_000:
                output = output[:100_000] + "\n\n... [truncated at 100K chars]"
            return output

        else:
            return f"Error: Unknown tool '{name}'"

    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 300 seconds"
    except ValueError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error executing {name}: {type(e).__name__}: {e}"


class BudgetExhaustedError(Exception):
    """Raised when the API returns a credit/budget exhaustion error."""
    pass


class MaxIterationsExceeded(Exception):
    """Raised when the agentic loop exceeds max_tool_iterations."""
    def __init__(self, message: str, usage: dict):
        super().__init__(message)
        self.usage = usage


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
    CIRCUIT_COOLDOWN = 300  # 5 minutes pause after budget error

    def __init__(self):
        self._semaphore = asyncio.Semaphore(settings.scheduler_max_concurrent)
        self._last_spawn_time: float = 0
        self._spawn_lock = asyncio.Lock()
        self._running_tasks: dict[int, asyncio.Task] = {}
        self._client: anthropic.AsyncAnthropic | None = None
        # Circuit breaker state
        self._circuit_open: bool = False
        self._circuit_open_until: float = 0

    def _get_client(self) -> anthropic.AsyncAnthropic:
        """Lazy-init the async Anthropic client with HTTP-level timeouts."""
        if self._client is None:
            kwargs = {}
            if settings.anthropic_api_key:
                kwargs["api_key"] = settings.anthropic_api_key
            # HTTP-level timeout ensures the connection is forcibly closed
            # even if asyncio task cancellation is not honored by the SDK.
            # connect=30s, read=600s (10min per chunk), write=30s, pool=30s
            kwargs["timeout"] = httpx.Timeout(
                connect=30.0,
                read=600.0,
                write=30.0,
                pool=30.0,
            )
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

    def _check_circuit(self) -> bool:
        """Return True if circuit is open (API calls should be blocked)."""
        if not self._circuit_open:
            return False
        if time.monotonic() >= self._circuit_open_until:
            self._circuit_open = False
            logger.info("Circuit breaker RESET — resuming API calls")
            return False
        return True

    def _trip_circuit(self, reason: str = "budget exhausted"):
        """Trip the circuit breaker, blocking API calls for CIRCUIT_COOLDOWN seconds."""
        self._circuit_open = True
        self._circuit_open_until = time.monotonic() + self.CIRCUIT_COOLDOWN
        logger.critical(
            f"CIRCUIT BREAKER TRIPPED ({reason}) — "
            f"blocking API calls for {self.CIRCUIT_COOLDOWN}s"
        )

    @property
    def circuit_open(self) -> bool:
        """Public read-only check (auto-resets if cooldown expired)."""
        return self._check_circuit()  # side-effect: resets if expired

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
        """Execute a Claude API call with tool-use loop, semaphore gating, and rate limiting."""
        # Circuit breaker check — return immediately if API is paused
        if self._check_circuit():
            remaining = self._circuit_open_until - time.monotonic()
            logger.info(
                f"Task {task_db_id} blocked by circuit breaker "
                f"({remaining:.0f}s remaining)"
            )
            return ExecutionResult(
                exit_code=-2,
                stdout="",
                stderr=f"Circuit breaker open — API paused for {remaining:.0f}s",
                pid=None,
                duration_seconds=0,
            )

        async with self._semaphore:
            # Re-check circuit after waiting for semaphore — another task
            # may have tripped it while we were queued
            if self._check_circuit():
                remaining = self._circuit_open_until - time.monotonic()
                logger.info(
                    f"Task {task_db_id} blocked by circuit breaker "
                    f"(after semaphore, {remaining:.0f}s remaining)"
                )
                return ExecutionResult(
                    exit_code=-2,
                    stdout="",
                    stderr=f"Circuit breaker open — API paused for {remaining:.0f}s",
                    pid=None,
                    duration_seconds=0,
                )

            await self._wait_for_rate_limit()

            # Final circuit check right before API call — catches tasks
            # that were waiting on the rate limiter when circuit tripped
            if self._check_circuit():
                remaining = self._circuit_open_until - time.monotonic()
                logger.info(
                    f"Task {task_db_id} blocked by circuit breaker "
                    f"(pre-call, {remaining:.0f}s remaining)"
                )
                return ExecutionResult(
                    exit_code=-2,
                    stdout="",
                    stderr=f"Circuit breaker open — API paused for {remaining:.0f}s",
                    pid=None,
                    duration_seconds=0,
                )

            # Resolve working directory
            wd = working_directory or settings.project_root

            system_prompt, user_message = build_api_messages(
                prompt, task_id, attempt, max_retries,
            )
            m = model or settings.claude_model

            logger.info(
                f"Calling Claude API for task {task_db_id} "
                f"(model={m}, max_tokens={settings.claude_max_tokens}, "
                f"working_dir={wd})"
            )
            start_time = time.monotonic()

            # Wrap the agentic loop in an asyncio.Task so we can cancel it
            api_coro = self._call_api_with_tools(system_prompt, user_message, m, wd, task_db_id)
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

            except BudgetExhaustedError as e:
                duration = time.monotonic() - start_time
                self._trip_circuit(str(e))
                return ExecutionResult(
                    exit_code=-2,
                    stdout="",
                    stderr=str(e),
                    pid=None,
                    duration_seconds=duration,
                )

            except MaxIterationsExceeded as e:
                duration = time.monotonic() - start_time
                logger.warning(f"Task {task_db_id}: {e}")
                return ExecutionResult(
                    exit_code=-1,
                    stdout="",
                    stderr=str(e),
                    pid=None,
                    duration_seconds=duration,
                    usage=e.usage,
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

    async def _call_api_with_tools(
        self,
        system_prompt: str,
        user_message: str,
        model: str,
        working_directory: str,
        task_db_id: int | None = None,
    ) -> tuple[str, dict]:
        """Agentic tool-use loop. Calls Claude, executes tools, repeats until done."""
        client = self._get_client()
        messages = [{"role": "user", "content": user_message}]

        total_input_tokens = 0
        total_output_tokens = 0
        iteration = 0
        max_iterations = settings.max_tool_iterations

        while True:
            iteration += 1
            if iteration > max_iterations:
                logger.warning(
                    f"Task {task_db_id}: max tool iterations ({max_iterations}) exceeded"
                )
                raise MaxIterationsExceeded(
                    f"Max tool iterations ({max_iterations}) exceeded. Task may be incomplete.",
                    usage={
                        "input_tokens": total_input_tokens,
                        "output_tokens": total_output_tokens,
                        "tool_iterations": iteration - 1,
                    },
                )

            try:
                response = await client.messages.create(
                    model=model,
                    max_tokens=settings.claude_max_tokens,
                    system=system_prompt,
                    messages=messages,
                    tools=TOOL_DEFINITIONS,
                )
            except anthropic.BadRequestError as e:
                error_body = str(e)
                logger.warning(
                    f"Task {task_db_id} iter {iteration}: "
                    f"API BadRequestError: {error_body[:300]}"
                )
                # Budget / credit exhaustion — unrecoverable, trip circuit
                if "credit" in error_body.lower() or "balance" in error_body.lower() or "budget" in error_body.lower():
                    raise BudgetExhaustedError(f"API budget exhausted: {error_body[:200]}")
                if "content filtering" in error_body.lower():
                    # Content filter blocked the output — tell Claude to rephrase
                    messages.append({
                        "role": "user",
                        "content": (
                            "Your previous response was blocked by the API content "
                            "filtering policy. This often happens when generating "
                            "full license texts, security policies, or similar "
                            "boilerplate. Please try a different approach:\n"
                            "- For LICENSE files, use run_command to download the "
                            "license text (e.g., curl from a trusted source) or "
                            "write a brief placeholder pointing to the full text.\n"
                            "- For SECURITY.md, keep the content concise and "
                            "avoid detailed vulnerability exploitation steps.\n"
                            "- Break large file writes into smaller chunks if needed.\n"
                            "Please continue with the task."
                        ),
                    })
                    continue
                raise
            except anthropic.RateLimitError:
                logger.warning(
                    f"Task {task_db_id} iter {iteration}: rate-limited (429), "
                    f"sleeping 60s then retrying"
                )
                await asyncio.sleep(60)
                continue
            except anthropic.InternalServerError:
                logger.warning(
                    f"Task {task_db_id} iter {iteration}: server overload (5xx), "
                    f"sleeping 30s then retrying"
                )
                await asyncio.sleep(30)
                continue

            total_input_tokens += response.usage.input_tokens
            total_output_tokens += response.usage.output_tokens

            # Append the assistant response to the conversation
            messages.append({"role": "assistant", "content": response.content})

            # If the model stopped for a reason other than tool_use, we're done
            if response.stop_reason != "tool_use":
                # Extract final text
                text_parts = []
                for block in response.content:
                    if block.type == "text":
                        text_parts.append(block.text)
                result_text = "\n".join(text_parts)
                usage_info = {
                    "input_tokens": total_input_tokens,
                    "output_tokens": total_output_tokens,
                    "tool_iterations": iteration,
                }
                return result_text, usage_info

            # Process tool calls
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input
                    tool_use_id = block.id

                    logger.info(
                        f"Task {task_db_id} iter {iteration}: "
                        f"tool={tool_name}, input_keys={list(tool_input.keys())}"
                    )

                    # Execute tool on disk (synchronous — runs in thread pool)
                    result_str = await asyncio.get_event_loop().run_in_executor(
                        None, _execute_tool, tool_name, tool_input, working_directory
                    )

                    is_error = result_str.startswith("Error:")
                    if is_error:
                        logger.warning(
                            f"Task {task_db_id} iter {iteration}: "
                            f"tool {tool_name} error: {result_str[:200]}"
                        )

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": result_str,
                        "is_error": is_error,
                    })

            # Append tool results as the next user message
            messages.append({"role": "user", "content": tool_results})

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
