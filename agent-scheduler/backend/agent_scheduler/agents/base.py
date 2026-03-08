import asyncio
import datetime
import logging
from abc import ABC, abstractmethod

import anthropic
import httpx

from ..config import now, settings
from ..database import async_session
from ..models import AgentRun
from ..scheduler import sse_broadcaster

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all new lifecycle agents.

    Subclasses implement `run_cycle()` which returns a dict with:
      - summary: str
      - items_processed: int
      - items_found: int
      - output: str (optional extra detail)
    """

    NAME: str = "BaseAgent"
    DEFAULT_INTERVAL: int = 300
    DESCRIPTION: str = ""

    # Shared semaphore to prevent concurrent Claude API calls from agents
    _claude_semaphore = asyncio.Semaphore(1)
    _claude_client: anthropic.AsyncAnthropic | None = None

    def __init__(self):
        self._running = False
        self._task: asyncio.Task | None = None
        self._last_action: datetime.datetime | None = None
        self._action_count: int = 0
        self._interval: int = self.DEFAULT_INTERVAL
        self._current_run_id: int | None = None
        self._cycle_usage: dict = self._empty_usage()

    @property
    def status(self) -> str:
        return "running" if self._running else "stopped"

    def to_dict(self) -> dict:
        return {
            "name": self.NAME,
            "status": self.status,
            "interval_seconds": self._interval,
            "description": self.DESCRIPTION,
            "last_action": self._last_action.isoformat() if self._last_action else None,
            "action_count": self._action_count,
        }

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("%s started (interval=%ds)", self.NAME, self._interval)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("%s stopped", self.NAME)

    @staticmethod
    def _empty_usage() -> dict:
        return {"input_tokens": 0, "output_tokens": 0, "model": "", "api_calls": 0}

    async def trigger(self):
        """Manual one-shot execution."""
        logger.info("%s triggered manually", self.NAME)
        try:
            self._cycle_usage = self._empty_usage()
            run_id = await self._record_start()
            result = await self.run_cycle()
            await self._record_finish(run_id, "completed", result)
            self._last_action = now()
            self._action_count += 1
            return result
        except Exception:
            logger.exception("Error in %s manual trigger", self.NAME)
            if run_id:
                await self._record_finish(run_id, "failed", {
                    "summary": "Error during manual trigger",
                })
            raise

    async def _loop(self):
        while self._running:
            try:
                await asyncio.sleep(self._interval)
                self._cycle_usage = self._empty_usage()
                run_id = await self._record_start()
                try:
                    result = await self.run_cycle()
                    await self._record_finish(run_id, "completed", result)
                except Exception:
                    logger.exception("Error in %s cycle", self.NAME)
                    await self._record_finish(run_id, "failed", {
                        "summary": "Cycle error",
                    })
                self._last_action = now()
                self._action_count += 1
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in %s loop", self.NAME)
                await asyncio.sleep(30)

    async def _record_start(self) -> int:
        """Create an AgentRun row at cycle start. Returns the run id."""
        async with async_session() as session:
            agent_run = AgentRun(
                agent_name=self.NAME,
                status="running",
            )
            session.add(agent_run)
            await session.commit()
            await session.refresh(agent_run)
            return agent_run.id

    async def _record_finish(self, run_id: int, status: str, result: dict):
        """Update the AgentRun row at cycle end."""
        from ..executor import estimate_cost

        async with async_session() as session:
            agent_run = await session.get(AgentRun, run_id)
            if agent_run:
                agent_run.finished_at = now()
                agent_run.status = status
                agent_run.summary = result.get("summary", "")
                agent_run.output = result.get("output", "")
                agent_run.items_processed = result.get("items_processed", 0)
                agent_run.items_found = result.get("items_found", 0)
                # Token usage
                agent_run.input_tokens = self._cycle_usage["input_tokens"]
                agent_run.output_tokens = self._cycle_usage["output_tokens"]
                agent_run.model = self._cycle_usage["model"] or None
                agent_run.total_cost = estimate_cost(
                    agent_run.model,
                    agent_run.input_tokens,
                    agent_run.output_tokens,
                )
                await session.commit()

    @classmethod
    def _get_claude_client(cls) -> anthropic.AsyncAnthropic:
        """Lazy-init the shared async Anthropic client for agents."""
        if cls._claude_client is None:
            kwargs = {}
            if settings.anthropic_api_key:
                kwargs["api_key"] = settings.anthropic_api_key
            kwargs["timeout"] = httpx.Timeout(
                connect=30.0,
                read=600.0,
                write=30.0,
                pool=30.0,
            )
            cls._claude_client = anthropic.AsyncAnthropic(**kwargs)
        return cls._claude_client

    async def _call_claude(
        self,
        prompt: str,
        *,
        system: str | None = None,
        model: str | None = None,
        max_tokens: int = 4096,
        timeout: int = 120,
    ) -> tuple[int, str]:
        """Call Claude API with semaphore gating.

        Returns (exit_code, response_text) to match the pattern used by agents.
        exit_code is 0 on success, -1 on failure.
        Token usage is accumulated in self._cycle_usage for the current cycle.
        """
        # Check circuit breaker — skip Claude call if API is paused
        from ..executor import executor
        if executor.circuit_open:
            logger.info(
                "%s: skipping Claude call — circuit breaker open", self.NAME
            )
            return -1, ""

        client = self._get_claude_client()
        m = model or settings.claude_model

        try:
            kwargs: dict = {
                "model": m,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system:
                kwargs["system"] = system

            response = await asyncio.wait_for(
                client.messages.create(**kwargs),
                timeout=timeout,
            )

            # Accumulate token usage for this cycle
            self._cycle_usage["input_tokens"] += response.usage.input_tokens
            self._cycle_usage["output_tokens"] += response.usage.output_tokens
            self._cycle_usage["model"] = m
            self._cycle_usage["api_calls"] += 1

            text_parts = []
            for block in response.content:
                if block.type == "text":
                    text_parts.append(block.text)
            return 0, "\n".join(text_parts)

        except asyncio.TimeoutError:
            logger.warning("Claude API call timed out after %ds", timeout)
            return -1, ""
        except anthropic.BadRequestError as e:
            error_body = str(e).lower()
            if "credit" in error_body or "balance" in error_body or "budget" in error_body:
                logger.warning("%s: budget exhausted, tripping circuit breaker", self.NAME)
                executor._trip_circuit(f"budget exhausted (via {self.NAME})")
            else:
                logger.warning("Claude API BadRequestError: %s", e)
            return -1, ""
        except anthropic.APIError as e:
            logger.warning("Claude API error: %s", e)
            return -1, ""
        except Exception as e:
            logger.exception("Unexpected error calling Claude API: %s", e)
            return -1, ""

    async def _run_subprocess(
        self, cmd: str, cwd: str | None = None, timeout: int = 120
    ) -> tuple[int, str, str]:
        """Run a shell command with timeout. Returns (returncode, stdout, stderr)."""
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return -1, "", f"Command timed out after {timeout}s"

            return (
                proc.returncode or 0,
                stdout.decode(errors="replace"),
                stderr.decode(errors="replace"),
            )
        except Exception as e:
            return -1, "", str(e)

    @abstractmethod
    async def run_cycle(self) -> dict:
        """Execute one cycle of the agent's work.

        Returns a dict with at least:
          - summary: str
          - items_processed: int
          - items_found: int
        """
        ...
