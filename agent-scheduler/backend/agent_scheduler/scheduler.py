import asyncio
import datetime
import json
import logging
import re

from sqlalchemy import func as sa_func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .config import now, settings
from .database import async_session
from .executor import ExecutionResult, estimate_cost, executor
from .models import Log, Run, RunStatus, Task, TaskStatus

logger = logging.getLogger(__name__)

# Priority mapping for string values (from Claude-generated tasks)
_PRIORITY_MAP = {"critical": 10, "high": 7, "medium": 5, "low": 3}


def _safe_priority(val) -> int:
    """Convert priority to int, handling None, strings like 'high', and garbage."""
    if val is None:
        return 0
    if isinstance(val, int):
        return val
    try:
        return int(val)
    except (ValueError, TypeError):
        return _PRIORITY_MAP.get(str(val).lower(), 0)


class SSEBroadcaster:
    """Simple broadcaster for Server-Sent Events."""

    def __init__(self):
        self._queues: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._queues.remove(q)

    async def broadcast(self, event: str, data: dict):
        msg = {"event": event, "data": data}
        dead: list[asyncio.Queue] = []
        for q in self._queues:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
            except Exception:
                dead.append(q)
        for q in dead:
            try:
                self._queues.remove(q)
            except ValueError:
                pass


sse_broadcaster = SSEBroadcaster()


class Scheduler:
    def __init__(self):
        self._running = False
        self._paused = False
        self._task: asyncio.Task | None = None
        self._last_action: datetime.datetime | None = None
        self._action_count: int = 0
        self._wake_event: asyncio.Event = asyncio.Event()

    def notify(self):
        """Wake the scheduler loop immediately for event-driven dispatch."""
        self._wake_event.set()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def status(self) -> str:
        if not self._running:
            return "stopped"
        if self._paused:
            return "paused"
        return "running"

    def to_dict(self) -> dict:
        return {
            "name": "Scheduler",
            "status": self.status,
            "interval_seconds": 5,
            "description": "Dispatches eligible tasks based on dependencies and priority",
            "last_action": self._last_action.isoformat() if self._last_action else None,
            "action_count": self._action_count,
        }

    async def start(self):
        if self._running:
            return
        # Recover orphaned tasks from previous crash
        await self._recover_orphaned_tasks()
        self._running = True
        self._paused = False
        self._task = asyncio.create_task(self._loop())
        logger.info("Scheduler started")
        await sse_broadcaster.broadcast("scheduler", {"status": "running"})

    async def _recover_orphaned_tasks(self):
        """Reset tasks and runs stuck in RUNNING state from a previous process."""
        async with async_session() as session:
            # Recover orphaned tasks
            result = await session.execute(
                select(Task).where(Task.status == TaskStatus.RUNNING)
            )
            orphaned = result.scalars().all()
            if orphaned:
                for task in orphaned:
                    task.status = TaskStatus.PENDING
                logger.info(f"Recovered {len(orphaned)} orphaned tasks back to PENDING")

            # Cancel orphaned running runs
            run_result = await session.execute(
                select(Run).where(Run.status == RunStatus.RUNNING)
            )
            orphaned_runs = run_result.scalars().all()
            if orphaned_runs:
                for run in orphaned_runs:
                    run.status = RunStatus.CANCELLED
                    run.finished_at = now()
                logger.info(f"Cancelled {len(orphaned_runs)} orphaned runs")

            await session.commit()

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Scheduler stopped")
        await sse_broadcaster.broadcast("scheduler", {"status": "stopped"})

    async def pause(self):
        self._paused = True
        logger.info("Scheduler paused")
        await sse_broadcaster.broadcast("scheduler", {"status": "paused"})

    async def resume(self):
        self._paused = False
        logger.info("Scheduler resumed")
        await sse_broadcaster.broadcast("scheduler", {"status": "running"})
        self.notify()

    async def _loop(self):
        """Main scheduler loop — event-driven with 5s fallback poll."""
        while self._running:
            try:
                if not self._paused:
                    await self._dispatch_eligible_tasks()
                self._last_action = now()
                self._action_count += 1
                # Wait for wake event or timeout after 5s (fallback poll)
                try:
                    await asyncio.wait_for(self._wake_event.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass
                self._wake_event.clear()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in scheduler loop")
                await asyncio.sleep(5)

    async def _dispatch_eligible_tasks(self):
        """Find and dispatch tasks that are ready to run."""
        # Don't dispatch anything while circuit breaker is open
        if executor._check_circuit():
            logger.info("Dispatch skipped: circuit breaker open")
            return

        async with async_session() as session:
            # Query 1: Only PENDING tasks (candidates)
            result = await session.execute(
                select(Task).where(Task.status == TaskStatus.PENDING)
            )
            pending_tasks = result.scalars().all()

            if not pending_tasks:
                return

            # Query 2: Terminal-status tasks for dependency checking
            # NOTE: FAILED is intentionally excluded — a failed dependency
            # should NOT unblock downstream tasks (they would just fail too)
            dep_result = await session.execute(
                select(Task.task_id, Task.status).where(
                    Task.status.in_([TaskStatus.COMPLETED, TaskStatus.SKIPPED, TaskStatus.SPLIT])
                )
            )
            status_map = {row.task_id: row.status for row in dep_result}

            # Find eligible tasks
            eligible = []
            for task in pending_tasks:
                # Check retry backoff
                if task.retry_count > 0:
                    backoff = settings.scheduler_retry_backoff * (2 ** (task.retry_count - 1))
                    if task.updated_at:
                        updated = task.updated_at if task.updated_at.tzinfo else task.updated_at.replace(tzinfo=settings.tz)
                        elapsed = (now() - updated).total_seconds()
                        if elapsed < backoff:
                            continue

                # Check dependencies
                deps = task.depends_on_list
                if deps:
                    all_met = all(
                        status_map.get(dep) in (TaskStatus.COMPLETED, TaskStatus.SKIPPED, TaskStatus.SPLIT)
                        for dep in deps
                    )
                    if not all_met:
                        continue

                eligible.append(task)

            # Sort by priority (higher first) then by id
            eligible.sort(key=lambda t: (-_safe_priority(t.priority), t.id))

            # Count RUNNING tasks from DB (not executor) to avoid race condition
            # where tasks are RUNNING in DB but waiting on the executor semaphore
            running_count_result = await session.execute(
                select(sa_func.count(Task.id)).where(Task.status == TaskStatus.RUNNING)
            )
            current_running = running_count_result.scalar() or 0

            # Auto-skip failed blockers when pipeline is stalled
            if not eligible and current_running == 0 and pending_tasks:
                failed_result = await session.execute(
                    select(Task).where(Task.status == TaskStatus.FAILED)
                )
                failed_tasks = failed_result.scalars().all()
                # Build set of task_ids that pending tasks depend on
                needed_deps: set[str] = set()
                for t in pending_tasks:
                    for dep in t.depends_on_list:
                        if dep not in status_map:
                            needed_deps.add(dep)
                # Skip failed tasks that are blocking pending ones
                skipped_ids = []
                for ft in failed_tasks:
                    if ft.task_id in needed_deps:
                        ft.status = TaskStatus.SKIPPED
                        ft.failure_reason = (ft.failure_reason or "") + " [auto-skipped: unblocking stalled pipeline]"
                        skipped_ids.append(ft.task_id)
                        status_map[ft.task_id] = TaskStatus.SKIPPED
                if skipped_ids:
                    await session.commit()
                    logger.warning(
                        "Pipeline stalled: auto-skipped %d failed blocker(s): %s",
                        len(skipped_ids), ", ".join(skipped_ids),
                    )
                    for sid in skipped_ids:
                        await sse_broadcaster.broadcast("task_update", {"task_id": sid, "status": "SKIPPED"})
                    # Re-evaluate eligible tasks with updated status_map
                    eligible = []
                    for task in pending_tasks:
                        if task.retry_count > 0:
                            backoff = settings.scheduler_retry_backoff * (2 ** (task.retry_count - 1))
                            if task.updated_at:
                                updated = task.updated_at if task.updated_at.tzinfo else task.updated_at.replace(tzinfo=settings.tz)
                                elapsed = (now() - updated).total_seconds()
                                if elapsed < backoff:
                                    continue
                        deps = task.depends_on_list
                        if deps:
                            all_met = all(
                                status_map.get(dep) in (TaskStatus.COMPLETED, TaskStatus.SKIPPED, TaskStatus.SPLIT)
                                for dep in deps
                            )
                            if not all_met:
                                continue
                        eligible.append(task)
                    eligible.sort(key=lambda t: (-_safe_priority(t.priority), t.id))

            # Dispatch tasks up to max_concurrent limit
            # Mark tasks as RUNNING in DB BEFORE spawning to prevent race conditions
            dispatched = 0
            dispatch_ids = []
            for task in eligible:
                if current_running + dispatched >= settings.scheduler_max_concurrent:
                    break
                task.status = TaskStatus.RUNNING
                dispatched += 1
                dispatch_ids.append(task.id)

            if dispatched > 0:
                await session.commit()
                logger.info(
                    f"Dispatched {dispatched}/{len(eligible)} eligible tasks "
                    f"(running={current_running})"
                )
                # Spawn async tasks AFTER committing status change
                for task_id in dispatch_ids:
                    asyncio.create_task(self._run_task(task_id))

    async def _run_task(self, task_db_id: int):
        """Wrapper that catches crashes and resets ghost tasks to PENDING."""
        try:
            await self._run_task_inner(task_db_id)
        except Exception:
            logger.exception(f"Task {task_db_id} crashed, resetting to PENDING")
            try:
                async with async_session() as session:
                    task = await session.get(Task, task_db_id)
                    if task and task.status == TaskStatus.RUNNING:
                        task.status = TaskStatus.PENDING
                        await session.commit()
                        await sse_broadcaster.broadcast("task_update", task.to_dict())
            except Exception:
                logger.exception(f"Task {task_db_id} CRITICAL: failed to reset")

    async def _run_task_inner(self, task_db_id: int):
        """Execute a single task and record results."""
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task is None or task.status != TaskStatus.RUNNING:
                return

            # Hard cap: refuse to run if total runs already exceeded
            run_count_result = await session.execute(
                select(sa_func.count(Run.id)).where(Run.task_id == task_db_id)
            )
            total_runs = run_count_result.scalar() or 0
            if total_runs >= settings.scheduler_max_total_runs:
                task.status = TaskStatus.FAILED
                task.failure_reason = (
                    f"Hard cap: {total_runs} total runs reached "
                    f"(max_total_runs={settings.scheduler_max_total_runs})"
                )
                await session.commit()
                logger.warning(
                    f"Task {task_db_id} ({task.task_id}) hit max_total_runs "
                    f"({total_runs}/{settings.scheduler_max_total_runs}), marking FAILED"
                )
                await session.refresh(task)
                await sse_broadcaster.broadcast("task_update", task.to_dict())
                return

            # Create run + log start in a single commit (status already RUNNING from dispatch)
            run = Run(
                task_id=task.id,
                attempt=task.retry_count + 1,
                status=RunStatus.RUNNING,
            )
            session.add(run)
            await session.flush()  # generates run.id
            log = Log(run_id=run.id, level="INFO", message=f"Starting task: {task.title}")
            session.add(log)
            await session.commit()
            await session.refresh(task)
            logger.info(f"Task {task.id} ({task.task_id}) status -> RUNNING")
            await sse_broadcaster.broadcast("task_update", task.to_dict())
            await sse_broadcaster.broadcast("log", log.to_dict())

            # Save values before session closes
            task_str_id = task.task_id
            task_title = task.title
            task_prompt = task.prompt
            task_working_dir = task.working_directory
            task_model = task.model
            task_attempt = task.retry_count + 1
            task_max_retries = task.max_retries
            task_target_files = task.target_files_list

        # Execute outside the session
        result: ExecutionResult = await executor.execute(
            prompt=task_prompt,
            working_directory=task_working_dir or None,
            model=task_model,
            task_db_id=task_db_id,
            task_id=task_str_id,
            attempt=task_attempt,
            max_retries=task_max_retries,
            target_files=task_target_files,
        )
        logger.info(
            f"Task {task_db_id} result: exit_code={result.exit_code}, "
            f"pid={result.pid}, timed_out={result.timed_out}, "
            f"duration={result.duration_seconds:.1f}s"
        )

        # Budget exhaustion (exit_code=-2): don't count as attempt, reset to PENDING
        if result.exit_code == -2:
            async with async_session() as session:
                task = await session.get(Task, task_db_id)
                run_result = await session.execute(
                    select(Run).where(Run.task_id == task_db_id, Run.status == RunStatus.RUNNING)
                    .order_by(Run.id.desc()).limit(1)
                )
                run = run_result.scalar_one_or_none()
                if run:
                    run.exit_code = -2
                    run.stderr = result.stderr
                    run.duration_seconds = result.duration_seconds
                    run.finished_at = now()
                    run.status = RunStatus.CANCELLED
                    log = Log(run_id=run.id, level="WARNING", message="Budget exhausted — circuit breaker tripped")
                    session.add(log)
                if task:
                    # Do NOT increment retry_count — this is not a real failure
                    task.status = TaskStatus.PENDING
                    logger.info(f"Task {task_db_id} reset to PENDING (budget exhausted, not counted as attempt)")
                await session.commit()
                if task:
                    await session.refresh(task)
                    await sse_broadcaster.broadcast("task_update", task.to_dict())
                await sse_broadcaster.broadcast("circuit_breaker", {"open": True, "reason": "budget_exhausted"})
            # Do NOT notify — circuit is open, nothing useful to dispatch
            return

        # Auto-commit on success
        commit_sha = None
        if result.exit_code == 0 and not result.timed_out:
            commit_sha = await self._git_auto_commit(task_db_id, task_str_id, task_title, task_working_dir)

        # Record results
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            run_result = await session.execute(
                select(Run).where(Run.task_id == task_db_id, Run.status == RunStatus.RUNNING)
                .order_by(Run.id.desc()).limit(1)
            )
            run = run_result.scalar_one_or_none()
            if not run:
                logger.warning(f"No RUNNING run record found for task {task_db_id}")

            if run:
                run.exit_code = result.exit_code
                run.pid = result.pid
                run.stdout = result.stdout
                run.stderr = result.stderr
                run.duration_seconds = result.duration_seconds
                run.finished_at = now()
                # Persist token usage
                usage = result.usage or {}
                run.input_tokens = usage.get("input_tokens", 0)
                run.output_tokens = usage.get("output_tokens", 0)
                run.model = usage.get("model", "")
                run.total_cost = estimate_cost(
                    run.model, run.input_tokens, run.output_tokens
                )

                if result.timed_out:
                    run.status = RunStatus.TIMEOUT
                elif result.exit_code == 0:
                    run.status = RunStatus.COMPLETED
                else:
                    run.status = RunStatus.FAILED

                # Log completion
                log_msg = (
                    f"Task finished: exit_code={result.exit_code}, "
                    f"duration={result.duration_seconds:.1f}s"
                )
                if commit_sha:
                    log_msg += f", commit={commit_sha}"
                log = Log(run_id=run.id, level="INFO", message=log_msg)
                session.add(log)

            if task:
                if result.exit_code == 0 and not result.timed_out:
                    task.status = TaskStatus.COMPLETED
                    if commit_sha:
                        task.git_commit_sha = commit_sha
                else:
                    task.retry_count += 1

                    # Detect MaxIterationsExceeded for auto-split
                    stderr_text = result.stderr or ""
                    is_max_iterations = (
                        result.exit_code == -1
                        and "Max tool iterations" in stderr_text
                    )

                    # --- Circuit breaker: cost cap ---
                    task_cost = await self._get_task_total_cost(session, task.id)
                    cost_limit = settings.scheduler_task_cost_limit
                    cost_exceeded = cost_limit > 0 and task_cost >= cost_limit

                    # --- Circuit breaker: duplicate error detection ---
                    current_error = self._extract_error_signature(result)
                    is_duplicate_error = await self._is_duplicate_error(
                        session, task.id, current_error
                    )

                    should_stop = (
                        task.retry_count >= task.max_retries
                        or cost_exceeded
                        or is_duplicate_error
                    )

                    if should_stop:
                        # Build failure reason
                        if cost_exceeded:
                            stop_reason = (
                                f"Cost limit exceeded: ${task_cost:.2f} >= "
                                f"${cost_limit:.2f} after {task.retry_count} attempts"
                            )
                        elif is_duplicate_error:
                            stop_reason = (
                                f"Duplicate error detected after {task.retry_count} "
                                f"attempts — same failure repeated"
                            )
                        else:
                            stop_reason = None  # normal max_retries

                        # Try auto-split for MaxIterationsExceeded (only if not cost/dup stopped)
                        if (
                            is_max_iterations
                            and not cost_exceeded
                            and not is_duplicate_error
                            and settings.scheduler_auto_split_enabled
                            and not task.task_id.endswith(("-a", "-b", "-c", "-d"))
                        ):
                            split_success = await self._auto_split_failed_task(
                                session, task
                            )
                            if split_success:
                                task.status = TaskStatus.SPLIT
                                task.failure_reason = (
                                    f"Auto-split: MaxIterationsExceeded after "
                                    f"{task.retry_count} attempts — subtasks created"
                                )
                                logger.info(
                                    f"Task {task_db_id} ({task.task_id}) auto-split "
                                    f"due to MaxIterationsExceeded"
                                )
                                log2 = Log(
                                    run_id=run.id if run else None,
                                    level="INFO",
                                    message=f"Task auto-split into subtasks",
                                )
                                session.add(log2)
                            else:
                                task.status = TaskStatus.FAILED
                                task.failure_reason = (
                                    f"MaxIterationsExceeded after {task.retry_count} "
                                    f"attempts (auto-split failed)"
                                )
                                log2 = Log(
                                    run_id=run.id if run else None,
                                    level="ERROR",
                                    message=task.failure_reason,
                                )
                                session.add(log2)
                        else:
                            task.status = TaskStatus.FAILED
                            if stop_reason:
                                reason = stop_reason
                            else:
                                reason = f"Execution failed after {task.retry_count}/{task.max_retries} attempts"
                                if result.timed_out:
                                    reason += " (last: timeout)"
                                elif result.exit_code != 0:
                                    error_hint = (result.stderr or result.stdout or "").strip().split("\n")[0][:200]
                                    if error_hint:
                                        reason += f" (last: {error_hint})"
                            task.failure_reason = reason
                            logger.warning(
                                f"Task {task_db_id} failed permanently: {reason}"
                            )
                            log2 = Log(
                                run_id=run.id if run else None,
                                level="ERROR",
                                message=reason,
                            )
                            session.add(log2)
                    else:
                        task.status = TaskStatus.PENDING  # Will retry
                        logger.info(
                            f"Task {task_db_id} will retry "
                            f"(attempt {task.retry_count}/{task.max_retries}, "
                            f"cost so far: ${task_cost:.2f})"
                        )

            await session.commit()

            if task:
                await session.refresh(task)
                await sse_broadcaster.broadcast("task_update", task.to_dict())
                # Fire auto-test if task completed successfully
                if task.status == TaskStatus.COMPLETED:
                    working_dir = task.working_directory
                    asyncio.create_task(self._run_auto_test(task_db_id, working_dir))
                # Wake scheduler for dependents / retries
                self.notify()
            if run:
                await session.refresh(run)
                await sse_broadcaster.broadcast("run_update", run.to_dict())

    async def _run_auto_test(self, task_db_id: int, working_dir: str):
        """Run auto-test command after task completion (non-blocking)."""
        test_command = settings.scheduler_test_command
        if not test_command:
            return

        cwd = working_dir or settings.project_root
        timeout = settings.scheduler_test_timeout

        # Mark as testing
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task:
                task.test_status = "testing"
                await session.commit()
                await session.refresh(task)
                await sse_broadcaster.broadcast("task_update", task.to_dict())

        try:
            proc = await asyncio.create_subprocess_shell(
                test_command,
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
                try:
                    await asyncio.wait_for(proc.communicate(), timeout=5)
                except asyncio.TimeoutError:
                    logger.warning(f"Test process for task {task_db_id} still alive after SIGKILL")
                stdout = b""
                stderr = b"Test timed out"

            output = (stdout.decode(errors="replace") + "\n" + stderr.decode(errors="replace")).strip()
            passed = proc.returncode == 0

            async with async_session() as session:
                task = await session.get(Task, task_db_id)
                if task:
                    task.test_status = "passed" if passed else "failed"
                    task.test_output = output[-10000:]  # cap output size
                    await session.commit()
                    await session.refresh(task)
                    await sse_broadcaster.broadcast("task_update", task.to_dict())

            logger.info(f"Auto-test for task {task_db_id}: {'passed' if passed else 'failed'}")

        except Exception:
            logger.exception(f"Auto-test failed for task {task_db_id}")
            async with async_session() as session:
                task = await session.get(Task, task_db_id)
                if task:
                    task.test_status = "failed"
                    task.test_output = "Auto-test execution error"
                    await session.commit()
                    await session.refresh(task)
                    await sse_broadcaster.broadcast("task_update", task.to_dict())

    @staticmethod
    async def _git_exec(*args: str, cwd: str, timeout: int = 30) -> tuple[int, bytes, bytes]:
        """Run a git command with timeout. Returns (returncode, stdout, stderr)."""
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await asyncio.wait_for(proc.communicate(), timeout=5)
            except asyncio.TimeoutError:
                pass
            return -1, b"", f"git {args[1] if len(args) > 1 else ''} timed out after {timeout}s".encode()
        return proc.returncode or 0, stdout, stderr

    async def _git_auto_commit(
        self, task_db_id: int, task_id: str, title: str, working_dir: str
    ) -> str | None:
        """Auto-commit changes after a successful task. Returns commit SHA or None."""
        cwd = working_dir or settings.project_root
        logger.info(f"Auto-commit check for {task_id} in {cwd}")
        try:
            # Check for changes
            rc, stdout, stderr = await self._git_exec("git", "status", "--porcelain", cwd=cwd)
            if rc != 0:
                logger.warning(f"Task {task_id}: git status failed: {stderr.decode(errors='replace')}")
                return None
            if not stdout or not stdout.strip():
                logger.info(f"Task {task_id}: no changes to commit")
                return None

            # Stage all changes
            rc, _, stderr = await self._git_exec("git", "add", "-A", cwd=cwd)
            if rc != 0:
                logger.warning(f"Task {task_id}: git add failed: {stderr.decode(errors='replace')}")
                return None

            # Commit
            commit_msg = f"feat({task_id}): {title}"
            rc, _, stderr = await self._git_exec("git", "commit", "-m", commit_msg, cwd=cwd)
            if rc != 0:
                logger.warning(f"Task {task_id}: git commit failed (exit {rc})")
                return None

            # Get commit SHA
            rc, stdout, _ = await self._git_exec("git", "rev-parse", "HEAD", cwd=cwd)
            sha = stdout.decode().strip()[:40] if rc == 0 and stdout else None
            if sha:
                logger.info(f"Task {task_id}: committed {sha[:8]}")
            return sha

        except Exception:
            logger.exception(f"Task {task_id}: git auto-commit failed")
            return None

    @staticmethod
    async def _get_task_total_cost(session: AsyncSession, task_db_id: int) -> float:
        """Sum total_cost across all runs for a task."""
        result = await session.execute(
            select(sa_func.coalesce(sa_func.sum(Run.total_cost), 0.0))
            .where(Run.task_id == task_db_id)
        )
        return float(result.scalar_one())

    @staticmethod
    def _extract_error_signature(result: ExecutionResult) -> str:
        """Extract a normalized error signature from execution result for dedup."""
        text = (result.stderr or result.stdout or "").strip()
        if not text:
            return f"exit_{result.exit_code}"
        # Take the first meaningful error line, strip variable parts
        for line in text.split("\n"):
            line = line.strip()
            if not line or line.startswith("Traceback") or line.startswith("  "):
                continue
            # Normalize: remove file paths, line numbers, timestamps
            sig = re.sub(r"/[^\s:]+", "<path>", line)
            sig = re.sub(r":\d+", ":<n>", sig)
            sig = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*", "<ts>", sig)
            return sig[:200]
        return f"exit_{result.exit_code}"

    @staticmethod
    async def _is_duplicate_error(
        session: AsyncSession, task_db_id: int, current_sig: str
    ) -> bool:
        """Check if the last N runs had the same error signature."""
        limit = settings.scheduler_duplicate_error_limit
        if limit <= 0:
            return False
        result = await session.execute(
            select(Run.stderr, Run.stdout, Run.exit_code)
            .where(Run.task_id == task_db_id)
            .where(Run.status.in_(["FAILED", "TIMEOUT"]))
            .order_by(Run.id.desc())
            .limit(limit)
        )
        rows = result.all()
        if len(rows) < limit:
            return False
        # Build signatures for previous runs and compare
        for row in rows:
            text = (row.stderr or row.stdout or "").strip()
            if not text:
                prev_sig = f"exit_{row.exit_code}"
            else:
                prev_sig = f"exit_{row.exit_code}"
                for line in text.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("Traceback") or line.startswith("  "):
                        continue
                    sig = re.sub(r"/[^\s:]+", "<path>", line)
                    sig = re.sub(r":\d+", ":<n>", sig)
                    sig = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*", "<ts>", sig)
                    prev_sig = sig[:200]
                    break
            if prev_sig != current_sig:
                return False
        return True

    async def _auto_split_failed_task(self, session: AsyncSession, task: Task) -> bool:
        """Split a failed task into subtasks using TaskCreatorAgent.

        Returns True if split was successful.
        """
        try:
            from .agents.task_creator import TaskCreatorAgent
            from .task_loader import load_tasks_into_db

            task_def = {
                "task_id": task.task_id,
                "title": task.title,
                "category": task.category,
                "phase": task.phase,
                "priority": task.priority,
                "prompt": task.prompt,
                "working_directory": task.working_directory,
                "target_files": task.target_files_list,
                "acceptance_criteria": task.acceptance_criteria,
            }

            creator = TaskCreatorAgent()
            subtasks = await creator._split_task_with_claude(task_def)

            if not subtasks:
                logger.warning(
                    "Auto-split: Claude returned no subtasks for %s", task.task_id
                )
                return False

            # Insert subtasks (bypass auto_split to avoid recursion)
            created, _ = await load_tasks_into_db(subtasks, auto_split=False)
            if created > 0:
                logger.info(
                    "Auto-split: created %d subtasks for failed task %s",
                    created, task.task_id,
                )
                return True

            return False

        except Exception:
            logger.exception("Auto-split error for task %s", task.task_id)
            return False

    # --- Manual controls ---

    async def trigger_task(self, task_db_id: int):
        """Manually trigger a specific task regardless of dependencies."""
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task is None:
                return False
            if task.status not in (TaskStatus.PENDING, TaskStatus.FAILED):
                return False
            task.status = TaskStatus.PENDING
            task.retry_count = 0
            task.quality_retry_count = 0
            task.verification_status = None
            task.verification_output = None
            task.test_status = None
            task.test_output = None
            task.git_commit_sha = None
            task.failure_reason = None
            await session.commit()

        asyncio.create_task(self._run_task(task_db_id))
        self.notify()
        return True

    async def skip_task(self, task_db_id: int):
        """Skip a task (marks as SKIPPED so dependents can proceed)."""
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task is None:
                return False
            task.status = TaskStatus.SKIPPED
            task.failure_reason = None
            await session.commit()
            await session.refresh(task)
            await sse_broadcaster.broadcast("task_update", task.to_dict())
        self.notify()
        return True

    async def reset_task(self, task_db_id: int):
        """Reset a task back to PENDING."""
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task is None:
                return False
            task.status = TaskStatus.PENDING
            task.retry_count = 0
            task.quality_retry_count = 0
            task.verification_status = None
            task.verification_output = None
            task.test_status = None
            task.test_output = None
            task.git_commit_sha = None
            task.failure_reason = None
            await session.commit()
            await session.refresh(task)
            await sse_broadcaster.broadcast("task_update", task.to_dict())
        self.notify()
        return True

    async def cancel_task(self, task_db_id: int):
        """Cancel a running task."""
        killed = await executor.cancel(task_db_id)
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task:
                task.status = TaskStatus.CANCELLED
                task.failure_reason = "Manually cancelled"
                await session.commit()
                await session.refresh(task)
                await sse_broadcaster.broadcast("task_update", task.to_dict())
        return killed


class RetryAgent:
    """Background agent that periodically resets FAILED tasks to PENDING."""

    INTERVAL_SECONDS = 300  # 5 minutes

    def __init__(self):
        self._running = False
        self._task: asyncio.Task | None = None
        self._last_action: datetime.datetime | None = None
        self._action_count: int = 0

    @property
    def status(self) -> str:
        return "running" if self._running else "stopped"

    def to_dict(self) -> dict:
        return {
            "name": "RetryAgent",
            "status": self.status,
            "interval_seconds": self.INTERVAL_SECONDS,
            "description": "Resets failed tasks back to pending for automatic retry",
            "last_action": self._last_action.isoformat() if self._last_action else None,
            "action_count": self._action_count,
        }

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("RetryAgent started (interval=%ds)", self.INTERVAL_SECONDS)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("RetryAgent stopped")

    async def _loop(self):
        while self._running:
            try:
                await asyncio.sleep(self.INTERVAL_SECONDS)
                await self._retry_failed_tasks()
                self._last_action = now()
                self._action_count += 1
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in RetryAgent loop")
                await asyncio.sleep(30)

    async def _retry_failed_tasks(self):
        async with async_session() as session:
            # 1. Pick up tasks with status=FAILED
            result = await session.execute(
                select(Task).where(Task.status == TaskStatus.FAILED)
            )
            failed_tasks = list(result.scalars().all())

            # 2. Also pick up stuck tasks: status=COMPLETED but verification/test failed
            #    These got stuck because verifier marked verification_status='failed'
            #    but didn't change status to FAILED (pre-fix or fail_action != 'reset')
            stuck_result = await session.execute(
                select(Task)
                .where(Task.status == TaskStatus.COMPLETED)
                .where(
                    (Task.verification_status == "failed") | (Task.test_status == "failed")
                )
            )
            stuck_tasks = list(stuck_result.scalars().all())

            all_candidates = failed_tasks + stuck_tasks
            if not all_candidates:
                return

            reset_tasks = []
            for task in all_candidates:
                if (task.quality_retry_count or 0) >= settings.scheduler_quality_retry_max:
                    continue  # permanently failed, skip

                reason = (task.failure_reason or "").lower()

                # Skip budget/credit failures — circuit breaker handles these
                if "budget" in reason or "credit" in reason:
                    continue

                # Skip hard-capped tasks
                if "hard cap" in reason or "max_total_runs" in reason:
                    continue

                # Classify failure: only retry transient or quality failures
                is_stuck = task in stuck_tasks  # verification/test failed
                is_transient = "timeout" in reason or "timed out" in reason
                is_deterministic = (
                    not is_stuck
                    and not is_transient
                    and task.retry_count >= task.max_retries
                )

                # Deterministic execution failures (hit max_retries with
                # consistent errors) should NOT be retried — the task's
                # code/prompt needs manual intervention
                if is_deterministic:
                    logger.info(
                        "RetryAgent: skipping %s (deterministic failure: %s)",
                        task.task_id, reason[:100],
                    )
                    continue

                new_qrc = (task.quality_retry_count or 0) + 1
                task.quality_retry_count = new_qrc
                task.status = TaskStatus.PENDING
                # Diminishing retries: each quality retry gets fewer normal retries
                # e.g., max_retries=5: q1->retry_count=1, q2->2, q3->3 (fewer attempts left)
                task.retry_count = min(new_qrc, task.max_retries - 1)
                task.verification_status = None
                task.verification_output = None
                task.test_status = None
                task.test_output = None
                task.git_commit_sha = None
                task.failure_reason = None
                reset_tasks.append(task)

            await session.commit()
            if reset_tasks:
                stuck_count = len([t for t in reset_tasks if t in stuck_tasks])
                logger.info(
                    "RetryAgent reset %d tasks to PENDING (%d failed, %d stuck)",
                    len(reset_tasks), len(reset_tasks) - stuck_count, stuck_count,
                )

            # Broadcast updates so the frontend reflects the changes
            for task in reset_tasks:
                await session.refresh(task)
                await sse_broadcaster.broadcast("task_update", task.to_dict())

            # Wake scheduler to pick up reset tasks immediately
            if reset_tasks:
                scheduler.notify()


class WatchdogAgent:
    """Background agent that monitors task progress and auto-stops when done.

    Every 2 minutes it:
      - Logs a progress summary (completed/running/pending/failed)
      - Broadcasts progress via SSE for the frontend
      - Auto-stops the scheduler + all agents when no work remains
    """

    INTERVAL_SECONDS = 120  # 2 minutes

    def __init__(self):
        self._running = False
        self._task: asyncio.Task | None = None
        self._last_action: datetime.datetime | None = None
        self._action_count: int = 0

    @property
    def status(self) -> str:
        return "running" if self._running else "stopped"

    def to_dict(self) -> dict:
        return {
            "name": "WatchdogAgent",
            "status": self.status,
            "interval_seconds": self.INTERVAL_SECONDS,
            "description": "Monitors progress and auto-stops scheduler when all tasks finish",
            "last_action": self._last_action.isoformat() if self._last_action else None,
            "action_count": self._action_count,
        }

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("WatchdogAgent started (interval=%ds)", self.INTERVAL_SECONDS)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("WatchdogAgent stopped")

    async def _loop(self):
        while self._running:
            try:
                await asyncio.sleep(self.INTERVAL_SECONDS)
                await self._check_progress()
                self._last_action = now()
                self._action_count += 1
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in WatchdogAgent loop")
                await asyncio.sleep(30)

    async def _check_progress(self):
        async with async_session() as session:
            result = await session.execute(select(Task))
            all_tasks = result.scalars().all()

        if not all_tasks:
            return

        from collections import Counter
        counts = Counter(t.status for t in all_tasks)
        total = len(all_tasks)
        completed = counts.get(TaskStatus.COMPLETED, 0)
        running = counts.get(TaskStatus.RUNNING, 0)
        pending = counts.get(TaskStatus.PENDING, 0)
        failed = counts.get(TaskStatus.FAILED, 0)
        skipped = counts.get(TaskStatus.SKIPPED, 0)
        cancelled = counts.get(TaskStatus.CANCELLED, 0)
        split = counts.get(TaskStatus.SPLIT, 0)

        pct = (completed / total * 100) if total else 0

        logger.info(
            "Watchdog: %d/%d done (%.0f%%) | running=%d pending=%d failed=%d skipped=%d cancelled=%d split=%d",
            completed, total, pct, running, pending, failed, skipped, cancelled, split,
        )

        # Detect ghost tasks: RUNNING in DB but no active process in executor
        running_tasks = [t for t in all_tasks if t.status == TaskStatus.RUNNING]
        for t in running_tasks:
            if t.id not in executor._running_tasks:
                logger.warning(
                    f"Ghost task detected: task {t.id} ({t.task_id}) is RUNNING "
                    f"in DB but has no active process"
                )

        # Broadcast progress to frontend
        await sse_broadcaster.broadcast("progress", {
            "total": total,
            "completed": completed,
            "running": running,
            "pending": pending,
            "failed": failed,
            "skipped": skipped,
            "cancelled": cancelled,
            "split": split,
            "percent": round(pct, 1),
        })

        # Check for retriable failed tasks and tasks mid-verification/testing
        retriable_failed = sum(
            1 for t in all_tasks
            if t.status == TaskStatus.FAILED
            and (t.quality_retry_count or 0) < settings.scheduler_quality_retry_max
        )
        mid_quality = sum(
            1 for t in all_tasks
            if t.verification_status == "verifying"
            or t.test_status == "testing"
        )

        # Auto-stop when all work is finished (nothing pending, running, retriable, or mid-quality)
        if pending == 0 and running == 0 and retriable_failed == 0 and mid_quality == 0:
            logger.info(
                "Watchdog: All tasks finished (%d completed, %d failed, %d skipped, %d cancelled). "
                "Stopping scheduler.",
                completed, failed, skipped, cancelled,
            )
            await sse_broadcaster.broadcast("scheduler", {
                "status": "finished",
                "message": f"All {total} tasks processed: {completed} completed, {failed} failed",
            })
            await scheduler.stop()
            await retry_agent.stop()

            # Stop new agents (except TaskCreatorAgent which may continue discovering)
            try:
                from .agents import ALL_NEW_AGENTS
                for agent in ALL_NEW_AGENTS:
                    if agent.NAME != "TaskCreatorAgent":
                        await agent.stop()
            except ImportError:
                pass

            self._running = False


# Module-level singletons
scheduler = Scheduler()
retry_agent = RetryAgent()
watchdog_agent = WatchdogAgent()
