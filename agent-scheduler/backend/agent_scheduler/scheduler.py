import asyncio
import datetime
import json
import logging

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .database import async_session
from .executor import ExecutionResult, executor
from .models import Log, Run, RunStatus, Task, TaskStatus

logger = logging.getLogger(__name__)


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
        for q in self._queues:
            await q.put(msg)


sse_broadcaster = SSEBroadcaster()


class Scheduler:
    def __init__(self):
        self._running = False
        self._paused = False
        self._task: asyncio.Task | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_paused(self) -> bool:
        return self._paused

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
                    run.finished_at = datetime.datetime.utcnow()
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

    async def _loop(self):
        """Main scheduler loop — checks for eligible tasks every 30s."""
        while self._running:
            try:
                if not self._paused:
                    await self._dispatch_eligible_tasks()
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in scheduler loop")
                await asyncio.sleep(10)

    async def _dispatch_eligible_tasks(self):
        """Find and dispatch tasks that are ready to run."""
        async with async_session() as session:
            # Get all tasks
            result = await session.execute(select(Task))
            all_tasks = result.scalars().all()

            # Build status lookup
            status_map = {t.task_id: t.status for t in all_tasks}

            # Find eligible tasks
            eligible = []
            for task in all_tasks:
                if task.status != TaskStatus.PENDING:
                    continue

                # Check retry backoff
                if task.retry_count > 0:
                    backoff = settings.scheduler_retry_backoff * (2 ** (task.retry_count - 1))
                    if task.updated_at:
                        elapsed = (datetime.datetime.utcnow() - task.updated_at).total_seconds()
                        if elapsed < backoff:
                            continue

                # Check dependencies
                deps = task.depends_on_list
                if deps:
                    all_met = all(
                        status_map.get(dep) in (TaskStatus.COMPLETED, TaskStatus.SKIPPED)
                        for dep in deps
                    )
                    if not all_met:
                        continue

                eligible.append(task)

            # Sort by priority (higher first) then by id
            eligible.sort(key=lambda t: (-t.priority, t.id))

            # Dispatch tasks up to max_concurrent limit
            dispatched = 0
            for task in eligible:
                if executor.running_count + dispatched >= settings.scheduler_max_concurrent:
                    break
                asyncio.create_task(self._run_task(task.id))
                dispatched += 1

    async def _run_task(self, task_db_id: int):
        """Execute a single task and record results."""
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task is None or task.status != TaskStatus.PENDING:
                return

            # Mark as running
            task.status = TaskStatus.RUNNING
            await session.commit()
            await session.refresh(task)
            await sse_broadcaster.broadcast("task_update", task.to_dict())

            # Create run record
            run = Run(
                task_id=task.id,
                attempt=task.retry_count + 1,
                status=RunStatus.RUNNING,
            )
            session.add(run)
            await session.commit()

            # Log start
            log = Log(run_id=run.id, level="INFO", message=f"Starting task: {task.title}")
            session.add(log)
            await session.commit()
            await sse_broadcaster.broadcast("log", log.to_dict())

            # Save values before session closes
            task_str_id = task.task_id
            task_title = task.title
            task_prompt = task.prompt
            task_working_dir = task.working_directory
            task_model = task.model
            task_attempt = task.retry_count + 1
            task_max_retries = task.max_retries

        # Execute outside the session
        result: ExecutionResult = await executor.execute(
            prompt=task_prompt,
            working_directory=task_working_dir or None,
            model=task_model,
            task_db_id=task_db_id,
            task_id=task_str_id,
            attempt=task_attempt,
            max_retries=task_max_retries,
        )

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

            if run:
                run.exit_code = result.exit_code
                run.pid = result.pid
                run.stdout = result.stdout
                run.stderr = result.stderr
                run.duration_seconds = result.duration_seconds
                run.finished_at = datetime.datetime.utcnow()

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
                    if task.retry_count >= task.max_retries:
                        task.status = TaskStatus.FAILED
                        log2 = Log(
                            run_id=run.id if run else None,
                            level="ERROR",
                            message=f"Task failed after {task.retry_count} attempts",
                        )
                        session.add(log2)
                    else:
                        task.status = TaskStatus.PENDING  # Will retry

            await session.commit()

            if task:
                await session.refresh(task)
                await sse_broadcaster.broadcast("task_update", task.to_dict())
            if run:
                await session.refresh(run)
                await sse_broadcaster.broadcast("run_update", run.to_dict())

    async def _git_auto_commit(
        self, task_db_id: int, task_id: str, title: str, working_dir: str
    ) -> str | None:
        """Auto-commit changes after a successful task. Returns commit SHA or None."""
        cwd = working_dir or settings.mxtac_project_root
        logger.info(f"Auto-commit check for {task_id} in {cwd}")
        try:
            # Check for changes
            proc = await asyncio.create_subprocess_exec(
                "git", "status", "--porcelain",
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if not stdout or not stdout.strip():
                logger.info(f"Task {task_id}: no changes to commit")
                return None

            # Stage all changes
            proc = await asyncio.create_subprocess_exec(
                "git", "add", "-A",
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            # Commit
            commit_msg = f"feat({task_id}): {title}"
            proc = await asyncio.create_subprocess_exec(
                "git", "commit", "-m", commit_msg,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if proc.returncode != 0:
                logger.warning(f"Task {task_id}: git commit failed (exit {proc.returncode})")
                return None

            # Get commit SHA
            proc = await asyncio.create_subprocess_exec(
                "git", "rev-parse", "HEAD",
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            sha = stdout.decode().strip()[:40] if stdout else None
            if sha:
                logger.info(f"Task {task_id}: committed {sha[:8]}")
            return sha

        except Exception:
            logger.exception(f"Task {task_id}: git auto-commit failed")
            return None

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
            await session.commit()

        asyncio.create_task(self._run_task(task_db_id))
        return True

    async def skip_task(self, task_db_id: int):
        """Skip a task (marks as SKIPPED so dependents can proceed)."""
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task is None:
                return False
            task.status = TaskStatus.SKIPPED
            await session.commit()
            await session.refresh(task)
            await sse_broadcaster.broadcast("task_update", task.to_dict())
        return True

    async def reset_task(self, task_db_id: int):
        """Reset a task back to PENDING."""
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task is None:
                return False
            task.status = TaskStatus.PENDING
            task.retry_count = 0
            await session.commit()
            await session.refresh(task)
            await sse_broadcaster.broadcast("task_update", task.to_dict())
        return True

    async def cancel_task(self, task_db_id: int):
        """Cancel a running task."""
        killed = await executor.cancel(task_db_id)
        async with async_session() as session:
            task = await session.get(Task, task_db_id)
            if task:
                task.status = TaskStatus.CANCELLED
                await session.commit()
                await session.refresh(task)
                await sse_broadcaster.broadcast("task_update", task.to_dict())
        return killed


# Module-level singleton
scheduler = Scheduler()
