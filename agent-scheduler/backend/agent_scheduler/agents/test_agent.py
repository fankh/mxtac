import json
import logging
from pathlib import Path

from sqlalchemy import select

from ..config import settings
from ..database import async_session
from ..models import Task, TaskStatus
from ..scheduler import sse_broadcaster
from .base import BaseAgent

logger = logging.getLogger(__name__)


class TestAgent(BaseAgent):
    NAME = "TestAgent"
    DEFAULT_INTERVAL = 300
    DESCRIPTION = "Runs test suites and detects coverage gaps"

    def __init__(self):
        super().__init__()
        self._interval = settings.agent_test_interval
        self._cycle_count = 0

    async def run_cycle(self) -> dict:
        self._cycle_count += 1
        project_root = Path(settings.mxtac_project_root)
        results = []

        # 1. Targeted tests for recently completed tasks
        targeted = await self._run_targeted_tests(project_root)
        results.extend(targeted)

        # 2. Full suite every Nth cycle
        full_suite_every = settings.agent_test_full_suite_every
        if self._cycle_count % full_suite_every == 0:
            suite_result = await self._run_full_suite(project_root)
            results.append(suite_result)

        # 3. Coverage gap report every 2Nth cycle
        if self._cycle_count % (full_suite_every * 2) == 0:
            gap_report = await self._coverage_gap_report(project_root)
            results.append(gap_report)

        passed = sum(1 for r in results if r.get("pass"))
        failed = sum(1 for r in results if not r.get("pass") and r.get("type") == "test")

        summary = f"Ran {len(results)} checks: {passed} passed, {failed} failed"

        await sse_broadcaster.broadcast("agent_report", {
            "agent": self.NAME,
            "summary": summary,
            "results": results[:20],
        })

        return {
            "summary": summary,
            "items_processed": len(results),
            "items_found": failed,
            "output": json.dumps(results[:10]),
        }

    async def _run_targeted_tests(self, root: Path) -> list[dict]:
        """Find completed tasks with no test_status and run their tests."""
        async with async_session() as session:
            result = await session.execute(
                select(Task)
                .where(Task.status == TaskStatus.COMPLETED)
                .where(Task.test_status.is_(None))
                .limit(5)
            )
            tasks = result.scalars().all()

        results = []
        for task in tasks:
            target_files = task.target_files_list
            test_files = self._map_to_test_files(root, target_files)

            if not test_files:
                continue

            for tf in test_files:
                if tf.endswith(".py"):
                    rc, stdout, stderr = await self._run_subprocess(
                        f"python -m pytest {tf} -v --tb=short",
                        cwd=str(root / "app" / "backend"),
                        timeout=settings.agent_test_timeout,
                    )
                elif tf.endswith((".ts", ".tsx")):
                    rc, stdout, stderr = await self._run_subprocess(
                        f"npx vitest run {tf}",
                        cwd=str(root / "app" / "frontend"),
                        timeout=settings.agent_test_timeout,
                    )
                else:
                    continue

                passed = rc == 0
                results.append({
                    "type": "test",
                    "task_id": task.task_id,
                    "test_file": tf,
                    "pass": passed,
                    "output": (stdout + stderr)[-2000:],
                })

                # Update task test_status
                async with async_session() as session:
                    t = await session.get(Task, task.id)
                    if t:
                        t.test_status = "passed" if passed else "failed"
                        t.test_output = (stdout + stderr)[-10000:]
                        await session.commit()
                        await session.refresh(t)
                        await sse_broadcaster.broadcast("task_update", t.to_dict())

        return results

    async def _run_full_suite(self, root: Path) -> dict:
        """Run the full backend test suite."""
        backend_tests = root / "app" / "backend" / "tests"
        if not backend_tests.exists():
            return {"type": "suite", "pass": True, "detail": "No test directory found"}

        rc, stdout, stderr = await self._run_subprocess(
            "python -m pytest tests/ -v --tb=short",
            cwd=str(root / "app" / "backend"),
            timeout=settings.agent_test_timeout,
        )

        return {
            "type": "suite",
            "pass": rc == 0,
            "detail": f"Full suite: {'PASS' if rc == 0 else 'FAIL'}",
            "output": (stdout + stderr)[-3000:],
        }

    async def _coverage_gap_report(self, root: Path) -> dict:
        """List untested services and endpoints."""
        gaps = []

        services_dir = root / "app" / "backend" / "app" / "services"
        tests_dir = root / "app" / "backend" / "tests" / "services"
        if services_dir.exists():
            for svc in services_dir.glob("*.py"):
                if svc.name.startswith("_"):
                    continue
                test_file = tests_dir / f"test_{svc.name}" if tests_dir.exists() else None
                if test_file is None or not test_file.exists():
                    gaps.append(f"service:{svc.stem}")

        endpoints_dir = root / "app" / "backend" / "app" / "api" / "v1" / "endpoints"
        endpoint_tests_dir = root / "app" / "backend" / "tests" / "api" / "v1"
        if endpoints_dir.exists():
            for ep in endpoints_dir.glob("*.py"):
                if ep.name.startswith("_"):
                    continue
                test_file = endpoint_tests_dir / f"test_{ep.name}" if endpoint_tests_dir.exists() else None
                if test_file is None or not test_file.exists():
                    gaps.append(f"endpoint:{ep.stem}")

        await sse_broadcaster.broadcast("agent_report", {
            "agent": self.NAME,
            "type": "coverage_gaps",
            "gaps": gaps,
        })

        return {
            "type": "coverage",
            "pass": len(gaps) == 0,
            "detail": f"{len(gaps)} untested modules",
            "gaps": gaps[:20],
        }

    def _map_to_test_files(self, root: Path, target_files: list[str]) -> list[str]:
        """Map source files to their corresponding test files."""
        test_files = []
        for f in target_files:
            p = Path(f)
            if "services" in p.parts and p.suffix == ".py":
                test_path = root / "app" / "backend" / "tests" / "services" / f"test_{p.name}"
                if test_path.exists():
                    test_files.append(str(test_path))
            elif "endpoints" in p.parts and p.suffix == ".py":
                test_path = root / "app" / "backend" / "tests" / "api" / "v1" / f"test_{p.name}"
                if test_path.exists():
                    test_files.append(str(test_path))
        return test_files
