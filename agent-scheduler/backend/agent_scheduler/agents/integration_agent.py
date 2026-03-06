import datetime
import json
import logging
from pathlib import Path

from sqlalchemy import select

from ..config import now, settings
from ..database import async_session
from ..models import Task, TaskStatus
from ..scheduler import sse_broadcaster
from .base import BaseAgent

logger = logging.getLogger(__name__)


class IntegrationAgent(BaseAgent):
    NAME = "IntegrationAgent"
    DEFAULT_INTERVAL = 900
    DESCRIPTION = "Validates app startup, API smoke tests, cross-task conflict detection"

    def __init__(self):
        super().__init__()
        self._interval = settings.agent_integration_interval

    async def run_cycle(self) -> dict:
        project_root = Path(settings.project_root)
        results = []

        # 1. Import check
        import_result = await self._import_check(project_root)
        results.append(import_result)

        # 2. API smoke tests
        smoke_url = settings.agent_integration_smoke_url
        if smoke_url:
            smoke_result = await self._smoke_test(smoke_url)
            results.append(smoke_result)

        # 3. Conflict detection
        conflicts = await self._detect_conflicts()
        results.append(conflicts)

        errors = sum(1 for r in results if not r.get("pass"))
        summary = f"Integration: {len(results)} checks, {errors} issues"

        await sse_broadcaster.broadcast("agent_report", {
            "agent": self.NAME,
            "summary": summary,
            "results": results,
        })

        return {
            "summary": summary,
            "items_processed": len(results),
            "items_found": errors,
            "output": json.dumps(results),
        }

    async def _import_check(self, root: Path) -> dict:
        """Verify the backend app can be imported without errors."""
        backend_dir = root / "app" / "backend"
        if not backend_dir.exists():
            return {"check": "import", "pass": True, "detail": "Backend dir not found"}

        rc, stdout, stderr = await self._run_subprocess(
            'python -c "from app.main import app; print(\'OK\')"',
            cwd=str(backend_dir),
            timeout=30,
        )

        return {
            "check": "import",
            "pass": rc == 0 and "OK" in stdout,
            "detail": "App imports successfully" if rc == 0 else f"Import failed: {stderr[:500]}",
        }

    async def _smoke_test(self, base_url: str) -> dict:
        """Hit health and ready endpoints."""
        checks = []

        for endpoint in ["/health", "/api/v1/ready"]:
            url = f"{base_url.rstrip('/')}{endpoint}"
            rc, stdout, stderr = await self._run_subprocess(
                f"curl -sf -o /dev/null -w '%{{http_code}}' {url}",
                timeout=10,
            )

            status_code = stdout.strip() if rc == 0 else "error"
            checks.append({
                "endpoint": endpoint,
                "status": status_code,
                "pass": status_code == "200",
            })

        all_pass = all(c["pass"] for c in checks)
        return {
            "check": "smoke",
            "pass": all_pass,
            "detail": f"Smoke tests: {'all pass' if all_pass else 'some failed'}",
            "endpoints": checks,
        }

    async def _detect_conflicts(self) -> dict:
        """Find completed tasks from last 24h with overlapping target_files."""
        cutoff = now() - datetime.timedelta(hours=24)

        async with async_session() as session:
            result = await session.execute(
                select(Task)
                .where(Task.status == TaskStatus.COMPLETED)
                .where(Task.updated_at >= cutoff)
            )
            recent_tasks = result.scalars().all()

        # Build file -> task mapping
        file_map: dict[str, list[str]] = {}
        for task in recent_tasks:
            for f in task.target_files_list:
                if f not in file_map:
                    file_map[f] = []
                file_map[f].append(task.task_id)

        # Find overlaps
        conflicts = []
        for file_path, task_ids in file_map.items():
            if len(task_ids) > 1:
                conflicts.append({
                    "file": file_path,
                    "tasks": task_ids,
                })

        return {
            "check": "conflicts",
            "pass": len(conflicts) == 0,
            "detail": f"{len(conflicts)} file conflicts detected" if conflicts else "No conflicts",
            "conflicts": conflicts[:10],
        }
