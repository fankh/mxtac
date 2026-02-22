import json
import logging
import re
from pathlib import Path

from sqlalchemy import select

from ..config import settings
from ..database import async_session
from ..models import Task, TaskStatus
from ..scheduler import sse_broadcaster
from ..task_loader import load_tasks_into_db
from .base import BaseAgent

logger = logging.getLogger(__name__)


class TaskCreatorAgent(BaseAgent):
    NAME = "TaskCreatorAgent"
    DEFAULT_INTERVAL = 3600
    DESCRIPTION = "Scans MxTac codebase to discover gaps and generate task definitions"

    def __init__(self):
        super().__init__()
        self._interval = settings.agent_task_creator_interval

    async def run_cycle(self) -> dict:
        project_root = Path(settings.mxtac_project_root)
        gaps = []

        # 1. Heuristic discovery
        gaps.extend(await self._scan_checklist(project_root))
        gaps.extend(await self._scan_implementation_plan(project_root))
        gaps.extend(await self._scan_test_gaps(project_root))
        gaps.extend(await self._scan_todos(project_root))

        # 2. Dedup against existing tasks
        gaps = await self._dedup_gaps(gaps)

        if not gaps:
            return {
                "summary": "No new gaps discovered",
                "items_processed": 0,
                "items_found": 0,
            }

        # 3. Limit to max_tasks_per_cycle
        max_tasks = settings.agent_task_creator_max_tasks_per_cycle
        gaps = gaps[:max_tasks]

        # 4. Generate task definitions (optionally with Claude)
        task_defs = []
        if settings.agent_task_creator_use_claude:
            task_defs = await self._generate_with_claude(gaps)
        else:
            task_defs = self._generate_basic(gaps)

        # 5. Load into DB
        created = 0
        if task_defs:
            created, _ = await load_tasks_into_db(task_defs)

        # 6. Broadcast events
        for td in task_defs[:created]:
            await sse_broadcaster.broadcast("task_created", {
                "task_id": td.get("task_id", ""),
                "title": td.get("title", ""),
            })

        return {
            "summary": f"Discovered {len(gaps)} gaps, created {created} tasks",
            "items_processed": len(gaps),
            "items_found": created,
            "output": json.dumps([g["id"] for g in gaps[:20]]),
        }

    async def _scan_checklist(self, root: Path) -> list[dict]:
        """Parse docs/19-FEATURE-CHECKLIST.md for unchecked items."""
        checklist = root / "docs" / "19-FEATURE-CHECKLIST.md"
        if not checklist.exists():
            return []

        gaps = []
        try:
            text = checklist.read_text(errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                # Match [ ] or [~] items
                m = re.match(r"^\s*-\s*\[([ ~])\]\s*(.+)$", line)
                if m:
                    status_char, description = m.groups()
                    item_slug = re.sub(r"[^a-z0-9]+", "-", description.lower().strip())[:40]
                    gaps.append({
                        "id": f"auto-checklist-{item_slug}",
                        "source": "checklist",
                        "description": description.strip(),
                        "line": i,
                        "partial": status_char == "~",
                    })
        except Exception:
            logger.exception("Error scanning checklist")
        return gaps

    async def _scan_implementation_plan(self, root: Path) -> list[dict]:
        """Parse docs/18-AI-AGENT-IMPLEMENTATION-PLAN.md for uncompleted tasks."""
        plan_file = root / "docs" / "18-AI-AGENT-IMPLEMENTATION-PLAN.md"
        if not plan_file.exists():
            return []

        gaps = []
        try:
            text = plan_file.read_text(errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                m = re.match(r"^\s*-\s*\[([ ~])\]\s*(.+)$", line)
                if m:
                    status_char, description = m.groups()
                    item_slug = re.sub(r"[^a-z0-9]+", "-", description.lower().strip())[:40]
                    gaps.append({
                        "id": f"auto-plan-{item_slug}",
                        "source": "implementation-plan",
                        "description": description.strip(),
                        "line": i,
                        "partial": status_char == "~",
                    })
        except Exception:
            logger.exception("Error scanning implementation plan")
        return gaps

    async def _scan_test_gaps(self, root: Path) -> list[dict]:
        """Find services/endpoints without corresponding test files."""
        gaps = []

        # Backend services vs tests
        services_dir = root / "app" / "backend" / "app" / "services"
        tests_dir = root / "app" / "backend" / "tests" / "services"
        if services_dir.exists():
            for svc in services_dir.glob("*.py"):
                if svc.name.startswith("_"):
                    continue
                test_file = tests_dir / f"test_{svc.name}" if tests_dir.exists() else None
                if test_file is None or not test_file.exists():
                    name = svc.stem
                    gaps.append({
                        "id": f"auto-test-gap-{name}",
                        "source": "test-gap",
                        "description": f"Missing tests for service: {name}",
                        "file": str(svc),
                    })

        # Backend endpoints vs tests
        endpoints_dir = root / "app" / "backend" / "app" / "api" / "v1" / "endpoints"
        endpoint_tests_dir = root / "app" / "backend" / "tests" / "api" / "v1"
        if endpoints_dir.exists():
            for ep in endpoints_dir.glob("*.py"):
                if ep.name.startswith("_"):
                    continue
                test_file = endpoint_tests_dir / f"test_{ep.name}" if endpoint_tests_dir.exists() else None
                if test_file is None or not test_file.exists():
                    name = ep.stem
                    gaps.append({
                        "id": f"auto-test-gap-endpoint-{name}",
                        "source": "test-gap",
                        "description": f"Missing tests for endpoint: {name}",
                        "file": str(ep),
                    })

        return gaps

    async def _scan_todos(self, root: Path) -> list[dict]:
        """Grep for TODO/FIXME comments in backend source."""
        gaps = []
        backend_app = root / "app" / "backend" / "app"
        if not backend_app.exists():
            return gaps

        rc, stdout, _ = await self._run_subprocess(
            "grep -rn 'TODO\\|FIXME' --include='*.py' .",
            cwd=str(backend_app),
            timeout=30,
        )
        if rc == 0 and stdout:
            seen = set()
            for line in stdout.strip().splitlines()[:50]:
                # Extract a unique identifier from the TODO
                m = re.match(r"^(.+?):(\d+):\s*#?\s*(TODO|FIXME):?\s*(.+)$", line)
                if m:
                    file_path, line_no, tag, msg = m.groups()
                    slug = re.sub(r"[^a-z0-9]+", "-", msg.lower().strip())[:30]
                    gap_id = f"auto-todo-{slug}"
                    if gap_id not in seen:
                        seen.add(gap_id)
                        gaps.append({
                            "id": gap_id,
                            "source": "todo",
                            "description": f"{tag}: {msg.strip()}",
                            "file": file_path,
                            "line": int(line_no),
                        })

        return gaps

    async def _dedup_gaps(self, gaps: list[dict]) -> list[dict]:
        """Remove gaps that already have corresponding tasks in the DB."""
        if not gaps:
            return gaps

        async with async_session() as session:
            result = await session.execute(select(Task.task_id))
            existing_ids = {row[0] for row in result.all()}

        return [g for g in gaps if g["id"] not in existing_ids]

    async def _generate_with_claude(self, gaps: list[dict]) -> list[dict]:
        """Use Claude CLI to generate structured task definitions."""
        task_defs = []
        project_root = settings.mxtac_project_root

        # Process in batches of 5
        for i in range(0, len(gaps), 5):
            batch = gaps[i:i + 5]
            gap_descriptions = "\n".join(
                f"- {g['id']}: {g['description']} (source: {g['source']})"
                for g in batch
            )

            prompt = (
                f"Generate task definitions for the MxTac project. "
                f"For each gap below, create a JSON object with fields: "
                f"task_id, title, category, phase, priority (0-10), prompt, "
                f"working_directory, target_files (list), acceptance_criteria.\n\n"
                f"Gaps:\n{gap_descriptions}\n\n"
                f"Working directory: {project_root}\n"
                f"Respond with a JSON array only, no markdown."
            )

            async with self._claude_semaphore:
                rc, stdout, stderr = await self._run_subprocess(
                    f'{settings.claude_cli_path} -p "{prompt}" --output-format json 2>/dev/null',
                    timeout=120,
                )

            if rc == 0 and stdout.strip():
                try:
                    # Try to extract JSON array from response
                    text = stdout.strip()
                    # Find JSON array in response
                    start = text.find("[")
                    end = text.rfind("]") + 1
                    if start >= 0 and end > start:
                        parsed = json.loads(text[start:end])
                        if isinstance(parsed, list):
                            task_defs.extend(parsed)
                except (json.JSONDecodeError, ValueError):
                    logger.warning("Failed to parse Claude response for task generation")
                    # Fall back to basic generation for this batch
                    task_defs.extend(self._generate_basic(batch))
            else:
                task_defs.extend(self._generate_basic(batch))

        return task_defs

    def _generate_basic(self, gaps: list[dict]) -> list[dict]:
        """Generate basic task definitions without Claude."""
        task_defs = []
        for g in gaps:
            task_defs.append({
                "task_id": g["id"],
                "title": g["description"],
                "category": g.get("source", "auto-discovered"),
                "phase": "auto-discovery",
                "priority": 3,
                "prompt": f"Address the following gap: {g['description']}",
                "working_directory": settings.mxtac_project_root,
                "target_files": [g["file"]] if "file" in g else [],
                "acceptance_criteria": f"The gap '{g['description']}' has been addressed.",
            })
        return task_defs
