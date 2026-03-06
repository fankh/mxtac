import json
import logging
from pathlib import Path

from ..config import settings
from ..rules_checker import check_all as rules_check_all
from ..scheduler import sse_broadcaster
from .base import BaseAgent

logger = logging.getLogger(__name__)


class LintAgent(BaseAgent):
    NAME = "LintAgent"
    DEFAULT_INTERVAL = 600
    DESCRIPTION = "Runs linting and type-checking on project codebase"

    def __init__(self):
        super().__init__()
        self._interval = settings.agent_lint_interval

    async def run_cycle(self) -> dict:
        project_root = Path(settings.project_root)
        results = []

        # 1. Ruff (Python linting)
        ruff_result = await self._run_ruff(project_root)
        results.append(ruff_result)

        # 2. TypeScript type checking
        tsc_result = await self._run_tsc(project_root)
        results.append(tsc_result)

        # 3. Project-specific rules
        rules_result = self._run_project_rules(project_root)
        results.append(rules_result)

        total_errors = sum(r.get("errors", 0) for r in results)
        total_warnings = sum(r.get("warnings", 0) for r in results)

        summary = f"Lint: {total_errors} errors, {total_warnings} warnings"

        await sse_broadcaster.broadcast("agent_report", {
            "agent": self.NAME,
            "summary": summary,
            "errors": total_errors,
            "warnings": total_warnings,
            "results": results,
        })

        return {
            "summary": summary,
            "items_processed": len(results),
            "items_found": total_errors,
            "output": json.dumps(results),
        }

    async def _run_ruff(self, root: Path) -> dict:
        """Run ruff check on backend Python code."""
        backend_dir = root / "app" / "backend"
        if not backend_dir.exists():
            return {"tool": "ruff", "errors": 0, "warnings": 0, "detail": "Backend dir not found"}

        rc, stdout, stderr = await self._run_subprocess(
            "ruff check app/ --output-format=json",
            cwd=str(backend_dir),
            timeout=60,
        )

        errors = 0
        warnings = 0
        issues = []

        if stdout.strip():
            try:
                parsed = json.loads(stdout)
                if isinstance(parsed, list):
                    for issue in parsed:
                        code = issue.get("code", "")
                        if code.startswith("E") or code.startswith("F"):
                            errors += 1
                        else:
                            warnings += 1
                    issues = parsed[:20]  # Keep first 20 for reporting
            except json.JSONDecodeError:
                # Count lines as a fallback
                errors = len(stdout.strip().splitlines())

        threshold = settings.agent_lint_error_threshold
        return {
            "tool": "ruff",
            "errors": errors,
            "warnings": warnings,
            "above_threshold": errors > threshold,
            "detail": f"{errors} errors, {warnings} warnings",
            "issues": issues,
        }

    async def _run_tsc(self, root: Path) -> dict:
        """Run TypeScript type checking on frontend."""
        frontend_dir = root / "app" / "frontend"
        tsconfig = frontend_dir / "tsconfig.json"
        if not tsconfig.exists():
            return {"tool": "tsc", "errors": 0, "warnings": 0, "detail": "No tsconfig.json found"}

        rc, stdout, stderr = await self._run_subprocess(
            "npx tsc --noEmit",
            cwd=str(frontend_dir),
            timeout=120,
        )

        output = stdout + stderr
        error_lines = [l for l in output.splitlines() if "error TS" in l]
        errors = len(error_lines)

        return {
            "tool": "tsc",
            "errors": errors,
            "warnings": 0,
            "detail": f"{errors} type errors",
            "output": output[-2000:] if errors > 0 else "",
        }

    def _run_project_rules(self, root: Path) -> dict:
        """Run project-specific rules from .agent-scheduler/lint-rules.yaml."""
        try:
            return rules_check_all(root)
        except Exception as e:
            logger.error(f"Project rules check failed: {e}")
            return {"tool": "project_rules", "errors": 0, "warnings": 0, "detail": f"Error: {e}"}
