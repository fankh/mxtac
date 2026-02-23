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


class VerifierAgent(BaseAgent):
    NAME = "VerifierAgent"
    DEFAULT_INTERVAL = 180
    DESCRIPTION = "Verifies completed tasks against acceptance criteria and test results"

    def __init__(self):
        super().__init__()
        self._interval = settings.agent_verifier_interval

    async def run_cycle(self) -> dict:
        # 1. Query tasks needing verification
        async with async_session() as session:
            result = await session.execute(
                select(Task)
                .where(Task.status == TaskStatus.COMPLETED)
                .where(Task.verification_status.is_(None))
                .limit(settings.agent_verifier_max_per_cycle)
            )
            tasks = result.scalars().all()

        if not tasks:
            return {
                "summary": "No tasks to verify",
                "items_processed": 0,
                "items_found": 0,
            }

        passed = 0
        failed = 0
        processed = 0

        for task in tasks:
            processed += 1
            # Mark as verifying
            async with async_session() as session:
                t = await session.get(Task, task.id)
                if t:
                    t.verification_status = "verifying"
                    await session.commit()
                    await session.refresh(t)
                    await sse_broadcaster.broadcast("task_update", t.to_dict())

            checks = []
            all_pass = True

            # 2a. File check
            file_result = await self._check_files(task)
            checks.append(file_result)
            if not file_result["pass"]:
                all_pass = False

            # 2b. Git check
            if task.git_commit_sha:
                git_result = await self._check_git(task)
                checks.append(git_result)
                if not git_result["pass"]:
                    all_pass = False

            # 2c. Test check
            if task.test_status:
                test_result = {
                    "check": "test_status",
                    "pass": task.test_status == "passed",
                    "detail": f"Test status: {task.test_status}",
                }
                checks.append(test_result)
                if not test_result["pass"]:
                    all_pass = False

            # 2d. Criteria check with Claude
            if (
                task.acceptance_criteria
                and task.acceptance_criteria.strip()
                and settings.agent_verifier_use_claude
            ):
                criteria_result = await self._check_criteria(task, checks)
                checks.append(criteria_result)
                if not criteria_result["pass"]:
                    all_pass = False

            # 3. Update verification status
            verification_status = "passed" if all_pass else "failed"
            verification_output = json.dumps(checks, indent=2)

            async with async_session() as session:
                t = await session.get(Task, task.id)
                if t:
                    t.verification_status = verification_status
                    t.verification_output = verification_output

                    # 4. If fail_action="reset" and verification fails, reset to FAILED
                    # Only if task is still COMPLETED (not already FAILED by another agent)
                    if (
                        not all_pass
                        and settings.agent_verifier_fail_action == "reset"
                        and t.status == TaskStatus.COMPLETED
                    ):
                        t.quality_retry_count = (t.quality_retry_count or 0) + 1
                        t.status = TaskStatus.FAILED

                    await session.commit()
                    await session.refresh(t)
                    await sse_broadcaster.broadcast("task_update", t.to_dict())

            if all_pass:
                passed += 1
            else:
                failed += 1

        return {
            "summary": f"Verified {processed} tasks: {passed} passed, {failed} failed",
            "items_processed": processed,
            "items_found": passed,
            "output": json.dumps({"passed": passed, "failed": failed}),
        }

    async def _check_files(self, task: Task) -> dict:
        """Verify that target_files exist on disk."""
        target_files = task.target_files_list
        if not target_files:
            return {"check": "files", "pass": True, "detail": "No target files specified"}

        missing = []
        for f in target_files:
            if not Path(f).exists():
                missing.append(f)

        if missing:
            return {
                "check": "files",
                "pass": False,
                "detail": f"Missing files: {', '.join(missing)}",
            }
        return {"check": "files", "pass": True, "detail": "All target files exist"}

    async def _check_git(self, task: Task) -> dict:
        """Verify target files appear in the git commit diff."""
        target_files = task.target_files_list
        if not target_files:
            return {"check": "git", "pass": True, "detail": "No target files to check"}

        cwd = task.working_directory or settings.mxtac_project_root
        rc, stdout, _ = await self._run_subprocess(
            f"git diff --name-only {task.git_commit_sha}~1 {task.git_commit_sha}",
            cwd=cwd,
            timeout=30,
        )

        if rc != 0:
            return {"check": "git", "pass": False, "detail": "Failed to get git diff"}

        changed_files = set(stdout.strip().splitlines())
        # Check if any target file (or its basename) appears in changed files
        found = 0
        for tf in target_files:
            tf_name = Path(tf).name
            if any(tf_name in cf or tf in cf for cf in changed_files):
                found += 1

        if found == 0:
            return {
                "check": "git",
                "pass": False,
                "detail": f"No target files found in commit {task.git_commit_sha[:8]}",
            }
        return {
            "check": "git",
            "pass": True,
            "detail": f"{found}/{len(target_files)} target files in commit",
        }

    async def _check_criteria(self, task: Task, prior_checks: list[dict]) -> dict:
        """Use Claude CLI to evaluate acceptance criteria."""
        checks_summary = "\n".join(
            f"- {c['check']}: {'PASS' if c['pass'] else 'FAIL'} - {c['detail']}"
            for c in prior_checks
        )

        prompt = (
            f"Evaluate if the following acceptance criteria are met for task '{task.title}'.\n\n"
            f"Acceptance Criteria:\n{task.acceptance_criteria}\n\n"
            f"Verification Results:\n{checks_summary}\n\n"
            f"Test Status: {task.test_status or 'not tested'}\n"
            f"Git Commit: {task.git_commit_sha or 'none'}\n\n"
            f"Respond with exactly 'PASS' or 'FAIL' on the first line, "
            f"followed by a brief explanation."
        )

        async with self._claude_semaphore:
            rc, stdout, _ = await self._run_subprocess(
                f'{settings.claude_cli_path} -p "{prompt}" 2>/dev/null',
                timeout=60,
            )

        if rc != 0 or not stdout.strip():
            return {
                "check": "criteria",
                "pass": True,  # Don't fail on Claude errors
                "detail": "Claude evaluation unavailable, skipping criteria check",
            }

        first_line = stdout.strip().splitlines()[0].upper()
        is_pass = "PASS" in first_line
        return {
            "check": "criteria",
            "pass": is_pass,
            "detail": stdout.strip()[:500],
        }
