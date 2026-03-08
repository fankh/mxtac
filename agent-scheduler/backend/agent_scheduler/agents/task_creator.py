import json
import logging
import re
import time
from pathlib import Path

from sqlalchemy import select

from ..config import settings
from ..database import async_session
from ..models import Task, TaskStatus
from ..scheduler import sse_broadcaster
from ..task_loader import load_tasks_into_db, parse_yaml_directory
from .base import BaseAgent

logger = logging.getLogger(__name__)


class TaskCreatorAgent(BaseAgent):
    NAME = "TaskCreatorAgent"
    DEFAULT_INTERVAL = 3600
    DESCRIPTION = "Scans project codebase to discover gaps and generate task definitions"

    def __init__(self):
        super().__init__()
        self._interval = settings.agent_task_creator_interval
        # Tier 2 rotation state
        self._claude_scan_index: int = 0
        self._spec_scan_index: int = 0
        self._security_scan_index: int = 0
        self._quality_scan_index: int = 0
        self._scanned_files: dict[str, float] = {}  # path -> last-scanned timestamp

    async def run_cycle(self) -> dict:
        project_root = Path(settings.project_root)

        # Tier -1: Load YAML task files from tasks/ directory
        yaml_created, yaml_skipped = await self._load_yaml_tasks(project_root)

        gaps = []

        # Tier 0: Heuristic (free, always)
        gaps.extend(await self._scan_checklist(project_root))
        gaps.extend(await self._scan_implementation_plan(project_root))
        gaps.extend(await self._scan_test_gaps(project_root))
        gaps.extend(await self._scan_todos(project_root))

        # Tier 1: Structural cross-reference (free, always)
        gaps.extend(await self._scan_architectural_gaps(project_root))
        gaps.extend(await self._scan_stub_implementations(project_root))
        gaps.extend(await self._scan_mock_data_dependencies(project_root))

        # Tier 2: Claude semantic (1 of 3 per cycle, rotating)
        if settings.agent_task_creator_use_claude:
            idx = self._claude_scan_index % 3
            if idx == 0:
                gaps.extend(await self._scan_spec_compliance(project_root))
            elif idx == 1:
                gaps.extend(await self._scan_security_gaps(project_root))
            else:
                gaps.extend(await self._scan_code_quality(project_root))
            self._claude_scan_index += 1

        # Dedup against existing tasks
        gaps = await self._dedup_gaps(gaps)

        if not gaps:
            return {
                "summary": f"YAML: {yaml_created} created/{yaml_skipped} skipped. No new gaps discovered",
                "items_processed": 0,
                "items_found": yaml_created,
                "yaml_created": yaml_created,
                "yaml_skipped": yaml_skipped,
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

        # 4b. Auto-split oversized tasks before DB insertion
        if settings.scheduler_auto_split_enabled:
            task_defs = await self._estimate_and_split(task_defs)

        # 5. Load into DB
        created = 0
        if task_defs:
            created, _ = await load_tasks_into_db(task_defs, auto_split=False)

        # 6. Broadcast events
        for td in task_defs[:created]:
            await sse_broadcaster.broadcast("task_created", {
                "task_id": td.get("task_id", ""),
                "title": td.get("title", ""),
            })

        return {
            "summary": f"YAML: {yaml_created} created/{yaml_skipped} skipped. Gaps: {len(gaps)} discovered, {created} tasks created",
            "items_processed": len(gaps),
            "items_found": yaml_created + created,
            "yaml_created": yaml_created,
            "yaml_skipped": yaml_skipped,
            "output": json.dumps([g["id"] for g in gaps[:20]]),
        }

    async def _load_yaml_tasks(self, root: Path) -> tuple[int, int]:
        """Scan tasks/ directory for YAML files and load new tasks into DB."""
        yaml_dir = root / settings.agent_task_creator_yaml_dir
        if not yaml_dir.is_dir():
            return 0, 0

        try:
            task_defs = parse_yaml_directory(yaml_dir)
        except Exception:
            logger.exception("Failed to parse YAML task directory %s", yaml_dir)
            return 0, 0

        if not task_defs:
            return 0, 0

        created, skipped = await load_tasks_into_db(task_defs)
        if created > 0:
            logger.info("YAML loader: %d new tasks created from %s", created, yaml_dir)
            for td in task_defs:
                await sse_broadcaster.broadcast("task_created", {
                    "task_id": td.get("task_id", ""),
                    "title": td.get("title", ""),
                    "source": "yaml",
                })

        return created, skipped

    async def _scan_checklist(self, root: Path) -> list[dict]:
        """Parse checklist markdown for unchecked items."""
        checklist = root / settings.agent_task_creator_checklist_path
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
        """Parse implementation plan markdown for uncompleted tasks."""
        plan_file = root / settings.agent_task_creator_plan_path
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

    # -- Tier 1: Structural cross-reference (no Claude API) ----------------

    async def _scan_architectural_gaps(self, root: Path) -> list[dict]:
        """Cross-reference project layers to find structural holes."""
        gaps = []
        backend = root / "app" / "backend" / "app"

        # 1. Models without repositories
        models_dir = backend / "models"
        repos_dir = backend / "repositories"
        if models_dir.exists() and repos_dir.exists():
            repo_stems = {
                p.stem.removesuffix("_repo")
                for p in repos_dir.glob("*.py")
                if not p.name.startswith("_")
            }
            for model_file in models_dir.glob("*.py"):
                if model_file.name.startswith("_") or model_file.stem == "base":
                    continue
                if model_file.stem not in repo_stems:
                    gaps.append({
                        "id": f"auto-arch-missing-repo-{model_file.stem}",
                        "source": "architectural-gap",
                        "description": (
                            f"Model '{model_file.stem}' has no repository — "
                            f"expected repositories/{model_file.stem}_repo.py"
                        ),
                        "file": str(model_file),
                    })

        # 2. Services / repos / connectors / engine / pipeline without tests
        test_root = root / "app" / "backend" / "tests"
        scan_layers = [
            ("repositories", "repositories"),
            ("connectors", "connectors"),
            ("engine", "engine"),
            ("pipeline", "pipeline"),
        ]
        for layer, test_subdir in scan_layers:
            src_dir = backend / layer
            tst_dir = test_root / test_subdir
            if not src_dir.exists():
                continue
            for src_file in src_dir.glob("*.py"):
                if src_file.name.startswith("_"):
                    continue
                test_file = tst_dir / f"test_{src_file.name}" if tst_dir.exists() else None
                if test_file is None or not test_file.exists():
                    gaps.append({
                        "id": f"auto-test-gap-{layer}-{src_file.stem}",
                        "source": "test-gap",
                        "description": f"Missing tests for {layer}/{src_file.name}",
                        "file": str(src_file),
                    })

        # 3. Endpoints importing from mock_data
        rc, stdout, _ = await self._run_subprocess(
            r"grep -rn 'from.*mock_data import\|import.*mock_data' --include='*.py' .",
            cwd=str(backend / "api" / "v1" / "endpoints") if (backend / "api" / "v1" / "endpoints").exists() else str(backend),
            timeout=15,
        )
        if rc == 0 and stdout:
            for line in stdout.strip().splitlines():
                m = re.match(r"^(.+?):(\d+):", line)
                if m:
                    fpath = m.group(1).lstrip("./")
                    gaps.append({
                        "id": f"auto-arch-mock-import-{fpath.replace('/', '-').replace('.py', '')}",
                        "source": "architectural-gap",
                        "description": f"Endpoint {fpath} still imports mock_data — replace with real DB queries",
                        "file": fpath,
                        "line": int(m.group(2)),
                    })

        return gaps

    async def _scan_stub_implementations(self, root: Path) -> list[dict]:
        """Find functions whose body is only pass, ..., or raise NotImplementedError."""
        gaps = []
        backend = root / "app" / "backend" / "app"

        scan_dirs = ["services", "connectors", "repositories", "engine", "pipeline"]
        for dirname in scan_dirs:
            src_dir = backend / dirname
            if not src_dir.exists():
                continue

            # Use grep + awk to find stub functions:
            # Match "def foo(...):" followed by a line that is only pass/Ellipsis/raise NotImplementedError
            rc, stdout, _ = await self._run_subprocess(
                r"""grep -rn -A1 '^\s*\(async \)\?def ' --include='*.py' . | """
                r"""awk '/def /{fname=$0; next} """
                r"""/^\s*(pass|\.\.\.|\.\.\.|raise NotImplementedError)\s*$/{print fname}'""",
                cwd=str(src_dir),
                timeout=30,
            )
            if rc == 0 and stdout:
                for line in stdout.strip().splitlines():
                    m = re.match(r"^(.+?)[:-](\d+)[:-]\s*(async\s+)?def\s+(\w+)", line)
                    if m:
                        fpath, lineno, _, func_name = m.groups()
                        fpath = fpath.lstrip("./")
                        slug = f"{dirname}-{fpath.replace('/', '-').replace('.py', '')}-{func_name}"
                        gaps.append({
                            "id": f"auto-stub-{slug}",
                            "source": "stub-implementation",
                            "description": (
                                f"Stub function '{func_name}' in {dirname}/{fpath}:{lineno} "
                                f"— body is pass/NotImplementedError"
                            ),
                            "file": str(src_dir / fpath),
                            "line": int(lineno),
                        })

        return gaps

    async def _scan_mock_data_dependencies(self, root: Path) -> list[dict]:
        """Find every endpoint still relying on services/mock_data.py constants."""
        gaps = []
        mock_data_file = root / "app" / "backend" / "app" / "services" / "mock_data.py"
        endpoints_dir = root / "app" / "backend" / "app" / "api" / "v1" / "endpoints"

        if not mock_data_file.exists() or not endpoints_dir.exists():
            return gaps

        # Extract exported constant names from mock_data.py (uppercase identifiers at module level)
        rc, stdout, _ = await self._run_subprocess(
            r"grep -n '^[A-Z_][A-Z_0-9]*\s*[=:]' " + str(mock_data_file),
            timeout=10,
        )
        if rc != 0 or not stdout:
            return gaps

        constants = []
        for line in stdout.strip().splitlines():
            m = re.match(r"^\d+:\s*([A-Z_][A-Z_0-9]*)", line)
            if m:
                constants.append(m.group(1))

        if not constants:
            return gaps

        # For each endpoint file, check which constants are imported/used
        for ep_file in endpoints_dir.glob("*.py"):
            if ep_file.name.startswith("_"):
                continue
            try:
                content = ep_file.read_text(errors="replace")
            except Exception:
                continue

            for const in constants:
                if const in content:
                    ep_name = ep_file.stem
                    gaps.append({
                        "id": f"auto-mock-dep-{ep_name}-{const.lower()}",
                        "source": "mock-data-dependency",
                        "description": (
                            f"Endpoint '{ep_name}' uses mock constant {const} — "
                            f"replace with real DB/service call"
                        ),
                        "file": str(ep_file),
                    })

        return gaps

    # -- Tier 2: Claude semantic analysis (rotates 1 per cycle) ------------

    async def _scan_spec_compliance(self, root: Path) -> list[dict]:
        """Compare API spec doc against actual endpoint implementations."""
        gaps = []
        spec_file = root / settings.agent_task_creator_api_spec_path
        endpoints_dir = root / "app" / "backend" / "app" / "api" / "v1" / "endpoints"

        if not spec_file.exists() or not endpoints_dir.exists():
            return gaps

        # Get list of endpoint files to scan (rotate through them)
        ep_files = sorted(
            [f for f in endpoints_dir.glob("*.py") if not f.name.startswith("_")],
            key=lambda f: f.name,
        )
        if not ep_files:
            return gaps

        # Select batch of 5 based on rotation index
        batch_size = 5
        start = (self._spec_scan_index * batch_size) % len(ep_files)
        batch = ep_files[start:start + batch_size]
        self._spec_scan_index += 1

        # Read spec (truncate to stay within token limits)
        try:
            spec_text = spec_file.read_text(errors="replace")[:12000]
        except Exception:
            return gaps

        # Extract implemented routes from each file
        for ep_file in batch:
            try:
                code = ep_file.read_text(errors="replace")
            except Exception:
                continue

            # Extract route decorators for context
            routes = re.findall(r'@router\.\w+\(["\']([^"\']+)', code)
            if not routes:
                continue

            prompt = (
                f"Compare this API specification excerpt against the endpoint implementation below.\n"
                f"Identify SPECIFIC gaps: missing query parameters, missing response fields, "
                f"pagination deviations, missing auth/permission checks, missing error responses.\n\n"
                f"--- SPEC (excerpt) ---\n{spec_text[:6000]}\n\n"
                f"--- ENDPOINT: {ep_file.name} (routes: {', '.join(routes)}) ---\n{code[:6000]}\n\n"
                f"Respond with a JSON array of objects, each with:\n"
                f'  {{"gap": "short description", "severity": "high|medium|low", "route": "/path"}}\n'
                f"If no gaps found, return empty array []. JSON only, no markdown."
            )

            async with self._claude_semaphore:
                rc, stdout = await self._call_claude(prompt, max_tokens=2048, timeout=90)

            if rc == 0 and stdout.strip():
                parsed = self._parse_json_array(stdout)
                for item in parsed:
                    desc = item.get("gap", "")
                    route = item.get("route", "")
                    severity = item.get("severity", "medium")
                    slug = re.sub(r"[^a-z0-9]+", "-", desc.lower())[:40]
                    gaps.append({
                        "id": f"auto-spec-{ep_file.stem}-{slug}",
                        "source": "spec-compliance",
                        "description": f"[{severity}] {ep_file.stem} ({route}): {desc}",
                        "file": str(ep_file),
                    })

        return gaps

    async def _scan_security_gaps(self, root: Path) -> list[dict]:
        """Cross-reference security implementation doc against code."""
        gaps = []
        sec_doc = root / settings.agent_task_creator_security_doc_path
        backend = root / "app" / "backend" / "app"

        if not sec_doc.exists():
            return gaps

        # Pre-scan: routes missing require_permission() or get_current_user
        endpoints_dir = backend / "api" / "v1" / "endpoints"
        unprotected = []
        if endpoints_dir.exists():
            for ep_file in sorted(endpoints_dir.glob("*.py")):
                if ep_file.name.startswith("_"):
                    continue
                try:
                    code = ep_file.read_text(errors="replace")
                except Exception:
                    continue
                routes = re.findall(r'@router\.\w+\(["\']([^"\']+)', code)
                has_auth = "get_current_user" in code or "require_permission" in code
                has_post_patch = re.search(r"@router\.(post|put|patch)\(", code)
                has_validator = "BaseModel" in code or "Body(" in code

                if routes and not has_auth:
                    unprotected.append((ep_file.stem, routes))
                if has_post_patch and not has_validator:
                    gaps.append({
                        "id": f"auto-sec-no-validator-{ep_file.stem}",
                        "source": "security-gap",
                        "description": (
                            f"Endpoint '{ep_file.stem}' has POST/PATCH routes "
                            f"without Pydantic request validation"
                        ),
                        "file": str(ep_file),
                    })

            for ep_name, routes in unprotected:
                gaps.append({
                    "id": f"auto-sec-no-auth-{ep_name}",
                    "source": "security-gap",
                    "description": (
                        f"Endpoint '{ep_name}' routes {routes[:3]} have no "
                        f"auth check (require_permission / get_current_user)"
                    ),
                    "file": str(endpoints_dir / f"{ep_name}.py"),
                })

        # Claude-powered deep analysis: rotate through domains
        domains = ["authentication", "rbac", "input-validation"]
        domain = domains[self._security_scan_index % len(domains)]
        self._security_scan_index += 1

        try:
            sec_text = sec_doc.read_text(errors="replace")[:8000]
        except Exception:
            return gaps

        # Gather relevant code snippets based on domain
        if domain == "authentication":
            code_dir = backend / "core"
            code_files = ["security.py", "api_key_auth.py"]
        elif domain == "rbac":
            code_dir = backend / "core"
            code_files = ["rbac.py"]
        else:
            code_dir = backend / "schemas"
            code_files = sorted(
                [f.name for f in code_dir.glob("*.py") if not f.name.startswith("_")]
            )[:3] if code_dir.exists() else []

        code_snippets = []
        if code_dir.exists():
            for fname in code_files:
                fpath = code_dir / fname
                if fpath.exists():
                    try:
                        code_snippets.append(
                            f"--- {fname} ---\n{fpath.read_text(errors='replace')[:4000]}"
                        )
                    except Exception:
                        pass

        if not code_snippets:
            return gaps

        prompt = (
            f"Analyze the {settings.project_name} backend '{domain}' implementation for security gaps.\n"
            f"Compare the security spec against the actual code.\n\n"
            f"--- SECURITY SPEC (excerpt) ---\n{sec_text}\n\n"
            f"--- CODE ---\n{''.join(code_snippets)}\n\n"
            f"Identify SPECIFIC security gaps: missing checks, weak defaults, "
            f"missing rate limiting, insecure patterns, missing audit logging.\n"
            f"Respond with a JSON array of objects:\n"
            f'  {{"gap": "description", "severity": "critical|high|medium|low", "file": "filename"}}\n'
            f"JSON only, no markdown."
        )

        async with self._claude_semaphore:
            rc, stdout = await self._call_claude(prompt, max_tokens=2048, timeout=90)

        if rc == 0 and stdout.strip():
            parsed = self._parse_json_array(stdout)
            for item in parsed:
                desc = item.get("gap", "")
                severity = item.get("severity", "medium")
                fname = item.get("file", "")
                slug = re.sub(r"[^a-z0-9]+", "-", desc.lower())[:40]
                gaps.append({
                    "id": f"auto-sec-{domain}-{slug}",
                    "source": "security-gap",
                    "description": f"[{severity}] {domain}: {desc}",
                    "file": fname,
                })

        return gaps

    async def _scan_code_quality(self, root: Path) -> list[dict]:
        """Claude-powered analysis of rotating file sample for quality issues."""
        gaps = []
        backend = root / "app" / "backend" / "app"
        if not backend.exists():
            return gaps

        now_ts = time.time()
        cooldown = 86400  # 24 hours

        # Collect candidate files, prioritized
        candidates: list[Path] = []
        for dirname in ["services", "connectors", "repositories", "engine"]:
            src_dir = backend / dirname
            if src_dir.exists():
                for f in src_dir.glob("*.py"):
                    if f.name.startswith("_"):
                        continue
                    # Skip if scanned within cooldown
                    last = self._scanned_files.get(str(f), 0)
                    if now_ts - last < cooldown:
                        continue
                    candidates.append(f)

        if not candidates:
            return gaps

        # Sort: larger files first (more likely to have issues)
        candidates.sort(key=lambda f: f.stat().st_size, reverse=True)

        sample_size = settings.agent_task_creator_quality_sample_size
        sample = candidates[:sample_size]

        for fpath in sample:
            try:
                code = fpath.read_text(errors="replace")
            except Exception:
                continue

            # Truncate very large files
            if len(code) > 8000:
                code = code[:8000] + "\n... (truncated)"

            rel_path = fpath.relative_to(backend)
            prompt = (
                f"Analyze this Python file from the {settings.project_name} project for code quality issues.\n"
                f"File: {rel_path}\n\n"
                f"```python\n{code}\n```\n\n"
                f"Find SPECIFIC, actionable issues:\n"
                f"- Stub functions (pass/NotImplementedError body)\n"
                f"- Missing error handling for external calls\n"
                f"- Hardcoded values that should be configurable\n"
                f"- Mock data usage instead of real data sources\n"
                f"- Missing logging for important operations\n"
                f"- Functions that are defined but never complete their stated purpose\n\n"
                f"Respond with a JSON array of objects:\n"
                f'  {{"issue": "description", "severity": "high|medium|low", '
                f'"line": 0, "function": "name_or_empty"}}\n'
                f"If the file is well-implemented with no issues, return []. JSON only."
            )

            async with self._claude_semaphore:
                rc, stdout = await self._call_claude(prompt, max_tokens=2048, timeout=90)

            self._scanned_files[str(fpath)] = now_ts

            if rc == 0 and stdout.strip():
                parsed = self._parse_json_array(stdout)
                for item in parsed:
                    desc = item.get("issue", "")
                    severity = item.get("severity", "medium")
                    func_name = item.get("function", "")
                    slug = re.sub(r"[^a-z0-9]+", "-", desc.lower())[:40]
                    gap_id = f"auto-quality-{rel_path.stem}-{slug}"
                    gaps.append({
                        "id": gap_id,
                        "source": "code-quality",
                        "description": (
                            f"[{severity}] {rel_path}"
                            + (f" ({func_name})" if func_name else "")
                            + f": {desc}"
                        ),
                        "file": str(fpath),
                        "line": item.get("line", 0),
                    })

        return gaps

    @staticmethod
    def _complexity_score(td: dict) -> int:
        """Language-agnostic complexity score for a task definition.

        Signals (all derivable from task metadata, no codebase knowledge):
          - target_files count: 3 points per file
          - Directive verbs in prompt: 2 points each
          - Prompt length: 1 point per 200 words
          - Acceptance criteria count (split on ';' or newlines): 2 points each

        Threshold: score > 8 → pre-split before execution.
        """
        score = 0
        target_files = td.get("target_files", [])
        prompt_text = td.get("prompt", "")
        criteria = td.get("acceptance_criteria", "")

        # File count
        score += len(target_files) * 3

        # Directive verbs (case-insensitive)
        directives = re.findall(
            r"\b(create|implement|add|build|write|register|configure|test|wire|setup)\b",
            prompt_text, re.IGNORECASE,
        )
        score += len(directives) * 2

        # Prompt length
        score += len(prompt_text.split()) // 200

        # Acceptance criteria count
        if criteria:
            parts = re.split(r"[;\n]", criteria)
            criteria_count = sum(1 for p in parts if p.strip())
            score += max(0, criteria_count - 1) * 2  # first criterion is free

        return score

    @staticmethod
    def _deterministic_split(td: dict) -> list[dict] | None:
        """Split a task by target_files — one file per subtask, chained.

        Returns None if deterministic split doesn't apply (e.g., single file
        but prompt is too complex — needs Claude).
        """
        target_files = td.get("target_files", [])
        if len(target_files) <= 1:
            return None  # Can't deterministically split single-file tasks

        parent_id = td.get("task_id", "unknown")
        suffixes = "abcdefghij"
        subtasks = []

        for i, tf in enumerate(target_files):
            suffix = suffixes[i] if i < len(suffixes) else str(i)
            child_id = f"{parent_id}-{suffix}"

            # Derive a focused sub-prompt
            filename = tf.rsplit("/", 1)[-1] if "/" in tf else tf
            sub_prompt = (
                f"{td.get('prompt', '')}\n\n"
                f"SCOPE: Focus ONLY on this file: {tf}\n"
                f"Do not modify other files unless absolutely necessary."
            )

            subtask = {
                "task_id": child_id,
                "title": f"{td.get('title', '')} — {filename}",
                "category": td.get("category", ""),
                "phase": td.get("phase", ""),
                "priority": td.get("priority", 0),
                "prompt": sub_prompt,
                "working_directory": td.get("working_directory", ""),
                "target_files": [tf],
                "acceptance_criteria": f"File {tf} exists and compiles/passes lint",
                "max_retries": 2,
                "depends_on": [f"{parent_id}-{suffixes[i-1]}"] if i > 0 else [],
            }
            subtasks.append(subtask)

        return subtasks

    async def _estimate_and_split(self, task_defs: list[dict]) -> list[dict]:
        """Score each task and pre-split oversized ones BEFORE execution."""
        result = []
        for td in task_defs:
            score = self._complexity_score(td)
            target_files = td.get("target_files", [])

            # Threshold: score > 8 or too many files
            if score <= 8 and len(target_files) <= settings.scheduler_max_target_files:
                result.append(td)
                continue

            logger.info(
                "Pre-split: task %s has complexity score %d (files=%d)",
                td.get("task_id", "?"), score, len(target_files),
            )

            # Try deterministic split first (cheaper than Claude)
            subtasks = self._deterministic_split(td)
            if not subtasks:
                # Fall back to Claude-assisted split
                try:
                    subtasks = await self._split_task_with_claude(td)
                except Exception:
                    logger.exception("Pre-split failed for %s", td.get("task_id", "?"))

            if subtasks:
                result.extend(subtasks)
            else:
                # Can't split — keep original but cap target_files
                if len(target_files) > settings.scheduler_max_target_files:
                    td["target_files"] = target_files[:settings.scheduler_max_target_files]
                result.append(td)

        return result

    async def _split_task_with_claude(self, task_def: dict) -> list[dict]:
        """Use Claude Haiku to split an oversized task into 2-4 subtasks."""
        parent_id = task_def.get("task_id", "unknown")
        prompt = (
            f"Split this oversized task into 2-4 smaller subtasks.\n\n"
            f"TASK:\n"
            f"  task_id: {parent_id}\n"
            f"  title: {task_def.get('title', '')}\n"
            f"  target_files: {json.dumps(task_def.get('target_files', []))}\n"
            f"  prompt: {task_def.get('prompt', '')[:3000]}\n"
            f"  working_directory: {task_def.get('working_directory', '')}\n\n"
            f"SPLITTING RULES (hard requirements):\n"
            f"1. Max 2 target_files per subtask\n"
            f"2. Separate entity/model creation from service logic\n"
            f"3. Separate code implementation from tests\n"
            f"4. Separate DTOs/schemas from repositories\n"
            f"5. Set max_retries: 2 on all subtasks\n"
            f"6. Chain dependencies: each subtask depends_on the previous one\n\n"
            f"Subtask IDs must be: {parent_id}-a, {parent_id}-b, {parent_id}-c, etc.\n\n"
            f"Return a JSON array of subtask objects with fields:\n"
            f"  task_id, title, category, phase, priority, prompt, "
            f"working_directory, target_files (list, max 2), "
            f"acceptance_criteria, depends_on (list), max_retries\n\n"
            f"JSON array only, no markdown."
        )

        async with self._claude_semaphore:
            rc, stdout = await self._call_claude(
                prompt,
                model="claude-haiku-4-5-20251001",
                max_tokens=4096,
                timeout=120,
            )

        if rc != 0 or not stdout.strip():
            logger.warning("Auto-split Claude call failed for task %s", parent_id)
            return []

        parsed = self._parse_json_array(stdout)
        if not parsed:
            logger.warning("Auto-split: no valid JSON returned for task %s", parent_id)
            return []

        # Validate and fix subtasks
        suffixes = "abcdefghij"
        for i, subtask in enumerate(parsed):
            # Ensure correct subtask ID
            expected_id = f"{parent_id}-{suffixes[i]}" if i < len(suffixes) else f"{parent_id}-{i}"
            subtask["task_id"] = expected_id

            # Enforce max 2 target files
            if len(subtask.get("target_files", [])) > 2:
                subtask["target_files"] = subtask["target_files"][:2]

            # Enforce max_retries
            subtask["max_retries"] = 2

            # Carry over fields from parent if missing
            subtask.setdefault("working_directory", task_def.get("working_directory", ""))
            subtask.setdefault("category", task_def.get("category", ""))
            subtask.setdefault("phase", task_def.get("phase", ""))
            subtask.setdefault("priority", task_def.get("priority", 0))

            # Chain dependencies: each subtask depends on the previous
            if i > 0:
                prev_id = f"{parent_id}-{suffixes[i - 1]}" if (i - 1) < len(suffixes) else f"{parent_id}-{i - 1}"
                deps = subtask.get("depends_on", [])
                if prev_id not in deps:
                    deps.append(prev_id)
                subtask["depends_on"] = deps

        return parsed

    @staticmethod
    def _parse_json_array(text: str) -> list[dict]:
        """Extract a JSON array from Claude's response text."""
        text = text.strip()
        start = text.find("[")
        end = text.rfind("]") + 1
        if start >= 0 and end > start:
            try:
                parsed = json.loads(text[start:end])
                if isinstance(parsed, list):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass
        return []

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
        project_root = settings.project_root

        # Process in batches of 5
        for i in range(0, len(gaps), 5):
            batch = gaps[i:i + 5]
            gap_descriptions = "\n".join(
                f"- {g['id']}: {g['description']} (source: {g['source']})"
                for g in batch
            )

            prompt = (
                f"Generate task definitions for the {settings.project_name} project. "
                f"For each gap below, create a JSON object with fields: "
                f"task_id, title, category, phase, priority (0-10), prompt, "
                f"working_directory, target_files (list), acceptance_criteria.\n\n"
                f"Gaps:\n{gap_descriptions}\n\n"
                f"Working directory: {project_root}\n"
                f"Respond with a JSON array only, no markdown."
            )

            async with self._claude_semaphore:
                rc, stdout = await self._call_claude(
                    prompt,
                    max_tokens=4096,
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
                "working_directory": settings.project_root,
                "target_files": [g["file"]] if "file" in g else [],
                "acceptance_criteria": f"The gap '{g['description']}' has been addressed.",
            })
        return task_defs
