import json
import logging
from pathlib import Path

from ..config import settings
from ..scheduler import sse_broadcaster
from .base import BaseAgent

logger = logging.getLogger(__name__)


class SecurityAuditAgent(BaseAgent):
    NAME = "SecurityAuditAgent"
    DEFAULT_INTERVAL = 1800
    DESCRIPTION = "Runs security scans: bandit, secret detection, RBAC validation"

    def __init__(self):
        super().__init__()
        self._interval = settings.agent_security_interval

    async def run_cycle(self) -> dict:
        project_root = Path(settings.project_root)
        results = []
        critical_findings = []

        # 1. Bandit scan
        bandit_result = await self._run_bandit(project_root)
        results.append(bandit_result)
        if bandit_result.get("high_severity", 0) > 0:
            critical_findings.append(f"Bandit: {bandit_result['high_severity']} high-severity issues")

        # 2. Secret scan
        secret_result = await self._scan_secrets(project_root)
        results.append(secret_result)
        if secret_result.get("findings", 0) > 0:
            critical_findings.append(f"Secrets: {secret_result['findings']} potential hardcoded secrets")

        # 3. RBAC audit
        rbac_result = await self._audit_rbac(project_root)
        results.append(rbac_result)
        if rbac_result.get("unprotected", 0) > 0:
            critical_findings.append(f"RBAC: {rbac_result['unprotected']} unprotected routes")

        total_issues = sum(r.get("findings", r.get("high_severity", r.get("unprotected", 0))) for r in results)
        summary = f"Security: {total_issues} findings across {len(results)} scans"

        await sse_broadcaster.broadcast("agent_report", {
            "agent": self.NAME,
            "summary": summary,
            "results": results,
        })

        # Broadcast critical alert if needed
        if critical_findings:
            await sse_broadcaster.broadcast("security_alert", {
                "agent": self.NAME,
                "severity": "CRITICAL",
                "findings": critical_findings,
            })

        return {
            "summary": summary,
            "items_processed": len(results),
            "items_found": total_issues,
            "output": json.dumps(results),
        }

    async def _run_bandit(self, root: Path) -> dict:
        """Run bandit security scanner on Python code."""
        backend_dir = root / "app" / "backend"
        if not backend_dir.exists():
            return {"scan": "bandit", "findings": 0, "high_severity": 0, "detail": "Backend dir not found"}

        skip_flag = ""
        if settings.agent_security_bandit_skip:
            skip_flag = f" -s {settings.agent_security_bandit_skip}"

        rc, stdout, stderr = await self._run_subprocess(
            f"bandit -r app/ -f json -ll{skip_flag}",
            cwd=str(backend_dir),
            timeout=120,
        )

        high_severity = 0
        medium_severity = 0
        issues = []

        if stdout.strip():
            try:
                parsed = json.loads(stdout)
                results_list = parsed.get("results", [])
                for issue in results_list:
                    severity = issue.get("issue_severity", "").upper()
                    if severity == "HIGH":
                        high_severity += 1
                    elif severity == "MEDIUM":
                        medium_severity += 1
                issues = results_list[:10]
            except json.JSONDecodeError:
                pass

        return {
            "scan": "bandit",
            "findings": high_severity + medium_severity,
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "detail": f"{high_severity} high, {medium_severity} medium severity issues",
            "issues": issues,
        }

    async def _scan_secrets(self, root: Path) -> dict:
        """Grep for hardcoded passwords, keys, and tokens in source."""
        patterns = [
            r"password\s*=\s*[\"'][^\"']+[\"']",
            r"api_key\s*=\s*[\"'][^\"']+[\"']",
            r"secret\s*=\s*[\"'][^\"']+[\"']",
            r"token\s*=\s*[\"'][A-Za-z0-9+/=]{20,}[\"']",
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        ]

        findings = []
        app_dir = root / "app"
        if not app_dir.exists():
            return {"scan": "secrets", "findings": 0, "detail": "App dir not found"}

        for pattern in patterns:
            rc, stdout, _ = await self._run_subprocess(
                f"grep -rn -E '{pattern}' --include='*.py' --include='*.ts' --include='*.tsx' --include='*.env' . || true",
                cwd=str(app_dir),
                timeout=30,
            )
            if stdout.strip():
                for line in stdout.strip().splitlines()[:5]:
                    # Skip test files and example configs
                    if "test" in line.lower() or "example" in line.lower() or "mock" in line.lower():
                        continue
                    findings.append(line.strip()[:200])

        return {
            "scan": "secrets",
            "findings": len(findings),
            "detail": f"{len(findings)} potential hardcoded secrets found",
            "locations": findings[:10],
        }

    async def _audit_rbac(self, root: Path) -> dict:
        """Scan endpoint files for routes missing auth dependencies."""
        endpoints_dir = root / "app" / "backend" / "app" / "api" / "v1" / "endpoints"
        if not endpoints_dir.exists():
            return {"scan": "rbac", "unprotected": 0, "detail": "Endpoints dir not found"}

        unprotected = []

        for ep_file in endpoints_dir.glob("*.py"):
            if ep_file.name.startswith("_"):
                continue

            try:
                content = ep_file.read_text(errors="replace")

                # Check if file has route decorators
                has_routes = any(
                    decorator in content
                    for decorator in ["@router.get", "@router.post", "@router.put", "@router.delete", "@router.patch"]
                )

                if has_routes:
                    # Check for auth dependency
                    has_auth = any(
                        auth_pattern in content
                        for auth_pattern in ["get_current_user", "require_auth", "Depends("]
                    )
                    if not has_auth:
                        unprotected.append(ep_file.name)
            except Exception:
                continue

        return {
            "scan": "rbac",
            "unprotected": len(unprotected),
            "detail": f"{len(unprotected)} endpoint files without auth" if unprotected else "All endpoints protected",
            "files": unprotected,
        }
