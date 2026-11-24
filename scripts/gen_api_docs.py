"""Generate docs/api.md from the FastAPI application.

Usage (from the repository root, with the backend dependencies installed):

    python scripts/gen_api_docs.py

The script imports ``app.main:app`` in SQLite mode, so it needs no running
database. It only reads the registered routes and the RBAC permission matrix.
"""
import io
import logging
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("SQLITE_MODE", "true")
sys.path.insert(0, str(REPO_ROOT / "app" / "backend"))
logging.disable(logging.CRITICAL)

from app.core.rbac import PERMISSIONS, ROLES  # noqa: E402
from app.main import app  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402


def deps(dependant, acc):
    for d in dependant.dependencies:
        c = d.call
        name = getattr(c, "__qualname__", str(c))
        perm = None
        for cell in (getattr(c, "__closure__", None) or ()):
            try: v = cell.cell_contents
            except ValueError: continue
            if isinstance(v, str) and v in PERMISSIONS: perm = v
        acc.append(perm or name)
        deps(d, acc)

SPECIAL = {
 "/api/v1/auth/login": "Public. Email and password in the body",
 "/api/v1/auth/mfa/verify": "MFA token from the login response",
 "/api/v1/auth/refresh": "Refresh token in the body",
 "/api/v1/auth/logout": "Bearer access token",
 "/api/v1/auth/change-password": "Password-change token from the login response",
 "/api/v1/ingest": "`X-MxTac-Source` and `X-MxTac-Token` headers of a `generic` connector",
 "/api/v1/ingest/test": "`X-MxTac-Source` and `X-MxTac-Token` headers of a `generic` connector",
 "/health": "Public", "/ready": "Public", "/metrics": "Public",
}
GROUPS = [
 ("Operations", lambda p: not p.startswith("/api/v1")),
 ("Authentication", lambda p: p.startswith("/api/v1/auth")),
 ("Overview", lambda p: p.startswith("/api/v1/overview")),
 ("Coverage", lambda p: p.startswith("/api/v1/coverage")),
 ("Detections", lambda p: p.startswith("/api/v1/detections")),
 ("Incidents", lambda p: p.startswith("/api/v1/incidents")),
 ("Sigma rules", lambda p: p.startswith("/api/v1/rules")),
 ("Connectors", lambda p: p.startswith("/api/v1/connectors")),
 ("Users", lambda p: p.startswith("/api/v1/users")),
 ("Events", lambda p: p.startswith("/api/v1/events")),
 ("Saved hunt queries", lambda p: p.startswith("/api/v1/hunt")),
 ("Webhook ingest", lambda p: p.startswith("/api/v1/ingest")),
]
rows = {g: [] for g, _ in GROUPS}
ws = []
for r in app.routes:
    path = getattr(r, "path", "")
    if isinstance(r, APIRoute):
        acc = []; deps(r.dependant, acc)
        perms = [a for a in acc if a in PERMISSIONS]
        if path in SPECIAL: auth = SPECIAL[path]
        elif perms: auth = "`%s`" % perms[0]
        elif "get_current_user" in acc: auth = "Any signed-in user"
        else: auth = "UNKNOWN"
        desc = (r.summary or (r.endpoint.__doc__ or "").strip().split("\n")[0]).strip().rstrip(".")
        desc = desc.replace("|", "\\|").replace("\u2014", "-").replace("\u00d7", "x")
        if not desc: desc = r.name.replace("_", " ").capitalize()
        for g, f in GROUPS:
            if f(path):
                for m in sorted(r.methods): rows[g].append((m, path, auth, desc))
                break
        else: raise SystemExit("ungrouped " + path)
    elif type(r).__name__ == "APIWebSocketRoute":
        ws.append(path)

out = io.StringIO(newline="\n")
w = lambda s="": out.write(s + "\n")
w("# API reference")
w()
w("This file is generated from the FastAPI application (`app.main:app`) by `scripts/gen_api_docs.py`. Do not edit it by hand. It lists every route the backend registers. For request and response schemas, start the backend and open `/docs` (Swagger UI) or `/openapi.json`.")
w()
w("## Conventions")
w()
w("- All REST routes except the operations routes are under `/api/v1`.")
w("- Send the access token as `Authorization: Bearer <token>`. `POST /api/v1/auth/login` returns it.")
w("- The **Auth** column shows the permission a route requires. The permission table below maps permissions to roles.")
w("- A request without a valid token gets `401`. A role without the permission gets `403`.")
w("- Rate limits apply per client IP and minute: 10 requests for login and MFA routes, 5 for export routes, 60 for other `POST`, `PUT`, `PATCH` and `DELETE` requests, and 300 for `GET` requests. A limited request gets `429` with a `Retry-After` header. `/health`, `/ready` and `/metrics` are not limited.")
w()
w("## Permissions")
w()
w("Source: `app/backend/app/core/rbac.py`.")
w()
w("| Permission | " + " | ".join(ROLES) + " |")
w("|---|" + "|".join([":-:"] * len(ROLES)) + "|")
for perm, allowed in PERMISSIONS.items():
    w("| `%s` | " % perm + " | ".join("yes" if role in allowed else "-" for role in ROLES) + " |")
w()
w("## Routes")
for g, _ in GROUPS:
    if not rows[g]: continue
    w(); w("### " + g); w()
    w("| Method | Path | Auth | Description |")
    w("|---|---|---|---|")
    for m, p, a, d in rows[g]:
        w("| %s | `%s` | %s | %s |" % (m, p, a, d))
w()
w("### WebSocket")
w()
w("| Path | Auth | Description |")
w("|---|---|---|")
for p in ws:
    w("| `%s` | None. The server does not validate the `token` query parameter the UI sends | Pushes each new detection as `{\"type\": \"alert\", \"data\": {...}}` and a `ping` message every 30 seconds |" % p)
w()
w("### Interactive documentation")
w()
w("| Path | Description |")
w("|---|---|")
w("| `/docs` | Swagger UI |")
w("| `/redoc` | ReDoc |")
w("| `/openapi.json` | OpenAPI schema |")
open(r"C:\repos\mxtac\docs\api.md", "w", encoding="utf-8", newline="\n").write(out.getvalue())
n = sum(len(v) for v in rows.values())
unk = [r for v in rows.values() for r in v if r[2] == "UNKNOWN"]
print("routes", n, "ws", ws, "unknown", unk)
