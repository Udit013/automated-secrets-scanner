"""
CipherWatch — FastAPI backend
"""

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import AsyncSessionLocal, init_db
from .models import AppSetting
from .workers.scheduler import start_scheduler, stop_scheduler, restore_schedules
from .routers import scans, export, schedules, stats, projects
from .security import auth_required, require_access

logger = logging.getLogger(__name__)

APP_VERSION = "3.0.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Reconcile in-process state lost by the last restart before serving.
    interrupted = await scans.mark_interrupted_scans()
    start_scheduler()
    restored = await restore_schedules()
    if interrupted or restored:
        logger.warning(
            "Startup: marked %d interrupted scan(s) failed, restored %d schedule(s)",
            interrupted, restored,
        )
    yield
    stop_scheduler()


app = FastAPI(
    title="CipherWatch API",
    description=(
        "Credential exposure ledger: detects hardcoded secrets in GitHub "
        "repositories and their history, tracks each credential from first "
        "commit to rotation, and gates CI on new leaks."
    ),
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    # Auth is a bearer header, not a cookie, so credentialed CORS is unneeded.
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    # Lets the frontend read the filename when it downloads an export via fetch.
    expose_headers=["Content-Disposition", "Retry-After"],
)

# Every API route sits behind the access check; it is a no-op in demo mode
# (ACCESS_TOKEN unset). /health stays public so the frontend can discover
# which mode it is talking to.
for r in (scans.router, export.router, schedules.router, stats.router, projects.router):
    app.include_router(r, prefix="/api/v1", dependencies=[Depends(require_access)])

# WebSocket route lives inside the scans router (/api/v1/scans/ws/{scan_id})


@app.get("/health")
async def health():
    async with AsyncSessionLocal() as db:
        demo = await db.get(AppSetting, "demo_seeded") is not None
    return {"status": "ok", "version": APP_VERSION, "auth_required": auth_required(), "demo": demo}
