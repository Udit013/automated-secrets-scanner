"""
CipherWatch — FastAPI backend
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db
from .workers.scheduler import start_scheduler, stop_scheduler, restore_schedules
from .routers import scans, export, schedules, stats

logger = logging.getLogger(__name__)


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
        "DevSecOps tool for detecting hardcoded secrets using regex pattern "
        "matching, Shannon entropy analysis, and placeholder filtering."
    ),
    version="2.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router, prefix="/api/v1")
app.include_router(export.router, prefix="/api/v1")
app.include_router(schedules.router, prefix="/api/v1")
app.include_router(stats.router, prefix="/api/v1")

# WebSocket route lives inside the scans router (/api/v1/scans/ws/{scan_id})


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.1.0"}
