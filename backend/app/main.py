"""
Automated Secrets Scanner — FastAPI backend
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db
from .workers.scheduler import start_scheduler, stop_scheduler
from .routers import scans, export, schedules, stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(
    title="Automated Secrets Scanner API",
    description=(
        "DevSecOps tool for detecting hardcoded secrets using pattern matching, "
        "Shannon entropy analysis, and semantic heuristics."
    ),
    version="2.0.0",
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
    return {"status": "ok", "version": "2.0.0"}
