"""
Scan management endpoints + WebSocket for live progress.
"""

import asyncio
import hashlib
import json
import logging
from typing import Annotated

from fastapi import (
    APIRouter, BackgroundTasks, Depends, HTTPException, Query,
    WebSocket, WebSocketDisconnect,
)
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Scan, Finding as FindingModel, utcnow_naive
from ..schemas import (
    StartScanRequest, ScanOut, ScanListItem, FindingOut,
    ScanDiffOut, DiffFinding,
)
from ..scanner.core import scan_text, Finding
from ..scanner.github_scanner import scan_github_repo
from ..notifications import send_critical_alert
from ..config import settings
from ..security import WS_SUBPROTOCOL, limit_scan_creation
from ..services import inventory

router = APIRouter(prefix="/scans", tags=["scans"])
logger = logging.getLogger(__name__)

# In-memory registry: scan_id -> list of connected websockets
_ws_registry: dict[str, list[WebSocket]] = {}

# Strong references to fire-and-forget tasks; asyncio only keeps weak ones,
# so an unreferenced task can be garbage-collected before it finishes.
_background_tasks: set[asyncio.Task] = set()


def paste_label(content: str) -> str:
    """
    Stable, non-reversible stand-in for pasted content. Pasted text is full
    of the very secrets being scanned for, so it is never persisted — the
    digest still lets re-scans of identical content find each other as a
    differential baseline.
    """
    return "paste:" + hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]


async def mark_interrupted_scans() -> int:
    """
    Scans run as in-process background tasks, so a restart abandons any
    that were mid-flight. Run at startup to fail them explicitly instead
    of leaving them reported as running forever.
    """
    from ..database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        stale = (
            await db.execute(select(Scan).where(Scan.status.in_(("queued", "running"))))
        ).scalars().all()
        for scan in stale:
            scan.status = "failed"
            scan.error_message = "Interrupted by a server restart; run the scan again."
            scan.progress = 100
            scan.completed_at = utcnow_naive()
        await db.commit()
        return len(stale)


async def _broadcast(scan_id: str, payload: dict):
    sockets = _ws_registry.get(scan_id, [])
    dead = []
    for ws in sockets:
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            dead.append(ws)
    for d in dead:
        sockets.remove(d)


async def _close_scan_sockets(scan_id: str):
    """
    Call once a scan reaches a terminal state (completed/failed): nothing
    will ever be broadcast for this scan_id again, so close any sockets
    still listening and drop the registry entry — otherwise `_ws_registry`
    grows by one entry per scan ever run, for the life of the process.
    """
    sockets = _ws_registry.pop(scan_id, [])
    for ws in sockets:
        try:
            await ws.close()
        except Exception:
            pass


async def _run_scan(scan_id: str, paste_content: str | None = None):
    from ..database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            return

        scan.status = "running"
        await db.commit()

    await _broadcast(scan_id, {"event": "started", "progress": 0})

    findings: list[Finding] = []
    files_scanned = 0

    try:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)

            if scan.source_type == "paste":
                if paste_content is None:
                    raise ValueError("Pasted content is not retained; submit it again.")
                # Scanning is CPU-bound; a worker thread keeps the event loop
                # free for other requests and progress broadcasts.
                findings = await asyncio.to_thread(
                    scan_text, paste_content, "paste", scan.min_entropy
                )
                files_scanned = 1
                await _broadcast(scan_id, {"event": "progress", "progress": 80})

            elif scan.source_type == "github":
                async def _progress(pct: int, msg: str):
                    await _broadcast(scan_id, {"event": "progress", "progress": pct, "message": msg})

                findings, files_scanned = await scan_github_repo(
                    scan.source_ref,
                    scan_git_history_flag=scan.scan_git_history,
                    max_commits=scan.max_commits,
                    min_entropy=scan.min_entropy,
                    progress_callback=_progress,
                )

            # Persist findings
            for f in findings:
                db.add(FindingModel(
                    scan_id=scan_id,
                    file_path=f.file_path,
                    line_number=f.line_number,
                    secret_type=f.secret_type,
                    matched_string=f.matched_string,
                    entropy=f.entropy,
                    severity=f.severity,
                    confidence=f.confidence,
                    context=f.context,
                    commit_hash=f.commit_hash,
                    remediation=f.remediation,
                    is_in_history=f.is_in_history,
                    risk_score=f.risk_score,
                    risk_factors=f.risk_factors,
                    occurrences=f.occurrences,
                    introduced_at=f.introduced_at,
                    last_seen_at=f.last_seen_at,
                    exposure_days=f.exposure_days,
                    commits_affected=f.commits_affected,
                    authors_count=f.authors_count,
                    fingerprint=f.fingerprint,
                ))

            scan.status = "completed"
            scan.total_findings = len(findings)
            scan.files_scanned = files_scanned
            scan.progress = 100
            scan.completed_at = utcnow_naive()
            await db.commit()

        await _broadcast(scan_id, {
            "event": "completed",
            "progress": 100,
            "total_findings": len(findings),
            "files_scanned": files_scanned,
        })
        await _close_scan_sockets(scan_id)

        # Alert only on CRITICAL credentials that are new since the previous
        # scan of this source and not triaged away — not on every CRITICAL
        # finding, which made a schedule re-send the same alert every run.
        # The scan is already saved as completed — an alerting error must not
        # fall through to the failure handler below and mark it failed.
        try:
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                fresh = await inventory.new_open_critical(db, scan)
            if fresh:
                source = "pasted content" if scan.source_type == "paste" else scan.source_ref
                task = asyncio.create_task(send_critical_alert(scan_id, len(fresh), source))
                _background_tasks.add(task)
                task.add_done_callback(_background_tasks.discard)
        except Exception:
            logger.warning("Alert evaluation failed for scan %s", scan_id, exc_info=True)

    except Exception as e:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.progress = 100
                scan.completed_at = utcnow_naive()
                await db.commit()
        await _broadcast(scan_id, {"event": "failed", "error": str(e)})
        await _close_scan_sockets(scan_id)


@router.post(
    "", response_model=ScanListItem, status_code=202,
    dependencies=[Depends(limit_scan_creation)],
)
async def start_scan(
    body: StartScanRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    # Scans run in-process; cap how many run at once so a burst can't
    # exhaust a small instance's memory.
    active = (
        await db.execute(select(func.count(Scan.id)).where(Scan.status.in_(("queued", "running"))))
    ).scalar_one()
    if active >= settings.MAX_CONCURRENT_SCANS:
        raise HTTPException(
            429, f"{active} scans are already running. Try again in a minute.",
            headers={"Retry-After": "60"},
        )

    is_paste = body.source_type == "paste"
    scan = Scan(
        source_type=body.source_type,
        source_ref=paste_label(body.source_ref) if is_paste else body.source_ref,
        scan_git_history=body.scan_git_history,
        max_commits=body.max_commits,
        min_entropy=body.min_entropy,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    scan_id = scan.id
    await db.commit()

    # Pasted content travels only in memory, straight to the scan task.
    background_tasks.add_task(_run_scan, scan_id, body.source_ref if is_paste else None)
    return scan


@router.get("", response_model=list[ScanListItem])
async def list_scans(
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    )
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
async def get_findings(
    scan_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    severity: str | None = None,
    secret_type: str | None = None,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    q = select(FindingModel).where(FindingModel.scan_id == scan_id)
    if severity:
        q = q.where(FindingModel.severity == severity.upper())
    if secret_type:
        q = q.where(FindingModel.secret_type == secret_type)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{scan_id}/diff", response_model=ScanDiffOut)
async def diff_scan(scan_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    """
    Compare this scan with the most recent earlier completed scan of the same
    source, counted in credentials, not lines. A credential that moved files,
    or whose line shifted, is unchanged; a rotated key that reappears with a
    new value is new.
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    states = await inventory.load_states(db, scan.source_ref)
    current = inventory.group_credentials(await inventory.scan_findings(db, scan_id), states)
    baseline = await inventory.latest_completed_scan(db, scan.source_ref, before=scan.created_at)
    if baseline is None:
        return ScanDiffOut(has_baseline=False, current_total=len(current))
    previous = inventory.group_credentials(await inventory.scan_findings(db, baseline.id), states)

    cur_map = {c["fingerprint"]: c for c in current}
    base_map = {c["fingerprint"]: c for c in previous}
    new_keys = cur_map.keys() - base_map.keys()
    resolved_keys = base_map.keys() - cur_map.keys()

    def to_diff(c: dict) -> DiffFinding:
        loc = c["locations"][0]
        return DiffFinding(
            secret_type=c["secret_type"], severity=c["severity"],
            file_path=loc["file_path"], line_number=loc["line_number"],
            risk_score=c["risk_score"],
        )

    return ScanDiffOut(
        has_baseline=True,
        baseline_scan_id=baseline.id,
        baseline_created_at=baseline.created_at,
        current_total=len(cur_map),
        baseline_total=len(base_map),
        new_count=len(new_keys),
        resolved_count=len(resolved_keys),
        unchanged_count=len(cur_map.keys() & base_map.keys()),
        net_change=len(cur_map) - len(base_map),
        # Riskiest first; set order would differ from one request to the next.
        new_findings=sorted((to_diff(cur_map[k]) for k in new_keys), key=lambda d: -d.risk_score),
        resolved_findings=sorted((to_diff(base_map[k]) for k in resolved_keys), key=lambda d: -d.risk_score),
    )


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    await db.delete(scan)
    await db.commit()


@router.websocket("/ws/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """
    Push-only progress channel: the server broadcasts scan events, the
    client never sends anything. We still `receive()` in a loop because
    that is what surfaces the disconnect — sleeping instead would leave
    this coroutine (and its socket) alive until the process exits.
    """
    # Echo our subprotocol when offered: the client sends it alongside the
    # token (see security._presented_token), and a browser drops the
    # connection unless the server selects one of the protocols it offered.
    offered = [p.strip() for p in websocket.headers.get("sec-websocket-protocol", "").split(",")]
    await websocket.accept(subprotocol=WS_SUBPROTOCOL if WS_SUBPROTOCOL in offered else None)
    _ws_registry.setdefault(scan_id, []).append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        # Normal close, client disconnect, or a server-side close from
        # _close_scan_sockets — all end the connection the same way.
        pass
    finally:
        sockets = _ws_registry.get(scan_id, [])
        if websocket in sockets:
            sockets.remove(websocket)
