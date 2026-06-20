"""
Scan management endpoints + WebSocket for live progress.
"""

import asyncio
import json
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Scan, Finding as FindingModel
from ..schemas import (
    StartScanRequest, ScanOut, ScanListItem, FindingOut,
    ScanDiffOut, DiffFinding,
)
from ..scanner.core import scan_text, Finding
from ..scanner.github_scanner import scan_github_repo
from ..notifications import send_critical_alert

router = APIRouter(prefix="/scans", tags=["scans"])

# In-memory registry: scan_id -> list of connected websockets
_ws_registry: dict[str, list[WebSocket]] = {}


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


async def _run_scan(scan_id: str):
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
                findings = scan_text(scan.source_ref, "paste", scan.min_entropy)
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
                ))

            scan.status = "completed"
            scan.total_findings = len(findings)
            scan.files_scanned = files_scanned
            scan.progress = 100
            scan.completed_at = datetime.utcnow()
            await db.commit()

        await _broadcast(scan_id, {
            "event": "completed",
            "progress": 100,
            "total_findings": len(findings),
            "files_scanned": files_scanned,
        })

        # Email alert for critical findings
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        if critical > 0:
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                asyncio.create_task(
                    send_critical_alert(scan_id, critical, scan.source_ref)
                )

    except Exception as e:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.progress = 100
                scan.completed_at = datetime.utcnow()
                await db.commit()
        await _broadcast(scan_id, {"event": "failed", "error": str(e)})


@router.post("", response_model=ScanListItem, status_code=202)
async def start_scan(
    body: StartScanRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    scan = Scan(
        source_type=body.source_type,
        source_ref=body.source_ref,
        scan_git_history=body.scan_git_history,
        max_commits=body.max_commits,
        min_entropy=body.min_entropy,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    scan_id = scan.id
    await db.commit()

    background_tasks.add_task(_run_scan, scan_id)
    return scan


@router.get("", response_model=list[ScanListItem])
async def list_scans(
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 50,
    offset: int = 0,
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
    limit: int = 500,
    offset: int = 0,
):
    q = select(FindingModel).where(FindingModel.scan_id == scan_id)
    if severity:
        q = q.where(FindingModel.severity == severity.upper())
    if secret_type:
        q = q.where(FindingModel.secret_type == secret_type)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    return result.scalars().all()


def _finding_key(f) -> tuple:
    """Stable identity for a secret across scans (line numbers may shift)."""
    return (f.file_path, f.secret_type, f.matched_string)


@router.get("/{scan_id}/diff", response_model=ScanDiffOut)
async def diff_scan(scan_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    """
    Compare this scan against the most recent earlier *completed* scan of the
    same source — surfacing newly introduced and resolved secrets.
    """
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    baseline = (
        await db.execute(
            select(Scan)
            .where(
                Scan.source_ref == scan.source_ref,
                Scan.status == "completed",
                Scan.created_at < scan.created_at,
                Scan.id != scan.id,
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    cur = (
        await db.execute(select(FindingModel).where(FindingModel.scan_id == scan_id))
    ).scalars().all()

    if not baseline:
        return ScanDiffOut(has_baseline=False, current_total=len(cur))

    base = (
        await db.execute(select(FindingModel).where(FindingModel.scan_id == baseline.id))
    ).scalars().all()

    cur_map = {_finding_key(f): f for f in cur}
    base_map = {_finding_key(f): f for f in base}

    new_keys = cur_map.keys() - base_map.keys()
    resolved_keys = base_map.keys() - cur_map.keys()
    unchanged_keys = cur_map.keys() & base_map.keys()

    def to_diff(f) -> DiffFinding:
        return DiffFinding(
            secret_type=f.secret_type,
            severity=f.severity,
            file_path=f.file_path,
            line_number=f.line_number,
            risk_score=f.risk_score or 0,
        )

    return ScanDiffOut(
        has_baseline=True,
        baseline_scan_id=baseline.id,
        baseline_created_at=baseline.created_at,
        current_total=len(cur),
        baseline_total=len(base),
        new_count=len(new_keys),
        resolved_count=len(resolved_keys),
        unchanged_count=len(unchanged_keys),
        net_change=len(cur) - len(base),
        new_findings=[to_diff(cur_map[k]) for k in new_keys],
        resolved_findings=[to_diff(base_map[k]) for k in resolved_keys],
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
    await websocket.accept()
    _ws_registry.setdefault(scan_id, []).append(websocket)
    try:
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        sockets = _ws_registry.get(scan_id, [])
        if websocket in sockets:
            sockets.remove(websocket)
