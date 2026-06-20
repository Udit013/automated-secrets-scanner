import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Annotated

from ..database import get_db
from ..models import Scan, Finding
from ..scanner.sarif import build_sarif
from ..scanner.remediation import build_remediation, build_patch

router = APIRouter(prefix="/export", tags=["export"])


async def _load_scan_findings(scan_id: str, db: AsyncSession):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    return scan, result.scalars().all()


@router.get("/{scan_id}/json")
async def export_json(scan_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = result.scalars().all()

    payload = {
        "scan_id": scan.id,
        "source_type": scan.source_type,
        "source_ref": scan.source_ref,
        "status": scan.status,
        "total_findings": scan.total_findings,
        "files_scanned": scan.files_scanned,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "findings": [
            {
                "id": f.id,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "secret_type": f.secret_type,
                "matched_string": f.matched_string,
                "entropy": f.entropy,
                "severity": f.severity,
                "confidence": f.confidence,
                "context": f.context,
                "commit_hash": f.commit_hash,
                "remediation": f.remediation,
                "is_in_history": f.is_in_history,
                "risk_score": f.risk_score,
                "risk_factors": f.risk_factors,
                "occurrences": f.occurrences,
                "introduced_at": f.introduced_at.isoformat() if f.introduced_at else None,
                "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
                "exposure_days": f.exposure_days,
                "commits_affected": f.commits_affected,
                "authors_count": f.authors_count,
            }
            for f in findings
        ],
    }

    content = json.dumps(payload, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id[:8]}.json"'},
    )


@router.get("/{scan_id}/csv")
async def export_csv(scan_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = result.scalars().all()

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "file_path", "line_number", "secret_type", "matched_string",
            "entropy", "severity", "confidence", "context", "commit_hash",
            "is_in_history", "remediation",
        ],
    )
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "file_path": f.file_path,
            "line_number": f.line_number,
            "secret_type": f.secret_type,
            "matched_string": f.matched_string,
            "entropy": f.entropy,
            "severity": f.severity,
            "confidence": f.confidence,
            "context": f.context,
            "commit_hash": f.commit_hash or "",
            "is_in_history": f.is_in_history,
            "remediation": f.remediation,
        })

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id[:8]}.csv"'},
    )


@router.get("/{scan_id}/sarif")
async def export_sarif(scan_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    """SARIF 2.1.0 — compatible with GitHub Advanced Security code scanning."""
    scan, findings = await _load_scan_findings(scan_id, db)
    content = json.dumps(build_sarif(scan, findings), indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id[:8]}.sarif"'},
    )


@router.get("/{scan_id}/remediation")
async def export_remediation(scan_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    """Structured remediation report (JSON) — before/after, .env.example, next steps."""
    scan, findings = await _load_scan_findings(scan_id, db)
    return build_remediation(scan, findings)


@router.get("/{scan_id}/patch")
async def export_patch(scan_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    """Downloadable remediation.patch (unified-diff style env-var replacements)."""
    scan, findings = await _load_scan_findings(scan_id, db)
    content = build_patch(scan, findings)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/x-patch",
        headers={"Content-Disposition": f'attachment; filename="remediation_{scan_id[:8]}.patch"'},
    )
