from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Scan, Finding
from ..schemas import StatsOut, ScanListItem

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsOut)
async def get_stats(db: Annotated[AsyncSession, Depends(get_db)]):
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar_one()
    total_findings = (await db.execute(select(func.count(Finding.id)))).scalar_one()

    sev_counts: dict[str, int] = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = (
            await db.execute(
                select(func.count(Finding.id)).where(Finding.severity == sev)
            )
        ).scalar_one()
        sev_counts[sev] = count

    # By type
    type_rows = (
        await db.execute(
            select(Finding.secret_type, func.count(Finding.id).label("c"))
            .group_by(Finding.secret_type)
            .order_by(func.count(Finding.id).desc())
            .limit(20)
        )
    ).all()
    by_type = {row.secret_type: row.c for row in type_rows}

    # Recent scans
    recent = (
        await db.execute(
            select(Scan).order_by(Scan.created_at.desc()).limit(5)
        )
    ).scalars().all()

    # Findings over time (last 30 days, grouped by date)
    from sqlalchemy import cast, Date, text
    date_rows = (
        await db.execute(
            select(
                func.date(Scan.created_at).label("date"),
                func.coalesce(func.sum(Scan.total_findings), 0).label("count"),
            )
            .group_by(func.date(Scan.created_at))
            .order_by(func.date(Scan.created_at))
            .limit(30)
        )
    ).all()
    findings_over_time = [{"date": str(r.date), "count": int(r.count)} for r in date_rows]

    return StatsOut(
        total_scans=total_scans,
        total_findings=total_findings,
        critical_count=sev_counts.get("CRITICAL", 0),
        high_count=sev_counts.get("HIGH", 0),
        medium_count=sev_counts.get("MEDIUM", 0),
        low_count=sev_counts.get("LOW", 0),
        by_type=by_type,
        recent_scans=[ScanListItem.model_validate(s) for s in recent],
        findings_over_time=findings_over_time,
    )
