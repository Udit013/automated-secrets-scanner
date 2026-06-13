from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import ScanSchedule
from ..schemas import ScheduleCreate, ScheduleOut

router = APIRouter(prefix="/schedules", tags=["schedules"])


@router.post("", response_model=ScheduleOut, status_code=201)
async def create_schedule(
    body: ScheduleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    schedule = ScanSchedule(
        name=body.name,
        source_type=body.source_type,
        source_ref=body.source_ref,
        cron_expression=body.cron_expression,
        scan_git_history=body.scan_git_history,
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)

    # Register with APScheduler
    from ..workers.scheduler import add_schedule
    next_run = add_schedule(schedule.id, schedule.cron_expression, schedule.source_type, schedule.source_ref)
    schedule.next_run_at = next_run
    await db.commit()
    return schedule


@router.get("", response_model=list[ScheduleOut])
async def list_schedules(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(select(ScanSchedule).order_by(ScanSchedule.created_at.desc()))
    return result.scalars().all()


@router.get("/{schedule_id}", response_model=ScheduleOut)
async def get_schedule(schedule_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    s = await db.get(ScanSchedule, schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    return s


@router.patch("/{schedule_id}/toggle", response_model=ScheduleOut)
async def toggle_schedule(schedule_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    s = await db.get(ScanSchedule, schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    s.enabled = not s.enabled
    from ..workers.scheduler import pause_schedule, resume_schedule
    if s.enabled:
        resume_schedule(schedule_id)
    else:
        pause_schedule(schedule_id)
    await db.commit()
    return s


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: str, db: Annotated[AsyncSession, Depends(get_db)]):
    s = await db.get(ScanSchedule, schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    from ..workers.scheduler import remove_schedule
    remove_schedule(schedule_id)
    await db.delete(s)
    await db.commit()
