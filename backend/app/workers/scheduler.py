"""
APScheduler-based recurring scan scheduler.
Uses AsyncIOScheduler with in-memory job store.
"""

import asyncio
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

_scheduler = AsyncIOScheduler()


def start_scheduler():
    if not _scheduler.running:
        _scheduler.start()


def stop_scheduler():
    if _scheduler.running:
        _scheduler.shutdown(wait=False)


async def _run_scheduled_scan(schedule_id: str, source_type: str, source_ref: str):
    from ..database import AsyncSessionLocal
    from ..models import ScanSchedule, Scan
    from ..routers.scans import _run_scan
    from datetime import datetime

    async with AsyncSessionLocal() as db:
        schedule = await db.get(ScanSchedule, schedule_id)
        if not schedule or not schedule.enabled:
            return

        scan = Scan(
            source_type=source_type,
            source_ref=source_ref,
            scan_git_history=schedule.scan_git_history,
        )
        db.add(scan)
        await db.flush()
        await db.refresh(scan)
        scan_id = scan.id

        schedule.last_run_at = datetime.utcnow()
        schedule.last_scan_id = scan_id
        await db.commit()

    await _run_scan(scan_id)

    async with AsyncSessionLocal() as db:
        schedule = await db.get(ScanSchedule, schedule_id)
        if schedule:
            job = _scheduler.get_job(schedule_id)
            if job and job.next_run_time:
                schedule.next_run_at = job.next_run_time
            await db.commit()


def add_schedule(
    schedule_id: str,
    cron_expression: str,
    source_type: str,
    source_ref: str,
) -> Optional[datetime]:
    parts = cron_expression.strip().split()
    if len(parts) != 5:
        raise ValueError("Cron expression must have 5 fields: minute hour day month weekday")

    minute, hour, day, month, weekday = parts
    trigger = CronTrigger(
        minute=minute, hour=hour, day=day, month=month, day_of_week=weekday
    )

    _scheduler.add_job(
        _run_scheduled_scan,
        trigger=trigger,
        id=schedule_id,
        replace_existing=True,
        args=[schedule_id, source_type, source_ref],
    )

    job = _scheduler.get_job(schedule_id)
    return job.next_run_time if job else None


def remove_schedule(schedule_id: str):
    try:
        _scheduler.remove_job(schedule_id)
    except Exception:
        pass


def pause_schedule(schedule_id: str):
    try:
        _scheduler.pause_job(schedule_id)
    except Exception:
        pass


def resume_schedule(schedule_id: str):
    try:
        _scheduler.resume_job(schedule_id)
    except Exception:
        pass
