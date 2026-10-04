"""
APScheduler-based recurring scan scheduler.
Uses AsyncIOScheduler with in-memory job store.
"""

import logging
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

logger = logging.getLogger(__name__)

_scheduler = AsyncIOScheduler()


def start_scheduler():
    if not _scheduler.running:
        _scheduler.start()


def stop_scheduler():
    if _scheduler.running:
        _scheduler.shutdown(wait=False)


async def _run_scheduled_scan(schedule_id: str, source_type: str, source_ref: str):
    from ..database import AsyncSessionLocal
    from ..models import ScanSchedule, Scan, utcnow_naive
    from ..routers.scans import _run_scan

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

        schedule.last_run_at = utcnow_naive()
        schedule.last_scan_id = scan_id
        await db.commit()

    await _run_scan(scan_id)

    async with AsyncSessionLocal() as db:
        schedule = await db.get(ScanSchedule, schedule_id)
        if schedule:
            nrt = _next_run_time(_scheduler.get_job(schedule_id))
            if nrt:
                schedule.next_run_at = nrt
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
    return _next_run_time(job)


async def restore_schedules() -> int:
    """
    Re-register every stored schedule with the in-memory scheduler.

    APScheduler's job store lives in process memory, so without this every
    restart (or free-tier sleep/wake) silently drops all schedules while the
    database and UI still report them as armed. Paused schedules are
    registered too — otherwise re-enabling one later would have no job to
    resume.
    """
    from ..database import AsyncSessionLocal
    from ..models import ScanSchedule

    restored = 0
    async with AsyncSessionLocal() as db:
        schedules = (await db.execute(select(ScanSchedule))).scalars().all()
        for s in schedules:
            if s.source_type != "github":
                logger.warning("Skipping schedule %s: unsupported source type %r", s.id, s.source_type)
                continue
            try:
                next_run = add_schedule(s.id, s.cron_expression, s.source_type, s.source_ref)
            except ValueError:
                logger.warning("Skipping schedule %s: invalid cron %r", s.id, s.cron_expression)
                continue
            if s.enabled:
                s.next_run_at = next_run
            else:
                pause_schedule(s.id)
            restored += 1
        await db.commit()
    return restored


def _next_run_time(job) -> Optional[datetime]:
    """
    Safe accessor: a Job only gains `next_run_time` once the scheduler is
    running; before that (e.g. during startup or in tests) the attribute
    does not exist at all. Fall back to computing it from the trigger.
    """
    if job is None:
        return None
    nrt = getattr(job, "next_run_time", None)
    if nrt is not None:
        return nrt
    try:
        from datetime import timezone
        return job.trigger.get_next_fire_time(None, datetime.now(timezone.utc))
    except Exception:
        return None


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
