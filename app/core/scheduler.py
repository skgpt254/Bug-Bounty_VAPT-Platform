"""Continuous monitoring. On a per-program interval, runs an INCREMENTAL scan
(no fuzzing — fast, polite) and relies on the orchestrator's built-in diff +
alerting to only notify on genuinely new subdomains/endpoints/findings.
"""

from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select

from app.core.orchestrator import run_scan
from app.database import async_session
from app.models import Program, ScanMode

logger = logging.getLogger("bugbounty.scheduler")

scheduler = AsyncIOScheduler()

JOB_PREFIX = "monitor_program_"


async def _run_monitor_scan(program_id: int) -> None:
    async with async_session() as session:
        program = await session.get(Program, program_id)
        if not program or not program.monitoring_enabled:
            return
        logger.info("continuous monitoring: running incremental scan for %s", program.name)
        await run_scan(session, program, mode=ScanMode.INCREMENTAL)


def schedule_program(program: Program) -> None:
    job_id = f"{JOB_PREFIX}{program.id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if not program.monitoring_enabled:
        return
    scheduler.add_job(
        _run_monitor_scan,
        "interval",
        minutes=program.monitoring_interval_minutes,
        args=[program.id],
        id=job_id,
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    logger.info("scheduled continuous monitoring for %s every %d minutes",
                program.name, program.monitoring_interval_minutes)


def unschedule_program(program_id: int) -> None:
    job_id = f"{JOB_PREFIX}{program_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


async def load_all_schedules() -> None:
    async with async_session() as session:
        programs = (await session.execute(select(Program).where(Program.monitoring_enabled.is_(True)))).scalars()
        for program in programs:
            schedule_program(program)
