from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.orchestrator import run_scan
from app.database import async_session, get_session
from app.models import Program, ScanMode, ScanRun, ScanStatus
from app.schemas import ScanRunOut, ScanTrigger

router = APIRouter(tags=["scans"])


async def _background_scan(program_id: int, scan_id: int, mode: ScanMode) -> None:
    # Runs in its own session — the request that triggered it returns
    # immediately with a QUEUED scan record; the dashboard/API polls status.
    async with async_session() as session:
        program = await session.get(Program, program_id)
        scan = await session.get(ScanRun, scan_id)
        if program and scan:
            await run_scan(session, program, mode=mode, scan=scan)


@router.post("/api/programs/{program_id}/scan", response_model=ScanRunOut)
async def trigger_scan(
    program_id: int,
    payload: ScanTrigger,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
):
    program = await session.get(Program, program_id)
    if not program:
        raise HTTPException(404, "program not found")

    mode = ScanMode.FULL if payload.mode == "full" else ScanMode.INCREMENTAL

    # Create a placeholder QUEUED row immediately so the UI has something to
    # show/poll before the background task actually starts the orchestrator.
    placeholder = ScanRun(program_id=program.id, mode=mode, status=ScanStatus.QUEUED)
    session.add(placeholder)
    await session.commit()
    await session.refresh(placeholder)

    background_tasks.add_task(_background_scan, program_id, placeholder.id, mode)
    return placeholder


@router.get("/api/scans/{scan_id}", response_model=ScanRunOut)
async def get_scan(scan_id: int, session: AsyncSession = Depends(get_session)):
    scan = await session.get(ScanRun, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    return scan


@router.get("/api/programs/{program_id}/scans", response_model=list[ScanRunOut])
async def list_scans(program_id: int, session: AsyncSession = Depends(get_session)):
    result = await session.execute(
        select(ScanRun).where(ScanRun.program_id == program_id).order_by(ScanRun.id.desc())
    )
    return list(result.scalars())
