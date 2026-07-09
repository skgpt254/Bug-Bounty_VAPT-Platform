from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import diff_engine
from app.database import get_session
from app.models import Program, ScanRun
from app.schemas import DiffOut

router = APIRouter(prefix="/api/programs", tags=["diffs"])


@router.get("/{program_id}/diff/{scan_id}", response_model=DiffOut)
async def diff_scan(program_id: int, scan_id: int, session: AsyncSession = Depends(get_session)):
    """Diff `scan_id` against the previous completed run of the same program.
    Recomputes rather than trusting persisted is_new flags, so this endpoint
    is safe to call for historical comparisons too.
    """
    program = await session.get(Program, program_id)
    scan = await session.get(ScanRun, scan_id)
    if not program or not scan or scan.program_id != program_id:
        raise HTTPException(404, "program or scan not found")

    return await diff_engine.compute_diff(session, program, scan)
