from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_session
from app.models import Finding
from app.schemas import FindingOut

router = APIRouter(prefix="/api/programs", tags=["findings"])


@router.get("/{program_id}/findings", response_model=list[FindingOut])
async def list_findings(
    program_id: int,
    severity: str | None = None,
    finding_type: str | None = None,
    only_new: bool = False,
    session: AsyncSession = Depends(get_session),
):
    query = select(Finding).where(Finding.program_id == program_id).order_by(Finding.id.desc())
    if severity:
        query = query.where(Finding.severity == severity)
    if finding_type:
        query = query.where(Finding.finding_type == finding_type)
    if only_new:
        query = query.where(Finding.is_new.is_(True))

    result = await session.execute(query.limit(500))
    return list(result.scalars())
