from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import is_public_http_target
from app.core import scheduler as scheduler_module
from app.core.scope import UnsafeScopeRegexError, validate_scope_regex
from app.core.security import require_api_key
from app.database import get_session
from app.models import Program
from app.schemas import ProgramCreate, ProgramOut

router = APIRouter(prefix="/api/programs", tags=["programs"], dependencies=[Depends(require_api_key)])


def _validate_program_payload(scope_regex: str, out_of_scope_regex: str, webhook_url: str) -> None:
    try:
        validate_scope_regex(scope_regex)
        if out_of_scope_regex:
            validate_scope_regex(out_of_scope_regex)
    except UnsafeScopeRegexError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:  # re.error etc.
        raise HTTPException(400, f"invalid regex: {exc}")

    if webhook_url and not is_public_http_target(webhook_url):
        raise HTTPException(
            400,
            "webhook_url must be a public https/http URL — localhost, private IP ranges, "
            "and link-local addresses are rejected to prevent SSRF",
        )


@router.post("", response_model=ProgramOut)
async def create_program(payload: ProgramCreate, session: AsyncSession = Depends(get_session)):
    _validate_program_payload(payload.scope_regex, payload.out_of_scope_regex, payload.webhook_url)

    existing = await session.execute(select(Program).where(Program.name == payload.name))
    if existing.scalar_one_or_none():
        raise HTTPException(409, "a program with this name already exists")

    program = Program(**payload.model_dump())
    session.add(program)
    await session.commit()
    await session.refresh(program)

    if program.monitoring_enabled:
        scheduler_module.schedule_program(program)

    return program


@router.get("", response_model=list[ProgramOut])
async def list_programs(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Program).order_by(Program.created_at.desc()))
    return list(result.scalars())


@router.get("/{program_id}", response_model=ProgramOut)
async def get_program(program_id: int, session: AsyncSession = Depends(get_session)):
    program = await session.get(Program, program_id)
    if not program:
        raise HTTPException(404, "program not found")
    return program


@router.patch("/{program_id}/monitoring", response_model=ProgramOut)
async def update_monitoring(
    program_id: int,
    enabled: bool,
    interval_minutes: int = 360,
    webhook_url: str = "",
    session: AsyncSession = Depends(get_session),
):
    program = await session.get(Program, program_id)
    if not program:
        raise HTTPException(404, "program not found")

    if webhook_url and not is_public_http_target(webhook_url):
        raise HTTPException(400, "webhook_url rejected — must be a public https/http URL (SSRF guard)")

    program.monitoring_enabled = enabled
    program.monitoring_interval_minutes = max(interval_minutes, 15)
    if webhook_url:
        program.webhook_url = webhook_url
    await session.commit()
    await session.refresh(program)

    if enabled:
        scheduler_module.schedule_program(program)
    else:
        scheduler_module.unschedule_program(program.id)

    return program


@router.delete("/{program_id}")
async def delete_program(program_id: int, session: AsyncSession = Depends(get_session)):
    program = await session.get(Program, program_id)
    if not program:
        raise HTTPException(404, "program not found")
    scheduler_module.unschedule_program(program.id)
    await session.delete(program)
    await session.commit()
    return {"deleted": True}
