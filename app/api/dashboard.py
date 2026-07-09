from __future__ import annotations

import re

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import diff_engine
from app.core import scheduler as scheduler_module
from app.database import get_session
from app.models import Finding, Program, ScanMode, ScanRun, ScanStatus, Severity, Subdomain, Endpoint

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="app/templates")


async def _program_summary(session: AsyncSession, program: Program) -> dict:
    latest_scan = (await session.execute(
        select(ScanRun).where(ScanRun.program_id == program.id).order_by(ScanRun.id.desc()).limit(1)
    )).scalar_one_or_none()

    sev_counts = {}
    if latest_scan:
        rows = (await session.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_run_id == latest_scan.id)
            .group_by(Finding.severity)
        )).all()
        sev_counts = {sev.value if hasattr(sev, "value") else sev: count for sev, count in rows}

    return {"program": program, "latest_scan": latest_scan, "sev_counts": sev_counts}


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, session: AsyncSession = Depends(get_session)):
    programs = (await session.execute(select(Program).order_by(Program.created_at.desc()))).scalars()
    summaries = [await _program_summary(session, p) for p in programs]
    return templates.TemplateResponse("dashboard.html", {"request": request, "summaries": summaries})


@router.post("/programs/create")
async def create_program_form(
    name: str = Form(...),
    root_domain: str = Form(...),
    scope_regex: str = Form(...),
    out_of_scope_regex: str = Form(""),
    monitoring_enabled: bool = Form(False),
    monitoring_interval_minutes: int = Form(360),
    webhook_url: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    try:
        re.compile(scope_regex)
    except re.error:
        return RedirectResponse("/?error=invalid_regex", status_code=303)

    program = Program(
        name=name, root_domain=root_domain, scope_regex=scope_regex,
        out_of_scope_regex=out_of_scope_regex, monitoring_enabled=monitoring_enabled,
        monitoring_interval_minutes=max(monitoring_interval_minutes, 15), webhook_url=webhook_url,
    )
    session.add(program)
    await session.commit()
    await session.refresh(program)
    if program.monitoring_enabled:
        scheduler_module.schedule_program(program)
    return RedirectResponse(f"/programs/{program.id}", status_code=303)


@router.get("/programs/{program_id}", response_class=HTMLResponse)
async def program_detail(request: Request, program_id: int, session: AsyncSession = Depends(get_session)):
    program = await session.get(Program, program_id)
    if not program:
        return HTMLResponse("Program not found", status_code=404)

    scans = list((await session.execute(
        select(ScanRun).where(ScanRun.program_id == program_id).order_by(ScanRun.id.desc()).limit(20)
    )).scalars())

    latest_completed = next((s for s in scans if s.status == ScanStatus.COMPLETED), None)

    findings, diff, subdomains, endpoints = [], None, [], []
    if latest_completed:
        findings = list((await session.execute(
            select(Finding).where(Finding.scan_run_id == latest_completed.id)
            .order_by(Finding.severity.desc(), Finding.id.desc())
        )).scalars())
        diff = await diff_engine.compute_diff(session, program, latest_completed)
        subdomains = list((await session.execute(
            select(Subdomain).where(Subdomain.scan_run_id == latest_completed.id).order_by(Subdomain.hostname)
        )).scalars())
        endpoints = list((await session.execute(
            select(Endpoint).where(Endpoint.scan_run_id == latest_completed.id).order_by(Endpoint.url)
        )).scalars())

    return templates.TemplateResponse("program_detail.html", {
        "request": request, "program": program, "scans": scans,
        "latest_completed": latest_completed, "findings": findings, "diff": diff,
        "subdomains": subdomains, "endpoints": endpoints, "severities": [s.value for s in Severity],
    })


@router.post("/programs/{program_id}/scan")
async def trigger_scan_form(
    program_id: int,
    background_tasks: BackgroundTasks,
    mode: str = Form("full"),
    session: AsyncSession = Depends(get_session),
):
    from app.api.scans import _background_scan  # reuse the same background runner as the JSON API

    program = await session.get(Program, program_id)
    if not program:
        return HTMLResponse("Program not found", status_code=404)

    scan_mode = ScanMode.FULL if mode == "full" else ScanMode.INCREMENTAL
    placeholder = ScanRun(program_id=program.id, mode=scan_mode, status=ScanStatus.QUEUED)
    session.add(placeholder)
    await session.commit()
    await session.refresh(placeholder)

    background_tasks.add_task(_background_scan, program_id, placeholder.id, scan_mode)
    return RedirectResponse(f"/programs/{program_id}", status_code=303)


@router.post("/programs/{program_id}/monitoring")
async def update_monitoring_form(
    program_id: int,
    enabled: bool = Form(False),
    interval_minutes: int = Form(360),
    webhook_url: str = Form(""),
    session: AsyncSession = Depends(get_session),
):
    program = await session.get(Program, program_id)
    if program:
        program.monitoring_enabled = enabled
        program.monitoring_interval_minutes = max(interval_minutes, 15)
        if webhook_url:
            program.webhook_url = webhook_url
        await session.commit()
        if enabled:
            scheduler_module.schedule_program(program)
        else:
            scheduler_module.unschedule_program(program.id)
    return RedirectResponse(f"/programs/{program_id}", status_code=303)
