from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Program, ScanRun, Subdomain, Endpoint, Finding, ScanStatus
from app.schemas import DiffOut, FindingOut


def fingerprint(finding_type: str, target: str, name: str) -> str:
    """Stable identity for a finding across runs, independent of exact wording
    or timestamps. Used to decide "have we seen this before" for both the
    is_new flag and alert dedupe.
    """
    raw = f"{finding_type}|{target}|{name}".lower().strip()
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


async def _previous_completed_run(session: AsyncSession, program: Program, before_id: int) -> ScanRun | None:
    result = await session.execute(
        select(ScanRun)
        .where(ScanRun.program_id == program.id)
        .where(ScanRun.status == ScanStatus.COMPLETED)
        .where(ScanRun.id < before_id)
        .order_by(ScanRun.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def compute_diff(session: AsyncSession, program: Program, current: ScanRun) -> DiffOut:
    baseline = await _previous_completed_run(session, program, current.id)

    cur_subs = {s.hostname for s in (await session.execute(
        select(Subdomain).where(Subdomain.scan_run_id == current.id)
    )).scalars()}
    cur_eps = {e.url for e in (await session.execute(
        select(Endpoint).where(Endpoint.scan_run_id == current.id)
    )).scalars()}
    cur_findings = list((await session.execute(
        select(Finding).where(Finding.scan_run_id == current.id)
    )).scalars())

    if baseline is None:
        # First scan for this program — everything is "new" by definition,
        # but we don't call it a diff finding-by-finding to avoid alert spam
        # on day one. Assets are still recorded as new for dashboard display.
        for s_row in (await session.execute(select(Subdomain).where(Subdomain.scan_run_id == current.id))).scalars():
            s_row.is_new = True
        for e_row in (await session.execute(select(Endpoint).where(Endpoint.scan_run_id == current.id))).scalars():
            e_row.is_new = True
        for f_row in cur_findings:
            f_row.is_new = False  # don't alert on baseline; do surface on dashboard as "first scan"
        await session.commit()
        return DiffOut(
            baseline_scan_id=None, current_scan_id=current.id,
            new_subdomains=sorted(cur_subs), removed_subdomains=[],
            new_endpoints=sorted(cur_eps), new_findings=[],
        )

    prev_subs = {s.hostname for s in (await session.execute(
        select(Subdomain).where(Subdomain.scan_run_id == baseline.id)
    )).scalars()}
    prev_eps = {e.url for e in (await session.execute(
        select(Endpoint).where(Endpoint.scan_run_id == baseline.id)
    )).scalars()}
    prev_fingerprints = {f.fingerprint for f in (await session.execute(
        select(Finding).where(Finding.scan_run_id == baseline.id)
    )).scalars()}

    new_subs = cur_subs - prev_subs
    removed_subs = prev_subs - cur_subs
    new_eps = cur_eps - prev_eps

    new_finding_rows = []
    for f_row in cur_findings:
        if f_row.fingerprint not in prev_fingerprints:
            f_row.is_new = True
            new_finding_rows.append(f_row)

    sub_rows = (await session.execute(select(Subdomain).where(Subdomain.scan_run_id == current.id))).scalars()
    for s_row in sub_rows:
        s_row.is_new = s_row.hostname in new_subs

    ep_rows = (await session.execute(select(Endpoint).where(Endpoint.scan_run_id == current.id))).scalars()
    for e_row in ep_rows:
        e_row.is_new = e_row.url in new_eps

    await session.commit()

    return DiffOut(
        baseline_scan_id=baseline.id,
        current_scan_id=current.id,
        new_subdomains=sorted(new_subs),
        removed_subdomains=sorted(removed_subs),
        new_endpoints=sorted(new_eps),
        new_findings=[FindingOut.model_validate(f) for f in new_finding_rows],
    )
