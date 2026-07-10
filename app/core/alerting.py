from __future__ import annotations

import logging

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings, is_public_http_target
from app.models import AlertLog, Finding, Program
from app.schemas import DiffOut

logger = logging.getLogger("bugbounty.alerting")

SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _format_message(program: Program, diff: DiffOut) -> str:
    lines = [f"*New findings for {program.name}* (scan #{diff.current_scan_id})"]
    if diff.new_subdomains:
        lines.append(f"• {len(diff.new_subdomains)} new subdomain(s): " + ", ".join(diff.new_subdomains[:10]))
    for f in diff.new_findings[:25]:
        emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
        lines.append(f"{emoji} [{f.severity.upper()}] {f.name} — {f.target}")
    if len(diff.new_findings) > 25:
        lines.append(f"...and {len(diff.new_findings) - 25} more.")
    return "\n".join(lines)


async def send_new_finding_alerts(session: AsyncSession, program: Program, diff: DiffOut) -> None:
    """Alert only on findings that (a) are new this run and (b) haven't
    already been alerted on before (checked against AlertLog), so a program
    that's re-scanned on a schedule never gets re-notified about the same
    open finding.
    """
    webhook = program.webhook_url or settings.alert_webhook_url
    if not diff.new_findings and not diff.new_subdomains:
        return

    already_alerted = {row.fingerprint for row in (await session.execute(
        select(AlertLog).where(AlertLog.program_id == program.id)
    )).scalars()}

    truly_new = [f for f in diff.new_findings if _finding_fp(f) not in already_alerted]
    if not truly_new and not diff.new_subdomains:
        return

    diff_for_message = diff.model_copy(update={"new_findings": truly_new})

    if webhook:
        if not is_public_http_target(webhook):
            logger.warning(
                "program %s has a webhook_url that resolves to a non-public/loopback/private "
                "target — refusing to POST to it (SSRF guard). Use a real external webhook URL.",
                program.id,
            )
        else:
            message = _format_message(program, diff_for_message)
            try:
                async with aiohttp.ClientSession() as http:
                    await http.post(webhook, json={"text": message}, timeout=aiohttp.ClientTimeout(total=10))
            except Exception:
                logger.exception("failed to deliver webhook alert for program %s", program.id)
    else:
        logger.info("no webhook configured for program %s — new findings recorded in DB only", program.id)

    for f in truly_new:
        session.add(AlertLog(program_id=program.id, fingerprint=_finding_fp(f)))
    await session.commit()


def _finding_fp(f) -> str:
    # FindingOut doesn't carry fingerprint (kept out of the public schema);
    # recompute it the same way diff_engine does.
    from app.core.diff_engine import fingerprint
    return fingerprint(f.finding_type, f.target, f.name)
