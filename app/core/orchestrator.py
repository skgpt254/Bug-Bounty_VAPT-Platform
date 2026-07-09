"""
Orchestrator — runs one full scan for a Program end to end:

  passive recon -> DNS resolve -> HTTP probe -> crawl -> JS/secrets
  -> [active: nuclei, fuzzing, CORS, takeover, cloud]
  -> persist to DB -> diff against previous run -> alert on new findings

Two modes:
  FULL        every phase, including the expensive/active ones (fuzzing).
  INCREMENTAL passive+DNS+HTTP+crawl+nuclei+CORS+takeover only — no directory/
              param fuzzing. This is what the continuous-monitoring scheduler
              runs on its interval, so it stays fast and polite.

Scope enforcement: every active phase receives only URLs/hosts that already
passed ScopeFilter.in_scope(). This mirrors the SCOPE_REGEX / OUT_OF_SCOPE_REGEX
gates in the original bash script, just centralized in one place instead of
repeated per phase.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core import diff_engine, alerting
from app.core.phases import (
    passive_recon, dns_resolve, http_probe, crawl, js_secrets,
    vuln_scan, fuzzing, cors_check, takeover_check, cloud_check,
)
from app.core.scope import ScopeFilter
from app.models import Program, ScanRun, ScanMode, ScanStatus, Subdomain, Endpoint, Finding

logger = logging.getLogger("bugbounty.orchestrator")


async def run_scan(
    session: AsyncSession,
    program: Program,
    mode: ScanMode = ScanMode.FULL,
    scan: ScanRun | None = None,
) -> ScanRun:
    """Run one full scan. If `scan` is provided (e.g. a QUEUED placeholder row
    created by the API so the caller gets an id back immediately), it's
    promoted to RUNNING and reused instead of creating a second row.
    """
    scope = ScopeFilter(program)
    workdir = settings.workspace_path / program.name.replace(" ", "_") / datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    workdir.mkdir(parents=True, exist_ok=True)

    if scan is None:
        scan = ScanRun(program_id=program.id, mode=mode, status=ScanStatus.RUNNING, workspace_path=str(workdir))
        session.add(scan)
    else:
        scan.status = ScanStatus.RUNNING
        scan.workspace_path = str(workdir)
    await session.commit()
    await session.refresh(scan)

    phases_run: list[str] = []
    all_findings: list[dict] = []

    try:
        t0 = time.monotonic()

        # 1. Passive recon
        passive = await passive_recon.run(program.root_domain, workdir)
        hosts = scope.filter(sorted(passive["hosts"]))
        phases_run.append("passive_recon")

        # 2. DNS resolve
        dns_result = await dns_resolve.run(program.root_domain, set(hosts), workdir)
        resolved_hosts = list(dns_result["resolved"].keys())
        phases_run.append("dns_resolve")

        # 3. HTTP probe (only hosts that actually resolved)
        probe_targets = resolved_hosts or hosts
        live_records = await http_probe.run(probe_targets, workdir)
        live_urls = scope.filter([r["url"] for r in live_records])
        phases_run.append("http_probe")

        # 4. Crawl
        crawl_result = await crawl.run(live_urls, workdir)
        js_files = scope.filter(crawl_result["js_files"])
        phases_run.append("crawl")

        # 5. JS / secrets analysis
        js_findings = await js_secrets.run(js_files, workdir)
        all_findings += js_findings
        phases_run.append("js_secrets")

        # 6. Active: nuclei vuln scan (both modes — this is the core VAPT signal)
        nuclei_findings = await vuln_scan.run(live_urls, workdir)
        all_findings += nuclei_findings
        phases_run.append("vuln_scan")

        # 7. Active: CORS
        cors_findings = await cors_check.run(live_urls, program.root_domain, workdir)
        all_findings += cors_findings
        phases_run.append("cors_check")

        # 8. Active: subdomain takeover
        takeover_findings = await takeover_check.run(resolved_hosts, live_urls, workdir)
        all_findings += takeover_findings
        phases_run.append("takeover_check")

        # 9. Active: cloud bucket exposure (cheap, always worth it)
        cloud_findings = await cloud_check.run(program.root_domain, workdir)
        all_findings += cloud_findings
        phases_run.append("cloud_check")

        if mode == ScanMode.FULL:
            # 10. Active: fuzzing — expensive/noisy, full-scan only, never in
            #     continuous monitoring so scheduled runs stay fast and polite.
            fuzz_findings = await fuzzing.run(live_urls, workdir)
            all_findings += fuzz_findings
            phases_run.append("fuzzing")

        # ---- persist ----
        for host in hosts:
            session.add(Subdomain(
                program_id=program.id, scan_run_id=scan.id, hostname=host,
                resolved_ip=dns_result["resolved"].get(host, ""),
                source=",".join(passive["sources"].get(host, [])),
            ))
        for rec in live_records:
            session.add(Endpoint(
                program_id=program.id, scan_run_id=scan.id, url=rec["url"],
                status_code=rec.get("status_code", 0), title=rec.get("title", ""),
                tech=str(rec.get("tech", "")), content_length=rec.get("content_length", 0),
            ))
        for f in all_findings:
            session.add(Finding(
                program_id=program.id, scan_run_id=scan.id,
                finding_type=f["finding_type"], severity=f["severity"],
                target=f["target"], name=f["name"], detail=f.get("detail", ""),
                fingerprint=diff_engine.fingerprint(f["finding_type"], f["target"], f["name"]),
            ))

        scan.status = ScanStatus.COMPLETED
        scan.finished_at = datetime.utcnow()
        scan.phases_run = ",".join(phases_run)
        await session.commit()

        # ---- diff against previous run + alert on genuinely new findings ----
        diff = await diff_engine.compute_diff(session, program, scan)
        await alerting.send_new_finding_alerts(session, program, diff)

        logger.info("scan %s completed in %.1fs (%d findings, %d new)",
                     scan.id, time.monotonic() - t0, len(all_findings), len(diff.new_findings))

    except Exception as exc:
        logger.exception("scan %s failed", scan.id)
        scan.status = ScanStatus.FAILED
        scan.error = str(exc)
        scan.finished_at = datetime.utcnow()
        scan.phases_run = ",".join(phases_run)
        await session.commit()

    return scan
