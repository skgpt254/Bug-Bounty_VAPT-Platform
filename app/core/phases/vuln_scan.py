"""Phase 6 — Active vulnerability scanning via nuclei. This is the platform's
main *active* phase: it sends crafted requests, not just passive lookups.
Scope filtering happens in the orchestrator before this is ever called —
this module trusts the URL list it's handed is already in-scope.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.config import settings
from app.core.tool_runner import has_tool, run_tool

logger = logging.getLogger("bugbounty.vuln_scan")

SEVERITY_MAP = {"info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}


async def run(live_urls: list[str], workdir: Path) -> list[dict]:
    workdir = workdir / "vulns"
    workdir.mkdir(parents=True, exist_ok=True)

    if not has_tool("nuclei") or not live_urls:
        if not has_tool("nuclei"):
            logger.info("nuclei not installed — skipping active vuln scan phase")
        return []

    input_data = "\n".join(live_urls)
    result = await run_tool(
        "nuclei",
        ["-jsonl", "-silent", "-nc",
         "-rate-limit", str(int(settings.global_rate_limit)),
         "-random-agent",
         "-tags", "cve,exposures,misconfiguration,default-login,panel,backup,debug,redirect,sqli,ssrf,xss,lfi,rce,idor",
         "-severity", "critical,high,medium,low",
         "-exclude-tags", "dos,fuzz,brute-force",
         "-H", f"X-Bug-Bounty: researcher={settings.researcher_name}"],
        workdir=workdir,
        output_file="nuclei.jsonl",
        timeout=1800,
        input_data=input_data,
    )

    findings = []
    if result.ok and result.stdout_path:
        for line in result.stdout_path.read_text().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = rec.get("info", {})
            findings.append({
                "finding_type": "nuclei",
                "severity": SEVERITY_MAP.get(info.get("severity", "info"), "info"),
                "target": rec.get("matched-at") or rec.get("host", ""),
                "name": info.get("name", rec.get("template-id", "unknown")),
                "detail": json.dumps({"template-id": rec.get("template-id"), "tags": info.get("tags")}),
            })
    elif result.skipped_reason:
        logger.info("nuclei skipped/failed: %s", result.skipped_reason)

    logger.info("vuln_scan: %d nuclei findings", len(findings))
    return findings
