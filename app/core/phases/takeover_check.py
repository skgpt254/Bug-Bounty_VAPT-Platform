"""Phase 9 — Subdomain takeover detection. Looks for CNAMEs pointing at
third-party services that no longer have anything claiming that hostname
(dangling CNAME), which is the classic takeover primitive. Uses `nuclei`'s
takeover templates when available for signature confirmation, plus a native
CNAME + fingerprint check as a fallback.
"""

from __future__ import annotations

import logging
from pathlib import Path

import aiohttp
import dns.asyncresolver
import dns.exception

from app.config import settings
from app.core.rate_limiter import RateLimiter
from app.core.tool_runner import has_tool, run_tool

logger = logging.getLogger("bugbounty.takeover_check")

# Fingerprints of "this service says nobody owns that hostname" responses.
# Deliberately small and high-confidence — false positives here are costly
# (they'd point a researcher at a target that isn't actually takeable).
SERVICE_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "no such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "cloudfront.net": "Bad request",
    "readme.io": "Project doesnt exist",
    "surge.sh": "project not found",
    "unbouncepages.com": "The requested URL was not found on this server",
}


async def _get_cname(resolver: dns.asyncresolver.Resolver, host: str) -> str:
    try:
        answer = await resolver.resolve(host, "CNAME")
        return str(answer[0].target).rstrip(".")
    except (dns.exception.DNSException, Exception):
        return ""


async def native_takeover_check(hosts: list[str], workdir: Path) -> list[dict]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    limiter = RateLimiter(settings.global_rate_limit)
    findings = []

    async with aiohttp.ClientSession(headers=settings.bb_header) as session:
        for host in hosts:
            cname = await _get_cname(resolver, host)
            if not cname:
                continue
            for service, fingerprint in SERVICE_FINGERPRINTS.items():
                if service not in cname:
                    continue
                await limiter.acquire()
                try:
                    async with session.get(f"http://{host}", timeout=6, ssl=False) as resp:
                        body = await resp.text(errors="ignore")
                except Exception:
                    continue
                if fingerprint.lower() in body.lower():
                    findings.append({
                        "finding_type": "takeover",
                        "severity": "high",
                        "target": host,
                        "name": f"possible subdomain takeover via {service}",
                        "detail": f"CNAME={cname}; matched fingerprint '{fingerprint}'. "
                                  f"Heuristic CNAME+response-body match — verify manually before reporting: "
                                  f"try claiming the resource on {service} yourself to confirm.",
                        "confidence": "unconfirmed",
                    })
    return findings


async def nuclei_takeover_check(live_urls: list[str], workdir: Path) -> list[dict]:
    import json
    if not has_tool("nuclei") or not live_urls:
        return []
    result = await run_tool(
        "nuclei",
        ["-jsonl", "-silent", "-nc", "-tags", "takeover",
         "-rate-limit", str(int(settings.global_rate_limit)),
         "-H", f"X-Bug-Bounty: researcher={settings.researcher_name}"],
        workdir=workdir, output_file="nuclei_takeover.jsonl", timeout=600,
        input_data="\n".join(live_urls),
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
                "finding_type": "takeover",
                "severity": "high",
                "target": rec.get("matched-at", ""),
                "name": info.get("name", "subdomain takeover"),
                "detail": rec.get("template-id", ""),
                "confidence": "confirmed",
            })
    return findings


async def run(hosts: list[str], live_urls: list[str], workdir: Path) -> list[dict]:
    workdir = workdir / "takeover"
    workdir.mkdir(parents=True, exist_ok=True)
    findings = await native_takeover_check(hosts, workdir)
    findings += await nuclei_takeover_check(live_urls, workdir)
    logger.info("takeover_check: %d findings", len(findings))
    return findings
