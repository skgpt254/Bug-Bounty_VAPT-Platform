"""Phase 5 — JS analysis. Fetches discovered JS files and regex-scans them
for likely secrets (API keys, tokens, private cloud endpoints). Uses
`trufflehog` for verified-secret detection when installed, since regex alone
produces a lot of noise.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import aiohttp

from app.config import settings
from app.core.rate_limiter import RateLimiter
from app.core.tool_runner import has_tool, run_tool

logger = logging.getLogger("bugbounty.js_secrets")

# Deliberately conservative, well-known patterns — high-precision over recall.
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    "stripe_key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "generic_bearer": re.compile(r"bearer\s+[a-zA-Z0-9_\-\.=]{20,}", re.IGNORECASE),
    "private_key_block": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
}

ENDPOINT_PATTERNS = {
    "graphql": re.compile(r"[\"'](/[a-zA-Z0-9_\-/]*graphql[a-zA-Z0-9_\-/]*)[\"']"),
    "internal_api": re.compile(r"[\"'](/(api|internal|admin)/[a-zA-Z0-9_\-/{}]+)[\"']"),
}


async def fetch_js(urls: list[str], workdir: Path) -> dict[str, str]:
    limiter = RateLimiter(settings.global_rate_limit)
    bodies: dict[str, str] = {}
    async with aiohttp.ClientSession(headers=settings.bb_header) as session:
        for url in urls:
            await limiter.acquire()
            try:
                async with session.get(url, timeout=10, ssl=False) as resp:
                    if resp.status == 200:
                        bodies[url] = await resp.text(errors="ignore")
            except Exception:
                continue
    (workdir / "js_bodies_count.txt").write_text(str(len(bodies)))
    return bodies


def regex_scan(bodies: dict[str, str]) -> list[dict]:
    findings = []
    for url, body in bodies.items():
        for name, pattern in SECRET_PATTERNS.items():
            for match in set(pattern.findall(body)):
                snippet = match if isinstance(match, str) else match[0]
                findings.append({
                    "finding_type": "secret",
                    "severity": "high" if name != "jwt" else "medium",
                    "target": url,
                    "name": f"possible_{name}",
                    "detail": snippet[:120],
                })
        for name, pattern in ENDPOINT_PATTERNS.items():
            for match in set(pattern.findall(body)):
                path = match if isinstance(match, str) else match[0]
                findings.append({
                    "finding_type": "js_endpoint",
                    "severity": "info",
                    "target": url,
                    "name": name,
                    "detail": path,
                })
    return findings


async def run_trufflehog(js_urls_file: Path, workdir: Path) -> list[dict]:
    if not has_tool("trufflehog") or not js_urls_file.exists():
        return []
    result = await run_tool(
        "trufflehog", ["filesystem", str(js_urls_file), "--json", "--only-verified"],
        workdir=workdir, output_file="trufflehog.json", timeout=300,
    )
    findings = []
    if result.ok and result.stdout_path:
        for line in result.stdout_path.read_text().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append({
                "finding_type": "secret_verified",
                "severity": "critical",
                "target": rec.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "js"),
                "name": rec.get("DetectorName", "verified_secret"),
                "detail": "Verified live credential — trufflehog confirmed it against the provider API.",
            })
    return findings


async def run(js_urls: list[str], workdir: Path) -> list[dict]:
    workdir = workdir / "js_analysis"
    workdir.mkdir(parents=True, exist_ok=True)

    if not js_urls:
        return []

    bodies = await fetch_js(js_urls, workdir)
    findings = regex_scan(bodies)

    # trufflehog needs files on disk, not URLs — dump bodies then scan.
    dump_dir = workdir / "js_dump"
    dump_dir.mkdir(exist_ok=True)
    for i, (url, body) in enumerate(bodies.items()):
        (dump_dir / f"{i}.js").write_text(body)

    findings += await run_trufflehog(dump_dir, workdir)

    (workdir / "findings.json").write_text(json.dumps(findings, indent=2))
    logger.info("js_secrets: %d findings across %d JS files", len(findings), len(bodies))
    return findings
