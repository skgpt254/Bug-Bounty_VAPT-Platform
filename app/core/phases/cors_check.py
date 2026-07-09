"""Phase 8 — CORS misconfiguration analysis. Sends a handful of crafted
Origin headers per endpoint and looks for reflected/wildcard ACAO, especially
combined with Access-Control-Allow-Credentials: true.
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

from app.config import settings
from app.core.rate_limiter import RateLimiter

logger = logging.getLogger("bugbounty.cors_check")


def _test_origins(root_domain: str) -> list[str]:
    return [
        "https://evil.com",
        f"https://attacker.{root_domain}",
        f"https://{root_domain}.evil.com",
        "null",
        f"https://evil.{root_domain}",
    ]


async def run(live_urls: list[str], root_domain: str, workdir: Path, max_targets: int = 200) -> list[dict]:
    workdir = workdir / "vulns"
    workdir.mkdir(parents=True, exist_ok=True)
    limiter = RateLimiter(settings.global_rate_limit)
    findings: list[dict] = []
    origins = _test_origins(root_domain)

    async with aiohttp.ClientSession(headers=settings.bb_header) as session:
        for url in live_urls[:max_targets]:
            for origin in origins:
                await limiter.acquire()
                try:
                    async with session.get(url, headers={"Origin": origin}, timeout=6, ssl=False) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                except Exception:
                    continue

                acao_l = acao.lower()
                if any(tag in acao_l for tag in ("evil", "attacker", "null", "*")):
                    findings.append({
                        "finding_type": "cors",
                        "severity": "high" if acac.lower() == "true" else "medium",
                        "target": url,
                        "name": "CORS reflects/wildcards untrusted origin",
                        "detail": f"origin={origin} ACAO={acao} ACAC={acac}",
                    })
                elif acac.lower() == "true" and root_domain in acao_l:
                    findings.append({
                        "finding_type": "cors",
                        "severity": "low",
                        "target": url,
                        "name": "CORS allows credentials with static allow-list origin",
                        "detail": f"origin={origin} ACAO={acao} ACAC={acac}",
                    })

    logger.info("cors_check: %d findings", len(findings))
    return findings
