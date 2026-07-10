"""Phase — IP enrichment via Shodan's InternetDB (internetdb.shodan.io).
Unauthenticated, free, rate-limited but generous. For every resolved IP it
returns open ports, detected CPEs, hostnames sharing that IP, and any CVEs
Shodan's own scanning has already associated with it — genuinely
high-signal, zero-cost context that a pure subdomain/HTTP pipeline misses
entirely (e.g. an exposed non-HTTP service like Redis or a database port).
"""

from __future__ import annotations

import logging
from pathlib import Path

import aiohttp

from app.config import settings
from app.core.rate_limiter import RateLimiter

logger = logging.getLogger("bugbounty.enrichment")


async def _lookup_ip(session: aiohttp.ClientSession, ip: str) -> dict | None:
    try:
        async with session.get(f"https://internetdb.shodan.io/{ip}", timeout=8, ssl=False) as resp:
            if resp.status != 200:
                return None
            return await resp.json()
    except Exception as exc:
        logger.debug("internetdb lookup failed for %s: %s", ip, exc)
        return None


async def run(resolved: dict[str, str], workdir: Path) -> list[dict]:
    """`resolved` is {hostname: ip}. Dedupes by IP since many hostnames often
    share one IP (esp. behind a CDN/load balancer) — no point querying twice.
    """
    workdir = workdir / "enrichment"
    workdir.mkdir(parents=True, exist_ok=True)

    ip_to_hosts: dict[str, list[str]] = {}
    for host, ip in resolved.items():
        if ip:
            ip_to_hosts.setdefault(ip, []).append(host)

    if not ip_to_hosts:
        return []

    limiter = RateLimiter(min(settings.global_rate_limit, 4))  # InternetDB is generous but let's stay polite
    findings: list[dict] = []

    async with aiohttp.ClientSession(headers=settings.bb_header) as session:
        for ip, hosts in ip_to_hosts.items():
            await limiter.acquire()
            data = await _lookup_ip(session, ip)
            if not data:
                continue

            ports = data.get("ports", [])
            cves = data.get("vulns", [])
            host_label = hosts[0] + (f" (+{len(hosts) - 1} more on this IP)" if len(hosts) > 1 else "")

            if ports:
                findings.append({
                    "finding_type": "exposure",
                    "severity": "info",
                    "target": f"{ip} ({host_label})",
                    "name": "open ports (Shodan InternetDB)",
                    "detail": f"ports={sorted(ports)} cpes={data.get('cpes', [])}",
                    "confidence": "confirmed",
                })
            for cve in cves:
                findings.append({
                    "finding_type": "exposure",
                    "severity": "high",  # Shodan doesn't grade these; treat any known-CVE surface as worth triage
                    "target": f"{ip} ({host_label})",
                    "name": f"known CVE associated with exposed service: {cve}",
                    "detail": f"Reported by Shodan InternetDB for {ip}. Verify the affected service/version "
                              f"before treating this as confirmed-exploitable — InternetDB flags exposure, "
                              f"not confirmed vulnerability to your specific instance.",
                    "confidence": "unconfirmed",
                })

    logger.info("enrichment: %d IPs queried, %d findings", len(ip_to_hosts), len(findings))
    return findings
