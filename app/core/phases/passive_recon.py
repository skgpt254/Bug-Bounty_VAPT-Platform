"""Phase 1 — Passive subdomain collection. No packets sent to the target
itself; everything here queries third-party OSINT sources (CT logs, passive
DNS databases, code search, the Wayback Machine).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import aiohttp

from app.config import settings
from app.core.tool_runner import has_tool, run_tool

logger = logging.getLogger("bugbounty.passive_recon")

HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$")


async def _fetch_json(session: aiohttp.ClientSession, url: str, timeout: int = 20):
    try:
        async with session.get(url, timeout=timeout, ssl=False) as resp:
            if resp.status != 200:
                return None
            return await resp.json(content_type=None)
    except Exception as exc:
        logger.debug("passive fetch failed %s: %s", url, exc)
        return None


async def _fetch_text(session: aiohttp.ClientSession, url: str, timeout: int = 20) -> str:
    try:
        async with session.get(url, timeout=timeout, ssl=False) as resp:
            if resp.status != 200:
                return ""
            return await resp.text()
    except Exception as exc:
        logger.debug("passive fetch failed %s: %s", url, exc)
        return ""


def _clean(hosts: set[str], domain: str) -> set[str]:
    out = set()
    for h in hosts:
        h = h.strip().lstrip("*.").lower()
        if HOSTNAME_RE.match(h) and h.endswith(domain):
            out.add(h)
    return out


async def crtsh(session: aiohttp.ClientSession, domain: str) -> set[str]:
    data = await _fetch_json(session, f"https://crt.sh/?q=%.{domain}&output=json")
    if not data:
        return set()
    hosts = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).split("\n"):
            hosts.add(name)
    return hosts


async def wayback(session: aiohttp.ClientSession, domain: str) -> set[str]:
    text = await _fetch_text(
        session,
        f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text"
        f"&fl=original&collapse=urlkey&limit=10000",
        timeout=30,
    )
    hosts = set()
    for line in text.splitlines():
        m = re.search(r"//([^/?]+)", line)
        if m:
            hosts.add(m.group(1))
    return hosts


async def rapiddns(session: aiohttp.ClientSession, domain: str) -> set[str]:
    text = await _fetch_text(session, f"https://rapiddns.io/subdomain/{domain}?full=1#result")
    return set(re.findall(rf"(?:[a-z0-9_-]+\.)+{re.escape(domain)}", text))


async def otx(session: aiohttp.ClientSession, domain: str) -> set[str]:
    data = await _fetch_json(session, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    if not data:
        return set()
    return {e.get("hostname", "") for e in data.get("passive_dns", [])}


async def subfinder(domain: str, workdir: Path) -> set[str]:
    result = await run_tool(
        "subfinder",
        ["-d", domain, "-all", "-recursive", "-silent", "-o", "subfinder.txt"],
        workdir=workdir,
        output_file=None,  # subfinder writes its own -o file
        timeout=300,
    )
    out = workdir / "subfinder.txt"
    if result.ran and result.ok and out.exists():
        return {line.strip() for line in out.read_text().splitlines() if line.strip()}
    return set()


async def assetfinder(domain: str, workdir: Path) -> set[str]:
    result = await run_tool("assetfinder", ["--subs-only", domain], workdir=workdir,
                             output_file="assetfinder.txt", timeout=120)
    if result.ok and result.stdout_path:
        return {line.strip() for line in result.stdout_path.read_text().splitlines() if line.strip()}
    return set()


async def github_subdomains(domain: str, workdir: Path) -> set[str]:
    if not settings.github_token:
        return set()
    result = await run_tool(
        "github-subdomains",
        ["-d", domain, "-t", settings.github_token, "-o", "github_subs.txt"],
        workdir=workdir, timeout=180,
    )
    out = workdir / "github_subs.txt"
    if result.ok and out.exists():
        return {line.strip() for line in out.read_text().splitlines() if line.strip()}
    return set()


# ---- API-backed sources — each is a no-op returning an empty set if its
# key isn't configured in .env, so the platform works with zero keys and
# gets progressively more thorough as you add them. ----

async def shodan(session: aiohttp.ClientSession, domain: str) -> set[str]:
    if not settings.shodan_api_key:
        return set()
    data = await _fetch_json(
        session, f"https://api.shodan.io/dns/domain/{domain}?key={settings.shodan_api_key}"
    )
    if not data:
        return set()
    return {f"{sub}.{domain}" if sub != "" else domain for sub in data.get("subdomains", [])}


async def censys(session: aiohttp.ClientSession, domain: str) -> set[str]:
    if not (settings.censys_api_id and settings.censys_api_secret):
        return set()
    auth = aiohttp.BasicAuth(settings.censys_api_id, settings.censys_api_secret)
    try:
        async with session.post(
            "https://search.censys.io/api/v2/hosts/search",
            json={"q": f"services.certificate.parsed.names: {domain}", "per_page": 100},
            auth=auth, timeout=20, ssl=False,
        ) as resp:
            if resp.status != 200:
                return set()
            data = await resp.json()
    except Exception as exc:
        logger.debug("censys fetch failed: %s", exc)
        return set()
    hosts = set()
    for hit in data.get("result", {}).get("hits", []):
        for name in hit.get("names", []) or []:
            hosts.add(name)
    return hosts


async def securitytrails(session: aiohttp.ClientSession, domain: str) -> set[str]:
    if not settings.securitytrails_api_key:
        return set()
    # SecurityTrails needs the key as a header, not a query param, so this
    # can't go through the generic _fetch_json helper.
    try:
        async with session.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": settings.securitytrails_api_key}, timeout=20, ssl=False,
        ) as resp:
            if resp.status != 200:
                return set()
            data = await resp.json()
    except Exception as exc:
        logger.debug("securitytrails fetch failed: %s", exc)
        return set()
    return {f"{sub}.{domain}" for sub in data.get("subdomains", [])}


async def virustotal(session: aiohttp.ClientSession, domain: str) -> set[str]:
    if not settings.virustotal_api_key:
        return set()
    try:
        async with session.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000",
            headers={"x-apikey": settings.virustotal_api_key}, timeout=20, ssl=False,
        ) as resp:
            if resp.status != 200:
                return set()
            data = await resp.json()
    except Exception as exc:
        logger.debug("virustotal fetch failed: %s", exc)
        return set()
    return {item.get("id", "") for item in data.get("data", [])}


async def urlscan(session: aiohttp.ClientSession, domain: str) -> set[str]:
    headers = {"API-Key": settings.urlscan_api_key} if settings.urlscan_api_key else {}
    try:
        async with session.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
            headers=headers, timeout=20, ssl=False,
        ) as resp:
            if resp.status != 200:
                return set()
            data = await resp.json()
    except Exception as exc:
        logger.debug("urlscan fetch failed: %s", exc)
        return set()
    hosts = set()
    for result in data.get("results", []):
        page = result.get("page", {})
        if page.get("domain"):
            hosts.add(page["domain"])
    return hosts


async def chaos(domain: str, workdir: Path) -> set[str]:
    """ProjectDiscovery Chaos dataset — curated bug-bounty subdomain data."""
    if not settings.chaos_api_key:
        return set()
    try:
        async with aiohttp.ClientSession(headers={"Authorization": settings.chaos_api_key}) as s:
            async with s.get(f"https://dns.projectdiscovery.io/dns/{domain}/subdomains", timeout=20, ssl=False) as resp:
                if resp.status != 200:
                    return set()
                data = await resp.json()
    except Exception as exc:
        logger.debug("chaos fetch failed: %s", exc)
        return set()
    return {f"{sub}.{domain}" for sub in data.get("subdomains", [])}


async def binaryedge(session: aiohttp.ClientSession, domain: str) -> set[str]:
    if not settings.binaryedge_api_key:
        return set()
    try:
        async with session.get(
            f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}",
            headers={"X-Key": settings.binaryedge_api_key}, timeout=20, ssl=False,
        ) as resp:
            if resp.status != 200:
                return set()
            data = await resp.json()
    except Exception as exc:
        logger.debug("binaryedge fetch failed: %s", exc)
        return set()
    return set(data.get("events", []))


async def leakix(session: aiohttp.ClientSession, domain: str) -> set[str]:
    if not settings.leakix_api_key:
        return set()
    try:
        async with session.get(
            f"https://leakix.net/api/subdomains/{domain}",
            headers={"api-key": settings.leakix_api_key}, timeout=20, ssl=False,
        ) as resp:
            if resp.status != 200:
                return set()
            data = await resp.json()
    except Exception as exc:
        logger.debug("leakix fetch failed: %s", exc)
        return set()
    hosts = set()
    for entry in data if isinstance(data, list) else []:
        subdomain = entry.get("subdomain", "")
        if subdomain:
            hosts.add(subdomain)
    return hosts


async def run(domain: str, workdir: Path) -> dict:
    """Run every passive source concurrently, merge + scope-clean the results."""
    workdir = workdir / "passive"
    workdir.mkdir(parents=True, exist_ok=True)

    async with aiohttp.ClientSession(headers=settings.bb_header) as session:
        results = {}
        import asyncio as _asyncio

        tasks = {
            "crtsh": crtsh(session, domain),
            "wayback": wayback(session, domain),
            "rapiddns": rapiddns(session, domain),
            "otx": otx(session, domain),
            "shodan": shodan(session, domain),
            "censys": censys(session, domain),
            "securitytrails": securitytrails(session, domain),
            "virustotal": virustotal(session, domain),
            "urlscan": urlscan(session, domain),
            "chaos": chaos(domain, workdir),
            "binaryedge": binaryedge(session, domain),
            "leakix": leakix(session, domain),
            "subfinder": subfinder(domain, workdir),
            "assetfinder": assetfinder(domain, workdir),
            "github_subdomains": github_subdomains(domain, workdir),
        }
        done = await _asyncio.gather(*tasks.values(), return_exceptions=True)
        for key, value in zip(tasks.keys(), done):
            if isinstance(value, Exception):
                logger.debug("passive source %s raised: %s", key, value)
            results[key] = value if isinstance(value, set) else set()

    all_hosts: set[str] = set()
    source_map: dict[str, list[str]] = {}
    for source, hosts in results.items():
        cleaned = _clean(hosts, domain)
        for h in cleaned:
            source_map.setdefault(h, []).append(source)
        all_hosts |= cleaned

    all_hosts.add(domain)  # apex is always in scope of its own program
    (workdir / "all_passive.json").write_text(json.dumps(sorted(all_hosts), indent=2))

    logger.info("passive recon: %d candidate hosts for %s", len(all_hosts), domain)
    return {"hosts": all_hosts, "sources": source_map}
