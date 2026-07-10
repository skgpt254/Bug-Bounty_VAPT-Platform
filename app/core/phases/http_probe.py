"""Phase 3 — HTTP probing. Prefers ProjectDiscovery's `httpx` CLI (fast,
handles TLS/redirects/tech-detection well); falls back to native aiohttp
probing over the resolved host list if it isn't installed.

Note: the CLI tool here is httpx (projectdiscovery.io/httpx), unrelated to
the `httpx` Python package used elsewhere in this project for outbound
requests — kept isolated in this module to avoid any naming confusion.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import aiohttp

from app.config import settings
from app.core.rate_limiter import RateLimiter
from app.core.tool_runner import has_tool, run_tool

logger = logging.getLogger("bugbounty.http_probe")

# Deliberately small, high-precision signature set — header/body substrings
# that are strong single-source evidence of a technology. This exists so the
# native fallback (used when httpx CLI isn't installed) isn't blind on tech
# detection; it will never be as thorough as httpx's Wappalyzer-derived
# fingerprint database, and that's stated in the finding rather than implied.
_HEADER_TECH_SIGNATURES: list[tuple[str, str, str]] = [
    # (header name, substring to match in its value, tech label)
    ("server", "cloudflare", "Cloudflare"),
    ("server", "nginx", "nginx"),
    ("server", "apache", "Apache"),
    ("server", "microsoft-iis", "IIS"),
    ("server", "openresty", "OpenResty"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "express", "Express.js"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-aspnet-version", "", "ASP.NET"),
    ("x-drupal-cache", "", "Drupal"),
    ("x-generator", "wordpress", "WordPress"),
    ("x-varnish", "", "Varnish"),
    ("via", "varnish", "Varnish"),
    ("cf-ray", "", "Cloudflare"),
    ("x-amz-cf-id", "", "Amazon CloudFront"),
    ("x-vercel-id", "", "Vercel"),
    ("x-github-request-id", "", "GitHub Pages"),
]
_BODY_TECH_SIGNATURES: list[tuple[str, str]] = [
    ('name="generator" content="wordpress', "WordPress"),
    ("wp-content/", "WordPress"),
    ("wp-includes/", "WordPress"),
    ("/sites/default/files", "Drupal"),
    ("joomla", "Joomla"),
    ("__next", "Next.js"),
    ("data-reactroot", "React"),
    ("ng-version", "Angular"),
    ("id=\"__nuxt\"", "Nuxt.js"),
    ("shopify", "Shopify"),
    ("cdn.shopify.com", "Shopify"),
    ("laravel_session", "Laravel"),
    ("csrf-token", "CSRF-protected framework (Laravel/Rails/Django-style)"),
]


def _fingerprint_tech(headers: dict, body: str) -> list[str]:
    found: set[str] = set()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for header_name, substr, label in _HEADER_TECH_SIGNATURES:
        value = headers_lower.get(header_name)
        if value is not None and (substr == "" or substr in value):
            found.add(label)
    body_lower = body.lower()[:20000]  # bound the scan — no need to regex a multi-MB body
    for substr, label in _BODY_TECH_SIGNATURES:
        if substr in body_lower:
            found.add(label)
    return sorted(found)


async def probe_with_cli(hosts: list[str], workdir: Path) -> list[dict]:
    input_data = "\n".join(hosts)
    result = await run_tool(
        "httpx",
        ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-content-length",
         "-rate-limit", str(int(settings.global_rate_limit)), "-random-agent",
         "-H", f"X-Bug-Bounty: researcher={settings.researcher_name}"],
        workdir=workdir,
        output_file="httpx.jsonl",
        timeout=600,
        input_data=input_data,
    )
    records = []
    if result.ok and result.stdout_path:
        for line in result.stdout_path.read_text().splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


async def probe_native(hosts: list[str], workdir: Path, concurrency: int = 20) -> list[dict]:
    limiter = RateLimiter(settings.global_rate_limit)
    records: list[dict] = []

    async with aiohttp.ClientSession(headers=settings.bb_header) as session:
        import asyncio
        sem = asyncio.Semaphore(concurrency)

        async def probe(host: str, scheme: str):
            url = f"{scheme}://{host}"
            async with sem:
                await limiter.acquire()
                try:
                    async with session.get(url, timeout=8, ssl=False, allow_redirects=True) as resp:
                        body = await resp.text(errors="ignore")
                        title = ""
                        if "<title" in body.lower():
                            start = body.lower().find("<title")
                            start = body.find(">", start) + 1
                            end = body.lower().find("</title>", start)
                            if end > start:
                                title = body[start:end].strip()[:200]
                        return {
                            "url": str(resp.url),
                            "status_code": resp.status,
                            "title": title,
                            "tech": ", ".join(_fingerprint_tech(dict(resp.headers), body)),
                            "content_length": len(body),
                        }
                except Exception:
                    return None

        tasks = [probe(h, scheme) for h in hosts for scheme in ("https", "http")]
        results = await asyncio.gather(*tasks)
        seen_hosts = set()
        for r in results:
            if r:
                from urllib.parse import urlparse
                netloc = urlparse(r["url"]).netloc
                if netloc in seen_hosts:
                    continue
                seen_hosts.add(netloc)
                records.append(r)

    (workdir / "httpx_native.json").write_text(json.dumps(records, indent=2))
    return records


async def run(hosts: list[str], workdir: Path) -> list[dict]:
    workdir = workdir / "http"
    workdir.mkdir(parents=True, exist_ok=True)

    if has_tool("httpx"):
        records = await probe_with_cli(hosts, workdir)
    else:
        records = await probe_native(hosts, workdir)

    live = [r for r in records if r.get("status_code")]
    (workdir / "live_urls.txt").write_text("\n".join(r["url"] for r in live))
    logger.info("http_probe: %d/%d hosts live", len(live), len(hosts))
    return live
