"""Phase 4 — Crawling. Uses `katana` for JS-aware crawling when available.
Falls back to a minimal same-host link extractor (regex-based, one hop) so
the pipeline still produces an endpoint list without it.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp

from app.config import settings
from app.core.tool_runner import has_tool, run_tool, strip_ansi

logger = logging.getLogger("bugbounty.crawl")

LINK_RE = re.compile(r'(?:href|src)=["\']([^"\']+)["\']')
JS_EXT_RE = re.compile(r"\.js(\?|$)")


async def crawl_with_katana(urls: list[str], workdir: Path, depth: int = 3, duration: int = 300) -> list[str]:
    input_data = "\n".join(urls)
    result = await run_tool(
        "katana",
        ["-silent", "-nc", "-jc", "-kf", "all", "-d", str(depth), "-timeout", "10",
         "-rate-limit", str(int(settings.global_rate_limit)), "-c", "10",
         "-H", f"X-Bug-Bounty: researcher={settings.researcher_name}"],
        workdir=workdir,
        output_file="katana.txt",
        timeout=duration,
        input_data=input_data,
    )
    if result.ok and result.stdout_path:
        return [strip_ansi(line).strip() for line in result.stdout_path.read_text(errors="replace").splitlines() if line.strip()]
    return []


async def crawl_native(urls: list[str], workdir: Path, max_per_host: int = 40) -> list[str]:
    found: set[str] = set()
    async with aiohttp.ClientSession(headers=settings.bb_header) as session:
        for base in urls[:50]:  # keep the native fallback bounded — it's not meant to replace katana
            try:
                async with session.get(base, timeout=8, ssl=False) as resp:
                    body = await resp.text(errors="ignore")
            except Exception:
                continue
            host = urlparse(base).netloc
            count = 0
            for link in LINK_RE.findall(body):
                abs_url = urljoin(base, link)
                if urlparse(abs_url).netloc == host:
                    found.add(abs_url)
                    count += 1
                if count >= max_per_host:
                    break
    return sorted(found)


async def run(live_urls: list[str], workdir: Path, depth: int = 3, duration: int = 300) -> dict:
    workdir = workdir / "crawl"
    workdir.mkdir(parents=True, exist_ok=True)

    if has_tool("katana"):
        endpoints = await crawl_with_katana(live_urls, workdir, depth, duration)
    else:
        endpoints = await crawl_native(live_urls, workdir)

    js_files = sorted({e for e in endpoints if JS_EXT_RE.search(e)})
    unique_endpoints = sorted(set(endpoints))

    (workdir / "unique_endpoints.txt").write_text("\n".join(unique_endpoints))
    (workdir / "js_files.txt").write_text("\n".join(js_files))

    logger.info("crawl: %d endpoints (%d JS files)", len(unique_endpoints), len(js_files))
    return {"endpoints": unique_endpoints, "js_files": js_files}
