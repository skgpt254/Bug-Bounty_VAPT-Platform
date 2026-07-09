"""Phase 10 — Cloud storage exposure. Derives plausible bucket names from the
program's domain/brand and checks common S3/GCS/Azure naming + listing
conventions for public read access. Intentionally small permutation set —
this is meant to catch the obvious "company-name-backups" bucket, not brute
force the entire namespace.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import aiohttp

from app.config import settings
from app.core.rate_limiter import RateLimiter

logger = logging.getLogger("bugbounty.cloud_check")


def _brand_candidates(root_domain: str) -> list[str]:
    brand = re.sub(r"\.(com|net|org|io|co|in)$", "", root_domain.split(".")[0] if "." in root_domain else root_domain)
    brand = re.sub(r"[^a-z0-9-]", "", brand.lower())
    suffixes = ["", "-backup", "-backups", "-static", "-assets", "-media", "-data",
                "-dev", "-staging", "-prod", "-files", "-uploads", "-public", "-private"]
    return [f"{brand}{s}" for s in suffixes]


def _bucket_urls(name: str) -> dict[str, str]:
    return {
        "aws_s3": f"https://{name}.s3.amazonaws.com/",
        "gcs": f"https://storage.googleapis.com/{name}/",
        "azure_blob": f"https://{name}.blob.core.windows.net/?comp=list",
    }


OPEN_SIGNATURES = {
    "aws_s3": ("<ListBucketResult", "AccessDenied"),   # first = open, second = exists-but-closed
    "gcs": ("<ListBucketResult", "AccessDenied"),
    "azure_blob": ("<EnumerationResults", "ResourceNotFound"),
}


async def run(root_domain: str, workdir: Path) -> list[dict]:
    workdir = workdir / "cloud"
    workdir.mkdir(parents=True, exist_ok=True)
    limiter = RateLimiter(settings.global_rate_limit)
    findings = []

    async with aiohttp.ClientSession(headers=settings.bb_header) as session:
        for name in _brand_candidates(root_domain):
            for provider, url in _bucket_urls(name).items():
                await limiter.acquire()
                try:
                    async with session.get(url, timeout=6, ssl=False) as resp:
                        body = await resp.text(errors="ignore")
                except Exception:
                    continue

                open_sig, exists_sig = OPEN_SIGNATURES[provider]
                if open_sig in body:
                    findings.append({
                        "finding_type": "cloud_bucket",
                        "severity": "high",
                        "target": url,
                        "name": f"publicly listable {provider} bucket",
                        "detail": f"candidate name '{name}'",
                    })
                elif exists_sig in body:
                    findings.append({
                        "finding_type": "cloud_bucket",
                        "severity": "info",
                        "target": url,
                        "name": f"{provider} bucket exists but is not publicly listable",
                        "detail": f"candidate name '{name}'",
                    })

    logger.info("cloud_check: %d findings", len(findings))
    return findings
