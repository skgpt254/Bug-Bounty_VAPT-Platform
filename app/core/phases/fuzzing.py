"""Phase 7 — Active VAPT fuzzing layer: hidden directories/files with `ffuf`,
hidden parameters with `x8`. This is the noisiest, most "active" phase in the
platform — it's opt-in per scan (full mode only, never in incremental/
monitoring runs) and always scope-checked before being called.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.config import settings
from app.core.tool_runner import has_tool, run_tool

logger = logging.getLogger("bugbounty.fuzzing")

DEFAULT_WORDLIST = Path(__file__).parent.parent / "wordlists" / "common_dirs.txt"
DEFAULT_PARAMS = Path(__file__).parent.parent / "wordlists" / "common_params.txt"


async def ffuf_dirs(url: str, workdir: Path, wordlist: Path) -> list[dict]:
    if not has_tool("ffuf"):
        return []
    target = url.rstrip("/") + "/FUZZ"
    safe_name = url.replace("://", "_").replace("/", "_")[:80]
    out_file = f"ffuf_{safe_name}.json"
    result = await run_tool(
        "ffuf",
        ["-u", target, "-w", str(wordlist), "-mc", "200,201,204,301,302,307,401,403",
         "-rate", str(int(settings.global_rate_limit)), "-t", "10", "-silent",
         "-H", f"X-Bug-Bounty: researcher={settings.researcher_name}",
         "-of", "json", "-o", out_file],
        workdir=workdir, output_file=None, timeout=300,
    )
    out_path = workdir / out_file
    findings = []
    if result.ok and out_path.exists():
        try:
            data = json.loads(out_path.read_text())
            for r in data.get("results", []):
                findings.append({
                    "finding_type": "fuzz_dir",
                    "severity": "info",
                    "target": r.get("url", url),
                    "name": f"discovered path (status {r.get('status')})",
                    "detail": r.get("input", {}).get("FUZZ", ""),
                })
        except json.JSONDecodeError:
            pass
    return findings


async def x8_params(url: str, workdir: Path, wordlist: Path) -> list[dict]:
    if not has_tool("x8"):
        return []
    safe_name = url.replace("://", "_").replace("/", "_")[:80]
    out_file = f"x8_{safe_name}.json"
    result = await run_tool(
        "x8",
        ["-u", url, "-w", str(wordlist), "--rate-limit", str(int(settings.global_rate_limit)),
         "-O", "json", "-o", out_file],
        workdir=workdir, output_file=None, timeout=300,
    )
    out_path = workdir / out_file
    findings = []
    if result.ok and out_path.exists():
        try:
            data = json.loads(out_path.read_text())
            for p in data.get("found_parameters", []) if isinstance(data, dict) else []:
                findings.append({
                    "finding_type": "fuzz_param",
                    "severity": "info",
                    "target": url,
                    "name": "hidden parameter discovered",
                    "detail": str(p),
                })
        except json.JSONDecodeError:
            pass
    return findings


async def run(live_urls: list[str], workdir: Path, max_targets: int = 25) -> list[dict]:
    """Bounded fuzzing pass — only the first `max_targets` live URLs, since
    directory/param fuzzing is expensive and noisy at scale. Widen this
    deliberately per-target rather than raising the default.
    """
    workdir = workdir / "fuzz"
    workdir.mkdir(parents=True, exist_ok=True)

    if not (has_tool("ffuf") or has_tool("x8")):
        logger.info("neither ffuf nor x8 installed — skipping active fuzzing phase")
        return []

    dir_wordlist = Path(settings.seclists_dir) / "Discovery/Web-Content/raft-large-directories.txt"
    if not dir_wordlist.exists():
        dir_wordlist = DEFAULT_WORDLIST
    param_wordlist = Path(settings.seclists_dir) / "Discovery/Web-Content/burp-parameter-names.txt"
    if not param_wordlist.exists():
        param_wordlist = DEFAULT_PARAMS

    findings: list[dict] = []
    for url in live_urls[:max_targets]:
        findings += await ffuf_dirs(url, workdir, dir_wordlist)
        findings += await x8_params(url, workdir, param_wordlist)

    logger.info("fuzzing: %d findings across %d targets", len(findings), min(len(live_urls), max_targets))
    return findings
