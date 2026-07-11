"""Phase 2 — DNS resolution. Prefers the `dnsx` CLI (fast, handles huge lists
well) and falls back to native async dnspython resolution so the platform
still works on a box that only has Python installed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import string
from pathlib import Path

import dns.asyncresolver
import dns.exception

from app.core.tool_runner import has_tool, run_tool, strip_ansi

logger = logging.getLogger("bugbounty.dns_resolve")


async def detect_wildcard(domain: str) -> bool:
    """Query a random, almost-certainly-nonexistent subdomain. If it resolves,
    the zone has a wildcard DNS record and naive resolution will produce mass
    false positives — callers should treat "resolves" as weaker evidence.
    """
    junk = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        await resolver.resolve(f"{junk}.{domain}", "A")
        return True
    except (dns.exception.DNSException, Exception):
        return False


async def _resolve_one(resolver: dns.asyncresolver.Resolver, host: str, sem: asyncio.Semaphore) -> tuple[str, str]:
    async with sem:
        try:
            answer = await resolver.resolve(host, "A")
            return host, answer[0].address
        except Exception:
            return host, ""


async def resolve_native(hosts: list[str], concurrency: int = 100) -> dict[str, str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 4
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    sem = asyncio.Semaphore(concurrency)
    pairs = await asyncio.gather(*(_resolve_one(resolver, h, sem) for h in hosts))
    return {h: ip for h, ip in pairs if ip}


async def resolve_with_dnsx(hosts: list[str], workdir: Path) -> dict[str, str]:
    """Uses dnsx's -json output rather than parsing its plain-text -resp
    columns. The text format's column layout varies across dnsx versions and
    some versions emit ANSI color codes even with -silent set (confirmed:
    this previously leaked raw escape sequences like "\\x1b[35mA\\x1b[0m"
    straight into the stored IP field). JSON is structured and unambiguous
    regardless of terminal-color behavior — strip_ansi() is still applied as
    a second line of defense in case a line is malformed.
    """
    input_data = "\n".join(hosts)
    result = await run_tool(
        "dnsx",
        ["-silent", "-a", "-json", "-nc"],
        workdir=workdir,
        output_file="dnsx.jsonl",
        timeout=300,
        input_data=input_data,
    )
    resolved: dict[str, str] = {}
    if result.ok and result.stdout_path:
        for raw_line in result.stdout_path.read_text(errors="replace").splitlines():
            line = strip_ansi(raw_line).strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = rec.get("host", "")
            a_records = rec.get("a") or []
            if host and a_records:
                resolved[host] = a_records[0]
    return resolved


async def run(domain: str, hosts: set[str], workdir: Path) -> dict:
    workdir = workdir / "dns"
    workdir.mkdir(parents=True, exist_ok=True)
    hosts_list = sorted(hosts)

    wildcard = await detect_wildcard(domain)
    if wildcard:
        logger.warning("wildcard DNS detected on %s — resolution alone is not proof of a live host", domain)

    if has_tool("dnsx"):
        resolved = await resolve_with_dnsx(hosts_list, workdir)
    else:
        resolved = await resolve_native(hosts_list)

    (workdir / "resolved.txt").write_text(
        "\n".join(f"{h} {ip}" for h, ip in sorted(resolved.items()))
    )
    logger.info("dns: %d/%d hosts resolved (wildcard=%s)", len(resolved), len(hosts_list), wildcard)
    return {"resolved": resolved, "wildcard": wildcard}
