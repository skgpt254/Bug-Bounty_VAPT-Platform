"""
Thin async wrapper around external CLI security tools (subfinder, httpx, katana,
nuclei, ffuf, ...). Every phase module goes through here rather than calling
asyncio.create_subprocess_exec directly, so we get consistent:

  - tool-availability checks (graceful skip, not a crash, if a tool isn't installed)
  - timeouts
  - captured stdout/stderr written to the scan workspace for later debugging
  - a single choke point where a global rate limiter could be enforced for
    tools that don't have their own -rate-limit flag
  - VISIBLE tool failures. A tool that exits non-zero (wrong flags for the
    installed version, a PATH collision with a different binary of the same
    name, auth failure, etc.) used to fail silently — the phase would just
    report "0 results", indistinguishable from a genuinely empty finding.
    That's the single most common cause of "this isn't finding anything"
    reports. Every non-zero exit is now logged at WARNING with a stderr
    excerpt, and collect_stderr_warnings() lets the orchestrator surface a
    per-scan summary in the UI instead of it only living in server logs.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("bugbounty.tool_runner")

_TOOL_CACHE: dict[str, bool] = {}
_STDERR_EXCERPT_LEN = 500


def has_tool(name: str) -> bool:
    if name not in _TOOL_CACHE:
        _TOOL_CACHE[name] = shutil.which(name) is not None
    return _TOOL_CACHE[name]


def resolved_path(name: str) -> str:
    """Full path of the binary that `name` actually resolves to on PATH —
    surfaced in warnings so a PATH collision (e.g. a *different* `httpx`
    shadowing ProjectDiscovery's) is diagnosable from the log line itself.
    """
    return shutil.which(name) or "<not found>"


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    returncode: int
    stdout_path: Path | None
    ran: bool
    skipped_reason: str = ""
    stderr_excerpt: str = ""

    @property
    def ok(self) -> bool:
        return self.ran and self.returncode == 0


async def run_tool(
    name: str,
    args: list[str],
    *,
    workdir: Path,
    output_file: str | None = None,
    timeout: int = 600,
    input_data: str | None = None,
) -> ToolResult:
    """Run `name args...`. Writes stdout to workdir/output_file if given.
    Never raises on tool failure — callers check .ok and degrade gracefully,
    matching the `|| true` safety pattern of the original bash pipeline.
    Non-zero exits are logged (not just silently swallowed) so a broken
    invocation is distinguishable from a genuinely empty result.
    """
    if not has_tool(name):
        logger.info("skip %s: not installed", name)
        return ToolResult(tool=name, command=[name, *args], returncode=-1, stdout_path=None, ran=False,
                           skipped_reason="not installed")

    workdir.mkdir(parents=True, exist_ok=True)
    out_path = workdir / output_file if output_file else None

    try:
        proc = await asyncio.create_subprocess_exec(
            name, *args,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(workdir),
        )
        stdin_bytes = input_data.encode() if input_data is not None else None
        stdout, stderr = await asyncio.wait_for(proc.communicate(stdin_bytes), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %ss (resolved path: %s)", name, timeout, resolved_path(name))
        try:
            proc.kill()
        except Exception:
            pass
        return ToolResult(tool=name, command=[name, *args], returncode=-1, stdout_path=None, ran=True,
                           skipped_reason=f"timeout after {timeout}s")
    except FileNotFoundError:
        return ToolResult(tool=name, command=[name, *args], returncode=-1, stdout_path=None, ran=False,
                           skipped_reason="not installed")

    if out_path:
        out_path.write_bytes(stdout)
    stderr_text = stderr.decode(errors="replace") if stderr else ""
    if stderr:
        (workdir / f"{name}.stderr.log").write_bytes(stderr)

    stderr_excerpt = stderr_text.strip()[:_STDERR_EXCERPT_LEN]

    if proc.returncode != 0:
        logger.warning(
            "%s exited %s (resolved path: %s) — treating this phase's output as empty/degraded, "
            "not as a confirmed empty result. stderr: %s",
            name, proc.returncode, resolved_path(name), stderr_excerpt or "<empty>",
        )
    elif stderr_text.strip() and not out_path:
        # Some tools (e.g. -silent flags that aren't fully silent on warnings)
        # exit 0 but still write something to stderr worth a second look.
        logger.info("%s exited 0 but wrote to stderr: %s", name, stderr_excerpt)

    return ToolResult(
        tool=name, command=[name, *args], returncode=proc.returncode, stdout_path=out_path, ran=True,
        stderr_excerpt=stderr_excerpt,
    )


async def run_many(coros, concurrency: int = 6):
    """Run a batch of tool coroutines with bounded concurrency."""
    sem = asyncio.Semaphore(concurrency)

    async def _wrap(c):
        async with sem:
            return await c

    return await asyncio.gather(*(_wrap(c) for c in coros), return_exceptions=True)


def collect_stderr_warnings(workdir: Path) -> list[str]:
    """Scan a scan's workspace for any *.stderr.log files with content and
    summarize them — called once at the end of orchestrator.run_scan() so
    the dashboard can show "N tool warnings" instead of these only being
    visible to someone tailing server logs.
    """
    warnings: list[str] = []
    if not workdir.exists():
        return warnings
    for stderr_file in sorted(workdir.rglob("*.stderr.log")):
        try:
            content = stderr_file.read_text(errors="replace").strip()
        except OSError:
            continue
        if not content:
            continue
        tool_name = stderr_file.name.replace(".stderr.log", "")
        first_line = content.splitlines()[0][:200]
        warnings.append(f"{tool_name}: {first_line}")
    return warnings
