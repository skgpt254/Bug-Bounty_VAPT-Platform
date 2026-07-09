"""
Thin async wrapper around external CLI security tools (subfinder, httpx, katana,
nuclei, ffuf, ...). Every phase module goes through here rather than calling
asyncio.create_subprocess_exec directly, so we get consistent:

  - tool-availability checks (graceful skip, not a crash, if a tool isn't installed)
  - timeouts
  - captured stdout/stderr written to the scan workspace for later debugging
  - a single choke point where a global rate limiter could be enforced for
    tools that don't have their own -rate-limit flag
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("bugbounty.tool_runner")

_TOOL_CACHE: dict[str, bool] = {}


def has_tool(name: str) -> bool:
    if name not in _TOOL_CACHE:
        _TOOL_CACHE[name] = shutil.which(name) is not None
    return _TOOL_CACHE[name]


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    returncode: int
    stdout_path: Path | None
    ran: bool
    skipped_reason: str = ""

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
        logger.warning("%s timed out after %ss", name, timeout)
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
    if stderr:
        (workdir / f"{name}.stderr.log").write_bytes(stderr)

    return ToolResult(tool=name, command=[name, *args], returncode=proc.returncode, stdout_path=out_path, ran=True)


async def run_many(coros, concurrency: int = 6):
    """Run a batch of tool coroutines with bounded concurrency."""
    sem = asyncio.Semaphore(concurrency)

    async def _wrap(c):
        async with sem:
            return await c

    return await asyncio.gather(*(_wrap(c) for c in coros), return_exceptions=True)
