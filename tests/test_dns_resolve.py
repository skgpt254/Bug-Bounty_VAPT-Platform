import os
import stat
from pathlib import Path

import pytest

from app.core.phases import dns_resolve


def _install_fake_dnsx(bin_dir: Path, body: str) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / "dnsx"
    script.write_text(f"#!/bin/bash\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)


@pytest.mark.asyncio
async def test_resolve_with_dnsx_parses_json_cleanly(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bin"
    # Simulate real dnsx -json output, including a version that still
    # embeds ANSI codes despite -silent -nc (the exact failure mode seen in
    # production) — the JSON structure itself must still parse correctly,
    # and strip_ansi must clean up anything malformed around it.
    _install_fake_dnsx(fake_bin, r'''
echo '{"host":"blog.salesflare.com","a":["172.66.43.150","172.66.40.106"]}'
echo -e '\x1b[35m{"host":"howto.salesflare.com","a":["172.66.40.106"]}\x1b[0m'
echo '{"host":"noanswer.salesflare.com","a":[]}'
''')
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")

    from app.core import tool_runner
    tool_runner._TOOL_CACHE = {}  # bypass has_tool() cache from any prior test in this process

    resolved = await dns_resolve.resolve_with_dnsx(
        ["blog.salesflare.com", "howto.salesflare.com", "noanswer.salesflare.com"], tmp_path
    )

    assert resolved["blog.salesflare.com"] == "172.66.43.150"
    assert resolved["howto.salesflare.com"] == "172.66.40.106"
    assert "noanswer.salesflare.com" not in resolved  # empty "a" list — correctly not "resolved"
    # Confirms the historical bug is gone: no raw escape/bracket garbage
    # anywhere in a stored value.
    for ip in resolved.values():
        assert "\x1b" not in ip and "[" not in ip
