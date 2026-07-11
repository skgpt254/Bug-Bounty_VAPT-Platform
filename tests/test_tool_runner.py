from pathlib import Path

import pytest

from app.core.tool_runner import collect_stderr_warnings, run_tool, strip_ansi


def test_collect_stderr_warnings_finds_nonempty_logs(tmp_path: Path):
    (tmp_path / "http").mkdir()
    (tmp_path / "http" / "httpx.stderr.log").write_text("FATAL: unknown flag -content-length\n")
    (tmp_path / "vulns").mkdir()
    (tmp_path / "vulns" / "nuclei.stderr.log").write_text("")  # empty — should be ignored

    warnings = collect_stderr_warnings(tmp_path)
    assert len(warnings) == 1
    assert "httpx" in warnings[0]
    assert "unknown flag" in warnings[0]


def test_collect_stderr_warnings_empty_workdir(tmp_path: Path):
    assert collect_stderr_warnings(tmp_path) == []


def test_collect_stderr_warnings_missing_workdir(tmp_path: Path):
    assert collect_stderr_warnings(tmp_path / "does_not_exist") == []


def test_strip_ansi_removes_color_codes():
    # This is the literal garbage that leaked into the Resolved IP column
    # before the dnsx fix: "\x1b[35mA\x1b[0m" rendering as "[35mA[0m".
    raw = "\x1b[35mA\x1b[0m 172.66.40.106"
    assert strip_ansi(raw) == "A 172.66.40.106"


def test_strip_ansi_leaves_plain_text_untouched():
    assert strip_ansi("blog.salesflare.com 172.66.43.150") == "blog.salesflare.com 172.66.43.150"


def test_strip_ansi_handles_multiple_codes():
    raw = "\x1b[1m\x1b[32mhost.example.com\x1b[0m [\x1b[36m1.2.3.4\x1b[0m]"
    assert strip_ansi(raw) == "host.example.com [1.2.3.4]"


@pytest.mark.asyncio
async def test_run_tool_skips_empty_input_instead_of_crashing(tmp_path: Path):
    # Reproduces the katana crash: an upstream phase found zero live URLs,
    # so input_data ends up "". Previously this invoked the tool with empty
    # stdin and let it fatal-error ("no input provided for crawling"),
    # which then showed up as a misleading tool_warning. It should now be
    # recognized as "nothing to do" and skipped without running the binary.
    result = await run_tool("cat", ["-"], workdir=tmp_path, input_data="   ")
    assert result.ran is False
    assert result.skipped_reason == "no input data"
    assert result.returncode == -1


@pytest.mark.asyncio
async def test_run_tool_still_runs_with_real_input(tmp_path: Path):
    result = await run_tool("cat", [], workdir=tmp_path, output_file="out.txt", input_data="hello\n")
    assert result.ran is True
    assert result.ok is True
    assert (tmp_path / "out.txt").read_text() == "hello\n"
