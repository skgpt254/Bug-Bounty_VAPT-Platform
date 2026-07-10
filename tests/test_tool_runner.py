from pathlib import Path

from app.core.tool_runner import collect_stderr_warnings


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
