"""Tests for the standalone secops-scan-repo CLI."""

import json

from secops_toolkit_mcp import cli


def test_clean_directory_exits_zero(tmp_path, capsys):
    (tmp_path / "README.md").write_text("hello")
    exit_code = cli.main([str(tmp_path)])
    out = capsys.readouterr().out
    assert exit_code == cli.EXIT_CLEAN
    assert "clean" in out


def test_finding_exits_one(tmp_path, capsys):
    (tmp_path / "git.exe").write_bytes(b"MZ")
    exit_code = cli.main([str(tmp_path)])
    out = capsys.readouterr().out
    assert exit_code == cli.EXIT_FINDINGS
    assert "CRITICAL" in out
    assert "git.exe" in out
    assert "git" in out


def test_json_output_matches_core_result(tmp_path, capsys):
    (tmp_path / "node.cmd").write_bytes(b"")
    exit_code = cli.main([str(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert exit_code == cli.EXIT_FINDINGS
    assert payload["findings"][0]["filename"] == "node.cmd"
    assert payload["findings"][0]["severity"] == "high"


def test_min_severity_filters_below_threshold(tmp_path, capsys):
    (tmp_path / "docker.bat").write_bytes(b"")  # medium
    exit_code = cli.main([str(tmp_path), "--min-severity", "high"])
    capsys.readouterr()
    assert exit_code == cli.EXIT_CLEAN


def test_min_severity_still_reports_at_or_above_threshold(tmp_path, capsys):
    (tmp_path / "git.exe").write_bytes(b"MZ")  # critical
    exit_code = cli.main([str(tmp_path), "--min-severity", "high"])
    capsys.readouterr()
    assert exit_code == cli.EXIT_FINDINGS


def test_missing_path_exits_error(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"
    exit_code = cli.main([str(missing)])
    err = capsys.readouterr().err
    assert exit_code == cli.EXIT_ERROR
    assert "does not exist" in err


def test_file_instead_of_directory_exits_error(tmp_path, capsys):
    f = tmp_path / "not_a_dir.txt"
    f.write_text("x")
    exit_code = cli.main([str(f)])
    err = capsys.readouterr().err
    assert exit_code == cli.EXIT_ERROR
    assert "not a directory" in err


def test_default_path_is_current_directory():
    parser = cli.build_parser()
    args = parser.parse_args([])
    assert args.path == "."


def test_version_flag_reports_package_version(capsys):
    try:
        cli.main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    out = capsys.readouterr().out
    assert "secops-scan-repo" in out
