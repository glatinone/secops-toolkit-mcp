"""Standalone command-line entry point for ``scan_repo_root``.

The rest of this project's tools are only reachable through an MCP client,
which is the right interface for an interactive agent session but the wrong
one for a pre-clone git hook or a CI step that needs a plain exit code before
an agent ever opens the directory. This wraps
:func:`secops_toolkit_mcp.core.scan_repo_root` as its own console script
(``secops-scan-repo``), mirroring how mcpscan exposes both a CLI and an MCP
server over the same scanning logic.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import core

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_SEVERITY_ORDER = {"medium": 0, "high": 1, "critical": 2}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secops-scan-repo",
        description=(
            "Check a directory's top-level entries for filenames that shadow "
            "common developer command names (git.exe, node.exe, npm.cmd, "
            "etc.), and the whole tree for symlinks that resolve outside the "
            "directory, before you clone-and-open it in an agentic coding tool."
        ),
    )
    p.add_argument("path", nargs="?", default=".", help="directory to scan (default: .)")
    p.add_argument("-f", "--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    p.add_argument("--min-severity", choices=["medium", "high", "critical"], default="medium",
                   help="minimum finding severity that causes a non-zero exit "
                        "(medium|high|critical; default: medium, i.e. any finding)")
    p.add_argument("-V", "--version", action="version",
                   version=f"secops-scan-repo {__version__}")
    return p


def _scanned_summary(result: dict[str, object]) -> str:
    return (
        f"{result['entries_scanned']} top-level file(s), "
        f"{result['symlinks_scanned']} symlink(s) scanned"
    )


def _render_finding(finding: dict[str, object]) -> str:
    severity = finding["severity"].upper()  # type: ignore[union-attr]
    if finding["kind"] == "symlink_escape":
        return (
            f"  [{severity}] {finding['path']} is a symlink resolving "
            f"outside the repo root, to {finding['resolves_to']}"
        )
    return (
        f"  [{severity}] {finding['filename']} shadows the "
        f"'{finding['shadows']}' command"
    )


def _render_text(result: dict[str, object]) -> str:
    if result["clean"]:
        return (
            f"secops-scan-repo: {result['path']} is clean "
            f"({_scanned_summary(result)})."
        )
    lines = [
        f"secops-scan-repo: {result['path']} ({_scanned_summary(result)})",
        "",
    ]
    for finding in result["findings"]:  # type: ignore[union-attr]
        lines.append(_render_finding(finding))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = core.scan_repo_root(args.path)
    except ValueError as exc:
        print(f"secops-scan-repo: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(_render_text(result))

    threshold = _SEVERITY_ORDER[args.min_severity]
    at_or_above = any(
        _SEVERITY_ORDER[f["severity"]] >= threshold  # type: ignore[index]
        for f in result["findings"]  # type: ignore[union-attr]
    )
    return EXIT_FINDINGS if at_or_above else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
