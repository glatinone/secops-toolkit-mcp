"""MCP server exposing the SecOps Toolkit helpers as tools.

This module is intentionally thin: every tool delegates to a pure function in
:mod:`secops_toolkit_mcp.core`. The docstrings below become the tool
descriptions an MCP client (e.g. an AI agent) reads to decide when to call them.
"""

from __future__ import annotations

from fastmcp import FastMCP

from . import core

mcp = FastMCP("SecOps Toolkit")


@mcp.tool
def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract indicators of compromise from free-form text or log output.

    Finds IPv4 addresses, URLs, domains, MD5/SHA1/SHA256 hashes, and CVE IDs.
    Defanged indicators (``1.2.3[.]4``, ``hxxp://``) are handled automatically.
    Returns a dict keyed by indicator type; only types that were found appear.
    """
    return core.extract_iocs(text)


@mcp.tool
def defang_ioc(indicator: str) -> str:
    """Make an indicator safe to share by defanging it (``1.2.3.4`` -> ``1.2.3[.]4``)."""
    return core.defang_ioc(indicator)


@mcp.tool
def refang_ioc(indicator: str) -> str:
    """Reverse a defanged indicator back to its real form (``1.2.3[.]4`` -> ``1.2.3.4``)."""
    return core.refang_ioc(indicator)


@mcp.tool
def hash_text(text: str, algorithm: str = "sha256") -> dict[str, str]:
    """Compute a cryptographic hash of a string.

    ``algorithm`` is one of md5, sha1, sha256 (default), or sha512.
    Returns the algorithm used and the lowercase hex digest.
    """
    return core.hash_text(text, algorithm)


@mcp.tool
def password_entropy(password: str) -> dict[str, object]:
    """Estimate password strength as bits of entropy over the charset used.

    Returns length, charset size, entropy in bits, and a strength label. This
    is a quick floor estimate, not a check of whether a specific password is
    on a breach list.
    """
    return core.password_entropy(password)


@mcp.tool
def cidr_info(cidr: str) -> dict[str, object]:
    """Describe an IPv4/IPv6 network: netmask, host range, size, and privacy.

    Accepts CIDR notation such as ``192.168.0.0/24`` or ``10.0.0.5/8``.
    """
    return core.cidr_info(cidr)


@mcp.tool
def ip_in_cidr(ip: str, cidr: str) -> bool:
    """Check whether an IP address falls inside a given CIDR network."""
    return core.ip_in_cidr(ip, cidr)


@mcp.tool
def scan_repo_root(path: str) -> dict[str, object]:
    """Check a repo's top-level directory for files that shadow common
    developer command names (``git.exe``, ``node.exe``, ``npm.cmd``, etc.),
    and the whole tree for symlinks that resolve outside the directory.

    Run this before opening a freshly cloned or downloaded repository in an
    agentic coding tool. On Windows, several tools (Cursor, GitHub Copilot
    CLI, Gemini CLI, Codex) resolve an unqualified command like ``git`` from
    the current directory before PATH, so a malicious repo shipping its own
    ``git.exe`` at the root runs instead of the real one, before any
    workspace-trust prompt appears. Severity: critical for ``git`` (the
    confirmed vector), high for shells/interpreters, medium for other common
    dev tools. Only the top-level directory is checked for this, not
    subdirectories.

    Separately, a symlink anywhere in the tree whose resolved target lies
    outside this directory is flagged too (the GhostApproval/DuneSlide
    hidden-write-target pattern: an approval dialog shows a decoy path while
    the symlink redirects the real write elsewhere, e.g.
    ``~/.ssh/authorized_keys``). Critical if the resolved target hits a known
    sensitive path (SSH/cloud-credential directories, private key files),
    high otherwise.
    """
    return core.scan_repo_root(path)


@mcp.tool
def assess_shell_command(command: str) -> dict[str, object]:
    """Assess a shell command for constructs that look benign to naive string
    matching but execute something else once a shell actually expands them.

    Closes the bypass class GuardFall (2026-06) confirmed against 10 of 11
    popular open-source AI coding agents (Aider, Cline, Goose, Plandex, and
    others): their command-safety guards check the raw string a model wrote,
    not what the shell rewrites it into via quote removal, backslash escapes,
    command substitution, and variable/IFS expansion. Never executes the
    command or any part of it.

    Tokenizes with real POSIX quote-removal rules so quote-fragmented or
    backslash-obfuscated commands (``r'm' -rf /``) normalize to what actually
    runs (``rm -rf /``) before any check. Flags command substitution
    (``$(...)``, backticks, recursively assessed), unquoted variable
    expansion, IFS manipulation, ANSI-C quoting, and a fetch-piped-to-
    interpreter shape (``curl ... | sh``). Returns ``risk`` (``safe``,
    ``suspicious``, or ``dangerous``), per-segment findings, and
    ``bypassed_raw_pattern_match`` -- concrete evidence a normalized segment
    caught something the raw text alone would have missed.
    """
    return core.assess_shell_command(command)


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
