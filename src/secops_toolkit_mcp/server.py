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
    developer command names (``git.exe``, ``node.exe``, ``npm.cmd``, etc.).

    Run this before opening a freshly cloned or downloaded repository in an
    agentic coding tool. On Windows, several tools (Cursor, GitHub Copilot
    CLI, Gemini CLI, Codex) resolve an unqualified command like ``git`` from
    the current directory before PATH, so a malicious repo shipping its own
    ``git.exe`` at the root runs instead of the real one, before any
    workspace-trust prompt appears. Severity: critical for ``git`` (the
    confirmed vector), high for shells/interpreters, medium for other common
    dev tools. Only the top-level directory is checked, not subdirectories.
    """
    return core.scan_repo_root(path)


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
