"""Pure, dependency-free SecOps helpers.

Everything here is a plain function with no MCP awareness, so the logic can be
unit-tested in isolation and reused outside the server. ``server.py`` is the
thin layer that exposes these as MCP tools.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from pathlib import Path

# --- Indicator-of-compromise (IOC) extraction -----------------------------

# Threat reports routinely "defang" indicators (1.2.3[.]4, hxxp://...) so they
# are not accidentally clickable. We refang the text first, then match, so the
# extractor works on both raw and defanged input.
_IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "url": re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}

# Trailing characters that are almost never part of a real URL when a URL
# appears mid-sentence or wrapped in brackets/quotes.
_URL_TRAILING_PUNCT = ".,;:!?'\")]}>"

# Hash patterns overlap (every sha256 contains a 40- and 32-char run only if it
# starts on a word boundary, which it does not here), but a 32-char md5 must not
# be reported when it is actually the prefix of a longer hex run. We therefore
# match longest-first and drop shorter substrings that fall inside a longer one.
_HASH_KEYS = ("sha256", "sha1", "md5")


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Pull indicators of compromise out of free-form text or logs.

    Returns a dict keyed by indicator type (ipv4, url, domain, md5, sha1,
    sha256, cve). Each value is a sorted, de-duplicated list. The input is
    refanged first so defanged indicators (``1.2.3[.]4``, ``hxxp://``) are
    caught too.
    """
    refanged = refang_ioc(text)

    result: dict[str, list[str]] = {}

    # Resolve hash overlaps: collect the spans of longer hashes so a shorter
    # pattern does not also claim the same characters.
    claimed_spans: list[tuple[int, int]] = []
    for key in _HASH_KEYS:
        found: list[str] = []
        for m in _IOC_PATTERNS[key].finditer(refanged):
            if any(start <= m.start() and m.end() <= end for start, end in claimed_spans):
                continue
            claimed_spans.append((m.start(), m.end()))
            found.append(m.group(0).lower())
        if found:
            result[key] = sorted(set(found))

    for key in ("ipv4", "url", "domain", "cve"):
        matches = _IOC_PATTERNS[key].findall(refanged)
        if matches:
            if key == "url":
                # Greedy URL matching grabs trailing sentence punctuation
                # ("...payload," / "(see http://x)"); strip it off.
                matches = [m.rstrip(_URL_TRAILING_PUNCT) for m in matches]
            elif key == "cve":
                matches = [m.upper() for m in matches]
            result[key] = sorted(set(matches))

    return result


# --- Defang / refang -------------------------------------------------------

# Order matters: refang the multi-char sequences before single chars.
_DEFANG_RULES = [("http", "hxxp"), ("://", "[://]"), (".", "[.]"), ("@", "[@]")]
_REFANG_RULES = [
    ("[://]", "://"),
    ("[.]", "."),
    ("(.)", "."),
    ("[@]", "@"),
    ("hxxp", "http"),
]


def defang_ioc(indicator: str) -> str:
    """Render an indicator safe to paste (``1.2.3.4`` -> ``1.2.3[.]4``)."""
    out = indicator
    for src, dst in _DEFANG_RULES:
        out = out.replace(src, dst)
    return out


def refang_ioc(indicator: str) -> str:
    """Reverse :func:`defang_ioc` (``hxxp://1.2.3[.]4`` -> ``http://1.2.3.4``)."""
    out = indicator
    for src, dst in _REFANG_RULES:
        out = out.replace(src, dst)
    return out


# --- Hashing ---------------------------------------------------------------

_SUPPORTED_HASHES = ("md5", "sha1", "sha256", "sha512")


def hash_text(text: str, algorithm: str = "sha256") -> dict[str, str]:
    """Hash a string with the named algorithm (default sha256).

    Returns the algorithm and lowercase hex digest. Raises ``ValueError`` for
    an unsupported algorithm so the caller gets a clear message.
    """
    algo = algorithm.lower()
    if algo not in _SUPPORTED_HASHES:
        raise ValueError(
            f"unsupported algorithm '{algorithm}'. "
            f"choose one of: {', '.join(_SUPPORTED_HASHES)}"
        )
    digest = hashlib.new(algo, text.encode("utf-8")).hexdigest()
    return {"algorithm": algo, "hex_digest": digest}


# --- Password entropy ------------------------------------------------------

# Symbol pool size is an approximation of printable ASCII punctuation (32).
_CHARSET_SIZES = {"lower": 26, "upper": 26, "digit": 10, "symbol": 32}


def password_entropy(password: str) -> dict[str, object]:
    """Estimate password strength as Shannon entropy over the used charset.

    This is the standard ``length * log2(pool_size)`` estimate, not a measure
    of how guessable a *specific* password is (it cannot tell that "Password1!"
    is weak). It is a quick floor, useful for policy checks.
    """
    if not password:
        return {
            "length": 0,
            "charset_size": 0,
            "entropy_bits": 0.0,
            "strength": "empty",
        }

    pool = 0
    if any(c.islower() for c in password):
        pool += _CHARSET_SIZES["lower"]
    if any(c.isupper() for c in password):
        pool += _CHARSET_SIZES["upper"]
    if any(c.isdigit() for c in password):
        pool += _CHARSET_SIZES["digit"]
    if any(not c.isalnum() for c in password):
        pool += _CHARSET_SIZES["symbol"]

    entropy = len(password) * math.log2(pool) if pool else 0.0

    if entropy < 28:
        strength = "very weak"
    elif entropy < 36:
        strength = "weak"
    elif entropy < 60:
        strength = "reasonable"
    elif entropy < 128:
        strength = "strong"
    else:
        strength = "very strong"

    return {
        "length": len(password),
        "charset_size": pool,
        "entropy_bits": round(entropy, 2),
        "strength": strength,
    }


# --- CIDR / subnet ---------------------------------------------------------


def cidr_info(cidr: str) -> dict[str, object]:
    """Describe an IPv4/IPv6 network in CIDR notation.

    Raises ``ValueError`` for malformed input.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR '{cidr}': {exc}") from exc

    info: dict[str, object] = {
        "network": str(net.network_address),
        "netmask": str(net.netmask),
        "prefix_length": net.prefixlen,
        "version": net.version,
        "num_addresses": net.num_addresses,
        "is_private": net.is_private,
    }
    # Usable host range only makes sense for networks with spare addresses.
    hosts = list(net.hosts())
    if hosts:
        info["first_host"] = str(hosts[0])
        info["last_host"] = str(hosts[-1])
    if net.version == 4:
        info["broadcast"] = str(net.broadcast_address)
    return info


# --- Repo-root binary masquerading -----------------------------------------

# Mindgard's disclosure (2026-07-15) found Cursor, GitHub Copilot CLI, Gemini
# CLI, and Codex all resolve an unqualified `git` command on startup, and
# Windows's process-creation search order checks the current working
# directory before PATH. A cloned repo that ships a file literally named
# `git.exe` at its root therefore runs attacker code the instant one of those
# tools opens it, before any workspace-trust prompt appears. This check looks
# for that same shape against any commonly unqualified-invoked binary name,
# not just `git`.

# `git` is the name the disclosure confirmed exploitable end-to-end.
_CRITICAL_SHADOW_NAMES = {"git"}
# Shells and interpreters agentic coding tools commonly invoke unqualified.
_HIGH_SHADOW_NAMES = {
    "node", "npm", "npx", "python", "python3", "pip", "pip3",
    "bash", "sh", "cmd", "powershell", "pwsh",
}
# Other developer tools plausibly invoked unqualified by the same class of
# startup/discovery code, but not confirmed by the disclosure itself.
_MEDIUM_SHADOW_NAMES = {
    "docker", "make", "curl", "wget", "ssh", "code", "gh", "yarn", "pnpm", "where",
}

# Extensions Windows resolves as directly executable from the current working
# directory ahead of PATH. Script hosts that need an interpreter (.js, .vbs,
# .wsf) are a different risk shape and out of scope here.
_WINDOWS_EXECUTABLE_EXTENSIONS = {".exe", ".cmd", ".bat", ".com"}


def scan_repo_root(path: str) -> dict[str, object]:
    """Scan a directory's top-level entries for filenames that shadow common
    developer-tool command names.

    Run this before opening a freshly cloned or downloaded repository in an
    agentic coding tool. Only the top level is checked (not recursively) —
    that matches Windows's actual unqualified-command search order, which
    looks at the current working directory, not subdirectories.

    Raises ``ValueError`` if ``path`` does not exist or is not a directory.
    """
    directory = Path(path)
    if not directory.exists():
        raise ValueError(f"path does not exist: {path}")
    if not directory.is_dir():
        raise ValueError(f"not a directory: {path}")

    findings: list[dict[str, str]] = []
    entries_scanned = 0
    for entry in sorted(directory.iterdir(), key=lambda p: p.name.lower()):
        if not entry.is_file():
            continue
        entries_scanned += 1

        suffix = entry.suffix.lower()
        if suffix not in _WINDOWS_EXECUTABLE_EXTENSIONS:
            continue

        stem = entry.stem.lower()
        if stem in _CRITICAL_SHADOW_NAMES:
            severity = "critical"
        elif stem in _HIGH_SHADOW_NAMES:
            severity = "high"
        elif stem in _MEDIUM_SHADOW_NAMES:
            severity = "medium"
        else:
            continue

        findings.append({"filename": entry.name, "shadows": stem, "severity": severity})

    return {
        "path": str(directory),
        "entries_scanned": entries_scanned,
        "clean": not findings,
        "findings": findings,
    }


def ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return True if ``ip`` falls within the ``cidr`` network.

    Raises ``ValueError`` if either argument is malformed.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"invalid IP address '{ip}': {exc}") from exc
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR '{cidr}': {exc}") from exc
    return addr in net
