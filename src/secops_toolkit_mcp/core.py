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
import shlex
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


# --- Shell command safety ----------------------------------------------------

# GuardFall (2026-06) found that 10 of 11 popular open-source AI coding agents'
# command-safety guards (Aider, Cline, Goose, Plandex, and others) inspect the
# *raw* string a model wrote, but a shell rewrites that string -- quote
# removal, backslash escapes, command substitution, variable expansion --
# before anything actually runs. `r'm' -rf /` looks nothing like `rm -rf /` to
# a naive pattern match, but a POSIX shell dequotes and concatenates it into
# exactly that. This assesses a command against real word-splitting/quote-
# removal rules instead of matching the raw text, and separately flags
# constructs (command substitution, unquoted variable expansion, IFS
# manipulation, ANSI-C quoting) whose real effect cannot be determined by
# string inspection alone. No shell is ever invoked; everything here is pure
# text analysis.

_RISK_ORDER = {"safe": 0, "suspicious": 1, "dangerous": 2}


def _max_risk(*risks: str) -> str:
    return max(risks, key=lambda r: _RISK_ORDER[r])


# Illustrative, not exhaustive -- the same posture as scan_repo_root's tiered
# severity. These are well-documented destructive/exfiltration shapes checked
# against the *normalized* (post-quote-removal) command, not the raw text.
_DENYLIST_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("world_writable_chmod", re.compile(r"\bchmod\s+(-R\s+)?0?777\b")),
    ("raw_disk_write", re.compile(r"\bdd\s+.*\bof=/dev/(sd|nvme|disk|hd)\w*")),
    ("filesystem_format", re.compile(r"\bmkfs(\.\w+)?\s+/dev/\w+")),
    ("reverse_shell", re.compile(r"\bnc\b.*-e\s+/bin/(sh|bash)")),
    (
        "credential_file_read",
        re.compile(r"\b(cat|less|more|head|tail)\s+.*(/etc/shadow|id_rsa\b)"),
    ),
)

# Fetch-then-execute is dangerous regardless of quoting tricks: piping a
# network download straight into an interpreter with no chance to inspect it.
_FETCH_COMMANDS = {"curl", "wget"}
_SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "node"}

# `rm`'s dangerous shape depends on which flags are present, not their order
# or whether they are combined (`-rf`) or separate (`-r -f`), so it is checked
# structurally against parsed tokens rather than with a regex.
_RM_SENSITIVE_TARGET_PREFIXES = ("/etc", "/usr", "/boot", "/bin", "/var", "/lib", "/root")
_RM_SENSITIVE_TARGETS = {"/", "/*", "~", "$HOME", "*"}


def _quote_states(text: str) -> list[str]:
    """Per-character quote state (``normal``, ``single``, or ``double``),
    tracking backslash escapes so a quote inside an escape is not mistaken
    for the start/end of a quoted run."""
    states: list[str] = []
    state = "normal"
    escape = False
    for ch in text:
        if escape:
            states.append(state)
            escape = False
            continue
        if state == "single":
            states.append(state)
            if ch == "'":
                state = "normal"
            continue
        if ch == "\\":
            states.append(state)
            escape = True
            continue
        if state == "double":
            states.append(state)
            if ch == '"':
                state = "normal"
            continue
        if ch == "'":
            state = "single"
        elif ch == '"':
            state = "double"
        states.append(state)
    return states


def _find_matching_paren(text: str, open_idx: int) -> int:
    """Return the index of the ``)`` matching the ``(`` at ``open_idx``.

    Paren-depth only, not quote-aware: an unbalanced paren nested inside a
    quoted string within the substitution is rare enough that under-matching
    here just leaves the construct un-recursed-into rather than mis-parsed.
    """
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _extract_command_substitutions(
    text: str,
) -> tuple[str, list[dict[str, str]]]:
    """Replace top-level ``$(...)``/backtick command substitutions with a
    placeholder token and return each substitution's raw form and inner
    command text for the caller to recursively assess.

    Single-quoted spans are skipped since single quotes disable all shell
    expansion, including command substitution.
    """
    states = _quote_states(text)
    out: list[str] = []
    substitutions: list[dict[str, str]] = []
    i = 0
    n = len(text)
    while i < n:
        if states[i] != "single" and text[i : i + 2] == "$(":
            close = _find_matching_paren(text, i + 1)
            if close == -1:
                out.append(text[i:])
                substitutions.append(
                    {"kind": "unbalanced_command_substitution", "raw": text[i:]}
                )
                break
            substitutions.append(
                {
                    "kind": "command_substitution",
                    "raw": text[i : close + 1],
                    "inner": text[i + 2 : close],
                }
            )
            out.append("SUBSHELLOUTPUT")
            i = close + 1
            continue
        if states[i] != "single" and text[i] == "`":
            close = text.find("`", i + 1)
            if close == -1:
                out.append(text[i:])
                substitutions.append(
                    {"kind": "unbalanced_command_substitution", "raw": text[i:]}
                )
                break
            substitutions.append(
                {
                    "kind": "backtick_substitution",
                    "raw": text[i : close + 1],
                    "inner": text[i + 1 : close],
                }
            )
            out.append("SUBSHELLOUTPUT")
            i = close + 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out), substitutions


def _split_logical_commands(text: str) -> list[tuple[str, str | None]]:
    """Split on unquoted ``;``, ``&&``, ``||``, ``|``, and newlines.

    Returns ``(segment, following_operator)`` pairs (``following_operator`` is
    ``None`` for the final segment) so callers can inspect what connects
    adjacent segments, e.g. a pipe feeding one command's output to the next.
    """
    states = _quote_states(text)
    segments: list[tuple[str, str | None]] = []
    buf: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if states[i] == "normal":
            if text[i] == "\n":
                segments.append(("".join(buf), "\n"))
                buf = []
                i += 1
                continue
            two = text[i : i + 2]
            if two in ("&&", "||"):
                segments.append(("".join(buf), two))
                buf = []
                i += 2
                continue
            if text[i] in (";", "|"):
                segments.append(("".join(buf), text[i]))
                buf = []
                i += 1
                continue
        buf.append(text[i])
        i += 1
    segments.append(("".join(buf), None))
    return [(seg.strip(), op) for seg, op in segments if seg.strip()]


def _unquoted_variable_expansions(text: str) -> list[str]:
    """Return each ``$VAR``/``${VAR}`` reference appearing outside single
    quotes -- its expanded value is unknown until the shell actually runs
    it, so a filter matching the literal text cannot see what it becomes."""
    states = _quote_states(text)
    found: list[str] = []
    for m in re.finditer(r"\$(\{\w+[^}]*\}|\w+)", text):
        if states[m.start()] != "single":
            found.append(m.group(0))
    return found


def _rm_recursive_force_sensitive_target(tokens: list[str]) -> bool:
    """True if ``tokens`` is an ``rm`` invocation with both a recurse flag
    (``-r``/``-R``) and a force flag (``-f``), targeting a filesystem root or
    other clearly sensitive path -- checked structurally so flag order
    (``-rf`` vs ``-r -f``) and separate short flags don't matter."""
    if not tokens or tokens[0].rsplit("/", 1)[-1] != "rm":
        return False
    flag_chars: set[str] = set()
    targets: list[str] = []
    literal_args = False
    for tok in tokens[1:]:
        if tok == "--":
            literal_args = True
            continue
        if not literal_args and tok.startswith("-") and tok != "-":
            flag_chars.update(tok.lstrip("-").lower())
        else:
            targets.append(tok)
    forceful = "r" in flag_chars and "f" in flag_chars
    sensitive = any(
        t in _RM_SENSITIVE_TARGETS or t.startswith(_RM_SENSITIVE_TARGET_PREFIXES)
        for t in targets
    )
    return forceful and sensitive


def _naive_split(segment: str) -> list[str]:
    """Whitespace-only split with no quote-removal -- what a raw-text
    command-name check would see, quote characters and all. Used solely as
    the "raw" baseline for the structural (non-regex) rm check, so
    ``bypassed_raw_pattern_match`` only fires when quote-removal was what
    made the finding appear, not for every plain, unobfuscated match too."""
    return segment.split()


def _is_pipe_to_interpreter(
    prev_tokens: list[str], op: str | None, next_tokens: list[str]
) -> bool:
    """True if a network fetch (``curl``/``wget``) is piped directly into a
    shell/language interpreter with no chance to inspect the downloaded
    content first."""
    if op != "|" or not prev_tokens or not next_tokens:
        return False
    prev_cmd = prev_tokens[0].rsplit("/", 1)[-1]
    next_cmd = next_tokens[0].rsplit("/", 1)[-1]
    if next_cmd == "sudo" and len(next_tokens) > 1:
        next_cmd = next_tokens[1].rsplit("/", 1)[-1]
    return prev_cmd in _FETCH_COMMANDS and next_cmd in _SHELL_INTERPRETERS


def assess_shell_command(command: str, _depth: int = 0) -> dict[str, object]:
    """Assess a shell command line for constructs that let it look benign to
    naive string/pattern matching while executing something else once a
    shell actually expands it.

    This is the bypass class GuardFall (2026-06) confirmed against 10 of 11
    popular open-source AI coding agents: a safety guard checks the string a
    model wrote, but Bash rewrites that string (quote removal, backslash
    escapes, command substitution, variable/IFS expansion) before running it.
    Does not execute the command, or any part of it, at any point.

    Each logical sub-command (split on unquoted ``;``/``&&``/``||``/``|``) is
    tokenized with real POSIX quote-removal rules (:mod:`shlex`), so a quote-
    fragmented or backslash-obfuscated command (``r'm' -rf /``,
    ``r\\m -rf /``) is normalized to what actually runs (``rm -rf /``) before
    any denylist check, instead of pattern-matching the raw text. Command
    substitutions (``$(...)``, backticks) are extracted and recursively
    assessed. Unquoted variable expansion, IFS manipulation, ANSI-C quoting,
    and unbalanced quotes are flagged as constructs whose real effect cannot
    be determined from the text alone.

    Returns a dict with:

    - ``risk``: ``"safe"``, ``"suspicious"``, or ``"dangerous"``.
    - ``logical_commands``: per-segment tokens, the normalized
      ``effective_command``, and any findings for that segment.
    - ``substitutions``: extracted ``$(...)``/backtick constructs, each with
      a recursive ``nested_assessment``.
    - ``pipe_findings``: cross-segment findings (currently: piping a fetch
      command straight into an interpreter).
    - ``bypassed_raw_pattern_match``: ``True`` if a normalized segment
      matched a denylist pattern that the *raw*, un-normalized segment text
      did not -- the concrete evidence that this closed a real bypass rather
      than just re-deriving what a raw regex already caught.
    """
    findings: list[dict[str, object]] = []
    placeholder_text, substitutions = _extract_command_substitutions(command)

    sub_risk = "safe"
    for sub in substitutions:
        entry: dict[str, object] = {"type": sub["kind"], "raw": sub["raw"]}
        if "inner" in sub and _depth < 5:
            nested = assess_shell_command(sub["inner"], _depth + 1)
            entry["nested_assessment"] = nested
            sub_risk = _max_risk(sub_risk, "suspicious", str(nested["risk"]))
        else:
            sub_risk = _max_risk(sub_risk, "suspicious")
        findings.append(entry)

    raw_split = _split_logical_commands(placeholder_text)
    logical_commands: list[dict[str, object]] = []
    parsed_tokens: list[list[str]] = []
    any_bypassed_raw = False

    for segment, _op in raw_split:
        seg_findings: list[str] = []
        try:
            tokens = shlex.split(segment, posix=True)
            effective_command = " ".join(tokens)
        except ValueError:
            tokens = []
            effective_command = segment
            seg_findings.append("unbalanced_quotes")

        if _unquoted_variable_expansions(segment):
            seg_findings.append("unquoted_variable_expansion")
        if re.search(r"\bIFS\s*=", segment) or "$IFS" in segment or "${IFS}" in segment:
            seg_findings.append("ifs_manipulation")
        if "$'" in segment:
            seg_findings.append("ansi_c_quoting")

        # Default IFS is whitespace, so an unassigned `$IFS`/`${IFS}` is a
        # literal stand-in for a space -- a documented technique for evading
        # filters that look for a literal space character. Re-tokenize
        # against that expansion too, so a real dangerous shape underneath
        # isn't hidden behind it.
        ifs_expanded = re.sub(r"\$\{?IFS\}?", " ", segment)
        ifs_tokens = tokens
        ifs_effective = effective_command
        if ifs_expanded != segment:
            try:
                ifs_tokens = shlex.split(ifs_expanded, posix=True)
                ifs_effective = " ".join(ifs_tokens)
            except ValueError:
                ifs_tokens, ifs_effective = [], ifs_expanded

        raw_hits = {name for name, pat in _DENYLIST_PATTERNS if pat.search(segment)}
        if _rm_recursive_force_sensitive_target(_naive_split(segment)):
            # Already recognizable without any quote-removal, so a normalized
            # match below is not evidence of a closed bypass.
            raw_hits.add("recursive_root_delete")

        normalized_hits = {
            name for name, pat in _DENYLIST_PATTERNS if pat.search(effective_command)
        }
        normalized_hits |= {
            name for name, pat in _DENYLIST_PATTERNS if pat.search(ifs_effective)
        }
        if _rm_recursive_force_sensitive_target(
            tokens
        ) or _rm_recursive_force_sensitive_target(ifs_tokens):
            normalized_hits.add("recursive_root_delete")

        bypassed_raw = sorted(normalized_hits - raw_hits)
        if bypassed_raw:
            seg_findings.append("bypassed_raw_pattern_match")
            any_bypassed_raw = True
        if normalized_hits:
            seg_findings.append("denylisted_pattern")

        seg_risk = "dangerous" if normalized_hits else ("suspicious" if seg_findings else "safe")

        logical_commands.append(
            {
                "raw_segment": segment,
                "tokens": tokens,
                "effective_command": effective_command,
                "findings": seg_findings,
                "raw_denylist_hits": sorted(raw_hits),
                "normalized_denylist_hits": sorted(normalized_hits),
                "risk": seg_risk,
            }
        )
        parsed_tokens.append(tokens)

    pipe_findings: list[dict[str, object]] = []
    for idx in range(len(raw_split) - 1):
        _, op = raw_split[idx]
        if _is_pipe_to_interpreter(parsed_tokens[idx], op, parsed_tokens[idx + 1]):
            pair = [
                logical_commands[idx]["raw_segment"],
                logical_commands[idx + 1]["raw_segment"],
            ]
            pipe_findings.append(
                {"type": "pipe_fetched_content_to_interpreter", "segments": pair}
            )
            for lc in (logical_commands[idx], logical_commands[idx + 1]):
                lc["findings"].append("pipe_fetched_content_to_interpreter")  # type: ignore[union-attr]
                lc["risk"] = "dangerous"

    overall = sub_risk
    for lc in logical_commands:
        overall = _max_risk(overall, str(lc["risk"]))
    if pipe_findings:
        overall = "dangerous"

    return {
        "command": command,
        "risk": overall,
        "logical_commands": logical_commands,
        "substitutions": findings,
        "pipe_findings": pipe_findings,
        "bypassed_raw_pattern_match": any_bypassed_raw,
    }
