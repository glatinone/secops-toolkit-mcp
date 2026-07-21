# SecOps Toolkit MCP

[![CI](https://github.com/glatinone/secops-toolkit-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/glatinone/secops-toolkit-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/glatinone/secops-toolkit-mcp)](https://github.com/glatinone/secops-toolkit-mcp/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small, dependency-light [Model Context Protocol](https://modelcontextprotocol.io)
server that gives an AI assistant a set of **defensive security helpers** for
working with logs, threat-intel notes, and network data — all running locally,
with no API keys and no outbound network calls.

Built with [FastMCP](https://github.com/jlowin/fastmcp).

## Tools

| Tool | What it does |
| --- | --- |
| `extract_iocs` | Pull IPs, URLs, domains, MD5/SHA1/SHA256 hashes, and CVE IDs out of free-form text. Handles defanged input (`1.2.3[.]4`, `hxxp://`). |
| `defang_ioc` | Make an indicator safe to paste: `1.2.3.4` → `1.2.3[.]4`. |
| `refang_ioc` | Reverse a defanged indicator back to its real form. |
| `hash_text` | Hash a string with md5 / sha1 / sha256 / sha512. |
| `password_entropy` | Estimate password strength in bits of entropy. |
| `cidr_info` | Describe a CIDR network: netmask, host range, size, privacy. |
| `ip_in_cidr` | Check whether an IP falls inside a CIDR range. |
| `scan_repo_root` | Check a repo's top-level directory for files that shadow common dev command names (`git.exe`, `node.exe`, etc.), and the whole tree for symlinks that resolve outside the repo, before you open it in an agentic coding tool. |
| `assess_shell_command` | Assess a shell command for constructs (quote fragmentation, command substitution, IFS tricks) that look benign to naive string matching but execute something else once a shell expands them. |

> These are **defensive / analysis** utilities — parsing, hashing, and network
> math. They don't scan, attack, or reach out to any host.

## Quickstart

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/glatinone/secops-toolkit-mcp.git
cd secops-toolkit-mcp
uv sync
uv run secops-toolkit-mcp   # starts the server over stdio
```

That's it, the server is now running and waiting for an MCP client to connect
over stdio. Wire it into a client (below), or call the underlying functions
directly in Python (see Examples).

## Use it from an MCP client

Add this to your client's MCP config (e.g. Claude Desktop's
`claude_desktop_config.json`). Point `--directory` at where you cloned the repo:

```json
{
  "mcpServers": {
    "secops-toolkit": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/secops-toolkit-mcp", "secops-toolkit-mcp"]
    }
  }
}
```

Then ask your assistant things like *"extract the IOCs from this alert"* or
*"is 10.0.4.20 inside 10.0.0.0/16?"* and it will call these tools.

## Standalone CLI: `secops-scan-repo`

`scan_repo_root` is also available outside an MCP client, as its own console
script, for the exact moment it matters most: right after you clone or
download a repo and before you open it in an agentic coding tool.

```bash
uv run secops-scan-repo /path/to/a/freshly-cloned-repo
# secops-scan-repo: /path/to/a/freshly-cloned-repo (4 top-level file(s), 1 symlink(s) scanned)
#
#   [CRITICAL] git.exe shadows the 'git' command
#   [CRITICAL] vendor_link is a symlink resolving outside the repo root, to /home/dev/.ssh/authorized_keys
```

Exits `0` on a clean directory, `1` if a finding is at or above
`--min-severity` (default `medium`, i.e. any finding), `2` on a bad path.
`-f/--format json` gives the same structure `scan_repo_root` returns, for
scripting. This makes it a one-liner in a pre-clone git hook:

```bash
#!/bin/sh
# .git/hooks/post-checkout (or a wrapper your clone script calls)
secops-scan-repo "$(git rev-parse --show-toplevel)" || {
  echo "secops-scan-repo: refusing to continue, see findings above" >&2
  exit 1
}
```

If installed system-wide (`uv tool install .` or `pip install .`), drop the
`uv run` prefix and call `secops-scan-repo` directly.

## Examples

The tools are plain functions in [`core.py`](src/secops_toolkit_mcp/core.py), so
you can call them directly (e.g. in a REPL or a script) without going through
an MCP client:

```python
from secops_toolkit_mcp.core import extract_iocs, defang_ioc, hash_text, password_entropy, cidr_info, ip_in_cidr, assess_shell_command

extract_iocs("Reached out to 1.2.3[.]4 and hxxp://evil.example.com, hash 5d41402abc4b2a76b9719d911017c592, see CVE-2024-1234")
# {'md5': ['5d41402abc4b2a76b9719d911017c592'], 'ipv4': ['1.2.3.4'],
#  'url': ['http://evil.example.com'], 'domain': ['evil.example.com'],
#  'cve': ['CVE-2024-1234']}

defang_ioc("http://1.2.3.4/payload")
# 'hxxp[://]1[.]2[.]3[.]4/payload'

hash_text("hello world")
# {'algorithm': 'sha256', 'hex_digest': 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'}

password_entropy("Tr0ub4dor&3")
# {'length': 11, 'charset_size': 94, 'entropy_bits': 72.1, 'strength': 'strong'}

cidr_info("10.0.0.0/24")
# {'network': '10.0.0.0', 'netmask': '255.255.255.0', 'prefix_length': 24,
#  'version': 4, 'num_addresses': 256, 'is_private': True,
#  'first_host': '10.0.0.1', 'last_host': '10.0.0.254', 'broadcast': '10.0.0.255'}

ip_in_cidr("10.0.0.5", "10.0.0.0/24")
# True

scan_repo_root("/path/to/a/freshly-cloned-repo")
# {'path': '/path/to/a/freshly-cloned-repo', 'entries_scanned': 4,
#  'symlinks_scanned': 1, 'clean': False, 'findings': [
#    {'kind': 'shadowed_name', 'filename': 'git.exe', 'shadows': 'git',
#     'severity': 'critical'},
#    {'kind': 'symlink_escape', 'path': 'vendor_link',
#     'resolves_to': '/home/dev/.ssh/authorized_keys', 'severity': 'critical'}
#  ]}

assess_shell_command("r'm' -rf /")
# {'command': "r'm' -rf /", 'risk': 'dangerous', 'logical_commands': [
#    {'raw_segment': "r'm' -rf /", 'tokens': ['rm', '-rf', '/'],
#     'effective_command': 'rm -rf /',
#     'findings': ['bypassed_raw_pattern_match', 'denylisted_pattern'],
#     'raw_denylist_hits': [], 'normalized_denylist_hits': ['recursive_root_delete'],
#     'risk': 'dangerous'}
#  ], 'substitutions': [], 'pipe_findings': [], 'bypassed_raw_pattern_match': True}
# Note raw_denylist_hits is empty: a filter matching the raw text "r'm' -rf /"
# finds nothing. normalized_denylist_hits catches it because the tokens are
# what a real shell would actually run.
```

From an MCP client, the same calls happen through natural language, for
example asking *"hash this string with sha256"* or *"describe the network
10.0.0.0/24"*.

## Why `scan_repo_root` exists

Mindgard disclosed (2026-07-15) that Cursor, GitHub Copilot CLI, Gemini CLI,
and Codex all resolve an unqualified `git` command on startup. Windows checks
the current working directory before `PATH`, so a cloned repo that ships a
file literally named `git.exe` at its root runs that file instead of the real
Git — before any workspace-trust prompt appears. As of this writing none of
the four vendors has shipped a fix.

`scan_repo_root` closes this independent of which tool eventually opens the
repo: point it at a directory before you open it (or wire it into a
pre-clone/pre-open hook) and it flags any top-level file whose name shadows a
commonly unqualified-invoked command (`git`, `node`, `npm`, `python`, `bash`,
`docker`, and similar), tiered by how directly the shape has been confirmed
exploitable:

- **critical** — `git`, the name Mindgard's disclosure confirmed end-to-end.
- **high** — shells and interpreters (`node`, `npm`, `npx`, `python`, `bash`,
  `cmd`, `powershell`, ...) that agentic tools commonly invoke unqualified.
- **medium** — other common dev tools (`docker`, `make`, `curl`, `ssh`, `gh`,
  ...) plausibly invoked the same way but not confirmed by the disclosure.

Only the top-level directory is checked, matching how Windows's own
unqualified-command search actually works (current directory, then `PATH` —
it does not recurse into subdirectories).

### Symlink-escape check

Wiz's "GhostApproval" (Amazon Q, Cursor) and Cursor's "DuneSlide"
(CVE-2026-50548/50549, CVSS 9.3-9.8) disclosures are a second, unrelated
masquerading shape: an approval dialog or sandbox check displays a decoy
path while a symlink silently redirects the actual write target outside the
trusted directory — up to and including `~/.ssh/authorized_keys`. Both are
zero-click once triggered by a prompt-injected agent action.

`scan_repo_root` also walks the whole repo tree (not just the top level —
a planted symlink can sit anywhere a tool later writes through it) and
flags any symlink whose resolved target lies outside the scanned root:

- **critical** — the resolved target hits a known sensitive path (an
  `.ssh`/`.aws`/`.gnupg`/`.docker`/`.kube`/`.azure` directory, or a private
  key/credential filename like `authorized_keys`, `id_rsa`, `.npmrc`,
  `.git-credentials`).
- **high** — resolves outside the root to anywhere else.

A symlinked directory's own contents are never walked into (only the
symlink entry itself is inspected), so this can't be tricked into
recursing outside the intended scan boundary.

## Why `assess_shell_command` exists

GuardFall (2026-06) tested 11 popular open-source AI coding agents (Aider,
Cline, Goose, Plandex, and others — roughly 548,000 combined GitHub stars)
and found that 10 of them run a command-safety guard which inspects the raw
string a model wrote, then hands that same string to a real shell. The shell
rewrites the string before anything executes: quotes get removed, backslash
escapes get resolved, `$(...)`/backtick command substitutions run, and
variables (including `$IFS`, the field separator, which defaults to
whitespace) get expanded. A guard that pattern-matches the raw text has
already lost by the time any of that happens. `r'm' -rf /` doesn't look like
`rm -rf /` to a regex, but a shell dequotes and concatenates it into exactly
that.

`assess_shell_command` closes that gap by tokenizing with the same
POSIX quote-removal rules a real shell uses (`shlex`), so the *normalized*
command is what gets checked, not the raw string. It also:

- Extracts `$(...)`/backtick command substitutions and recursively assesses
  the command hidden inside them.
- Flags unquoted variable expansion, `$IFS`-based space-substitution tricks,
  ANSI-C (`$'...'`) quoting, and unbalanced quotes — constructs whose real
  effect can't be determined from the text alone.
- Flags a fetch piped straight into an interpreter (`curl ... | sh`), a
  pattern that gives you no chance to inspect what you're about to run.

It never executes the command, or any part of it, at any point — this is
static text analysis, not a sandbox. Returns `risk` (`safe`, `suspicious`, or
`dangerous`) plus `bypassed_raw_pattern_match`: concrete, per-call evidence
that a normalized check caught something a raw-text filter would have missed.

## Run with Docker

The included `Dockerfile` builds a container that launches the server over
stdio, so an MCP client can run it without a local Python/uv install:

```bash
docker build -t secops-toolkit-mcp .
docker run -i --rm secops-toolkit-mcp
```

To use it from an MCP client, point the client's config at `docker run`
instead of `uv run`:

```json
{
  "mcpServers": {
    "secops-toolkit": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "secops-toolkit-mcp"]
    }
  }
}
```

## Troubleshooting

- **Client shows the server as disconnected / no tools listed.** MCP clients
  talk to this server over stdio, so anything else printed to stdout will
  break the protocol. Confirm you're running `uv run secops-toolkit-mcp` (or
  the Docker command above) exactly, not piping it through another wrapper
  that adds its own output.
- **`--directory` path errors in the client config.** The path must be
  absolute and point at the cloned repo root (the folder containing
  `pyproject.toml`), not the `src/` directory.
- **`ValueError` from `hash_text`, `cidr_info`, or `ip_in_cidr`.** These raise
  on bad input (unsupported hash algorithm, malformed IP/CIDR) with a message
  naming the invalid value, by design, rather than failing silently.
- **Python version errors during `uv sync`.** The project requires Python
  3.11+ (see `.python-version`); `uv` will fetch a matching interpreter
  automatically if one isn't already installed.

## Development

```bash
uv sync          # install deps (incl. dev)
uv run pytest    # run the test suite
```

The logic lives in [`core.py`](src/secops_toolkit_mcp/core.py) as plain,
testable functions; [`server.py`](src/secops_toolkit_mcp/server.py) is a thin
layer that exposes them as MCP tools.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow for adding a new
tool, and [CHANGELOG.md](CHANGELOG.md) for release history.

## Roadmap

- [x] Initial tool set: IOC extraction, defang/refang, hashing, password
  entropy, CIDR math (v0.1.0)
- [x] CI on Python 3.11 to 3.13, CHANGELOG (v0.2.0)
- [x] `scan_repo_root`, a pre-clone/pre-open check for binaries that shadow
  common dev command names (v0.3.0), closing the Mindgard 2026-07-15
  unqualified-`git` disclosure
- [x] `assess_shell_command`, a shell command safety check that assesses
  what a shell actually runs rather than the raw string a model wrote
  (v0.4.0), closing the GuardFall 2026-06 bypass class
- [x] `secops-scan-repo`, a standalone CLI for `scan_repo_root` (v0.5.0), so
  it can run in a pre-clone git hook or CI step without an MCP client
- [x] `scan_repo_root` symlink-escape check (v0.6.0): flags a symlink
  anywhere in the repo tree whose resolved target lies outside the repo
  root, closing the GhostApproval/DuneSlide hidden-write-target pattern
- [ ] Widen `scan_repo_root`'s shadowed-name/extension coverage, its
  sensitive-target symlink list, and `assess_shell_command`'s denylist
  patterns as real-world use surfaces gaps; all three are intentionally
  high-signal, not exhaustive (see the module comments in `core.py`)
- [ ] PyPI packaging, once the same pattern is proven end to end on
  [mcpscan](https://github.com/glatinone/mcpscan) first

Contributions welcome, open an issue or PR.

## License

MIT — see [LICENSE](LICENSE).
