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
| `scan_repo_root` | Check a repo's top-level directory for files that shadow common dev command names (`git.exe`, `node.exe`, etc.) before you open it in an agentic coding tool. |
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
# {'path': '/path/to/a/freshly-cloned-repo', 'entries_scanned': 5,
#  'clean': False, 'findings': [
#    {'filename': 'git.exe', 'shadows': 'git', 'severity': 'critical'}
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

## License

MIT — see [LICENSE](LICENSE).
