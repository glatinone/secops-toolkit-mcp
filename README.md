# SecOps Toolkit MCP

[![CI](https://github.com/glatinone/secops-toolkit-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/glatinone/secops-toolkit-mcp/actions/workflows/ci.yml)
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
from secops_toolkit_mcp.core import extract_iocs, defang_ioc, hash_text, password_entropy, cidr_info, ip_in_cidr

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
```

From an MCP client, the same calls happen through natural language, for
example asking *"hash this string with sha256"* or *"describe the network
10.0.0.0/24"*.

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

## License

MIT — see [LICENSE](LICENSE).
