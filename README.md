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

## Install & run

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/glatinone/secops-toolkit-mcp.git
cd secops-toolkit-mcp
uv sync
uv run secops-toolkit-mcp   # starts the server over stdio
```

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
