# Contributing to secops-toolkit-mcp

Thanks for your interest in improving this project. Contributions of all sizes
are welcome — new tools, bug fixes, docs, tests.

## Getting started

```bash
git clone https://github.com/glatinone/secops-toolkit-mcp.git
cd secops-toolkit-mcp
uv sync
uv run pytest -v
```

Requires Python 3.11+ (`uv` will fetch a matching interpreter automatically).
The test suite must stay green before a PR is merged.

## Project layout

- [`src/secops_toolkit_mcp/core.py`](src/secops_toolkit_mcp/core.py) — plain,
  testable Python functions. This is where the actual logic lives; each
  function should be callable and useful on its own, outside of any MCP client.
- [`src/secops_toolkit_mcp/server.py`](src/secops_toolkit_mcp/server.py) — a
  thin [FastMCP](https://github.com/jlowin/fastmcp) wrapper that exposes each
  `core.py` function as an MCP tool. It should not contain logic of its own.
- [`src/secops_toolkit_mcp/cli.py`](src/secops_toolkit_mcp/cli.py) — the
  standalone `secops-scan-repo` console script. Only `scan_repo_root` is
  wired up here today; a tool needs a standalone CLI use case (a pre-clone
  hook, a CI step) to justify one, not every tool needs one by default.
- [`tests/test_core.py`](tests/test_core.py) — unit tests for `core.py`.
- [`tests/test_cli.py`](tests/test_cli.py) — unit tests for `cli.py`.

## Adding a tool

1. Add the function to `core.py`. Raise `ValueError` (with a message naming
   the bad input) on invalid input rather than failing silently or returning
   a sentinel — existing tools follow this convention.
2. Register it as a tool in `server.py`, following the pattern of the
   existing tools.
3. Add unit tests in `tests/test_core.py` covering both expected input and the
   error cases.
4. Document it: add a row to the README's Tools table, a worked example under
   Examples using real (not hand-written) input/output, and an entry in
   `CHANGELOG.md`.

## Design principles

- **No API keys, no outbound network calls.** Every tool should run fully
  offline against local input. This is a hard constraint, not a preference.
- **Dependency-light.** Think twice before adding a new runtime dependency.
- **Fail loudly on bad input.** A `ValueError` with a clear message beats a
  silent wrong answer.

## Commit & PR

- Keep commits focused; write a clear, imperative summary.
- Run `uv run pytest` before pushing.
- Verify any example output in your PR description or the README against the
  actual function output rather than a plausible-looking guess.

By contributing you agree your work is licensed under the project's
[MIT License](LICENSE).
