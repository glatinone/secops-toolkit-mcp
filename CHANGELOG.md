# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `CONTRIBUTING.md`: project layout, how to add a new tool, and design
  principles (no API keys / no outbound network calls, dependency-light,
  fail loudly on bad input).
- Release badge in the README, alongside the existing CI and License badges.

### Changed

- CI: bumped `actions/checkout` (v4 → v7) and `astral-sh/setup-uv` (v4 →
  v8.3.2, pinned to the full tag since `astral-sh/setup-uv` doesn't publish a
  floating `v8` major-version alias yet) to clear a Node.js 20 deprecation
  warning noted since the v0.2.0 CI setup.

## [0.3.0] - 2026-07-19

### Added

- `scan_repo_root`: checks a repository's top-level directory for files that
  shadow common developer command names (`git.exe`, `node.exe`, `npm.cmd`,
  etc.), tiered critical/high/medium by how directly the shape has been
  confirmed exploitable. Closes a live, unpatched, multi-vendor gap: Mindgard
  disclosed (2026-07-15) that Cursor, GitHub Copilot CLI, Gemini CLI, and
  Codex all resolve an unqualified `git` command on startup, and Windows
  checks the current working directory before `PATH`, so a cloned repo
  shipping its own `git.exe` at the root executes attacker code before any
  workspace-trust prompt appears. Run this before opening a freshly cloned or
  downloaded repository in any of those tools. Only the top-level directory
  is checked, matching Windows's actual (non-recursive) search order.
- README: Quickstart, worked Examples for every tool with real input/output,
  a Docker usage section, and a Troubleshooting section.

## [0.2.0] - 2026-07-11

### Added

- GitHub Actions CI (`.github/workflows/ci.yml`): runs the test suite with `uv`
  on Python 3.11, 3.12, and 3.13, and verifies the package builds with `uv build`.
  The repo had no CI at all before this — every prior release depended on tests
  having been run locally before pushing.
- CI and License badges in the README.

## [0.1.0] - 2026-06-30

### Added

- Initial release: `extract_iocs`, `defang_ioc`, `refang_ioc`, `hash_text`,
  `password_entropy`, `cidr_info`, `ip_in_cidr` tools over FastMCP. Never tagged
  on GitHub — `0.2.0` is this project's first tagged release.

[Unreleased]: https://github.com/glatinone/secops-toolkit-mcp/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/glatinone/secops-toolkit-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/glatinone/secops-toolkit-mcp/compare/ca21900...v0.2.0
[0.1.0]: https://github.com/glatinone/secops-toolkit-mcp/commit/ca21900
