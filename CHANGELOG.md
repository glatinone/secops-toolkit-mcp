# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-07-19

### Added

- `assess_shell_command`: analyzes a shell command line for constructs that
  look benign to naive string matching but execute something else once a
  shell actually expands them. Closes the bypass class GuardFall (2026-06)
  confirmed against 10 of 11 popular open-source AI coding agents (Aider,
  Cline, Goose, Plandex, and others, ~548K combined GitHub stars): their
  command-safety guards check the raw string a model wrote, not what the
  shell rewrites it into via quote removal, backslash escapes, command
  substitution, and variable/IFS expansion. Tokenizes each logical
  sub-command with real POSIX quote-removal rules, so a quote-fragmented or
  backslash-obfuscated command (`r'm' -rf /`, `r\m -rf /`) normalizes to
  what actually runs (`rm -rf /`) before any denylist check. Recursively
  assesses command substitutions (`$(...)`, backticks), flags unquoted
  variable expansion, IFS-based space-substitution tricks, ANSI-C quoting,
  and a fetch-piped-to-interpreter shape (`curl ... | sh`). Never executes
  the command, or any part of it, at any point. 19 new tests (46 total, was
  27).
- `CONTRIBUTING.md`: project layout, how to add a new tool, and design
  principles (no API keys / no outbound network calls, dependency-light,
  fail loudly on bad input).
- Release badge in the README, alongside the existing CI and License badges.

### Changed

- CI: bumped `actions/checkout` (v4 → v7) and `astral-sh/setup-uv` (v4 →
  v8.3.2, pinned to the full tag since `astral-sh/setup-uv` doesn't publish a
  floating `v8` major-version alias yet) to clear a Node.js 20 deprecation
  warning noted since the v0.2.0 CI setup.
- `pyproject.toml`'s package description, stale since `scan_repo_root` shipped
  in v0.3.0, now names every current tool.

### Fixed

- `assess_shell_command`'s `bypassed_raw_pattern_match` flag was `True` for
  *every* detected `rm -rf <sensitive path>`, obfuscated or not. The
  recursive-delete check is structural, not regex-based, and was only ever
  evaluated against the normalized (post-quote-removal) tokens, with nothing
  to compare against — so a completely plain `rm -rf /` looked exactly like
  a closed bypass. Added a naive whitespace-only split as the "raw" baseline
  for this specific check, so the flag now only fires when quote-removal is
  what made the finding appear (confirmed against both a plain `rm -rf /`,
  now correctly unflagged, and the genuine `r'm' -rf /` bypass, still
  correctly flagged).

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

[Unreleased]: https://github.com/glatinone/secops-toolkit-mcp/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/glatinone/secops-toolkit-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/glatinone/secops-toolkit-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/glatinone/secops-toolkit-mcp/compare/ca21900...v0.2.0
[0.1.0]: https://github.com/glatinone/secops-toolkit-mcp/commit/ca21900
