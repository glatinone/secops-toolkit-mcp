# Security Policy

## Scope

This policy covers the `secops-toolkit-mcp` project: the MCP server implementation, its
CLI entry points (`secops-toolkit-mcp`, `secops-scan-repo`), and all code published in
this repository, including released packages built from it.

Because this project provides defensive security tooling (IOC extraction, defang/refang,
hashing, password entropy analysis, CIDR math, repo-root command-shadowing and
symlink-escape checks, and shell command safety assessment), vulnerabilities in its own
implementation are treated as high priority. A flaw in a security tool can produce
false assurances or be leveraged against the systems it is meant to help protect, and is
evaluated accordingly.

Examples of in-scope issues include, but are not limited to:

- Logic errors that cause a check (e.g. shell command safety assessment, CIDR
  containment, symlink-escape detection) to report a false negative
- Input handling flaws (parsing, regex, deserialization) that could lead to
  denial of service, resource exhaustion, or code execution
- Path traversal, symlink, or file-handling issues in repo-scanning functionality
- Weaknesses in hashing or entropy calculations that materially misrepresent the
  security properties being measured
- Dependency vulnerabilities that are exploitable through this project's exposed
  interfaces

Issues in third-party dependencies with no exploitable path through this project, and
purely theoretical weaknesses with no practical impact, are considered out of scope but
may still be reported for awareness.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately using GitHub Security
Advisories:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability** to open a new draft security advisory.
3. Provide as much detail as possible: affected version(s), a description of the
   issue, steps to reproduce, and potential impact.

Do not report security vulnerabilities through public GitHub issues, discussions, or
pull requests. Do not disclose the issue publicly until it has been investigated and a
fix or mitigation has been released.

If you are unable to use GitHub Security Advisories for any reason, open a regular
GitHub issue requesting a private contact channel, without including any vulnerability
details, and a maintainer will follow up.

## Response Process and Timelines

- **Acknowledgment:** Reports will be acknowledged within 72 hours of submission.
- **Triage:** The report will be assessed to confirm validity, determine severity, and
  identify affected versions.
- **Resolution target:** For confirmed vulnerabilities, the maintainers will aim to
  release a fix or mitigation and coordinate disclosure within 90 days of
  acknowledgment. If more time is required (for example, due to complexity or
  coordination with dependencies), reporters will be informed of the revised timeline.
- **Disclosure:** Once a fix is available, an advisory will be published through
  GitHub Security Advisories, and, where applicable, a new release will be issued along
  with an entry in the changelog. Public disclosure timing will be coordinated with the
  reporter, and by default will occur at or before the 90-day mark from acknowledgment.

## Supported Versions

Security fixes are provided for the latest released version on the default branch.
Users are expected to upgrade to the latest release to receive security fixes. Older
versions are not maintained.

## Reporter Recognition

With the reporter's consent, valid reports will be credited in the security advisory
and/or the project changelog once a fix has been published.
