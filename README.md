<div align="center">

  <h1 align="center">
    <br>
    <span style="font-size: 80px;">🔍 Golf Scanner</span>
    <br>
  </h1>

  <h3 align="center">
    Discover and audit MCP servers across your IDEs
  </h3>

  <br>

  <p>
    <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
    <a href="https://github.com/golf-mcp/golf-scanner/pulls"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs"></a>
    <a href="https://github.com/golf-mcp/golf-scanner/issues"><img src="https://img.shields.io/badge/support-contact%20author-purple.svg" alt="Support"></a>
  </p>

  <p>
    <a href="https://docs.golf.dev/scanner/overview"><strong>📚 Documentation</strong></a> · <a href="https://docs.golf.dev/scanner/quickstart"><strong>🚀 Quick Start</strong></a> · <a href="https://golf.dev"><strong>⛳ Golf</strong></a>
  </p>

</div>

---

Free, open-source CLI that discovers MCP server configurations across your machine and runs security checks to produce a risk score. Single binary. Zero telemetry. No account required.

## Quick Start

Install via Homebrew:

```bash
brew install golf-mcp/tap/golf-scanner
```

Or with Go:

```bash
go install github.com/golf-mcp/golf-scanner/cmd/golf-scanner@latest
```

Discover your MCP servers:

```bash
golf-scanner scan
```

Run a security audit:

```bash
golf-scanner audit
```

## What It Does

Golf Scanner is a single static binary (pure Go, 3 dependencies) that:

1. **Discovers** MCP server configurations across 7 IDEs — Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Kiro, and Antigravity
2. **Runs 20 security checks** — 9 offline (no network) + 11 online (queries OSV, GitHub, npm, PyPI, OCI registries, MCP Registry)
3. **Produces a 0–100 risk score** per server with severity-weighted scoring and hard caps

No account required. Runs offline. Zero telemetry.

### Supported IDEs

Claude Code · Cursor · VS Code · Windsurf · Gemini CLI · Kiro · Antigravity

## Usage

### `audit`

Discover servers and run security checks with risk scoring.

```bash
golf-scanner audit
```

Skip network checks (offline mode):

```bash
golf-scanner audit --offline
```

Verbose output with remediation details:

```bash
golf-scanner audit --verbose
```

CI/CD integration — fail if high or critical findings:

```bash
golf-scanner audit --fail-on high --json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--offline` | `false` | Skip network checks (OSV, GitHub, npm, PyPI, MCP Registry, OCI registries) |
| `--format` | `table` | Output format: `table` or `json` |
| `--json` | `false` | Shorthand for `--format json` |
| `--fail-on` | | Exit code 1 if findings at or above severity: `note`, `medium`, `high`, `critical` |
| `--verbose`, `-v` | `false` | Show full finding details including remediation |
| `--quiet`, `-q` | `false` | Show only the summary table |

`--verbose` and `--quiet` are mutually exclusive.

## Security Checks

| Check | What It Detects | Online |
|-------|-----------------|--------|
| Server Type | Classifies the server as package manager, container, binary, script, or HTTP | |
| Command Safety | Identifies risky patterns including privilege escalation and shell injection threats | |
| Credentials | Finds plaintext credentials in args, URLs, and environment variables | |
| Script Location | Flags scripts running from unsafe locations like `/tmp` or home directories | |
| Script Permissions | Detects world-writable script files | |
| Binary Location | Assesses executable placement across system paths and home directories | |
| Binary Permissions | Detects world-writable or group-writable binaries | |
| Container Isolation | Flags `--privileged` mode, dangerous capabilities, host namespace sharing | |
| Container Volumes | Flags dangerous volume mounts — root filesystem, `/etc`, Docker socket | |
| Registry Listing | Confirms MCP Registry inclusion status | Yes |
| Vulnerabilities | Queries OSV.dev for known CVEs and malware in npm/PyPI packages | Yes |
| Typosquatting | Identifies similarly-named packages suggesting malicious imitation | Yes |
| Distribution | Evaluates adoption through download metrics and package age | Yes |
| Source Repository | Checks whether the package links to a source repository | Yes |
| Unscoped Variant | Examines unscoped npm counterparts for security issues | Yes |
| GitHub Trust | Evaluates repository signals like activity, licensing, and contributor count | Yes |
| Container Image | Checks whether images use digest pinning (`@sha256:`) | Yes |
| Container Registry | Validates image presence and flags potential tampering via digest mismatch | Yes |
| Container Signature | Verifies cosign signatures with keyless authentication | Yes |
| OAuth | Discovers OAuth/OIDC configuration. Flags missing authentication | Yes |

For full details on each check, see the [Security Checks reference](https://docs.golf.dev/scanner/security-checks).

## Scoring

Each server receives a **0–100 risk score**:

1. Each check produces findings; the worst severity determines the per-check score (0–10)
2. Scores are combined via **severity-weighted average** (critical 10x, high 7.5x, medium 5x, note 1x)
3. The raw average is scaled to 0–100
4. **Hard caps** apply: any critical finding caps the score at 30, any high finding caps at 59
5. **Risk level**: Low (≥60), Moderate (>30), High (≤30)

For the full scoring explanation, see [Understanding Results](https://docs.golf.dev/scanner/understanding-results).

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | Optional. Increases GitHub API rate limit from 60 to 5,000 req/hr. |
| `GOLF_GITHUB_TOKEN` | Optional. Fallback if `GITHUB_TOKEN` is not set. |

No token is needed for most scans. The scanner makes ~3 GitHub API calls per unique repo (metadata, commits, contributors) with results cached, so you'll only hit the unauthenticated limit if you have 20+ servers pointing to distinct GitHub repos.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | No args, unknown command, `--fail-on` threshold exceeded, or flag conflict |
| 2 | JSON error or invalid `--fail-on` value |

## Golf

**Scanner = visibility** (what exists). **[Golf](https://golf.dev) = governance** (what's allowed, logged, and protected).

Golf Scanner gives you a point-in-time snapshot. The full Golf platform extends that into continuous governance:

- **Golf Inventory** — continuous MCP discovery, always up to date, not a point-in-time scan
- **Golf Gateway** — policy enforcement per server, per team, per data type. PII redaction and tool-level access controls
- **Audit Trail** — immutable logs of every connection, pre-mapped to SOC 2, ISO 27001, NIST AI RMF
- **Multi-Tool Support** — works with every AI tool (Cursor, Claude Code, Copilot, ChatGPT) without changing developer workflows

| | Golf Scanner (Free) | Golf |
|---|-------------------|------|
| **Discovery** | 7 IDEs, single machine, point-in-time | Continuous — every IDE, every machine, every team |
| **Security checks** | 9 offline + 11 online | All scanner checks + additional threat detection |
| **Audit trail** | CLI output | Immutable trail, pre-mapped to SOC 2, ISO 27001, NIST AI RMF |
| **Enforcement** | None | Policy enforcement per server/team/data type, PII redaction, tool-level access controls |
| **Monitoring** | One-time scan | Always up to date — new servers detected immediately |
| **Deployment** | Single binary | On-prem, hybrid, or cloud. Data never leaves your environment. |

Learn more at [golf.dev](https://golf.dev) or read the [documentation](https://docs.golf.dev/gateway/overview).

## License

Apache 2.0 — see [LICENSE](LICENSE).

<div align="center">
Made with ❤️ by the <a href="https://golf.dev">Golf</a> team
</div>
