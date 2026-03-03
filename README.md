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

### Tier 1 — Offline (9 checks)

| Check | What It Detects |
|-------|-----------------|
| Server Type Detection | Classifies servers (package manager, container, binary, script, HTTP) |
| Command Safety | 22 dangerous patterns: sudo, shell injection, network downloads, eval/exec |
| Credentials | Plaintext API keys (AWS, GitHub, Stripe, OpenAI, Anthropic), tokens, URL credentials |
| Script Location | Scripts in `/tmp` (critical), home directories (medium) |
| Script Permissions | World-writable scripts (critical) |
| Binary Location | Binaries in temp dirs (critical), unknown locations (high) |
| Binary Permissions | World-writable (critical) or group-writable (high) binaries |
| Container Isolation | `--privileged`, dangerous capabilities, host namespace sharing |
| Container Volumes | Dangerous mounts: root filesystem, Docker socket, SSH keys, AWS credentials |

### Tier 2 — Online (11 checks, skipped with `--offline`)

| Check | What It Detects |
|-------|-----------------|
| Registry Listing | Whether the server is in the official MCP Registry |
| Vulnerabilities | Known CVEs and malware via OSV.dev |
| Typosquatting | Similarly-named packages that could be malicious |
| Distribution | Low adoption signals (download count, package age) |
| Source Repository | Missing or unlinked source repository |
| Unscoped Variant | Malware in unscoped npm package variants |
| GitHub Trust | Archived repos, inactivity, no license, low stars, single contributor |
| Container Image | Missing digest pinning, Sigstore attestations |
| Container Registry | Image existence verification, digest tampering detection |
| Container Signature | Cosign signature verification in OCI registries |
| OAuth | Authentication presence and endpoint security for HTTP/SSE servers |

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

**Golf Scanner finds what's running. [Golf](https://golf.dev) governs it.**

Golf Scanner gives you a point-in-time inventory. But your auditor will ask: *who approved these connections? What data flowed through them? Can you prove compliance?*

Golf is the governance platform for MCP. It discovers every server across your org, logs every connection with full provenance, and enforces your policies — so you're always audit-ready.

| | Golf Scanner (Free) | Golf |
|---|-------------------|------|
| **Discovery** | 7 IDEs, single machine | Fleet-wide — every IDE, every machine, every team |
| **Security checks** | 9 offline + 11 online | All checks + LLM-powered threat detection |
| **Audit trail** | CLI output | 90-day immutable trail, pre-mapped to SOC 2, ISO 27001, NIST AI RMF |
| **Enforcement** | None | PII redaction, RBAC, approval workflows for high-risk actions |
| **Monitoring** | One-time scan | Continuous — new servers detected immediately |
| **Deployment** | Single binary | On-prem, hybrid, or cloud. Data never leaves your environment. |

Learn more at [golf.dev](https://golf.dev) or read the [documentation](https://docs.golf.dev/gateway/overview).

## License

Apache 2.0 — see [LICENSE](LICENSE).

<div align="center">
Made with ❤️ by the <a href="https://golf.dev">Golf</a> team
</div>
