---
date: 2026-03-03T11:08:13+0000
researcher: Claude
git_commit: 6e865fa7f1609731bfab031a203d4d9f48bd40c5
branch: main
repository: golf-scanner
topic: "Moving OSS golf-scanner from golf-gateway monorepo to golf-local repo"
tags: [research, codebase, scanner, auditor, extraction, open-source, golang]
status: complete
last_updated: 2026-03-03
last_updated_by: Claude
---

# Research: Moving OSS Golf Scanner to Standalone Repo

**Date**: 2026-03-03T11:08:13+0000
**Researcher**: Claude
**Git Commit**: 6e865fa7f1609731bfab031a203d4d9f48bd40c5
**Branch**: main
**Repository**: golf-scanner (https://github.com/golf-mcp/golf-scanner.git)

## Research Question

How to move the OSS part of the golf scanner from `golf-gateway/src/go/golf-scanner/` to the `golf-local` repo (github.com/golf-mcp/golf-scanner) and set it up for official release, per the extraction plan in `golf-gateway/docs/2026-02-24_mcp-scanner-opensource-extraction.md`.

## Summary

### Current State

The extraction is **already substantially complete** in the monorepo. The Go codebase at `golf-gateway/src/go/golf-scanner/` is a fully self-contained tool with:

- **Zero Control Plane coupling** -- no enrollment, no API calls to golf backend, no keychain token storage
- **All Tier 1 checks already ported to Go** -- server_type, command, credentials, script, binary, container (isolation + volumes + image)
- **All Tier 2 checks already ported to Go** -- container registry/signature, MCP registry verification, package vulnerability/typosquatting/distribution/repository/unscoped, GitHub trust, OAuth
- **Scoring engine ported to Go** -- same formula as Python (weighted average, hard caps, coverage gate)
- **Identity computation + grouping** -- deduplication by computed identity (URL, package, container, command)
- **Report formatting** -- JSON output and styled terminal table with progress spinner
- **Test fixtures** -- 12 server configs in `testdata/` with expected output
- **Module path already set**: `github.com/golf-mcp/golf-scanner`

The Go tool has **more checks than the extraction doc planned**. It includes 20 checks (10 offline + 10 online) vs the doc's Phase 1 target of 6 Tier 1 checks. The full Tier 2 network checks (Phase 2 in the plan) are also done.

### What Needs to Happen

The golf-local repo (github.com/golf-mcp/golf-scanner) is **empty** -- only a placeholder README and .gitignore. The migration is essentially:

1. **Copy the Go source** from `golf-gateway/src/go/golf-scanner/` to the repo root
2. **Verify module path** -- already `github.com/golf-mcp/golf-scanner`, correct
3. **Add LICENSE** -- Apache 2.0 (per extraction plan)
4. **Write README** -- install instructions, usage examples, "upgrade to Golf Gateway" CTA
5. **Set up CI/CD** -- GitHub Actions for test/build/release
6. **Set up goreleaser** -- multi-platform binaries + Homebrew formula
7. **Wire monorepo to import** -- `go get github.com/golf-mcp/mcp-scanner` (Phase 3)

## Detailed Findings

### 1. Source Codebase Analysis (golf-gateway/src/go/golf-scanner/)

#### Directory Structure (what to copy)

```
golf-scanner/
├── go.mod                              # Module: github.com/golf-mcp/golf-scanner, Go 1.23
├── go.sum
├── cmd/golf-scanner/
│   └── main.go                         # CLI: scan, audit, version commands
├── scanner/                            # Discovery package (7 IDE scanners)
│   ├── common.go                       # Scanner interface, ScanResult, arg scrubbing, file metadata
│   ├── claude.go                       # Claude Desktop/Code
│   ├── cursor.go                       # Cursor IDE
│   ├── vscode.go                       # VS Code
│   ├── windsurf.go                     # Windsurf
│   ├── gemini.go                       # Gemini CLI
│   ├── antigravity.go                  # Antigravity
│   ├── kiro.go                         # Kiro
│   ├── file_metadata_unix.go           # Unix file metadata (syscall.Stat_t)
│   ├── file_metadata_other.go          # Windows stub
│   ├── common_test.go
│   ├── claude_test.go
│   ├── cursor_test.go
│   ├── vscode_test.go
│   ├── windsurf_test.go
│   ├── gemini_test.go
│   └── kiro_test.go
├── auditor/                            # Audit engine + checks
│   ├── models.go                       # Severity, ServerType, Finding, ServerInventory, AuditContext
│   ├── engine.go                       # Check interface, RunAudit (two-phase)
│   ├── scoring.go                      # Weighted scoring, hard caps, risk levels
│   ├── identity.go                     # ComputeIdentity, ComputeDisplayName
│   ├── convert.go                      # InventoryFromScanResults
│   ├── group.go                        # GroupInventory, UniqueFileMetadataInstances
│   ├── identity_test.go
│   ├── scoring_test.go
│   ├── convert_test.go
│   ├── group_test.go
│   ├── checks/                         # 20 security checks
│   │   ├── server_type.go              # Tier 0: type detection
│   │   ├── command.go                  # Command sanitization (22 patterns)
│   │   ├── credentials.go             # Credential/secret detection
│   │   ├── script.go                   # Script location + permissions
│   │   ├── binary.go                   # Binary location + permissions
│   │   ├── container.go                # Container isolation + volumes
│   │   ├── container_image.go          # Image tagging + Sigstore attestation
│   │   ├── container_registry.go       # OCI registry verification
│   │   ├── container_signature.go      # Cosign signature detection
│   │   ├── registry_verification.go    # MCP Registry lookup
│   │   ├── package_vulnerability.go    # OSV vulnerability queries
│   │   ├── package_typosquatting.go    # deps.dev similar name check
│   │   ├── package_distribution.go     # Download count + age
│   │   ├── package_repository.go       # Source repo discovery
│   │   ├── package_unscoped.go         # Unscoped npm variant malware check
│   │   ├── github_trust.go            # GitHub repo trust signals
│   │   ├── oauth.go                    # OAuth/auth discovery
│   │   ├── package_util.go            # Shared package utilities
│   │   ├── shared.go                   # Localhost detection, URL parsing
│   │   ├── server_type_test.go
│   │   ├── command_test.go
│   │   ├── credentials_test.go
│   │   ├── script_test.go
│   │   ├── binary_test.go
│   │   ├── container_test.go
│   │   ├── checks_test.go             # Integration tests (testdata fixtures)
│   │   └── testdata_test.go           # Fixture loading helpers
│   ├── apiclient/                      # External API clients
│   │   ├── registry.go                 # MCP Registry
│   │   ├── github.go                   # GitHub API
│   │   ├── npm.go                      # npm registry
│   │   ├── pypi.go                     # PyPI
│   │   ├── osv.go                      # OSV vulnerability DB
│   │   ├── depsdev.go                  # deps.dev
│   │   ├── oci.go                      # OCI registries (Docker Hub, GHCR, etc.)
│   │   ├── urlutil.go                  # GitHub URL utilities
│   │   └── urlutil_test.go
│   └── httpclient/                     # Shared HTTP client
│       ├── client.go                   # 20s timeout, 10MB limit
│       └── ssrf.go                     # SSRF protection
├── report/                             # Output formatting
│   ├── types.go                        # Report, ServerResult, Summary structs
│   ├── json.go                         # JSON output
│   ├── table.go                        # Terminal table (3 verbosity levels)
│   ├── progress.go                     # Animated spinner/progress bar
│   └── table_test.go
└── testdata/                           # 12 fixture pairs
    ├── servers/                         # Input JSON configs
    └── expected/                        # Expected findings
```

#### Dependencies (go.mod)

| Dependency | Purpose |
|---|---|
| `github.com/charmbracelet/lipgloss` | Terminal styling (colored tables, badges) |
| `github.com/charmbracelet/x/term` | TTY detection (progress spinner) |
| `github.com/tailscale/hujson` | JSONC parsing (IDE configs with comments) |

No Golf API, no enrollment, no keychain, no database dependencies.

#### CLI Commands

| Command | Description |
|---|---|
| `scan` | Discovery only -- lists servers across 7 IDEs (JSON or table) |
| `audit` | Discovery + security checks + risk scoring |
| `version` | Print version string |

Key flags: `--json`, `--offline` (skip Tier 2), `--fail-on <severity>` (exit code), `-v`/`-q` (verbosity)

#### Check Inventory (20 checks, already in Go)

**Tier 0 (always runs):**
- `type.detection` -- server type classification

**Tier 1 (offline, 9 checks):**
- `cmd.sanitization` -- 22 dangerous command patterns
- `cmd.credentials` -- credential/secret detection
- `script.location` + `script.permissions` -- script safety
- `binary.location` + `binary.permissions` -- binary safety
- `container.isolation` + `container.volumes` -- container security
- `container.image` -- image tagging + Sigstore attestation

**Tier 2 (online, 10 checks):**
- `container.registry` + `container.signature` -- OCI registry/cosign
- `registry.verification` -- MCP Registry lookup
- `package.vulnerability` + `package.typosquatting` + `package.distribution` + `package.repository` + `package.unscoped` -- package security
- `github.trust` -- GitHub repo trust signals
- `http.auth` -- OAuth/auth discovery

### 2. Target Repo State (golf-local / golf-scanner)

The repo at `https://github.com/golf-mcp/golf-scanner` is essentially empty:

| Item | Status |
|---|---|
| Committed files | `README.md` ("# golf-scanner"), `.gitignore` (".claude/*") |
| Commits | 1 (`6e865fa` - "first commit") |
| Go code | None |
| LICENSE | None |
| CI/CD | None |
| Build config | None |

### 3. Extraction Plan Comparison: Plan vs Reality

The extraction doc proposed a phased approach. Here's what's already done:

| Plan Item | Status |
|---|---|
| Phase 1: Create OSS repo | Done (github.com/golf-mcp/golf-scanner) |
| Phase 1: Copy Go scanner | **Ready** -- code exists, module path is already correct |
| Phase 1: Remove CP code | **Already done** -- no CP code exists in golf-scanner |
| Phase 1: Rename dry-run to scan | **Already done** -- `scan` command exists |
| Phase 1: Port Tier 1 checks to Go | **Already done** -- all 9 Tier 1 checks exist |
| Phase 1: Port scoring engine | **Already done** -- `auditor/scoring.go` |
| Phase 1: Add audit command | **Already done** -- `audit` command with full pipeline |
| Phase 1: Create testdata | **Already done** -- 12 fixture pairs |
| Phase 1: Write README | **TODO** |
| Phase 1: Add LICENSE | **TODO** |
| Phase 2: Tier 2 network checks | **Already done** -- all 10 online checks exist |
| Phase 2: --online flag | **Done** (inverted as `--offline` to skip them) |
| Phase 3: Wire monorepo | **TODO** -- monorepo needs to import OSS module |
| CI/CD + goreleaser | **TODO** |
| Homebrew formula | **TODO** |

### 4. What Needs to Be Done to Ship

#### Must-Have for Release

1. **Copy source code** -- All files from `golf-gateway/src/go/golf-scanner/` to `golf-local/` root
2. **LICENSE** -- Apache 2.0 file
3. **README.md** -- Proper README with:
   - Project description and value prop
   - Installation (go install, brew, GitHub releases)
   - Usage examples (scan, audit, audit --offline, --json, --fail-on)
   - Output examples (table, JSON)
   - Supported IDEs list
   - Check descriptions
   - "Upgrade to Golf Gateway" CTA
4. **Verify builds + tests pass** -- `go build ./...` and `go test ./...`
5. **GitHub Actions CI** -- Test on push/PR (linux, macos, windows)
6. **goreleaser config** -- Multi-platform binary builds + GitHub Releases
7. **Homebrew formula** -- `brew install golf-mcp/tap/golf-scanner` (or similar)

#### Nice-to-Have for v1.0

- SARIF output format (IDE/GitHub Code Scanning integration)
- `CONTRIBUTING.md`
- `SECURITY.md`
- Code of Conduct
- Issue/PR templates
- Changelog/release notes

### 5. Key Differences from Original Extraction Plan

| Aspect | Plan Said | Reality |
|---|---|---|
| Binary name | `mcp-scanner` | `golf-scanner` (module = `github.com/golf-mcp/golf-scanner`) |
| Package structure | `cmd/mcp-scanner/` | `cmd/golf-scanner/` |
| CP code removal | Needed | Already clean -- no CP code exists |
| Check count | Phase 1: 6 checks | Already: 20 checks (all tiers) |
| Online checks | Phase 2 | Already implemented |
| Flag design | `--online` opt-in | `--offline` opt-out (online is default) |
| Module path | `github.com/golf-mcp/mcp-scanner` | `github.com/golf-mcp/golf-scanner` |

The naming question (mcp-scanner vs golf-scanner) from the plan's Open Questions is resolved: the repo is `golf-scanner`.

### 6. Python Checks NOT Ported (Tier 3 -- Stays Proprietary)

These checks remain in the Python auditor and are **intentionally excluded** from the OSS release:

| Check ID | Reason |
|---|---|
| `universal.description_change` | Requires PostgreSQL history for TOFU/rug-pull detection |
| `universal.tool_description_injection` | Requires Anthropic API (LLM-powered detection) |
| `capability.server_analysis` + 7 category checks | Requires Anthropic API + sandbox capabilities |
| `package.sandbox.analysis` | Requires Blaxel cloud sandbox |
| `package.sandbox.secrets` | Requires sandbox results |
| `package.sandbox.dependencies` | Requires sandbox results |
| `package.sandbox.external_communication` | Requires sandbox results |
| `runtime.environment` | Requires sandbox probe data |
| `gateway.assignment` | Requires Golf Gateway backend |
| `http.private.tls` | Currently disabled (SKIP) |
| `http.private.auth` | Currently disabled (SKIP) |
| `binary.codesigning` | Exists in Python but not yet in Go |

## Code References

- `golf-gateway/src/go/golf-scanner/cmd/golf-scanner/main.go` -- CLI entry point (scan, audit, version)
- `golf-gateway/src/go/golf-scanner/go.mod` -- Module path github.com/golf-mcp/golf-scanner
- `golf-gateway/src/go/golf-scanner/scanner/common.go` -- Scanner interface, ScanResult, arg scrubbing
- `golf-gateway/src/go/golf-scanner/auditor/engine.go` -- Check interface, RunAudit
- `golf-gateway/src/go/golf-scanner/auditor/scoring.go` -- Risk scoring engine
- `golf-gateway/src/go/golf-scanner/auditor/models.go` -- Severity, Finding, ServerInventory
- `golf-gateway/src/go/golf-scanner/auditor/checks/` -- All 20 security checks
- `golf-gateway/src/go/golf-scanner/report/table.go` -- Terminal table output
- `golf-gateway/src/go/golf-scanner/testdata/` -- 12 test fixtures
- `golf-gateway/docs/2026-02-24_mcp-scanner-opensource-extraction.md` -- Original extraction plan

## Architecture Insights

1. **The Go tool is already the complete OSS product.** The extraction doc planned a multi-phase approach, but the development in `golf-gateway/src/go/golf-scanner/` jumped ahead -- all checks (Tier 1 + Tier 2) are already ported and working.

2. **No CP code to remove.** Unlike the original `scanner-mcp/` directory (which had `enroll.go`, keychain access, and API calls), the `golf-scanner/` directory is a clean standalone tool. The extraction was done correctly during development.

3. **Extension-based inter-check communication** mirrors the Python auditor's pattern. The Go `AuditContext.Extensions` map serves the same role as Python's `AuditContext._extensions` dict. Check IDs and extension keys are consistent between implementations.

4. **Module path is already correct** (`github.com/golf-mcp/golf-scanner`), so the monorepo can `go get` it and import the packages directly once published.

5. **The naming settled on `golf-scanner`** (not `mcp-scanner`), which keeps the Golf brand. The CLI binary, module path, and GitHub repo all align.

## Open Questions

1. **Binary naming**: The extraction plan suggested `mcp-scanner` for broader community appeal vs `golf-scanner` for brand. The current code uses `golf-scanner`. Is this the final name?
2. **Homebrew tap**: Need to create `golf-mcp/homebrew-tap` repo (or similar) for `brew install`.
3. **goreleaser**: Need `.goreleaser.yml` for multi-platform builds (linux/darwin/windows, amd64/arm64).
4. **CI**: GitHub Actions workflow for test matrix (Go versions, OS matrix).
5. **Phase 3 monorepo wiring**: After publishing, the monorepo needs to import the OSS packages and create a separate `golf-scanner` binary with CP integration.
6. **Version**: What version to tag for the initial release? v0.1.0? v1.0.0?
7. **SARIF output**: Worth adding before initial release or as a fast-follow?
