// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/checks"
	"github.com/golf-mcp/golf-scanner/report"
	"github.com/golf-mcp/golf-scanner/scanner"
)

var Version = "dev"

var scannerRegistry = []scanner.Scanner{
	&scanner.ClaudeScanner{},
	&scanner.CursorScanner{},
	&scanner.VSCodeScanner{},
	&scanner.WindsurfScanner{},
	&scanner.GeminiScanner{},
	&scanner.AntigravityScanner{},
	&scanner.KiroScanner{},
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		runScan()
	case "audit":
		runAudit()
	case "version":
		fmt.Printf("golf-scanner %s\n", Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: golf-scanner <command> [options]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  scan      Discover MCP servers across all supported IDEs\n")
	fmt.Fprintf(os.Stderr, "  audit     Run security audit on discovered MCP servers\n")
	fmt.Fprintf(os.Stderr, "  version   Print version information\n")
	fmt.Fprintf(os.Stderr, "\nCommon Options:\n")
	fmt.Fprintf(os.Stderr, "  --format <format>       Output format: table (default), json\n")
	fmt.Fprintf(os.Stderr, "  --json                  Output as JSON (shorthand for --format json)\n")
	fmt.Fprintf(os.Stderr, "\nAudit Options:\n")
	fmt.Fprintf(os.Stderr, "  --offline               Skip network checks (OSV, GitHub, npm, etc.)\n")
	fmt.Fprintf(os.Stderr, "  --fail-on <severity>    Exit 1 if findings at or above: note, medium, high, critical, skip\n")
	fmt.Fprintf(os.Stderr, "  --verbose, -v           Show full finding details (remediation)\n")
	fmt.Fprintf(os.Stderr, "  --quiet, -q             Show only the summary table\n")
	fmt.Fprintf(os.Stderr, "\nUse \"golf-scanner <command> --help\" for more information about a command.\n")
}

func runScan() {
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	format := scanCmd.String("format", "table", "Output format: table, json")
	jsonOutput := scanCmd.Bool("json", false, "Output as JSON (shorthand for --format json)")
	scanCmd.Parse(os.Args[2:])

	if *jsonOutput {
		*format = "json"
	}

	scans := discoverServers()

	switch *format {
	case "json":
		output, err := json.MarshalIndent(scans, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling results: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(string(output))
	default:
		// Group for display; JSON stays raw
		inventory := auditor.InventoryFromScanResults(scans)
		groups := auditor.GroupInventory(inventory)
		report.PrintGroupedScanTable(os.Stdout, groups, len(scans))
	}
}

func discoverServers() []scanner.ScanResult {
	var scans []scanner.ScanResult
	userHomes := scanner.GetUserHomes()

	for username, homeDir := range userHomes {
		for _, s := range scannerRegistry {
			results := s.ScanHome(homeDir, username)
			scans = append(scans, results...)
		}
	}

	return scans
}


// allChecks returns the ordered list of audit checks.
func allChecks() []auditor.Check {
	return []auditor.Check{
		// Tier 0: Type detection (must run first)
		&checks.ServerTypeCheck{},

		// Tier 1: Offline checks
		&checks.CommandSanitizationCheck{},
		&checks.CredentialDetectionCheck{},
		&checks.ScriptLocationCheck{},
		&checks.ScriptPermissionsCheck{},
		&checks.BinaryLocationCheck{},
		&checks.BinaryPermissionsCheck{},
		&checks.ContainerIsolationCheck{},
		&checks.ContainerVolumeCheck{},

		// Tier 2: Online checks (skipped with --offline flag)
		&checks.RegistryVerificationCheck{},
		&checks.PackageVulnerabilityCheck{},
		&checks.PackageTyposquattingCheck{},
		&checks.PackageDistributionCheck{},
		&checks.PackageRepositoryCheck{},
		&checks.PackageUnscopedVariantCheck{},
		&checks.GitHubTrustCheck{},
		&checks.ContainerImageCheck{},
		&checks.ContainerRegistryCheck{},
		&checks.ContainerSignatureCheck{},
		&checks.OAuthCheck{},
	}
}

func runAudit() {
	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)
	offline := auditCmd.Bool("offline", false, "Skip network checks (OSV, GitHub, npm, etc.)")
	format := auditCmd.String("format", "table", "Output format: table, json")
	jsonOutput := auditCmd.Bool("json", false, "Output as JSON (shorthand for --format json)")
	failOn := auditCmd.String("fail-on", "", "Exit 1 if findings at or above severity: note, medium, high, critical")
	verbose := auditCmd.Bool("verbose", false, "Show full finding details (remediation)")
	quiet := auditCmd.Bool("quiet", false, "Show only the summary table")
	auditCmd.BoolVar(verbose, "v", false, "Show full finding details")
	auditCmd.BoolVar(quiet, "q", false, "Show only the summary table")
	auditCmd.Parse(os.Args[2:])

	if *jsonOutput {
		*format = "json"
	}

	// 1. Discover servers
	scans := discoverServers()

	// 2. Convert to inventory and group by identity
	inventory := auditor.InventoryFromScanResults(scans)
	groups := auditor.GroupInventory(inventory)

	if len(groups) == 0 {
		fmt.Println("No MCP servers found.")
		return
	}

	checkList := allChecks()

	// 3. Run audit on each unique server
	var results []report.ServerResult
	summary := report.Summary{TotalServers: len(groups)}

	progress := report.NewProgress(os.Stderr)

	for i, grp := range groups {
		if !*offline {
			progress.Update(grp.DisplayName, i+1, len(groups))
		}

		// Run full audit on canonical instance
		findings, checksRun, checksSkipped := auditor.RunAudit(grp.Canonical, checkList, !*offline)

		// Per-instance file checks: if file metadata differs across instances,
		// run file-specific checks on additional instances and merge findings
		if len(grp.Sources) > 1 {
			instances := grp.UniqueFileMetadataInstances()
			if len(instances) > 1 {
				fileChecks := filterFileChecks(checkList)
				for _, inst := range instances[1:] {
					extraFindings, _, _ := auditor.RunAudit(inst, fileChecks, false)
					findings = mergeFindings(findings, extraFindings)
				}
			}
		}

		// Detect server type for scoring
		var serverType auditor.ServerType
		for _, f := range findings {
			if f.CheckID == auditor.ExtKeyTypeDetection {
				if dt, ok := f.Metadata[auditor.ExtKeyDetectedType].(string); ok {
					serverType = auditor.ServerType(dt)
				}
				break
			}
		}

		score := auditor.ComputeAuditScore(findings, checksRun, serverType)

		// Build sources for report
		sources := make([]report.ServerSource, len(grp.Sources))
		for j, src := range grp.Sources {
			sources[j] = report.ServerSource{
				Name:        src.Name,
				IDE:         src.IDE,
				Scope:       src.Scope,
				ConfigPath:  src.ConfigPath,
				ProjectPath: src.ProjectPath,
			}
		}

		results = append(results, report.ServerResult{
			Name:          grp.DisplayName,
			Sources:       sources,
			Identity:      report.ServerIdentity{Type: grp.Identity.Type, Key: grp.Identity.Key},
			Type:          string(serverType),
			Score:         score,
			Findings:      findings,
			ChecksRun:     checksRun,
			ChecksSkipped: checksSkipped,
		})

		// Count worst severity per server for summary
		worstSev := auditor.SeverityNote
		for _, f := range findings {
			if f.Severity != auditor.SeveritySkip && auditor.SeverityRank(f.Severity) > auditor.SeverityRank(worstSev) {
				worstSev = f.Severity
			}
		}
		switch worstSev {
		case auditor.SeverityCritical:
			summary.Critical++
		case auditor.SeverityHigh:
			summary.High++
		case auditor.SeverityMedium:
			summary.Medium++
		default:
			summary.Note++
		}
	}

	progress.Done()

	rpt := report.Report{
		Version:  Version,
		ScanTime: time.Now().UTC(),
		Servers:  results,
		Summary:  summary,
	}

	if *verbose && *quiet {
		fmt.Fprintf(os.Stderr, "Error: --verbose and --quiet cannot be used together\n")
		os.Exit(1)
	}

	switch *format {
	case "json":
		if err := report.PrintJSON(os.Stdout, rpt); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
	default:
		verbosityLevel := report.VerbosityNormal
		if *verbose {
			verbosityLevel = report.VerbosityVerbose
		}
		if *quiet {
			verbosityLevel = report.VerbosityQuiet
		}
		report.PrintAuditTable(os.Stdout, rpt, verbosityLevel)
	}

	// Exit code based on --fail-on threshold
	if *failOn != "" {
		threshold := auditor.Severity(*failOn)
		if auditor.SeverityRank(threshold) == 0 && threshold != auditor.SeveritySkip {
			fmt.Fprintf(os.Stderr, "Error: invalid --fail-on severity %q (valid: note, medium, high, critical)\n", *failOn)
			os.Exit(2)
		}
		if hasFindingsAtOrAbove(results, threshold) {
			os.Exit(1)
		}
	}
}

func hasFindingsAtOrAbove(results []report.ServerResult, threshold auditor.Severity) bool {
	thresholdRank := auditor.SeverityRank(threshold)
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Severity != auditor.SeveritySkip && auditor.SeverityRank(f.Severity) >= thresholdRank {
				return true
			}
		}
	}
	return false
}

// filterFileChecks returns only checks that inspect file metadata.
func filterFileChecks(allChecks []auditor.Check) []auditor.Check {
	var fileChecks []auditor.Check
	for _, c := range allChecks {
		if auditor.FileMetadataCheckIDs[c.ID()] {
			fileChecks = append(fileChecks, c)
		}
	}
	return fileChecks
}

// mergeFindings adds findings from extra that aren't already in base.
func mergeFindings(base, extra []auditor.Finding) []auditor.Finding {
	type findingKey struct {
		checkID string
		message string
	}
	seen := make(map[findingKey]bool)
	for _, f := range base {
		seen[findingKey{f.CheckID, f.Message}] = true
	}
	for _, f := range extra {
		key := findingKey{f.CheckID, f.Message}
		if !seen[key] {
			base = append(base, f)
			seen[key] = true
		}
	}
	return base
}

func getArgsString(server map[string]any) string {
	argsRaw, ok := server["args"]
	if !ok {
		return ""
	}
	switch v := argsRaw.(type) {
	case []string:
		return strings.Join(v, " ")
	case []any:
		parts := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}
