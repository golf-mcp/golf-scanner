// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/x/term"
	"github.com/golf-mcp/golf-scanner/auditor"
)

// terminalWidth returns the width of the terminal for w, or 0 if not a TTY.
func terminalWidth(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if tw, _, err := term.GetSize(f.Fd()); err == nil && tw > 0 {
			return tw
		}
	}
	return 0
}

func renderRiskLevel(r *lipgloss.Renderer, rl auditor.RiskLevel) string {
	text := string(rl) + " Risk"
	switch rl {
	case auditor.RiskHigh:
		return r.NewStyle().Bold(true).Foreground(lipgloss.Color("9")).Render(text)
	case auditor.RiskModerate:
		return r.NewStyle().Foreground(lipgloss.Color("11")).Render(text)
	case auditor.RiskLow:
		return r.NewStyle().Foreground(lipgloss.Color("10")).Render(text)
	default:
		return text
	}
}

// PrintScanTable prints the scan discovery results to stdout.
func PrintScanTable(w io.Writer, scans []ScanEntry) {
	serverCount := 0
	for _, s := range scans {
		serverCount += s.ServerCount
	}

	if serverCount == 0 {
		fmt.Fprintln(w, "No MCP servers found.")
		return
	}

	fmt.Fprintf(w, "Found %d MCP server(s) in %d config(s)\n\n", serverCount, len(scans))

	for _, scan := range scans {
		if scan.ServerCount == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s [%s] %s\n", scan.IDE, scan.ScopeLabel, scan.ConfigPath)
		for _, srv := range scan.Servers {
			fmt.Fprintf(w, "    - %-30s  %s\n", srv.Name, srv.Description)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Summary: %d server(s) across %d config(s)\n", serverCount, len(scans))
}

// PrintGroupedScanTable prints the scan results grouped by server identity.
func PrintGroupedScanTable(w io.Writer, groups []auditor.GroupedInventory, totalConfigs int) {
	if len(groups) == 0 {
		fmt.Fprintln(w, "No MCP servers found.")
		return
	}

	ides := make(map[string]bool)
	for _, g := range groups {
		for _, s := range g.Sources {
			ides[s.IDE] = true
		}
	}

	fmt.Fprintf(w, "Found %d unique MCP server(s) in %d config(s) across %d IDE(s)\n\n",
		len(groups), totalConfigs, len(ides))

	for _, grp := range groups {
		typeDesc := describeServerCmd(grp.Canonical)
		fmt.Fprintf(w, "  %-40s %s\n", grp.DisplayName, typeDesc)
		fmt.Fprintf(w, "    Sources: %s\n", formatGroupedScanSources(grp.Sources))
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Summary: %d unique server(s) across %d config(s)\n", len(groups), totalConfigs)
}

func describeServerCmd(inv auditor.ServerInventory) string {
	switch inv.Transport {
	case "stdio":
		if inv.Cmd == "" {
			return "(no command)"
		}
		cmdBase := auditor.CommandBasename(inv.Cmd)
		return cmdBase
	case "http", "sse":
		return strings.ToUpper(inv.Transport)
	default:
		return inv.Transport
	}
}

func formatGroupedScanSources(sources []auditor.ServerSource) string {
	var parts []string
	for _, s := range sources {
		label := s.IDE + " [" + s.Scope
		if s.ProjectPath != "" {
			label += ": " + s.ProjectPath
		}
		label += "]"
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}

// ScanEntry represents a scan config group for table output.
type ScanEntry struct {
	IDE         string
	ScopeLabel  string
	ConfigPath  string
	ServerCount int
	Servers     []ScanServer
}

// ScanServer represents a server in the scan table.
type ScanServer struct {
	Name        string
	Description string
}

// Verbosity controls the detail level of table output.
type Verbosity int

const (
	VerbosityQuiet   Verbosity = -1
	VerbosityNormal  Verbosity = 0
	VerbosityVerbose Verbosity = 1
)

// PrintAuditTable prints the audit results as a formatted terminal table.
func PrintAuditTable(w io.Writer, rpt Report, verbosity Verbosity) {
	r := lipgloss.NewRenderer(w)
	bold := r.NewStyle().Bold(true)

	// Header
	tw := terminalWidth(w)
	width := 64
	if tw > 0 {
		width = tw - 4 // match indented table width (2-char indent + box chars)
	}
	border := strings.Repeat("\u2500", width)
	fmt.Fprintf(w, "  \u250c%s\u2510\n", border)
	title := bold.Render(fmt.Sprintf("Golf Scanner %s", rpt.Version))
	titleExtra := len(title) - lipgloss.Width(title)
	fmt.Fprintf(w, "  \u2502  %-*s\u2502\n", width-2+titleExtra, title)
	ideCount := countUniqueIDEs(rpt.Servers)
	subtitle := fmt.Sprintf("Scanned %d IDE(s) - Found %d MCP server(s)", ideCount, rpt.Summary.TotalServers)
	fmt.Fprintf(w, "  \u2502  %-*s\u2502\n", width-2, subtitle)
	fmt.Fprintf(w, "  \u2514%s\u2518\n\n", border)

	if verbosity != VerbosityQuiet {
		for _, srv := range rpt.Servers {
			printServerResult(w, r, srv, verbosity, tw)
		}
	}

	// Summary table
	printSummaryTable(w, r, rpt.Servers, tw)

	// Summary line
	// Color palette intentionally differs from the findings table (severity context)
	// and the summary table (risk context) to distinguish severity counts at a glance.
	critical := r.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	high := r.NewStyle().Foreground(lipgloss.Color("11"))
	medium := r.NewStyle().Foreground(lipgloss.Color("208"))
	clean := r.NewStyle().Foreground(lipgloss.Color("10"))

	fmt.Fprintf(w, "Summary: %d server(s)", rpt.Summary.TotalServers)
	if rpt.Summary.Critical > 0 {
		fmt.Fprintf(w, " \u2022 %s", critical.Render(fmt.Sprintf("%d critical", rpt.Summary.Critical)))
	}
	if rpt.Summary.High > 0 {
		fmt.Fprintf(w, " \u2022 %s", high.Render(fmt.Sprintf("%d high", rpt.Summary.High)))
	}
	if rpt.Summary.Medium > 0 {
		fmt.Fprintf(w, " \u2022 %s", medium.Render(fmt.Sprintf("%d medium", rpt.Summary.Medium)))
	}
	if rpt.Summary.Note > 0 {
		fmt.Fprintf(w, " \u2022 %s", clean.Render(fmt.Sprintf("%d note", rpt.Summary.Note)))
	}
	fmt.Fprintln(w)
}

func printServerResult(w io.Writer, re *lipgloss.Renderer, sr ServerResult, verbosity Verbosity, tw int) {
	bold := re.NewStyle().Bold(true)
	dim := re.NewStyle().Faint(true)

	// Server title
	fmt.Fprintf(w, "  %s\n", bold.Render(sr.Name))
	fmt.Fprintf(w, "  Sources: %s\n", formatSourcesDetail(sr.Sources))
	if configPaths := formatConfigPaths(sr.Sources); configPaths != "" {
		fmt.Fprintf(w, "  %s\n", dim.Render("Config: "+configPaths))
	}
	fmt.Fprintf(w, "  Type: %s\n", auditor.ServerType(sr.Type).DisplayName())

	// Score line
	scoreStr := fmt.Sprintf("%.0f/100", sr.Score.OverallScore)
	if sr.Score.RiskLevel != nil {
		scoreStr += fmt.Sprintf(" (%s)", renderRiskLevel(re, *sr.Score.RiskLevel))
	}
	fmt.Fprintf(w, "  Score: %s\n", scoreStr)

	// Findings table (sorted by severity, worst first)
	visibleFindings := filterVisibleFindings(sr.Findings)
	sort.Slice(visibleFindings, func(i, j int) bool {
		return auditor.SeverityRank(visibleFindings[i].Severity) > auditor.SeverityRank(visibleFindings[j].Severity)
	})
	if len(visibleFindings) > 0 {
		printFindingsTable(w, re, visibleFindings, tw)
		// In verbose mode, show remediation for each finding
		if verbosity == VerbosityVerbose {
			printRemediations(w, re, visibleFindings)
		}
	} else {
		greenCheck := re.NewStyle().Foreground(lipgloss.Color("10"))
		fmt.Fprintf(w, "  %s\n", greenCheck.Render("\u2713 No findings"))
	}
	fmt.Fprintln(w)
}

func printSummaryTable(w io.Writer, re *lipgloss.Renderer, servers []ServerResult, tw int) {
	rows := make([][]string, 0, len(servers))
	for _, srv := range servers {
		var crit, high, med, note int
		for _, f := range srv.Findings {
			switch f.Severity {
			case auditor.SeverityCritical:
				crit++
			case auditor.SeverityHigh:
				high++
			case auditor.SeverityMedium:
				med++
			case auditor.SeverityNote:
				note++
			}
		}

		var parts []string
		if crit > 0 {
			parts = append(parts, fmt.Sprintf("%d crit", crit))
		}
		if high > 0 {
			parts = append(parts, fmt.Sprintf("%d high", high))
		}
		if med > 0 {
			parts = append(parts, fmt.Sprintf("%d med", med))
		}
		if note > 0 {
			parts = append(parts, fmt.Sprintf("%d pass", note))
		}
		findingSummary := strings.Join(parts, " \u00b7 ")
		if findingSummary == "" {
			findingSummary = "\u2014"
		}

		riskStr := "\u2014"
		if srv.Score.RiskLevel != nil {
			switch *srv.Score.RiskLevel {
			case auditor.RiskHigh:
				riskStr = "\u25b2 High"
			case auditor.RiskModerate:
				riskStr = "\u2500 Moderate"
			case auditor.RiskLow:
				riskStr = "\u25bc Low"
			}
		}

		rows = append(rows, []string{
			srv.Name,
			formatSourcesSummary(srv.Sources),
			fmt.Sprintf("%.0f", srv.Score.OverallScore),
			riskStr,
			findingSummary,
		})
	}

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(re.NewStyle().Foreground(lipgloss.Color("238"))).
		Headers("Server", "Sources", "Score", "Risk", "Findings").
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			base := re.NewStyle().PaddingLeft(1).PaddingRight(1)
			if row == table.HeaderRow {
				return base.Bold(true)
			}
			if row >= 0 && row < len(servers) && col == 3 && servers[row].Score.RiskLevel != nil {
				switch *servers[row].Score.RiskLevel {
				case auditor.RiskHigh:
					return base.Bold(true).Foreground(lipgloss.Color("9"))
				case auditor.RiskModerate:
					return base.Foreground(lipgloss.Color("208"))
				case auditor.RiskLow:
					return base.Foreground(lipgloss.Color("10"))
				}
			}
			return base
		})

	if tw > 0 {
		t = t.Width(tw - 2) // account for 2-char indent
	}

	fmt.Fprintf(w, "%s\n\n", indentBlock(t.Render(), "  "))
}

func printRemediations(w io.Writer, re *lipgloss.Renderer, findings []auditor.Finding) {
	dim := re.NewStyle().Faint(true)
	for _, f := range findings {
		if f.Remediation != "" {
			fmt.Fprintf(w, "  %s %s\n", dim.Render("\u2192 "+checkDisplayName(f.CheckID)+":"), f.Remediation)
		}
	}
}

func printFindingsTable(w io.Writer, re *lipgloss.Renderer, findings []auditor.Finding, tw int) {
	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		sevLabel := strings.ToUpper(string(f.Severity))
		if f.Severity == auditor.SeverityNote {
			sevLabel = "PASS"
		}
		rows = append(rows, []string{
			checkDisplayName(f.CheckID),
			sevLabel,
			findingMessage(f),
		})
	}

	borderStyle := re.NewStyle().Foreground(lipgloss.Color("238"))

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(borderStyle).
		Headers("Check", "Sev.", "Finding").
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			base := re.NewStyle().PaddingLeft(1).PaddingRight(1)
			if row == table.HeaderRow {
				return base.Bold(true)
			}
			if col == 1 && row >= 0 && row < len(findings) {
				switch findings[row].Severity {
				case auditor.SeverityCritical:
					return base.Bold(true).Foreground(lipgloss.Color("9"))
				case auditor.SeverityHigh:
					return base.Foreground(lipgloss.Color("11"))
				case auditor.SeverityMedium:
					return base.Foreground(lipgloss.Color("208"))
				case auditor.SeverityNote:
					return base.Foreground(lipgloss.Color("10"))
				}
			}
			return base
		})

	if tw > 0 {
		t = t.Width(tw - 2) // account for 2-char indent
	}

	fmt.Fprintf(w, "%s\n", indentBlock(t.Render(), "  "))
}

// checkDisplayNames maps internal check IDs to human-readable labels.
var checkDisplayNames = map[string]string{
	"type.detection":                "Server Type",
	"universal.command_sanitization": "Command Safety",
	"universal.credential_detection": "Credentials",
	"universal.registry.verification": "Registry Listing",
	"universal.github.trust":         "GitHub Trust",
	"package.vulnerability":          "Vulnerabilities",
	"package.typosquatting":          "Typosquatting",
	"package.distribution":           "Distribution",
	"package.repository":             "Source Repository",
	"package.unscoped_variant":       "Unscoped Variant",
	"script.location":                "Script Location",
	"script.permissions":             "Script Permissions",
	"binary.location":                "Binary Location",
	"binary.permissions":             "Binary Permissions",
	"container.isolation":            "Container Isolation",
	"container.volumes":              "Container Volumes",
	"container.image":                "Container Image",
	"container.registry.existence":   "Container Registry",
	"container.registry.signature":   "Container Signature",
	"http.oauth":                     "OAuth",
}

// checkDisplayName returns a human-readable label for a check ID.
func checkDisplayName(checkID string) string {
	if name, ok := checkDisplayNames[checkID]; ok {
		return name
	}
	// Fallback: strip prefixes and replace underscores
	s := strings.TrimPrefix(checkID, "universal.")
	s = strings.TrimPrefix(s, "type.")
	s = strings.ReplaceAll(s, "_", " ")
	return s
}

// indentBlock prepends prefix to every line of a multi-line string.
func indentBlock(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

func findingMessage(f auditor.Finding) string {
	if f.Message != "" {
		return f.Message
	}
	if dt, ok := f.Metadata["display_title"].(string); ok {
		return dt
	}
	return ""
}

func filterVisibleFindings(findings []auditor.Finding) []auditor.Finding {
	var visible []auditor.Finding
	for _, f := range findings {
		if f.Severity != auditor.SeveritySkip {
			visible = append(visible, f)
		}
	}
	return visible
}

func countUniqueIDEs(servers []ServerResult) int {
	ides := make(map[string]bool)
	for _, s := range servers {
		for _, src := range s.Sources {
			if src.IDE != "" {
				ides[src.IDE] = true
			}
		}
	}
	return len(ides)
}

// formatSourcesSummary formats sources for the summary table column.
func formatSourcesSummary(sources []ServerSource) string {
	if len(sources) == 1 {
		return sources[0].IDE
	}
	ides := make(map[string]bool)
	for _, s := range sources {
		ides[s.IDE] = true
	}
	if len(ides) == 1 {
		for ide := range ides {
			return fmt.Sprintf("%s (%d configs)", ide, len(sources))
		}
	}
	names := make([]string, 0, len(ides))
	for ide := range ides {
		names = append(names, ide)
	}
	sort.Strings(names)
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%d IDEs", len(names))
}

// formatConfigPaths returns a comma-separated list of unique config file paths
// from the given sources, with the home directory prefix replaced by ~.
func formatConfigPaths(sources []ServerSource) string {
	seen := make(map[string]bool)
	var paths []string
	homeDir, _ := os.UserHomeDir()
	for _, s := range sources {
		if s.ConfigPath == "" || seen[s.ConfigPath] {
			continue
		}
		seen[s.ConfigPath] = true
		p := s.ConfigPath
		if homeDir != "" && strings.HasPrefix(p, homeDir) {
			p = "~" + p[len(homeDir):]
		}
		if strings.ContainsRune(p, ' ') {
			p = "\"" + p + "\""
		}
		paths = append(paths, p)
	}
	return strings.Join(paths, ", ")
}

// formatSourcesDetail formats sources for per-server detail sections.
func formatSourcesDetail(sources []ServerSource) string {
	if len(sources) == 0 {
		return "unknown"
	}
	var parts []string
	for _, s := range sources {
		label := s.IDE + " [" + s.Scope + "]"
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}

