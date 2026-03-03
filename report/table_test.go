// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
)

func TestFilterVisibleFindings(t *testing.T) {
	findings := []auditor.Finding{
		{CheckID: "a", Severity: auditor.SeverityHigh, Message: "high"},
		{CheckID: "b", Severity: auditor.SeveritySkip, Message: "skip"},
		{CheckID: "c", Severity: auditor.SeverityNote, Message: "note"},
	}

	visible := filterVisibleFindings(findings)
	if len(visible) != 2 {
		t.Fatalf("expected 2 visible findings, got %d", len(visible))
	}
	if visible[0].CheckID != "a" || visible[1].CheckID != "c" {
		t.Errorf("unexpected findings: %v, %v", visible[0].CheckID, visible[1].CheckID)
	}
}

func TestFilterVisibleFindingsAllSkip(t *testing.T) {
	findings := []auditor.Finding{
		{CheckID: "a", Severity: auditor.SeveritySkip},
	}
	visible := filterVisibleFindings(findings)
	if len(visible) != 0 {
		t.Fatalf("expected 0 visible findings, got %d", len(visible))
	}
}

func TestPrintAuditTableQuiet(t *testing.T) {
	rl := auditor.RiskHigh
	rpt := Report{
		Version: "test",
		Servers: []ServerResult{
			{
				Name:    "test-server",
				Sources: []ServerSource{{Name: "test-server", IDE: "Claude", Scope: "user"}},
				Type:    "binary",
				Score: auditor.AuditScore{
					Status:       auditor.StatusGraded,
					OverallScore: 30,
					RiskLevel:    &rl,
				},
				Findings: []auditor.Finding{
					{CheckID: "cmd.test", Severity: auditor.SeverityCritical, Message: "critical finding"},
				},
			},
		},
		Summary: Summary{TotalServers: 1, Critical: 1},
	}

	var buf bytes.Buffer
	PrintAuditTable(&buf, rpt, VerbosityQuiet)
	output := buf.String()

	// Should contain summary table (has server name in summary)
	if !strings.Contains(output, "test-server") {
		t.Error("quiet mode should contain server name in summary table")
	}

	// Should NOT contain per-server details like "Sources:"
	if strings.Contains(output, "Sources: Claude") {
		t.Error("quiet mode should not contain per-server detail section")
	}
}

func TestPrintAuditTableNormal(t *testing.T) {
	rl := auditor.RiskLow
	rpt := Report{
		Version: "test",
		Servers: []ServerResult{
			{
				Name:    "clean-server",
				Sources: []ServerSource{{Name: "clean-server", IDE: "VSCode", Scope: "user"}},
				Type:    "binary",
				Score: auditor.AuditScore{
					Status:       auditor.StatusGraded,
					OverallScore: 90,
					RiskLevel:    &rl,
				},
				Findings: []auditor.Finding{},
			},
		},
		Summary: Summary{TotalServers: 1, Note: 1},
	}

	var buf bytes.Buffer
	PrintAuditTable(&buf, rpt, VerbosityNormal)
	output := buf.String()

	// Should contain per-server details with Sources
	if !strings.Contains(output, "Sources: VSCode [user]") {
		t.Error("normal mode should contain per-server detail section with Sources")
	}

	// Clean server should show "No findings"
	if !strings.Contains(output, "No findings") {
		t.Error("clean server should show 'No findings'")
	}
}

func TestPrintAuditTableVerbose(t *testing.T) {
	rl := auditor.RiskHigh
	rpt := Report{
		Version: "test",
		Servers: []ServerResult{
			{
				Name:    "vuln-server",
				Sources: []ServerSource{{Name: "vuln-server", IDE: "Claude", Scope: "user"}},
				Type:    "script",
				Score: auditor.AuditScore{
					Status:       auditor.StatusGraded,
					OverallScore: 25,
					RiskLevel:    &rl,
				},
				Findings: []auditor.Finding{
					{
						CheckID:     "cmd.sanitization",
						Severity:    auditor.SeverityCritical,
						Message:     "Shell injection",
						Remediation: "Use exec.Command with explicit arguments",
					},
				},
			},
		},
		Summary: Summary{TotalServers: 1, Critical: 1},
	}

	var buf bytes.Buffer
	PrintAuditTable(&buf, rpt, VerbosityVerbose)
	output := buf.String()

	// Should contain remediation
	if !strings.Contains(output, "Use exec.Command with explicit arguments") {
		t.Error("verbose mode should contain remediation text")
	}
}

func TestSummaryTableMultipleServers(t *testing.T) {
	rlHigh := auditor.RiskHigh
	rlLow := auditor.RiskLow

	rpt := Report{
		Version: "test",
		Servers: []ServerResult{
			{
				Name:    "server-a",
				Sources: []ServerSource{{Name: "server-a", IDE: "Claude", Scope: "user"}},
				Score: auditor.AuditScore{
					Status:       auditor.StatusGraded,
					OverallScore: 20,
					RiskLevel:    &rlHigh,
				},
				Findings: []auditor.Finding{
					{Severity: auditor.SeverityCritical, Message: "crit"},
					{Severity: auditor.SeverityHigh, Message: "high"},
				},
			},
			{
				Name:    "server-b",
				Sources: []ServerSource{{Name: "server-b", IDE: "VSCode", Scope: "user"}},
				Score: auditor.AuditScore{
					Status:       auditor.StatusGraded,
					OverallScore: 85,
					RiskLevel:    &rlLow,
				},
				Findings: []auditor.Finding{},
			},
		},
		Summary: Summary{TotalServers: 2, Critical: 1, Note: 1},
	}

	var buf bytes.Buffer
	PrintAuditTable(&buf, rpt, VerbosityQuiet)
	output := buf.String()

	// Both servers should appear in summary
	if !strings.Contains(output, "server-a") {
		t.Error("summary table should contain server-a")
	}
	if !strings.Contains(output, "server-b") {
		t.Error("summary table should contain server-b")
	}
	// Risk levels
	if !strings.Contains(output, "High") {
		t.Error("summary table should show High risk")
	}
	if !strings.Contains(output, "Low") {
		t.Error("summary table should show Low risk")
	}
}

func TestCountUniqueIDEs(t *testing.T) {
	servers := []ServerResult{
		{Sources: []ServerSource{{IDE: "Claude"}}},
		{Sources: []ServerSource{{IDE: "VSCode"}}},
		{Sources: []ServerSource{{IDE: "Claude"}}},
		{Sources: []ServerSource{{IDE: ""}}},
	}
	count := countUniqueIDEs(servers)
	if count != 2 {
		t.Errorf("expected 2 unique IDEs, got %d", count)
	}
}

func TestCheckDisplayName(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"universal.credential_detection", "Credentials"},
		{"type.detection", "Server Type"},
		{"universal.command_sanitization", "Command Safety"},
		{"package.vulnerability", "Vulnerabilities"},
		// Fallback for unknown IDs
		{"universal.something_new", "something new"},
	}
	for _, tc := range tests {
		got := checkDisplayName(tc.input)
		if got != tc.expected {
			t.Errorf("checkDisplayName(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestFormatConfigPaths(t *testing.T) {
	tests := []struct {
		name     string
		sources  []ServerSource
		contains []string
		expected string
	}{
		{
			name:     "empty sources",
			sources:  nil,
			expected: "",
		},
		{
			name:     "no config paths",
			sources:  []ServerSource{{IDE: "Claude", Scope: "user"}},
			expected: "",
		},
		{
			name: "single path",
			sources: []ServerSource{
				{IDE: "Claude", Scope: "user", ConfigPath: "/tmp/test/.mcp.json"},
			},
			contains: []string{".mcp.json"},
		},
		{
			name: "deduplicates same path",
			sources: []ServerSource{
				{IDE: "Claude", Scope: "user", ConfigPath: "/tmp/a.json"},
				{IDE: "VSCode", Scope: "user", ConfigPath: "/tmp/a.json"},
			},
			expected: "/tmp/a.json",
		},
		{
			name: "multiple unique paths",
			sources: []ServerSource{
				{IDE: "Claude", Scope: "user", ConfigPath: "/tmp/a.json"},
				{IDE: "VSCode", Scope: "user", ConfigPath: "/tmp/b.json"},
			},
			expected: "/tmp/a.json, /tmp/b.json",
		},
		{
			name: "path with spaces is quoted",
			sources: []ServerSource{
				{IDE: "VSCode", Scope: "user", ConfigPath: "/Library/Application Support/Code/User/mcp.json"},
			},
			expected: `"/Library/Application Support/Code/User/mcp.json"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatConfigPaths(tc.sources)
			if tc.expected != "" && got != tc.expected {
				t.Errorf("formatConfigPaths() = %q, want %q", got, tc.expected)
			}
			for _, s := range tc.contains {
				if !strings.Contains(got, s) {
					t.Errorf("formatConfigPaths() = %q, should contain %q", got, s)
				}
			}
		})
	}
}

func TestPrintAuditTableNormalWithConfigPaths(t *testing.T) {
	rl := auditor.RiskLow
	rpt := Report{
		Version: "test",
		Servers: []ServerResult{
			{
				Name: "config-server",
				Sources: []ServerSource{
					{Name: "config-server", IDE: "Claude", Scope: "project", ConfigPath: "/tmp/proj/.mcp.json"},
				},
				Type: "binary",
				Score: auditor.AuditScore{
					Status:       auditor.StatusGraded,
					OverallScore: 90,
					RiskLevel:    &rl,
				},
				Findings: []auditor.Finding{},
			},
		},
		Summary: Summary{TotalServers: 1},
	}

	var buf bytes.Buffer
	PrintAuditTable(&buf, rpt, VerbosityNormal)
	output := buf.String()

	if !strings.Contains(output, "Config:") {
		t.Error("normal mode should show Config line when config paths are available")
	}
	if !strings.Contains(output, ".mcp.json") {
		t.Error("normal mode should show the config file path")
	}
}

func TestFindingMessage(t *testing.T) {
	// Primary: Message field
	f1 := auditor.Finding{Message: "primary message"}
	if msg := findingMessage(f1); msg != "primary message" {
		t.Errorf("expected 'primary message', got %q", msg)
	}

	// Fallback: display_title metadata
	f2 := auditor.Finding{Metadata: map[string]any{"display_title": "from metadata"}}
	if msg := findingMessage(f2); msg != "from metadata" {
		t.Errorf("expected 'from metadata', got %q", msg)
	}

	// Empty
	f3 := auditor.Finding{}
	if msg := findingMessage(f3); msg != "" {
		t.Errorf("expected empty string, got %q", msg)
	}
}
