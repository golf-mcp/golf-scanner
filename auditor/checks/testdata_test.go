// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
)

// serverFixture matches the JSON structure of testdata/servers/*.json.
type serverFixture struct {
	Name        string            `json:"name"`
	IDE         string            `json:"ide"`
	Scope       string            `json:"scope"`
	Transport   string            `json:"transport"`
	Cmd         string            `json:"cmd"`
	Args        []string          `json:"args"`
	Host        string            `json:"host"`
	ConfigPath  string            `json:"config_path"`
	ProjectPath string            `json:"project_path"`
	FileMode    *int              `json:"file_mode"`
	CmdFileMode *int              `json:"cmd_file_mode"`
	Env         map[string]string `json:"env"`
}

// expectedFinding matches the JSON structure of testdata/expected/*.json entries.
type expectedFinding struct {
	CheckID         string `json:"check_id"`
	Severity        string `json:"severity"`
	MessageContains string `json:"message_contains,omitempty"`
}

func loadServerFixture(t *testing.T, name string) auditor.ServerInventory {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "servers", name+".json"))
	if err != nil {
		t.Fatalf("failed to read server fixture %s: %v", name, err)
	}
	var fix serverFixture
	if err := json.Unmarshal(data, &fix); err != nil {
		t.Fatalf("failed to parse server fixture %s: %v", name, err)
	}
	return auditor.ServerInventory{
		Name:        fix.Name,
		IDE:         fix.IDE,
		Scope:       fix.Scope,
		Transport:   fix.Transport,
		Cmd:         fix.Cmd,
		Args:        fix.Args,
		Host:        fix.Host,
		ConfigPath:  fix.ConfigPath,
		ProjectPath: fix.ProjectPath,
		FileMode:    fix.FileMode,
		CmdFileMode: fix.CmdFileMode,
		Env:         fix.Env,
	}
}

func loadExpectedFindings(t *testing.T, name string) []expectedFinding {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "expected", name+".json"))
	if err != nil {
		t.Fatalf("failed to read expected fixture %s: %v", name, err)
	}
	var expected []expectedFinding
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("failed to parse expected fixture %s: %v", name, err)
	}
	return expected
}

// tier1Checks returns all offline checks in order.
func tier1Checks() []auditor.Check {
	return []auditor.Check{
		&ServerTypeCheck{},
		&CommandSanitizationCheck{},
		&CredentialDetectionCheck{},
		&ScriptLocationCheck{},
		&ScriptPermissionsCheck{},
		&BinaryLocationCheck{},
		&BinaryPermissionsCheck{},
		&ContainerIsolationCheck{},
		&ContainerVolumeCheck{},
	}
}

func TestGoldenFiles(t *testing.T) {
	fixtures := []string{
		"npx-basic",
		"npx-with-credentials",
		"docker-privileged",
		"docker-volumes",
		"binary-protected",
		"binary-world-writable",
		"script-tmp",
		"script-home",
		"http-localhost",
		"sudo-command",
		"shell-injection",
	}

	// Note: http-public is excluded because DNS resolution may vary in CI

	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			inv := loadServerFixture(t, name)
			expected := loadExpectedFindings(t, name)

			// Run all Tier 1 checks
			findings, _, _ := auditor.RunAudit(inv, tier1Checks(), false)

			// Build a map of check_id -> findings for lookup
			findingsByCheck := make(map[string][]auditor.Finding)
			for _, f := range findings {
				findingsByCheck[f.CheckID] = append(findingsByCheck[f.CheckID], f)
			}

			for _, exp := range expected {
				checkFindings, ok := findingsByCheck[exp.CheckID]
				if !ok {
					t.Errorf("[%s] expected findings for check %s, but none found", name, exp.CheckID)
					continue
				}

				// Find the worst severity among findings for this check
				worstSev := auditor.SeveritySkip
				var worstFinding auditor.Finding
				for _, f := range checkFindings {
					if auditor.SeverityRank(f.Severity) > auditor.SeverityRank(worstSev) {
						worstSev = f.Severity
						worstFinding = f
					}
				}

				if string(worstSev) != exp.Severity {
					t.Errorf("[%s] check %s: expected severity %s, got %s (message: %q)",
						name, exp.CheckID, exp.Severity, worstSev, worstFinding.Message)
				}

				if exp.MessageContains != "" {
					found := false
					for _, f := range checkFindings {
						msg := f.Message
						if dt, ok := f.Metadata["display_title"].(string); ok && msg == "" {
							msg = dt
						}
						if strings.Contains(strings.ToLower(msg), strings.ToLower(exp.MessageContains)) {
							found = true
							break
						}
					}
					if !found {
						msgs := make([]string, len(checkFindings))
						for i, f := range checkFindings {
							msgs[i] = f.Message
						}
						t.Errorf("[%s] check %s: no finding message contains %q (found: %v)",
							name, exp.CheckID, exp.MessageContains, msgs)
					}
				}
			}
		})
	}
}
