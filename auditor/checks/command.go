// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
)

type dangerousPattern struct {
	pattern       *regexp.Regexp
	customMatch   func(string) bool // Used when regex can't express the pattern (RE2 limitations)
	name          string
	description   string
	severity      auditor.Severity
	checklistID   string
	checkArgsOnly bool
}

var commandPatterns []dangerousPattern

// containsSinglePipe checks for pipe "|" that is not part of "||".
func containsSinglePipe(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			// Check if it's a double pipe
			if i+1 < len(s) && s[i+1] == '|' {
				i++ // Skip next '|'
				continue
			}
			// Check if it's preceded by another pipe (second char of ||)
			if i > 0 && s[i-1] == '|' {
				continue
			}
			return true
		}
	}
	return false
}

func init() {
	type rawPattern struct {
		pattern       string
		name          string
		description   string
		severity      auditor.Severity
		checklistID   string
		checkArgsOnly bool
	}

	raw := []rawPattern{
		// UC-1.1: Sudo usage (CRITICAL)
		{`(?i)\bsudo\b`, "sudo", "Administrator privileges requested", auditor.SeverityCritical, "UC-1.1", false},
		// UC-1.2: Command injection metacharacters (CRITICAL)
		{`;`, "semicolon", "Command chaining via semicolon", auditor.SeverityCritical, "UC-1.2", true},
		// pipe is handled via customMatch below
		{`&&`, "double-ampersand", "AND command chaining", auditor.SeverityCritical, "UC-1.2", true},
		{`\|\|`, "double-pipe", "OR command chaining", auditor.SeverityCritical, "UC-1.2", true},
		{`\$\(`, "command-substitution", "Command substitution $()", auditor.SeverityCritical, "UC-1.2", true},
		{"`", "backtick", "Command substitution via backticks", auditor.SeverityCritical, "UC-1.2", true},
		{`\$\{`, "variable-expansion", "Variable expansion ${...}", auditor.SeverityCritical, "UC-1.2", true},
		// UC-1.3: Network download commands (HIGH)
		{`(?i)\bcurl\b`, "curl", "Network download via curl", auditor.SeverityHigh, "UC-1.3", false},
		{`(?i)\bwget\b`, "wget", "Network download via wget", auditor.SeverityHigh, "UC-1.3", false},
		{`(?i)\b(nc|netcat|ncat)\b`, "netcat", "Network connection via netcat", auditor.SeverityHigh, "UC-1.3", false},
		// UC-1.3: Download utilities
		{`(?i)\b(fetch|aria2c|axel)\b`, "downloader", "Network download utility", auditor.SeverityHigh, "UC-1.3", false},
		// UC-1.4: Shell execution (HIGH)
		{`(?i)\b(bash|sh|zsh|ksh|csh|tcsh|fish|dash)\s+(-c|--command)\b`, "shell-exec", "Shell command execution via -c flag", auditor.SeverityHigh, "UC-1.4", false},
		// UC-1.5: Dynamic execution (HIGH)
		{`\s--exec\b`, "exec-flag", "Dynamic execution via --exec flag", auditor.SeverityHigh, "UC-1.5", false},
		{`\s-e\s+['"]`, "eval-flag", "Code execution via -e flag", auditor.SeverityHigh, "UC-1.5", false},
		{`(?i)\beval\s*[('"]`, "eval", "Dynamic code via eval", auditor.SeverityHigh, "UC-1.5", false},
		{`(?i)\bexec\s*\(`, "exec-func", "Dynamic code via exec()", auditor.SeverityHigh, "UC-1.5", false},
		// UC-1.6: Temporary paths (HIGH)
		{`(^|\s)/tmp/`, "tmp-path", "Execution from /tmp directory", auditor.SeverityHigh, "UC-1.6", false},
		{`(^|\s)/var/tmp/`, "var-tmp-path", "Execution from /var/tmp directory", auditor.SeverityHigh, "UC-1.6", false},
		{`(^|\s)/dev/shm/`, "dev-shm-path", "Execution from /dev/shm directory", auditor.SeverityHigh, "UC-1.6", false},
		{`(^|\s)/run/user/`, "run-user-path", "Execution from /run/user directory", auditor.SeverityHigh, "UC-1.6", false},
		{`%(TEMP|TMP)%`, "windows-temp", "Windows temporary directory", auditor.SeverityHigh, "UC-1.6", false},
		{`\$(\{TMPDIR\}|TMPDIR)`, "tmpdir-var", "TMPDIR environment variable", auditor.SeverityHigh, "UC-1.6", false},
	}

	for _, r := range raw {
		commandPatterns = append(commandPatterns, dangerousPattern{
			pattern:       regexp.MustCompile(r.pattern),
			name:          r.name,
			description:   r.description,
			severity:      r.severity,
			checklistID:   r.checklistID,
			checkArgsOnly: r.checkArgsOnly,
		})
	}

	// Add pipe pattern with custom matcher (RE2 doesn't support negative lookahead)
	commandPatterns = append(commandPatterns, dangerousPattern{
		customMatch:   containsSinglePipe,
		name:          "pipe",
		description:   "Command piping",
		severity:      auditor.SeverityCritical,
		checklistID:   "UC-1.2",
		checkArgsOnly: true,
	})
}

// CommandSanitizationCheck scans commands for dangerous patterns.
type CommandSanitizationCheck struct{}

func (c *CommandSanitizationCheck) ID() string           { return "universal.command_sanitization" }
func (c *CommandSanitizationCheck) Name() string         { return "Command safety check" }
func (c *CommandSanitizationCheck) RequiresOnline() bool { return false }

func (c *CommandSanitizationCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	target := ctx.Target

	if target.Cmd == "" && len(target.Args) == 0 {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "No command or arguments to check",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			// Checklist IDs ending in ".x" are wildcards covering multiple sub-checks.
		Metadata: map[string]any{"checklist_id": "UC-1.x"},
		}}
	}

	fullCommand := strings.TrimSpace(target.Cmd + " " + strings.Join(target.Args, " "))
	argsOnly := strings.Join(target.Args, " ")

	type issue struct {
		name        string
		description string
		checklistID string
	}

	var issues []issue
	checklistIDs := make(map[string]bool)
	maxSeverity := auditor.SeverityNote

	for _, p := range commandPatterns {
		searchText := fullCommand
		if p.checkArgsOnly {
			searchText = argsOnly
		}
		if searchText == "" {
			continue
		}

		matched := false
		if p.customMatch != nil {
			matched = p.customMatch(searchText)
		} else {
			matched = p.pattern.MatchString(searchText)
		}

		if matched {
			issues = append(issues, issue{
				name:        p.name,
				description: p.description,
				checklistID: p.checklistID,
			})
			checklistIDs[p.checklistID] = true
			maxSeverity = auditor.WorseSeverity(maxSeverity, p.severity)
		}
	}

	if len(issues) > 0 {
		names := make([]string, len(issues))
		issueDescs := make([]string, len(issues))
		for i, iss := range issues {
			names[i] = iss.name
			issueDescs[i] = fmt.Sprintf("%s: %s", iss.name, iss.description)
		}

		sortedIDs := make([]string, 0, len(checklistIDs))
		for id := range checklistIDs {
			sortedIDs = append(sortedIDs, id)
		}
		sort.Strings(sortedIDs)

		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    maxSeverity,
			Message:     "Dangerous command patterns detected: " + strings.Join(names, ", "),
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: buildCommandRemediation(checklistIDs),
			Metadata: map[string]any{
				"display_title": "Potentially harmful command patterns detected",
				"checklist_id":  strings.Join(sortedIDs, ", "),
				"issues":        issueDescs,
				"command":       target.Cmd,
				"args":          target.Args,
			},
		}}
	}

	return []auditor.Finding{{
		CheckID:    c.ID(),
		Severity:   auditor.SeverityNote,
		Message:    "No harmful command patterns",
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata: map[string]any{
			"display_title": "No harmful command patterns",
			"description":   "No sudo, curl, wget, nc, shell -c, eval, exec detected or other suspicious patterns",
			"checklist_id":  "UC-1.x",
		},
	}}
}

func buildCommandRemediation(ids map[string]bool) string {
	var parts []string
	if ids["UC-1.1"] {
		parts = append(parts, "Remove sudo - MCP servers should not require root")
	}
	if ids["UC-1.2"] {
		parts = append(parts, "Remove shell metacharacters to prevent command injection")
	}
	if ids["UC-1.3"] {
		parts = append(parts, "Avoid network download commands - use package managers instead")
	}
	if ids["UC-1.4"] {
		parts = append(parts, "Execute commands directly without shell wrapper")
	}
	if ids["UC-1.5"] {
		parts = append(parts, "Avoid dynamic code execution - use static configuration")
	}
	if ids["UC-1.6"] {
		parts = append(parts, "Install server in permanent location, not temporary directories")
	}
	return strings.Join(parts, ". ") + "."
}
