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

// Sensitive CLI flags that indicate credential parameters.
var sensitiveFlags = map[string]bool{
	"--api-key":     true,
	"--token":       true,
	"--secret":      true,
	"--dsn":         true,
	"--password":    true,
	"--credentials": true,
	"--auth":        true,
	"--key":         true,
	"--pass":        true,
	"--private-key": true,
	"--cert":        true,
	"--api-token":   true,
	"--access-key":  true,
	"--secret-key":  true,
}

type credentialPattern struct {
	pattern     *regexp.Regexp
	name        string
	description string
	severity    auditor.Severity
	checklistID string
}

var credentialPatterns []credentialPattern

// sensitiveEnvKeyRe matches environment variable names that likely hold credentials.
var sensitiveEnvKeyRe = regexp.MustCompile(`(?i)(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|DSN|PASS|PRIVATE)`)

func init() {
	type raw struct {
		pattern     string
		name        string
		description string
		severity    auditor.Severity
		checklistID string
	}

	patterns := []raw{
		{`AKIA[A-Z0-9]{16}`, "aws-access-key", "AWS Access Key ID detected", auditor.SeverityCritical, "CD-1.1"},
		{`gh[pous]_[A-Za-z0-9_]{36,}`, "github-token", "GitHub token detected", auditor.SeverityCritical, "CD-1.1"},
		{`sk_live_[A-Za-z0-9]{24,}`, "stripe-key", "Stripe live key detected", auditor.SeverityCritical, "CD-1.1"},
		{`xox[bpsar]-[A-Za-z0-9\-]{24,}`, "slack-token", "Slack token detected", auditor.SeverityCritical, "CD-1.1"},
		{`sk-ant-[A-Za-z0-9\-]{90,}`, "anthropic-key", "Anthropic API key detected", auditor.SeverityCritical, "CD-1.1"},
		{`sk-[A-Za-z0-9]{48,}`, "openai-key", "OpenAI API key detected", auditor.SeverityCritical, "CD-1.1"},
		{`AIza[0-9A-Za-z_\-]{35}`, "google-api-key", "Google API key detected", auditor.SeverityCritical, "CD-1.1"},
		{`glpat-[A-Za-z0-9_\-]{20,}`, "gitlab-token", "GitLab personal access token detected", auditor.SeverityHigh, "CD-1.2"},
		{`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`, "jwt-token", "JWT token detected", auditor.SeverityHigh, "CD-1.2"},
		{`://[^/\s]+:[^/\s]+@`, "credentials-in-url", "Credentials embedded in URL", auditor.SeverityCritical, "CD-1.5"},
		{`(?:^|[\s=])(sk-|api_|key_|token_)[A-Za-z0-9]{20,}`, "generic-api-key", "Possible API key with common prefix", auditor.SeverityMedium, "CD-1.3"},
	}

	for _, r := range patterns {
		credentialPatterns = append(credentialPatterns, credentialPattern{
			pattern:     regexp.MustCompile(r.pattern),
			name:        r.name,
			description: r.description,
			severity:    r.severity,
			checklistID: r.checklistID,
		})
	}
}

// CredentialDetectionCheck detects plaintext credentials in server args and host URLs.
type CredentialDetectionCheck struct{}

func (c *CredentialDetectionCheck) ID() string           { return "universal.credential_detection" }
func (c *CredentialDetectionCheck) Name() string         { return "Credential detection" }
func (c *CredentialDetectionCheck) RequiresOnline() bool { return false }

func (c *CredentialDetectionCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	target := ctx.Target

	if len(target.Args) == 0 && target.Host == "" && len(target.Env) == 0 {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "No arguments or host to scan",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			// Checklist IDs ending in ".x" are wildcards covering multiple sub-checks.
		Metadata: map[string]any{"checklist_id": "CD-1.x"},
		}}
	}

	type issue struct {
		name        string
		description string
		checklistID string
	}

	var issues []issue
	checklistIDs := make(map[string]bool)
	maxSeverity := auditor.SeverityNote

	// Scan args for sensitive flag + scrubbed value patterns
	for i, arg := range target.Args {
		argLower := strings.ToLower(arg)
		if sensitiveFlags[argLower] {
			var nextVal string
			if i+1 < len(target.Args) {
				nextVal = target.Args[i+1]
			}
			if nextVal == "****" {
				issues = append(issues, issue{
					name:        fmt.Sprintf("scrubbed-credential (%s)", arg),
					description: fmt.Sprintf("Plaintext credential was present for %s (scrubbed)", arg),
					checklistID: "CD-1.1",
				})
				checklistIDs["CD-1.1"] = true
				maxSeverity = auditor.WorseSeverity(maxSeverity, auditor.SeverityCritical)
			} else if nextVal != "" && strings.HasPrefix(nextVal, "${") {
				issues = append(issues, issue{
					name:        fmt.Sprintf("env-var-credential (%s)", arg),
					description: fmt.Sprintf("Credential dependency via env var for %s", arg),
					checklistID: "CD-1.3",
				})
				checklistIDs["CD-1.3"] = true
				maxSeverity = auditor.WorseSeverity(maxSeverity, auditor.SeverityMedium)
			}
		}
	}

	// Scan all args and host against regex patterns
	searchTexts := make([]string, len(target.Args))
	copy(searchTexts, target.Args)
	if target.Host != "" {
		searchTexts = append(searchTexts, target.Host)
	}

	for _, text := range searchTexts {
		for _, p := range credentialPatterns {
			if p.pattern.MatchString(text) {
				issues = append(issues, issue{
					name:        p.name,
					description: p.description,
					checklistID: p.checklistID,
				})
				checklistIDs[p.checklistID] = true
				maxSeverity = auditor.WorseSeverity(maxSeverity, p.severity)
				break // One match per text is enough
			}
		}
	}

	// Scan env block for credential indicators
	envKeys := make([]string, 0, len(target.Env))
	for k := range target.Env {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	for _, key := range envKeys {
		value := target.Env[key]
		if sensitiveEnvKeyRe.MatchString(key) {
			if value == "****" {
				issues = append(issues, issue{
					name:        fmt.Sprintf("env-credential (%s)", key),
					description: fmt.Sprintf("Plaintext credential in env var %s (scrubbed)", key),
					checklistID: "CD-1.1",
				})
				checklistIDs["CD-1.1"] = true
				maxSeverity = auditor.WorseSeverity(maxSeverity, auditor.SeverityCritical)
			} else if strings.HasPrefix(value, "${") {
				issues = append(issues, issue{
					name:        fmt.Sprintf("env-var-ref (%s)", key),
					description: fmt.Sprintf("Credential dependency via env var reference for %s", key),
					checklistID: "CD-1.3",
				})
				checklistIDs["CD-1.3"] = true
				maxSeverity = auditor.WorseSeverity(maxSeverity, auditor.SeverityMedium)
			}
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
			Message:     "Credential indicators detected: " + strings.Join(names, ", "),
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Use environment variables or a secrets manager instead of plaintext credentials. Remove hardcoded API keys and tokens from server configuration.",
			Metadata: map[string]any{
				"display_title": "Credential exposure detected",
				"checklist_id":  strings.Join(sortedIDs, ", "),
				"issues":        issueDescs,
			},
		}}
	}

	return []auditor.Finding{{
		CheckID:    c.ID(),
		Severity:   auditor.SeverityNote,
		Message:    "No credential exposure detected",
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata: map[string]any{
			"display_title": "No credential exposure detected",
			"checklist_id":  "CD-1.x",
		},
	}}
}
