// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"fmt"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
)

var scriptTempPaths = []string{"/tmp", "/var/tmp", "/dev/shm"}

func extractScriptPath(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg, "/") ||
			strings.HasSuffix(arg, ".py") ||
			strings.HasSuffix(arg, ".js") ||
			strings.HasSuffix(arg, ".rb") ||
			strings.HasSuffix(arg, ".pl") ||
			strings.HasSuffix(arg, ".sh") {
			return arg
		}
	}
	return ""
}

// ScriptLocationCheck checks script file location (SC-1.x).
type ScriptLocationCheck struct{}

func (c *ScriptLocationCheck) ID() string           { return "script.location" }
func (c *ScriptLocationCheck) Name() string         { return "Script Location Analysis" }
func (c *ScriptLocationCheck) RequiresOnline() bool { return false }

func (c *ScriptLocationCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if ctx.GetServerType() != auditor.ServerTypeScript {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "Not a script server",
			ServerName: ctx.Target.Name,
			Location:   ctx.Target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "SC-1.1"},
		}}
	}

	target := ctx.Target
	scriptPath := extractScriptPath(target.Args)

	if scriptPath == "" {
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Could not determine script path",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Use an explicit script path instead of module syntax so location can be verified",
			Metadata:    map[string]any{"checklist_id": "SC-1.3"},
		}}
	}

	// SC-1.1: Temporary location
	for _, temp := range scriptTempPaths {
		if strings.HasPrefix(scriptPath, temp) {
			return []auditor.Finding{{
				CheckID:     c.ID(),
				Severity:    auditor.SeverityCritical,
				Message:     fmt.Sprintf("Script runs from temporary location: %s", temp),
				ServerName:  target.Name,
				Location:    target.ConfigPath,
				Remediation: "Do not execute scripts from temporary directories",
				Metadata:    map[string]any{"checklist_id": "SC-1.1", "path": scriptPath},
			}}
		}
	}

	// SC-1.2: User home directory
	if strings.HasPrefix(scriptPath, "~") ||
		strings.Contains(scriptPath, "/home/") ||
		strings.Contains(scriptPath, "/Users/") {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityMedium,
			Message:    "Script in user home directory",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "SC-1.2", "path": scriptPath},
		}}
	}

	// SC-1.3: Acceptable location
	return []auditor.Finding{{
		CheckID:    c.ID(),
		Severity:   auditor.SeverityNote,
		Message:    "Script location OK",
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata:   map[string]any{"checklist_id": "SC-1.3", "path": scriptPath},
	}}
}

// ScriptPermissionsCheck checks script file permissions (SC-2.x).
type ScriptPermissionsCheck struct{}

func (c *ScriptPermissionsCheck) ID() string           { return "script.permissions" }
func (c *ScriptPermissionsCheck) Name() string         { return "Script File Permissions" }
func (c *ScriptPermissionsCheck) RequiresOnline() bool { return false }

func (c *ScriptPermissionsCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if ctx.GetServerType() != auditor.ServerTypeScript {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "Not a script server",
			ServerName: ctx.Target.Name,
			Location:   ctx.Target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "SC-2.1"},
		}}
	}

	target := ctx.Target

	if target.FileMode == nil {
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Script permissions not available, rescan with golf-scanner required",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Rescan with golf-scanner to collect file permissions",
			Metadata:    map[string]any{"checklist_id": "SC-2.1"},
		}}
	}

	// SC-2.1: World-writable (0o002)
	if *target.FileMode&0o002 != 0 {
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityCritical,
			Message:     "Script is world-writable",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "chmod o-w to remove world write permission",
			Metadata:    map[string]any{"checklist_id": "SC-2.1"},
		}}
	}

	return []auditor.Finding{{
		CheckID:    c.ID(),
		Severity:   auditor.SeverityNote,
		Message:    fmt.Sprintf("Script permissions OK: %#o", *target.FileMode),
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata:   map[string]any{"checklist_id": "SC-2.1"},
	}}
}
