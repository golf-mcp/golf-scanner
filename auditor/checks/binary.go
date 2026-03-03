// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"fmt"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
)

var (
	binaryProtectedPaths = []string{"/usr/bin", "/usr/local/bin", "/bin", "/sbin", "/usr/sbin"}
	binaryOptionalPaths  = []string{"/opt"}
	binaryTempPaths      = []string{"/tmp", "/var/tmp", "/dev/shm"}
)

// BinaryLocationCheck checks binary location (BN-1.x).
type BinaryLocationCheck struct{}

func (c *BinaryLocationCheck) ID() string           { return "binary.location" }
func (c *BinaryLocationCheck) Name() string         { return "Binary Location Analysis" }
func (c *BinaryLocationCheck) RequiresOnline() bool { return false }

func (c *BinaryLocationCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if ctx.GetServerType() != auditor.ServerTypeBinary {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "Not a binary server",
			ServerName: ctx.Target.Name,
			Location:   ctx.Target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "BN-1.1"},
		}}
	}

	target := ctx.Target
	cmdPath := target.Cmd

	if cmdPath == "" || !strings.HasPrefix(cmdPath, "/") {
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Binary path is not absolute",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Use absolute paths for binaries",
			Metadata:    map[string]any{"checklist_id": "BN-1.5"},
		}}
	}

	// BN-1.4: Temporary location (most critical)
	for _, temp := range binaryTempPaths {
		if strings.HasPrefix(cmdPath, temp) {
			return []auditor.Finding{{
				CheckID:     c.ID(),
				Severity:    auditor.SeverityCritical,
				Message:     fmt.Sprintf("Binary runs from temporary location: %s", temp),
				ServerName:  target.Name,
				Location:    target.ConfigPath,
				Remediation: "Do not execute binaries from temporary directories",
				Metadata:    map[string]any{"checklist_id": "BN-1.4", "path": cmdPath},
			}}
		}
	}

	// BN-1.1: Protected location
	for _, protected := range binaryProtectedPaths {
		if strings.HasPrefix(cmdPath, protected) {
			return []auditor.Finding{{
				CheckID:    c.ID(),
				Severity:   auditor.SeverityNote,
				Message:    fmt.Sprintf("Binary in protected system location: %s", protected),
				ServerName: target.Name,
				Location:   target.ConfigPath,
				Metadata:   map[string]any{"checklist_id": "BN-1.1", "path": cmdPath},
			}}
		}
	}

	// BN-1.2: Optional location
	for _, opt := range binaryOptionalPaths {
		if strings.HasPrefix(cmdPath, opt) {
			return []auditor.Finding{{
				CheckID:    c.ID(),
				Severity:   auditor.SeverityMedium,
				Message:    fmt.Sprintf("Binary in /opt directory: %s", cmdPath),
				ServerName: target.Name,
				Location:   target.ConfigPath,
				Metadata:   map[string]any{"checklist_id": "BN-1.2", "path": cmdPath},
			}}
		}
	}

	// BN-1.3: User home directory
	if strings.HasPrefix(cmdPath, "/home/") || strings.HasPrefix(cmdPath, "/Users/") {
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityMedium,
			Message:     "Binary in user home directory",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Consider installing to system location",
			Metadata:    map[string]any{"checklist_id": "BN-1.3", "path": cmdPath},
		}}
	}

	// BN-1.5: Unknown location
	return []auditor.Finding{{
		CheckID:     c.ID(),
		Severity:    auditor.SeverityHigh,
		Message:     fmt.Sprintf("Binary in unexpected location: %s", cmdPath),
		ServerName:  target.Name,
		Location:    target.ConfigPath,
		Remediation: "Verify binary provenance",
		Metadata:    map[string]any{"checklist_id": "BN-1.5", "path": cmdPath},
	}}
}

// BinaryPermissionsCheck checks binary file permissions (BN-2.x).
type BinaryPermissionsCheck struct{}

func (c *BinaryPermissionsCheck) ID() string           { return "binary.permissions" }
func (c *BinaryPermissionsCheck) Name() string         { return "Binary File Permissions" }
func (c *BinaryPermissionsCheck) RequiresOnline() bool { return false }

func (c *BinaryPermissionsCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if ctx.GetServerType() != auditor.ServerTypeBinary {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "Not a binary server",
			ServerName: ctx.Target.Name,
			Location:   ctx.Target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "BN-2.1"},
		}}
	}

	target := ctx.Target

	if target.CmdFileMode == nil {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "File permissions not available, rescan with golf-scanner required",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "BN-2.1"},
		}}
	}

	var findings []auditor.Finding

	// BN-2.1: World-writable (0o002)
	if *target.CmdFileMode&0o002 != 0 {
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityCritical,
			Message:     "Binary is world-writable",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "chmod o-w to remove world write permission",
			Metadata:    map[string]any{"checklist_id": "BN-2.1"},
		})
	}

	// BN-2.2: Group-writable (0o020)
	if *target.CmdFileMode&0o020 != 0 {
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Binary is group-writable",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "chmod g-w to remove group write permission",
			Metadata:    map[string]any{"checklist_id": "BN-2.2"},
		})
	}

	if len(findings) == 0 {
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    fmt.Sprintf("Binary permissions OK: %#o", *target.CmdFileMode),
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "BN-2.1"},
		})
	}

	return findings
}
