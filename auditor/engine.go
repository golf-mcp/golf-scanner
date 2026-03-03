// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

// Check is the interface all audit checks implement.
type Check interface {
	ID() string
	Name() string
	RequiresOnline() bool
	Run(ctx *AuditContext) []Finding
}

// FileMetadataCheckIDs contains check IDs that inspect file permissions/ownership.
// These checks may produce different results for different instances of the same identity.
var FileMetadataCheckIDs = map[string]bool{
	"script.location":    true,
	"script.permissions": true,
	"binary.location":    true,
	"binary.permissions": true,
}

// RunAudit runs all applicable checks against a server inventory.
// Returns (findings, checksRunIDs, checksSkippedIDs).
func RunAudit(target ServerInventory, checks []Check, online bool) ([]Finding, []string, []string) {
	ctx := &AuditContext{
		Target:     target,
		Extensions: make(map[string]any),
	}

	var allFindings []Finding
	var checksRun []string
	var checksSkipped []string

	// Phase 1: Run server_type check first (provides "server_type" extension)
	for _, c := range checks {
		if c.ID() == ExtKeyTypeDetection {
			if !online && c.RequiresOnline() {
				checksSkipped = append(checksSkipped, c.ID())
				continue
			}
			findings := c.Run(ctx)
			allFindings = append(allFindings, findings...)
			checksRun = append(checksRun, c.ID())
			ctx.ChecksRun = append(ctx.ChecksRun, c.ID())
			break
		}
	}

	// Phase 2: Run remaining checks
	for _, c := range checks {
		if c.ID() == ExtKeyTypeDetection {
			continue // Already ran
		}
		if !online && c.RequiresOnline() {
			checksSkipped = append(checksSkipped, c.ID())
			continue
		}
		findings := c.Run(ctx)
		allFindings = append(allFindings, findings...)
		checksRun = append(checksRun, c.ID())
		ctx.ChecksRun = append(ctx.ChecksRun, c.ID())
	}

	return allFindings, checksRun, checksSkipped
}
