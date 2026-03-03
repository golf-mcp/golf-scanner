// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/apiclient"
)

// PackageUnscopedVariantCheck checks for malicious unscoped variants of scoped npm packages.
type PackageUnscopedVariantCheck struct{}

func (c *PackageUnscopedVariantCheck) ID() string           { return "package.unscoped_variant" }
func (c *PackageUnscopedVariantCheck) Name() string          { return "Unscoped Variant Check" }
func (c *PackageUnscopedVariantCheck) RequiresOnline() bool   { return true }

func (c *PackageUnscopedVariantCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if !isPackageManager(ctx) {
		return []auditor.Finding{skipFinding(c.ID(), "PM-8.1", "Not a package manager server", ctx.Target)}
	}

	pkgInfo := ExtractPackageInfo(ctx.Target)
	if pkgInfo == nil || pkgInfo.Ecosystem != "npm" {
		return []auditor.Finding{skipFinding(c.ID(), "PM-8.1", "Not an npm package", ctx.Target)}
	}

	packageName := pkgInfo.Name
	unscopedName := extractUnscopedName(packageName)
	if unscopedName == "" {
		return []auditor.Finding{skipFinding(c.ID(), "PM-8.1", "Package is not scoped", ctx.Target)}
	}

	client := &apiclient.OSVClient{}
	result := client.QueryVulnerabilities(unscopedName, "npm")

	if result.Error != "" || len(result.Vulnerabilities) == 0 {
		return []auditor.Finding{skipFinding(c.ID(), "PM-8.1", "No vulnerabilities in unscoped variant", ctx.Target)}
	}

	target := ctx.Target

	// Check for malware specifically
	var malwareVulns, otherVulns []apiclient.VulnerabilityInfo
	for _, v := range result.Vulnerabilities {
		if v.IsMalware {
			malwareVulns = append(malwareVulns, v)
		} else {
			otherVulns = append(otherVulns, v)
		}
	}

	if len(malwareVulns) > 0 {
		vulnIDs := make([]string, len(malwareVulns))
		for i, v := range malwareVulns {
			vulnIDs[i] = v.ID
		}
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Malware detected in '" + unscopedName + "'",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Verify you are using the correct scoped package '" + packageName + "'",
			Metadata: map[string]any{
				"display_title":    "Malware in unscoped variant",
				"checklist_id":     "PM-8.1",
				"unscoped_variant": unscopedName,
				"scoped_package":   packageName,
				"vuln_ids":         vulnIDs,
			},
		}}
	}

	if len(otherVulns) > 0 {
		limit := 5
		if len(otherVulns) < limit {
			limit = len(otherVulns)
		}
		vulnIDs := make([]string, limit)
		for i := 0; i < limit; i++ {
			vulnIDs[i] = otherVulns[i].ID
		}
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityMedium,
			Message:     "Vulnerabilities found in '" + unscopedName + "'",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Verify you are using the correct scoped package '" + packageName + "'",
			Metadata: map[string]any{
				"display_title":    "Vulnerabilities in unscoped variant",
				"checklist_id":     "PM-8.1",
				"unscoped_variant": unscopedName,
				"scoped_package":   packageName,
				"vuln_ids":         vulnIDs,
			},
		}}
	}

	return []auditor.Finding{skipFinding(c.ID(), "PM-8.1", "No issues in unscoped variant", ctx.Target)}
}

func extractUnscopedName(packageName string) string {
	if !strings.HasPrefix(packageName, "@") {
		return ""
	}
	parts := strings.SplitN(packageName, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}
