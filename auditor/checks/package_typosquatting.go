// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"net/url"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/apiclient"
)

// PackageTyposquattingCheck checks for potential typosquatting via deps.dev.
type PackageTyposquattingCheck struct{}

func (c *PackageTyposquattingCheck) ID() string           { return "package.typosquatting" }
func (c *PackageTyposquattingCheck) Name() string          { return "Typosquatting Risk Detection" }
func (c *PackageTyposquattingCheck) RequiresOnline() bool   { return true }

func (c *PackageTyposquattingCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if !isPackageManager(ctx) {
		return []auditor.Finding{skipFinding(c.ID(), "PM-5.1", "Not a package manager server", ctx.Target)}
	}

	pkgInfo := ExtractPackageInfo(ctx.Target)
	if pkgInfo == nil {
		return []auditor.Finding{skipFinding(c.ID(), "PM-5.1", "Could not extract package info", ctx.Target)}
	}

	client := &apiclient.DepsDevClient{}
	result := client.GetPackageInfo(pkgInfo.Name, pkgInfo.Ecosystem)

	target := ctx.Target

	if result.Error != "" {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "Could not check typosquatting risk: " + result.Error,
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "PM-5.1", "error": result.Error},
		}}
	}

	ecosystemSlug := strings.ToLower(pkgInfo.Ecosystem)
	encodedName := url.QueryEscape(pkgInfo.Name)
	depsdevURL := "https://deps.dev/" + ecosystemSlug + "/" + encodedName

	if len(result.SimilarPackages) > 0 {
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Verify you're using the correct package name",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Check the package name for typos",
			Metadata: map[string]any{
				"display_title":    "Similar package names detected",
				"checklist_id":     "PM-5.1",
				"similar_packages": result.SimilarPackages,
				"depsdev_url":      depsdevURL,
			},
		}}
	}

	return []auditor.Finding{{
		CheckID:    c.ID(),
		Severity:   auditor.SeverityNote,
		Message:    "No similarly named packages detected",
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata: map[string]any{
			"display_title": "No similarly named packages detected",
			"checklist_id":  "PM-5.1",
			"depsdev_url":   depsdevURL,
		},
	}}
}
