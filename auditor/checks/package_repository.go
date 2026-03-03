// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/apiclient"
)

// PackageRepositoryCheck checks for source repository link.
type PackageRepositoryCheck struct{}

func (c *PackageRepositoryCheck) ID() string           { return "package.repository" }
func (c *PackageRepositoryCheck) Name() string          { return "Package repository" }
func (c *PackageRepositoryCheck) RequiresOnline() bool   { return true }

func (c *PackageRepositoryCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if !isPackageManager(ctx) {
		return []auditor.Finding{skipFinding(c.ID(), "PM-3.1", "Not a package manager server", ctx.Target)}
	}

	pkgInfo := ExtractPackageInfo(ctx.Target)
	if pkgInfo == nil {
		return []auditor.Finding{skipFinding(c.ID(), "PM-3.1", "Could not extract package info", ctx.Target)}
	}

	target := ctx.Target
	repoURL, source, directory := c.getRepositoryURL(pkgInfo, ctx)

	if repoURL != "" {
		repoExt := map[string]string{"url": repoURL, "source": source}
		if directory != "" {
			repoExt["directory"] = directory
		}
		ctx.SetExtension("source.repository", repoExt)

		if apiclient.IsGitHubURL(repoURL) {
			return []auditor.Finding{{
				CheckID:    c.ID(),
				Severity:   auditor.SeveritySkip,
				Message:    "GitHub repository - handled by trust check",
				ServerName: target.Name,
				Location:   target.ConfigPath,
				Metadata: map[string]any{
					"checklist_id": "PM-3.3",
					"repository":   repoURL,
					"source":       source,
				},
			}}
		}

		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "Source repository verified",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"display_title": "Source repository verified",
				"description":   "Repository: " + repoURL,
				"checklist_id":  "PM-3.3",
				"repository":    repoURL,
				"source":        source,
			},
		}}
	}

	return []auditor.Finding{{
		CheckID:     c.ID(),
		Severity:    auditor.SeverityCritical,
		Message:     "No source repository linked to package",
		ServerName:  target.Name,
		Location:    target.ConfigPath,
		Remediation: "Verify package source manually before using",
		Metadata: map[string]any{
			"checklist_id":    "PM-3.1",
			"checked_sources": []string{"mcp-registry", "package-registry", "deps.dev"},
		},
	}}
}

func (c *PackageRepositoryCheck) getRepositoryURL(pkg *PackageInfo, ctx *auditor.AuditContext) (string, string, string) {
	// 1. Check MCP Registry (from registry.status extension)
	if regStatus, ok := ctx.GetExtension("registry.status"); ok {
		if regMap, ok := regStatus.(map[string]any); ok {
			if repoURL, ok := regMap["repository_url"].(string); ok && repoURL != "" {
				return repoURL, "mcp-registry", ""
			}
		}
	}

	// 2. Try native package registry
	var repoURL, directory string
	if pkg.Ecosystem == "npm" {
		repoURL, directory = (&apiclient.NpmRegistryClient{}).GetRepositoryURL(pkg.Name)
	} else if pkg.Ecosystem == "PyPI" {
		repoURL, directory = (&apiclient.PyPIClient{}).GetRepositoryURL(pkg.Name)
	}
	if repoURL != "" {
		return repoURL, "package-registry", directory
	}

	// 3. Fall back to deps.dev
	result := (&apiclient.DepsDevClient{}).GetPackageInfo(pkg.Name, pkg.Ecosystem)
	if result.RepositoryURL != "" {
		return result.RepositoryURL, "deps.dev", ""
	}

	return "", "", ""
}
