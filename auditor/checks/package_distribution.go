// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/apiclient"
)

// PackageDistributionCheck checks download count and package age.
type PackageDistributionCheck struct{}

func (c *PackageDistributionCheck) ID() string           { return "package.distribution" }
func (c *PackageDistributionCheck) Name() string          { return "Package Distribution" }
func (c *PackageDistributionCheck) RequiresOnline() bool   { return true }

func (c *PackageDistributionCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if !isPackageManager(ctx) {
		return []auditor.Finding{skipFinding(c.ID(), "PM-6.1", "Not a package manager server", ctx.Target)}
	}

	pkgInfo := ExtractPackageInfo(ctx.Target)
	target := ctx.Target

	ecosystem := GetEcosystem(target.Cmd)
	baseTitle := "Distributed by package manager"
	if ecosystem != "" {
		baseTitle = "Distributed by " + ecosystem + " package manager"
	}

	var registryURL string
	if ecosystem != "" && pkgInfo != nil {
		registryURL = buildRegistryURL(pkgInfo.Name, ecosystem)
	}

	// Fetch download count
	var downloads *int
	if pkgInfo != nil {
		downloads = getDownloadCount(pkgInfo)
	}

	// Fetch package age
	var ageDays *int
	var ageStr string
	if pkgInfo != nil {
		createdAt := getCreatedDate(pkgInfo)
		if createdAt != nil {
			d := int(time.Since(*createdAt).Hours() / 24)
			ageDays = &d
			ageStr = formatAge(d)
		}
	}

	// Assess severity
	severity := auditor.SeverityNote
	var titleSuffixes []string

	if downloads != nil && *downloads < 1000 {
		titleSuffixes = append(titleSuffixes, "low download count")
		if *downloads < 100 {
			severity = auditor.WorseSeverity(severity, auditor.SeverityHigh)
		} else {
			severity = auditor.WorseSeverity(severity, auditor.SeverityMedium)
		}
	}

	if ageDays != nil && *ageDays < 180 {
		titleSuffixes = append(titleSuffixes, "young package")
		severity = auditor.WorseSeverity(severity, auditor.SeverityMedium)
	}

	displayTitle := baseTitle
	if len(titleSuffixes) > 0 {
		displayTitle = baseTitle + ", " + strings.Join(titleSuffixes, ", ")
	}

	// Build description
	var descParts []string
	if downloads != nil {
		descParts = append(descParts, fmt.Sprintf("%d downloads per week", *downloads))
	}
	if ageStr != "" {
		descParts = append(descParts, "created "+ageStr+" ago")
	}
	description := ""
	if len(descParts) > 0 {
		description = strings.Join(descParts, ", ") + "."
	}

	metadata := map[string]any{
		"display_title":     displayTitle,
		"description":       description,
		"checklist_id":      "PM-6.1",
		"downloads_warning": downloads != nil && *downloads < 1000,
		"age_warning":       ageDays != nil && *ageDays < 180,
	}
	if downloads != nil {
		metadata["weekly_downloads"] = *downloads
	}
	if ageDays != nil {
		metadata["age_days"] = *ageDays
	}
	if registryURL != "" {
		metadata["registry_url"] = registryURL
	}

	return []auditor.Finding{{
		CheckID:    c.ID(),
		Severity:   severity,
		Message:    description,
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata:   metadata,
	}}
}

func buildRegistryURL(packageName, ecosystem string) string {
	if ecosystem == "npm" {
		return "https://www.npmjs.com/package/" + packageName
	}
	if ecosystem == "PyPI" {
		normalized := strings.ToLower(strings.ReplaceAll(packageName, "_", "-"))
		return "https://pypi.org/project/" + url.QueryEscape(normalized)
	}
	return ""
}

func getDownloadCount(pkg *PackageInfo) *int {
	if pkg.Ecosystem == "npm" {
		return (&apiclient.NpmRegistryClient{}).GetDownloadCount(pkg.Name)
	}
	if pkg.Ecosystem == "PyPI" {
		return (&apiclient.PyPIClient{}).GetDownloadCount(pkg.Name)
	}
	return nil
}

func getCreatedDate(pkg *PackageInfo) *time.Time {
	if pkg.Ecosystem == "npm" {
		return (&apiclient.NpmRegistryClient{}).GetCreatedDate(pkg.Name)
	}
	if pkg.Ecosystem == "PyPI" {
		return (&apiclient.PyPIClient{}).GetCreatedDate(pkg.Name)
	}
	return nil
}

func formatAge(days int) string {
	if days < 7 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	if days < 30 {
		weeks := days / 7
		if weeks == 1 {
			return "1 week"
		}
		return fmt.Sprintf("%d weeks", weeks)
	}
	if days < 365 {
		months := days / 30
		if months == 1 {
			return "1 month"
		}
		return fmt.Sprintf("%d months", months)
	}
	years := days / 365
	if years == 1 {
		return "1 year"
	}
	return fmt.Sprintf("%d years", years)
}
