// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/apiclient"
)

const (
	starsExcellent = 1000
	starsGood      = 100
	starsLow       = 50
	staleDays      = 365
)

// GitHubTrustCheck evaluates GitHub repository trust signals (UC-3.x).
type GitHubTrustCheck struct{}

func (c *GitHubTrustCheck) ID() string           { return "universal.github.trust" }
func (c *GitHubTrustCheck) Name() string          { return "GitHub repository" }
func (c *GitHubTrustCheck) RequiresOnline() bool   { return true }

func (c *GitHubTrustCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	target := ctx.Target

	// Collect repo URLs from all sources and check for mismatch
	repoURLs := collectRepoURLs(ctx)
	repoMismatch := checkRepoMismatch(repoURLs)

	// Try to get GitHub metadata from multiple sources
	ghMeta, metaError := getGitHubMetadata(ctx)

	if metaError != "" {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"display_title": "GitHub metadata unavailable",
				"description":   "Could not fetch repository data: " + metaError,
				"checklist_id":  "UC-3.1",
			},
		}}
	}

	if ghMeta == nil {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"display_title": "GitHub trust check skipped",
				"description":   "No GitHub repository found for this server",
				"checklist_id":  "UC-3.1",
			},
		}}
	}

	stars := ghMeta.Stars
	forks := ghMeta.Forks
	archived := ghMeta.Archived
	licenseName := ghMeta.LicenseName
	ownerType := ghMeta.OwnerType

	var daysSinceUpdate *int
	if ghMeta.PushedAt != nil {
		d := int(time.Since(*ghMeta.PushedAt).Hours() / 24)
		daysSinceUpdate = &d
	}

	repoURL := getRepoURLFromContext(ctx)

	var findings []auditor.Finding

	// Repository URL mismatch - critical security issue
	if repoMismatch != nil {
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityHigh,
			Message:    "",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"display_title": "Repository URL mismatch detected",
				"description":   repoMismatch["description"],
				"checklist_id":  "UC-3.2",
				"sources":       repoMismatch["sources"],
			},
		})
	}

	// Check archived status
	if archived {
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityHigh,
			Message:    "",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"display_title":   "GitHub repository is archived",
				"description":     fmt.Sprintf("This repository is no longer maintained. %d stars, last updated %s.", stars, formatDaysAgo(daysSinceUpdate)),
				"checklist_id":    "UC-3.1",
				"github_stars":    stars,
				"github_archived": true,
				"repository_url":  repoURL,
			},
		})
		return findings
	}

	// Evaluate trust signals
	var warnings []string

	// Activity level
	if ghMeta.CommitsLastMonth != nil && *ghMeta.CommitsLastMonth == 0 {
		if daysSinceUpdate != nil && *daysSinceUpdate > staleDays {
			warnings = append(warnings, fmt.Sprintf("no commits in last month, last activity %s", formatDaysAgo(daysSinceUpdate)))
		} else {
			warnings = append(warnings, "no commits in last month")
		}
	} else if ghMeta.CommitsLastMonth == nil && daysSinceUpdate != nil && *daysSinceUpdate > staleDays {
		warnings = append(warnings, fmt.Sprintf("inactive for %s", formatDaysAgo(daysSinceUpdate)))
	}

	// License
	if licenseName == "" {
		warnings = append(warnings, "no license specified")
	}

	// Community adoption
	if stars < starsLow {
		warnings = append(warnings, fmt.Sprintf("only %d stars", stars))
	}

	// Contributors
	if ghMeta.ContributorCount != nil {
		if *ghMeta.ContributorCount == 1 {
			warnings = append(warnings, "single contributor")
		}
	}

	desc := buildDetailedDescription(stars, forks, licenseName, ownerType, ghMeta.CommitsLastMonth, ghMeta.ContributorCount)

	if len(warnings) > 0 {
		warningText := strings.Join(warnings, ", ")
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityMedium,
			Message:    "",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"display_title":  "GitHub repository has limited trust signals",
				"description":    fmt.Sprintf("Warning: %s. %s", warningText, desc),
				"checklist_id":   "UC-3.1",
				"github_stars":   stars,
				"github_forks":   forks,
				"github_license": licenseName,
				"repository_url": repoURL,
			},
		})
		return findings
	}

	// No warnings - positive verdict
	var verdict string
	if stars >= starsExcellent {
		verdict = "GitHub repository is well-established"
	} else if stars >= starsGood {
		verdict = "GitHub repository appears trustworthy"
	} else {
		verdict = "GitHub repository has basic trust signals"
	}

	findings = append(findings, auditor.Finding{
		CheckID:    c.ID(),
		Severity:   auditor.SeverityNote,
		Message:    "",
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata: map[string]any{
			"display_title":  verdict,
			"description":    desc,
			"checklist_id":   "UC-3.1",
			"github_stars":   stars,
			"github_forks":   forks,
			"github_license": licenseName,
			"repository_url": repoURL,
		},
	})
	return findings
}

func getRepoURLFromContext(ctx *auditor.AuditContext) string {
	if ext, ok := ctx.GetExtension("source.repository"); ok {
		if m, ok := ext.(map[string]string); ok {
			if u := m["url"]; u != "" {
				return u
			}
		}
	}
	if ext, ok := ctx.GetExtension("registry.status"); ok {
		if m, ok := ext.(map[string]any); ok {
			if u, ok := m["repository_url"].(string); ok && u != "" {
				return u
			}
		}
	}
	return ""
}

func collectRepoURLs(ctx *auditor.AuditContext) map[string]string {
	urls := make(map[string]string)

	// Source 1: MCP Registry
	if ext, ok := ctx.GetExtension("registry.status"); ok {
		if m, ok := ext.(map[string]any); ok {
			if u, ok := m["repository_url"].(string); ok && u != "" {
				if n := apiclient.NormalizeGitHubURL(u); n != "" {
					urls["mcp_registry"] = n
				}
			}
		}
	}

	// Source 2: deps.dev / source.repository
	if ext, ok := ctx.GetExtension("source.repository"); ok {
		if m, ok := ext.(map[string]string); ok {
			if u := m["url"]; u != "" {
				if n := apiclient.NormalizeGitHubURL(u); n != "" {
					urls["deps_dev"] = n
				}
			}
		}
	}

	// Source 3: Direct package registry lookup
	if ext, ok := ctx.GetExtension("package.info"); ok {
		if m, ok := ext.(map[string]string); ok {
			pkgName := m["name"]
			ecosystem := m["ecosystem"]

			if pkgName != "" && ecosystem == "npm" {
				repoURL, _ := (&apiclient.NpmRegistryClient{}).GetRepositoryURL(pkgName)
				if repoURL != "" {
					if n := apiclient.NormalizeGitHubURL(repoURL); n != "" {
						urls["npm_registry"] = n
					}
				}
			} else if pkgName != "" && ecosystem == "PyPI" {
				repoURL, _ := (&apiclient.PyPIClient{}).GetRepositoryURL(pkgName)
				if repoURL != "" {
					if n := apiclient.NormalizeGitHubURL(repoURL); n != "" {
						urls["pypi_registry"] = n
					}
				}
			}
		}
	}

	return urls
}

func checkRepoMismatch(repoURLs map[string]string) map[string]any {
	if len(repoURLs) <= 1 {
		return nil
	}

	unique := make(map[string]bool)
	for _, u := range repoURLs {
		unique[u] = true
	}
	if len(unique) == 1 {
		return nil
	}

	sourceLabels := map[string]string{
		"mcp_registry":  "MCP Registry",
		"deps_dev":      "deps.dev",
		"npm_registry":  "npm package.json",
		"pypi_registry": "PyPI metadata",
	}

	var sourcesDesc []string
	for source, u := range repoURLs {
		label := sourceLabels[source]
		if label == "" {
			label = source
		}
		sourcesDesc = append(sourcesDesc, fmt.Sprintf("%s: %s", label, u))
	}

	return map[string]any{
		"description": fmt.Sprintf("Different sources report different repositories: %s. This could indicate a supply chain attack or misconfiguration.", strings.Join(sourcesDesc, "; ")),
		"sources":     sourcesDesc,
	}
}

func getGitHubMetadata(ctx *auditor.AuditContext) (*apiclient.GitHubRepoMetadata, string) {
	// Source 1: Pre-fetched from registry check
	if ext, ok := ctx.GetExtension("registry.status"); ok {
		if m, ok := ext.(map[string]any); ok {
			if _, hasStars := m["github_stars"]; hasStars {
				return extractMetadataFromRegistryStatus(m), ""
			}
		}
	}

	// Source 2: Fetch from source.repository URL
	if ext, ok := ctx.GetExtension("source.repository"); ok {
		if m, ok := ext.(map[string]string); ok {
			repoURL := m["url"]
			if repoURL != "" && apiclient.IsGitHubURL(repoURL) {
				normalized := apiclient.NormalizeGitHubURL(repoURL)
				if normalized == "" {
					return nil, fmt.Sprintf("Invalid GitHub URL: %s", repoURL)
				}
				// Empty token is intentional — resolved from GITHUB_TOKEN/GOLF_GITHUB_TOKEN env vars inside the constructor.
			ghClient := apiclient.NewGitHubMetadataClient("")
				result := ghClient.GetRepoMetadata(normalized)
				if result.Metadata != nil {
					return result.Metadata, ""
				}
				if result.Error != "" {
					return nil, result.Error
				}
			}
		}
	}

	return nil, ""
}

func extractMetadataFromRegistryStatus(m map[string]any) *apiclient.GitHubRepoMetadata {
	meta := &apiclient.GitHubRepoMetadata{
		OwnerType: "Unknown",
	}

	if v, ok := m["github_stars"].(float64); ok {
		meta.Stars = int(v)
	} else if v, ok := m["github_stars"].(int); ok {
		meta.Stars = v
	}
	if v, ok := m["github_forks"].(float64); ok {
		meta.Forks = int(v)
	} else if v, ok := m["github_forks"].(int); ok {
		meta.Forks = v
	}
	if v, ok := m["github_archived"].(bool); ok {
		meta.Archived = v
	}
	if v, ok := m["github_license"].(string); ok {
		meta.LicenseName = v
	}
	if v, ok := m["github_owner_type"].(string); ok && v != "" {
		meta.OwnerType = v
	}
	if v, ok := m["github_pushed_at"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			meta.PushedAt = &t
		}
	}
	if v, ok := m["github_commits_last_month"].(float64); ok {
		i := int(v)
		meta.CommitsLastMonth = &i
	} else if v, ok := m["github_commits_last_month"].(int); ok {
		meta.CommitsLastMonth = &v
	}
	if v, ok := m["github_contributors_count"].(float64); ok {
		i := int(v)
		meta.ContributorCount = &i
	} else if v, ok := m["github_contributors_count"].(int); ok {
		meta.ContributorCount = &v
	}

	return meta
}

func formatDaysAgo(days *int) string {
	if days == nil {
		return "unknown time"
	}
	d := *days
	if d < 30 {
		return fmt.Sprintf("%d days ago", d)
	}
	if d < 365 {
		months := d / 30
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	}
	years := d / 365
	if years == 1 {
		return "1 year ago"
	}
	return fmt.Sprintf("%d years ago", years)
}

func buildDetailedDescription(stars, forks int, licenseName, ownerType string, commitsLastMonth, contributorCount *int) string {
	metrics := fmt.Sprintf("%d stars", stars)
	if forks > 0 {
		metrics += fmt.Sprintf(", %d forks", forks)
	}

	if contributorCount != nil {
		if *contributorCount == 1 {
			metrics += ", 1 contributor"
		} else {
			metrics += fmt.Sprintf(", %d contributors", *contributorCount)
		}
	}

	if commitsLastMonth != nil {
		if *commitsLastMonth >= 10 {
			metrics += fmt.Sprintf(", %d commits in last month", *commitsLastMonth)
		} else if *commitsLastMonth >= 1 {
			if *commitsLastMonth == 1 {
				metrics += ", 1 commit in last month"
			} else {
				metrics += fmt.Sprintf(", %d commits in last month", *commitsLastMonth)
			}
		} else {
			metrics += ", no recent commits"
		}
	}

	if ownerType == "Organization" {
		metrics += ", organization-owned"
	} else if ownerType == "User" {
		metrics += ", individual-owned"
	}

	return metrics + "."
}
