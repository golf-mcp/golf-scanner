// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"net/url"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/apiclient"
)

const registryWebURL = "https://registry.modelcontextprotocol.io"

// RegistryVerificationCheck checks if a server is listed in the official MCP Registry.
type RegistryVerificationCheck struct{}

func (c *RegistryVerificationCheck) ID() string           { return "universal.registry.verification" }
func (c *RegistryVerificationCheck) Name() string          { return "Official MCP registry" }
func (c *RegistryVerificationCheck) RequiresOnline() bool   { return true }

func (c *RegistryVerificationCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	target := ctx.Target

	// Skip for local/private HTTP servers
	if ctx.GetServerType() == auditor.ServerTypeLocalHTTP {
		ctx.SetExtension("registry.status", map[string]any{
			"listed": nil, "verified": nil, "reason": "Local/private network server",
		})
		return []auditor.Finding{skipFinding(c.ID(), "UC-2.x", "Registry verification skipped for local/private network server", target)}
	}

	searchTerm := c.extractSearchTerm(target)
	if searchTerm == "" {
		ctx.SetExtension("registry.status", map[string]any{
			"listed": nil, "verified": nil, "reason": "No identifiable server identifier",
		})
		return []auditor.Finding{skipFinding(c.ID(), "UC-2.3", "Cannot determine server identifier for registry lookup", target)}
	}

	client := apiclient.NewMCPRegistryClient()

	var result *apiclient.RegistryLookupResult
	if target.Transport == "http" || target.Transport == "sse" {
		result = client.LookupByHostname(searchTerm)
	} else {
		result = client.Lookup(searchTerm)
	}

	if result.Error != "" {
		ctx.SetExtension("registry.status", map[string]any{
			"listed": nil, "verified": nil, "reason": result.Error,
		})
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityNote,
			Message:     "Registry lookup failed: " + result.Error,
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Registry verification skipped due to network error",
			Metadata:    map[string]any{"checklist_id": "UC-2.3", "status": "error", "search_term": searchTerm},
		}}
	}

	if result.Found && result.Server != nil {
		info := result.Server
		registryURL := buildRegistrySearchURL(info.Name)

		// Fetch GitHub metadata if repository URL is available
		githubMeta := make(map[string]any)
		if info.RepositoryURL != "" && apiclient.IsGitHubURL(info.RepositoryURL) {
			// Empty token is intentional — resolved from GITHUB_TOKEN/GOLF_GITHUB_TOKEN env vars inside the constructor.
		ghClient := apiclient.NewGitHubMetadataClient("")
			ghResult := ghClient.GetRepoMetadata(info.RepositoryURL)
			if ghResult.Metadata != nil {
				m := ghResult.Metadata
				githubMeta["github_stars"] = m.Stars
				githubMeta["github_forks"] = m.Forks
				githubMeta["github_archived"] = m.Archived
				githubMeta["github_license"] = m.LicenseName
				githubMeta["github_owner_type"] = m.OwnerType
				if m.PushedAt != nil {
					githubMeta["github_pushed_at"] = m.PushedAt.Format("2006-01-02T15:04:05Z07:00")
				}
				if m.CommitsLastMonth != nil {
					githubMeta["github_commits_last_month"] = *m.CommitsLastMonth
				}
				if m.ContributorCount != nil {
					githubMeta["github_contributors_count"] = *m.ContributorCount
				}
			}
		}

		if info.Status == "active" {
			regStatus := map[string]any{
				"listed":         true,
				"verified":       true,
				"registry_name":  info.Name,
				"version":        info.Version,
				"registry_url":   registryURL,
				"repository_url": info.RepositoryURL,
			}
			for k, v := range githubMeta {
				regStatus[k] = v
			}
			ctx.SetExtension("registry.status", regStatus)

			metadata := map[string]any{
				"display_title":    "Listed in Official MCP Registry",
				"checklist_id":     "UC-2.1",
				"status":           "listed",
				"registry_name":    info.Name,
				"registry_version": info.Version,
				"registry_url":     registryURL,
				"repository_url":   info.RepositoryURL,
			}
			for k, v := range githubMeta {
				metadata[k] = v
			}
			return []auditor.Finding{{
				CheckID:    c.ID(),
				Severity:   auditor.SeverityNote,
				Message:    "",
				ServerName: target.Name,
				Location:   target.ConfigPath,
				Metadata:   metadata,
			}}
		}

		// Listed but not active
		regStatus := map[string]any{
			"listed":         true,
			"verified":       false,
			"registry_name":  info.Name,
			"status":         info.Status,
			"registry_url":   registryURL,
			"repository_url": info.RepositoryURL,
		}
		for k, v := range githubMeta {
			regStatus[k] = v
		}
		ctx.SetExtension("registry.status", regStatus)

		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Status: " + info.Status,
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "This server was removed from the registry, possibly due to policy violations or security issues",
			Metadata: map[string]any{
				"display_title": "Removed from Official MCP Registry",
				"checklist_id":  "UC-2.2",
				"status":        info.Status,
				"registry_name": info.Name,
				"registry_url":  registryURL,
			},
		}}
	}

	// Not listed
	searchURL := registryWebURL
	if searchTerm != "" {
		searchURL = buildRegistrySearchURL(searchTerm)
	}
	ctx.SetExtension("registry.status", map[string]any{
		"listed": false, "verified": false, "search_term": searchTerm,
	})
	return []auditor.Finding{{
		CheckID:    c.ID(),
		Severity:   auditor.SeverityMedium,
		Message:    "",
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata: map[string]any{
			"display_title": "Not listed in Official MCP Registry",
			"checklist_id":  "UC-2.3",
			"status":        "not_listed",
			"search_term":   searchTerm,
			"registry_url":  searchURL,
		},
	}}
}

func (c *RegistryVerificationCheck) extractSearchTerm(target auditor.ServerInventory) string {
	if target.Transport == "http" || target.Transport == "sse" {
		if target.Host != "" {
			return extractHostFromURL(target.Host)
		}
		return ""
	}

	if target.Cmd == "" {
		return ""
	}

	cmd := strings.ToLower(target.Cmd)
	if npmCommands[cmd] {
		return extractNpmPackage(target.Args)
	}
	if pypiCommands[cmd] {
		return extractPyPIPackage(target.Args)
	}
	if containerCommands[cmd] {
		return extractContainerImageForRegistry(target.Args)
	}

	return ""
}

func extractContainerImageForRegistry(args []string) string {
	imageRef := ExtractContainerImageRef(args)
	if imageRef == "" {
		return ""
	}
	return normalizeImageRefForRegistry(imageRef)
}

func normalizeImageRefForRegistry(imageRef string) string {
	// Strip tag or digest
	ref := strings.SplitN(imageRef, "@", 2)[0]
	ref = strings.SplitN(ref, ":", 2)[0]

	parts := strings.Split(ref, "/")
	hasRegistry := len(parts) >= 2 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost")

	if hasRegistry {
		if parts[0] == "docker.io" {
			if len(parts) >= 3 && parts[1] == "library" {
				return strings.Join(parts[2:], "/")
			}
			if len(parts) >= 2 {
				return strings.Join(parts[1:], "/")
			}
		}
		return ref
	}
	return ref
}

func buildRegistrySearchURL(name string) string {
	return registryWebURL + "/?q=" + url.QueryEscape(name)
}
