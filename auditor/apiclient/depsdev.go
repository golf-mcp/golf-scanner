// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor/httpclient"
)

const depsdevAPIURL = "https://api.deps.dev/v3"

// DepsDevClient queries the deps.dev API.
type DepsDevClient struct{}

// DepsDevResult holds the result of a deps.dev lookup.
type DepsDevResult struct {
	RepositoryURL   string
	SimilarPackages []string
	Error           string
}

// GetPackageInfo gets package metadata from deps.dev.
func (c *DepsDevClient) GetPackageInfo(packageName, ecosystem string) DepsDevResult {
	systemMap := map[string]string{"npm": "NPM", "PyPI": "PYPI"}
	system := systemMap[ecosystem]
	if system == "" {
		system = strings.ToUpper(ecosystem)
	}

	encodedName := url.PathEscape(packageName)

	// First request: get package info with version list
	body, status, err := httpclient.Get(depsdevAPIURL + "/systems/" + system + "/packages/" + encodedName)
	if err != nil {
		return DepsDevResult{Error: "deps.dev unreachable"}
	}
	if status == 404 {
		return DepsDevResult{Error: "Package not found in deps.dev"}
	}
	if status >= 400 {
		return DepsDevResult{Error: "deps.dev returned error"}
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return DepsDevResult{Error: "deps.dev returned invalid JSON"}
	}

	// Find latest version
	var latestVersion string
	if versions, ok := data["versions"].([]any); ok && len(versions) > 0 {
		for _, v := range versions {
			vMap, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if isDefault, _ := vMap["isDefault"].(bool); isDefault {
				if vk, ok := vMap["versionKey"].(map[string]any); ok {
					latestVersion, _ = vk["version"].(string)
				}
				break
			}
		}
		if latestVersion == "" {
			last := versions[len(versions)-1]
			if vMap, ok := last.(map[string]any); ok {
				if vk, ok := vMap["versionKey"].(map[string]any); ok {
					latestVersion, _ = vk["version"].(string)
				}
			}
		}
	}

	// Second request: get version-specific info with links
	var repoURL string
	if latestVersion != "" {
		encodedVersion := url.PathEscape(latestVersion)
		vBody, vStatus, vErr := httpclient.Get(
			depsdevAPIURL + "/systems/" + system + "/packages/" + encodedName + "/versions/" + encodedVersion,
		)
		if vErr == nil && vStatus == 200 {
			var vData map[string]any
			if json.Unmarshal(vBody, &vData) == nil {
				repoURL = extractRepoURL(vData)
			}
		}
	}

	// Extract similar packages
	similar := extractSimilarPackages(data)

	return DepsDevResult{
		RepositoryURL:   repoURL,
		SimilarPackages: similar,
	}
}

func extractRepoURL(vData map[string]any) string {
	// Try links array first
	if links, ok := vData["links"].([]any); ok {
		for _, l := range links {
			lMap, ok := l.(map[string]any)
			if !ok {
				continue
			}
			if lMap["label"] == "SOURCE_REPO" {
				if u, ok := lMap["url"].(string); ok {
					return CleanRepoURL(u)
				}
			}
		}
	}

	// Try attestations
	if attestations, ok := vData["attestations"].([]any); ok {
		for _, a := range attestations {
			aMap, ok := a.(map[string]any)
			if !ok {
				continue
			}
			if sr, ok := aMap["sourceRepository"].(string); ok && sr != "" {
				return CleanRepoURL(sr)
			}
		}
	}

	// Try relatedProjects
	if related, ok := vData["relatedProjects"].([]any); ok {
		for _, r := range related {
			rMap, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if rMap["relationType"] == "SOURCE_REPO" {
				if pk, ok := rMap["projectKey"].(map[string]any); ok {
					if id, ok := pk["id"].(string); ok && id != "" {
						return CleanRepoURL("https://" + id)
					}
				}
			}
		}
	}

	return ""
}

func extractSimilarPackages(data map[string]any) []string {
	var similar []string
	related, ok := data["relatedPackages"].(map[string]any)
	if !ok {
		return similar
	}
	similarNamed, ok := related["similarlyNamedPackages"].([]any)
	if !ok {
		return similar
	}
	for i, p := range similarNamed {
		if i >= 5 {
			break
		}
		pMap, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name, ok := pMap["name"].(string)
		if ok && name != "" {
			similar = append(similar, name)
		}
	}
	return similar
}
