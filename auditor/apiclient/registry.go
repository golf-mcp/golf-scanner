// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"

	"github.com/golf-mcp/golf-scanner/auditor/httpclient"
)

// mcpRegistryBaseURL is the official MCP server registry API (v0.1).
const mcpRegistryBaseURL = "https://registry.modelcontextprotocol.io/v0.1"

// RegistryServerInfo holds information about a server from the MCP Registry.
type RegistryServerInfo struct {
	Name          string
	Description   string
	Version       string
	Status        string
	RepositoryURL string
	IsLatest      bool
}

// RegistryLookupResult holds the result of a registry lookup.
type RegistryLookupResult struct {
	Found  bool
	Server *RegistryServerInfo
	Error  string
}

// MCPRegistryClient queries the MCP Registry API with caching.
type MCPRegistryClient struct {
	cache map[string]*RegistryLookupResult
	mu    sync.Mutex
}

// NewMCPRegistryClient creates a new MCP Registry client.
func NewMCPRegistryClient() *MCPRegistryClient {
	return &MCPRegistryClient{
		cache: make(map[string]*RegistryLookupResult),
	}
}

// Lookup searches the MCP Registry for a server by name/identifier.
func (c *MCPRegistryClient) Lookup(searchTerm string) *RegistryLookupResult {
	cacheKey := strings.ToLower(searchTerm)

	c.mu.Lock()
	if cached, ok := c.cache[cacheKey]; ok {
		c.mu.Unlock()
		return cached
	}
	c.mu.Unlock()

	result := c.queryRegistry(searchTerm)

	c.mu.Lock()
	c.cache[cacheKey] = result
	c.mu.Unlock()

	return result
}

// LookupByHostname searches the MCP Registry by hostname.
func (c *MCPRegistryClient) LookupByHostname(hostname string) *RegistryLookupResult {
	cacheKey := "hostname:" + strings.ToLower(hostname)

	c.mu.Lock()
	if cached, ok := c.cache[cacheKey]; ok {
		c.mu.Unlock()
		return cached
	}
	c.mu.Unlock()

	keywords := extractHostnameKeywords(hostname)
	if len(keywords) == 0 {
		result := &RegistryLookupResult{Found: false}
		c.mu.Lock()
		c.cache[cacheKey] = result
		c.mu.Unlock()
		return result
	}

	for _, keyword := range keywords {
		result := c.queryRegistryForHostname(keyword, hostname)
		if result.Found {
			c.mu.Lock()
			c.cache[cacheKey] = result
			c.mu.Unlock()
			return result
		}
	}

	result := &RegistryLookupResult{Found: false}
	c.mu.Lock()
	c.cache[cacheKey] = result
	c.mu.Unlock()
	return result
}

func extractHostnameKeywords(hostname string) []string {
	parts := strings.Split(strings.ToLower(hostname), ".")
	commonPrefixes := map[string]bool{"mcp": true, "api": true, "www": true, "server": true, "sse": true, "ws": true}
	commonTLDs := map[string]bool{"com": true, "io": true, "ai": true, "dev": true, "app": true, "net": true, "org": true, "co": true}

	var keywords []string
	for _, part := range parts {
		if !commonPrefixes[part] && !commonTLDs[part] && len(part) > 2 {
			keywords = append(keywords, part)
		}
	}
	return keywords
}

func (c *MCPRegistryClient) queryRegistry(searchTerm string) *RegistryLookupResult {
	body, status, err := httpclient.Get(
		mcpRegistryBaseURL + "/servers?search=" + url.QueryEscape(searchTerm) + "&version=latest",
	)
	if err != nil {
		return &RegistryLookupResult{Found: false, Error: "Registry unreachable"}
	}
	if status >= 400 {
		return &RegistryLookupResult{Found: false, Error: "Registry returned error"}
	}

	var data struct {
		Servers []json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return &RegistryLookupResult{Found: false, Error: "Registry returned invalid JSON"}
	}

	matched := findExactMatch(data.Servers, searchTerm)
	if matched == nil {
		return &RegistryLookupResult{Found: false}
	}
	return &RegistryLookupResult{Found: true, Server: matched}
}

func (c *MCPRegistryClient) queryRegistryForHostname(keyword, targetHostname string) *RegistryLookupResult {
	body, status, err := httpclient.Get(
		mcpRegistryBaseURL + "/servers?search=" + url.QueryEscape(keyword) + "&version=latest",
	)
	if err != nil {
		return &RegistryLookupResult{Found: false, Error: "Registry unreachable"}
	}
	if status >= 400 {
		return &RegistryLookupResult{Found: false, Error: "Registry returned error"}
	}

	var data struct {
		Servers []json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return &RegistryLookupResult{Found: false, Error: "Registry returned invalid JSON"}
	}

	matched := findByHostname(data.Servers, targetHostname)
	if matched == nil {
		return &RegistryLookupResult{Found: false}
	}
	return &RegistryLookupResult{Found: true, Server: matched}
}

func findExactMatch(servers []json.RawMessage, searchTerm string) *RegistryServerInfo {
	searchLower := strings.ToLower(searchTerm)

	for _, raw := range servers {
		var entry map[string]any
		if json.Unmarshal(raw, &entry) != nil {
			continue
		}

		serverData, _ := entry["server"].(map[string]any)
		if serverData == nil {
			continue
		}

		name, _ := serverData["name"].(string)
		matched := false

		// Match on name
		if strings.ToLower(name) == searchLower || strings.HasSuffix(strings.ToLower(name), "/"+searchLower) {
			matched = true
		}

		// Match on package identifier
		if !matched {
			if packages, ok := serverData["packages"].([]any); ok {
				for _, pkg := range packages {
					pkgMap, ok := pkg.(map[string]any)
					if !ok {
						continue
					}
					if id, ok := pkgMap["identifier"].(string); ok && strings.Contains(strings.ToLower(id), searchLower) {
						matched = true
						break
					}
				}
			}
		}

		// Match on remote URL
		if !matched {
			if remotes, ok := serverData["remotes"].([]any); ok {
				for _, remote := range remotes {
					rMap, ok := remote.(map[string]any)
					if !ok {
						continue
					}
					if u, ok := rMap["url"].(string); ok && strings.Contains(strings.ToLower(u), searchLower) {
						matched = true
						break
					}
				}
			}
		}

		if matched {
			return extractServerInfo(entry, serverData)
		}
	}
	return nil
}

func findByHostname(servers []json.RawMessage, targetHostname string) *RegistryServerInfo {
	targetLower := strings.ToLower(targetHostname)

	for _, raw := range servers {
		var entry map[string]any
		if json.Unmarshal(raw, &entry) != nil {
			continue
		}

		serverData, _ := entry["server"].(map[string]any)
		if serverData == nil {
			continue
		}

		remotes, ok := serverData["remotes"].([]any)
		if !ok {
			continue
		}

		for _, remote := range remotes {
			rMap, ok := remote.(map[string]any)
			if !ok {
				continue
			}
			if u, ok := rMap["url"].(string); ok && strings.Contains(strings.ToLower(u), targetLower) {
				return extractServerInfo(entry, serverData)
			}
		}
	}
	return nil
}

func extractServerInfo(entry map[string]any, serverData map[string]any) *RegistryServerInfo {
	meta, _ := entry["_meta"].(map[string]any)
	officialMeta, _ := meta["io.modelcontextprotocol.registry/official"].(map[string]any)

	name, _ := serverData["name"].(string)
	desc, _ := serverData["description"].(string)
	version, _ := serverData["version"].(string)

	status := "unknown"
	if officialMeta != nil {
		if s, ok := officialMeta["status"].(string); ok {
			status = s
		}
	}

	isLatest := false
	if officialMeta != nil {
		isLatest, _ = officialMeta["isLatest"].(bool)
	}

	var repoURL string
	if repo, ok := serverData["repository"].(map[string]any); ok {
		if u, ok := repo["url"].(string); ok {
			repoURL = CleanRepoURL(u)
		}
	}

	return &RegistryServerInfo{
		Name:          name,
		Description:   desc,
		Version:       version,
		Status:        status,
		RepositoryURL: repoURL,
		IsLatest:      isLatest,
	}
}
