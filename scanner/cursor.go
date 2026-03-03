// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"path/filepath"
	"runtime"
	"sort"
)

type CursorScanner struct{}

func (s *CursorScanner) Name() string {
	return "Cursor"
}

func (s *CursorScanner) Scan() []ScanResult {
	return s.ScanHome("", "")
}

func (s *CursorScanner) ScanHome(homeDir, username string) []ScanResult {
	var results []ScanResult
	effectiveHome, err := GetEffectiveHomeDir(homeDir)
	if err != nil {
		return results
	}

	userResults := s.scanUserConfig(effectiveHome)
	projectResults := s.scanProjectConfigs(effectiveHome)

	for i := range userResults {
		userResults[i].Username = username
	}
	for i := range projectResults {
		projectResults[i].Username = username
	}

	results = append(results, userResults...)
	results = append(results, projectResults...)
	return results
}

type cursorConfig struct {
	MCPServers map[string]cursorServerConfig `json:"mcpServers"`
}

type cursorServerConfig struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	EnvFile string            `json:"envFile,omitempty"`
	Type    string            `json:"type,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Auth    *cursorAuthConfig `json:"auth,omitempty"`
}

type cursorAuthConfig struct {
	ClientID     string   `json:"CLIENT_ID,omitempty"`
	ClientSecret string   `json:"CLIENT_SECRET,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// cursorStorage is an alias for the shared ideStorage type.
type cursorStorage = ideStorage

func (s *CursorScanner) scanUserConfig(homeDir string) []ScanResult {
	var results []ScanResult
	configPath := filepath.Join(homeDir, ".cursor", "mcp.json")
	servers := s.parseConfig(configPath)
	if len(servers) > 0 {
		results = append(results, ScanResult{
			IDE:             s.Name(),
			Scope:           "user",
			ConfigPath:      configPath,
			ConfigHash:      HashFile(configPath),
			DiscoverySource: "direct",
			Servers:         servers,
		})
	}
	return results
}

func (s *CursorScanner) scanProjectConfigs(homeDir string) []ScanResult {
	var results []ScanResult
	projectPaths := s.discoverProjects(homeDir)
	seenProjects := make(map[string]bool)
	for _, projectPath := range projectPaths {
		if seenProjects[projectPath] {
			continue
		}
		seenProjects[projectPath] = true
		mcpConfigPath := filepath.Join(projectPath, ".cursor", "mcp.json")
		servers := s.parseConfig(mcpConfigPath)
		if len(servers) > 0 {
			results = append(results, ScanResult{
				IDE:             s.Name(),
				Scope:           "project",
				ConfigPath:      mcpConfigPath,
				ConfigHash:      HashFile(mcpConfigPath),
				ProjectPath:     projectPath,
				DiscoverySource: "cursor_workspaces",
				Servers:         servers,
			})
		}
	}
	return results
}

func (s *CursorScanner) discoverProjects(homeDir string) []string {
	var projects []string
	var storagePaths []string
	switch runtime.GOOS {
	case "darwin":
		storagePaths = []string{
			filepath.Join(homeDir, "Library", "Application Support", "Cursor", "User", "globalStorage", "storage.json"),
		}
	case "linux":
		storagePaths = []string{
			filepath.Join(homeDir, ".config", "Cursor", "User", "globalStorage", "storage.json"),
		}
	case "windows":
		storagePaths = []string{
			filepath.Join(homeDir, "AppData", "Roaming", "Cursor", "User", "globalStorage", "storage.json"),
		}
	}
	for _, storagePath := range storagePaths {
		var storage cursorStorage
		if err := ReadJSONConfig(storagePath, &storage); err != nil {
			continue
		}
		for _, ws := range storage.OpenedPathsList.Workspaces3 {
			if path := UriToPath(ws); path != "" {
				projects = append(projects, path)
			}
		}
		for _, entry := range storage.OpenedPathsList.Entries {
			if path := UriToPath(entry.FolderUri); path != "" {
				projects = append(projects, path)
			}
		}
	}
	return projects
}

func (s *CursorScanner) parseConfig(path string) []map[string]any {
	var config cursorConfig
	if err := ReadJSONConfig(path, &config); err != nil {
		return nil
	}
	names := make([]string, 0, len(config.MCPServers))
	for name := range config.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)

	var servers []map[string]any
	for _, name := range names {
		server := config.MCPServers[name]
		transport, host := s.determineTransport(server)
		serverData := map[string]any{
			"name":      name,
			"transport": transport,
			"host":      host,
		}
		if server.Command != "" {
			serverData["cmd"] = server.Command
		}
		if len(server.Args) > 0 {
			serverData["args"] = ScrubArgs(server.Command, server.Args)
		}
		// Enrich with file metadata for security auditing
		EnrichServerWithFileMetadata(serverData)
		servers = append(servers, serverData)
	}
	return servers
}

func (s *CursorScanner) determineTransport(server cursorServerConfig) (transport, host string) {
	if server.URL != "" {
		return "sse", server.URL
	}
	return "stdio", ""
}
