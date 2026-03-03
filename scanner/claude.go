// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"sort"
)

type ClaudeScanner struct{}

func (s *ClaudeScanner) Name() string {
	return "Claude Code"
}

func (s *ClaudeScanner) Scan() []ScanResult {
	// Delegate to ScanHome with empty values for backward compatibility
	return s.ScanHome("", "")
}

func (s *ClaudeScanner) ScanHome(homeDir, username string) []ScanResult {
	var results []ScanResult
	effectiveHome, err := GetEffectiveHomeDir(homeDir)
	if err != nil {
		return results
	}

	// Run scans
	userResults := s.scanUserConfigs(effectiveHome)
	projectResults := s.scanClaudeProjects(effectiveHome)

	// Add username to all results
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

func (s *ClaudeScanner) scanClaudeProjects(homeDir string) []ScanResult {
	var results []ScanResult
	userSettings := s.loadUserSettings(homeDir)

	// Track which projects we've already scanned
	seenProjects := make(map[string]bool)

	// Method 1: Enumerate ~/.claude/projects/ directories (existing behavior)
	projectsDir := filepath.Join(homeDir, ".claude", "projects")
	entries, err := os.ReadDir(projectsDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			projectDir := filepath.Join(projectsDir, entry.Name())
			projectPath := getProjectPathFromIndex(projectDir)
			if projectPath == "" {
				continue
			}
			if seenProjects[projectPath] {
				continue
			}
			seenProjects[projectPath] = true
			results = append(results, s.scanProjectForMCP(projectPath, homeDir, userSettings)...)
		}
	}

	// Method 2: Directly iterate over projects in ~/.claude.json
	// This catches projects that have MCP servers configured but no session index
	if userSettings != nil {
		for projectPath, projectSettings := range userSettings.Projects {
			if seenProjects[projectPath] {
				continue
			}
			seenProjects[projectPath] = true

			// Only add if this project has MCP servers defined
			if len(projectSettings.MCPServers) > 0 {
				servers := s.convertServersToMap(projectSettings.MCPServers)
				if len(servers) > 0 {
					userSettingsPath := filepath.Join(homeDir, ".claude.json")
					results = append(results, ScanResult{
						IDE:             s.Name(),
						Scope:           "local",
						ConfigPath:      userSettingsPath,
						ConfigHash:      HashFile(userSettingsPath),
						ProjectPath:     projectPath,
						DiscoverySource: "claude_user_settings",
						Servers:         servers,
					})
				}
			}
		}
	}

	return results
}

func (s *ClaudeScanner) loadUserSettings(homeDir string) *claudeUserSettings {
	userSettingsPath := filepath.Join(homeDir, ".claude.json")
	var settings claudeUserSettings
	if err := ReadJSONConfig(userSettingsPath, &settings); err != nil {
		return nil
	}
	return &settings
}

func getProjectPathFromIndex(projectDir string) string {
	indexPath := filepath.Join(projectDir, "sessions-index.json")
	var index sessionsIndex
	if err := ReadJSONConfig(indexPath, &index); err != nil {
		return ""
	}
	if len(index.Entries) > 0 {
		return index.Entries[0].ProjectPath
	}
	return ""
}

func (s *ClaudeScanner) scanProjectForMCP(projectPath, homeDir string, userSettings *claudeUserSettings) []ScanResult {
	var results []ScanResult
	mcpJsonPath := filepath.Join(projectPath, ".mcp.json")
	if servers := s.parseConfig(mcpJsonPath); len(servers) > 0 {
		results = append(results, ScanResult{
			IDE:             s.Name(),
			Scope:           "project",
			ConfigPath:      mcpJsonPath,
			ConfigHash:      HashFile(mcpJsonPath),
			ProjectPath:     projectPath,
			DiscoverySource: "claude_projects",
			Servers:         servers,
		})
	}
	claudeMcpPath := filepath.Join(projectPath, ".claude", "mcp.json")
	if servers := s.parseConfig(claudeMcpPath); len(servers) > 0 {
		results = append(results, ScanResult{
			IDE:             s.Name(),
			Scope:           "project",
			ConfigPath:      claudeMcpPath,
			ConfigHash:      HashFile(claudeMcpPath),
			ProjectPath:     projectPath,
			DiscoverySource: "claude_projects",
			Servers:         servers,
		})
	}
	if userSettings != nil {
		if projectSettings, ok := userSettings.Projects[projectPath]; ok {
			if len(projectSettings.MCPServers) > 0 {
				servers := s.convertServersToMap(projectSettings.MCPServers)
				if len(servers) > 0 {
					userSettingsPath := filepath.Join(homeDir, ".claude.json")
					results = append(results, ScanResult{
						IDE:             s.Name(),
						Scope:           "local",
						ConfigPath:      userSettingsPath,
						ConfigHash:      HashFile(userSettingsPath),
						ProjectPath:     projectPath,
						DiscoverySource: "claude_user_settings",
						Servers:         servers,
					})
				}
			}
		}
	}
	return results
}

func (s *ClaudeScanner) convertServersToMap(mcpServers map[string]claudeServerConfig) []map[string]any {
	names := make([]string, 0, len(mcpServers))
	for name := range mcpServers {
		names = append(names, name)
	}
	sort.Strings(names)
	var servers []map[string]any
	for _, name := range names {
		server := mcpServers[name]
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

type claudeCodeConfig struct {
	MCPServers map[string]claudeServerConfig `json:"mcpServers"`
}

type claudeServerConfig struct {
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	URL     string   `json:"url,omitempty"`
	Type    string   `json:"type,omitempty"`
}

type claudeUserSettings struct {
	Projects map[string]claudeProjectSettings `json:"projects"`
}

type claudeProjectSettings struct {
	MCPServers map[string]claudeServerConfig `json:"mcpServers"`
}

type sessionsIndex struct {
	Version int                  `json:"version"`
	Entries []sessionsIndexEntry `json:"entries"`
}

type sessionsIndexEntry struct {
	ProjectPath string `json:"projectPath"`
}

func (s *ClaudeScanner) scanUserConfigs(homeDir string) []ScanResult {
	var results []ScanResult
	userConfigPaths := []string{
		filepath.Join(homeDir, ".config", "claude", "claude_desktop_config.json"),
		filepath.Join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(homeDir, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
	}
	for _, configPath := range userConfigPaths {
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
	}
	return results
}

func (s *ClaudeScanner) parseConfig(path string) []map[string]any {
	var config claudeCodeConfig
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

func (s *ClaudeScanner) determineTransport(server claudeServerConfig) (transport, host string) {
	if server.Type == "sse" {
		return "sse", server.URL
	}
	if server.URL != "" {
		return "http", server.URL
	}
	return "stdio", ""
}
