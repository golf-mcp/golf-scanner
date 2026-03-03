// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/tailscale/hujson"
)

type VSCodeScanner struct{}

func (s *VSCodeScanner) Name() string {
	return "VS Code"
}

func (s *VSCodeScanner) Scan() []ScanResult {
	return s.ScanHome("", "")
}

func (s *VSCodeScanner) ScanHome(homeDir, username string) []ScanResult {
	var results []ScanResult
	effectiveHome, err := GetEffectiveHomeDir(homeDir)
	if err != nil {
		return results
	}

	userSettingsResults := s.scanUserSettings(effectiveHome)
	userMCPResults := s.scanUserMCPFile(effectiveHome)
	projectResults := s.scanProjectConfigs(effectiveHome)
	workspaceResults := s.scanWorkspaceFiles(effectiveHome)

	for i := range userSettingsResults {
		userSettingsResults[i].Username = username
	}
	for i := range userMCPResults {
		userMCPResults[i].Username = username
	}
	for i := range projectResults {
		projectResults[i].Username = username
	}
	for i := range workspaceResults {
		workspaceResults[i].Username = username
	}

	results = append(results, userSettingsResults...)
	results = append(results, userMCPResults...)
	results = append(results, projectResults...)
	results = append(results, workspaceResults...)
	return results
}

type vscodeConfig struct {
	Inputs  []vscodeInputConfig           `json:"inputs,omitempty"`
	Servers map[string]vscodeServerConfig `json:"servers"`
}

// vscodeMCPConfig handles the "mcp.servers" format used in VS Code's mcp.json
type vscodeMCPConfig struct {
	MCPServers map[string]vscodeServerConfig `json:"mcp.servers"`
}

type vscodeInputConfig struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Password    bool   `json:"password,omitempty"`
}

type vscodeServerConfig struct {
	Type    string            `json:"type,omitempty"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	EnvFile string            `json:"envFile,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type vscodeUserSettings struct {
	MCP struct {
		Inputs  []vscodeInputConfig           `json:"inputs,omitempty"`
		Servers map[string]vscodeServerConfig `json:"servers"`
	} `json:"mcp"`
	Chat struct {
		MCP struct {
			Discovery struct {
				Enabled bool `json:"enabled"`
			} `json:"discovery"`
		} `json:"mcp"`
	} `json:"chat"`
}

type vscodeWorkspaceFile struct {
	Folders []struct {
		Path string `json:"path"`
	} `json:"folders"`
	Settings struct {
		MCP struct {
			Inputs  []vscodeInputConfig           `json:"inputs,omitempty"`
			Servers map[string]vscodeServerConfig `json:"servers"`
		} `json:"mcp"`
	} `json:"settings"`
}

// vscodeStorage is an alias for the shared ideStorage type.
type vscodeStorage = ideStorage

func (s *VSCodeScanner) scanUserSettings(homeDir string) []ScanResult {
	var results []ScanResult
	var settingsPaths []string
	switch runtime.GOOS {
	case "darwin":
		settingsPaths = []string{
			filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "settings.json"),
			filepath.Join(homeDir, "Library", "Application Support", "Code - Insiders", "User", "settings.json"),
		}
	case "linux":
		settingsPaths = []string{
			filepath.Join(homeDir, ".config", "Code", "User", "settings.json"),
			filepath.Join(homeDir, ".config", "Code - Insiders", "User", "settings.json"),
		}
	case "windows":
		settingsPaths = []string{
			filepath.Join(homeDir, "AppData", "Roaming", "Code", "User", "settings.json"),
			filepath.Join(homeDir, "AppData", "Roaming", "Code - Insiders", "User", "settings.json"),
		}
	}
	for _, settingsPath := range settingsPaths {
		servers := s.parseUserSettings(settingsPath)
		if len(servers) > 0 {
			results = append(results, ScanResult{
				IDE:             s.Name(),
				Scope:           "user",
				ConfigPath:      settingsPath,
				ConfigHash:      HashFile(settingsPath),
				DiscoverySource: "direct",
				Servers:         servers,
			})
		}
	}
	return results
}

func (s *VSCodeScanner) scanUserMCPFile(homeDir string) []ScanResult {
	var results []ScanResult
	var mcpPaths []string
	switch runtime.GOOS {
	case "darwin":
		mcpPaths = []string{
			filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "mcp.json"),
			filepath.Join(homeDir, "Library", "Application Support", "Code - Insiders", "User", "mcp.json"),
		}
	case "linux":
		mcpPaths = []string{
			filepath.Join(homeDir, ".config", "Code", "User", "mcp.json"),
			filepath.Join(homeDir, ".config", "Code - Insiders", "User", "mcp.json"),
		}
	case "windows":
		mcpPaths = []string{
			filepath.Join(homeDir, "AppData", "Roaming", "Code", "User", "mcp.json"),
			filepath.Join(homeDir, "AppData", "Roaming", "Code - Insiders", "User", "mcp.json"),
		}
	}
	for _, mcpPath := range mcpPaths {
		servers := s.parseVSCodeConfig(mcpPath)
		if len(servers) > 0 {
			results = append(results, ScanResult{
				IDE:             s.Name(),
				Scope:           "user",
				ConfigPath:      mcpPath,
				ConfigHash:      HashFile(mcpPath),
				DiscoverySource: "direct",
				Servers:         servers,
			})
		}
	}
	return results
}

func (s *VSCodeScanner) parseUserSettings(path string) []map[string]any {
	var settings vscodeUserSettings
	if err := ReadJSONConfig(path, &settings); err != nil {
		return nil
	}
	names := make([]string, 0, len(settings.MCP.Servers))
	for name := range settings.MCP.Servers {
		names = append(names, name)
	}
	sort.Strings(names)

	var servers []map[string]any
	for _, name := range names {
		servers = append(servers, s.serverToMap(name, settings.MCP.Servers[name]))
	}
	return servers
}

func (s *VSCodeScanner) serverToMap(name string, server vscodeServerConfig) map[string]any {
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
	return serverData
}

func (s *VSCodeScanner) determineTransport(server vscodeServerConfig) (transport, host string) {
	if server.Type != "" {
		switch server.Type {
		case "sse":
			return "sse", server.URL
		case "http":
			return "http", server.URL
		default:
			return "stdio", ""
		}
	}
	if server.URL != "" {
		return "sse", server.URL
	}
	return "stdio", ""
}

func (s *VSCodeScanner) scanProjectConfigs(homeDir string) []ScanResult {
	var results []ScanResult
	projectPaths := s.discoverProjects(homeDir)
	seenProjects := make(map[string]bool)
	for _, projectPath := range projectPaths {
		if seenProjects[projectPath] {
			continue
		}
		seenProjects[projectPath] = true
		mcpConfigPath := filepath.Join(projectPath, ".vscode", "mcp.json")
		servers := s.parseVSCodeConfig(mcpConfigPath)
		if len(servers) > 0 {
			results = append(results, ScanResult{
				IDE:             s.Name(),
				Scope:           "project",
				ConfigPath:      mcpConfigPath,
				ConfigHash:      HashFile(mcpConfigPath),
				ProjectPath:     projectPath,
				DiscoverySource: "vscode_workspaces",
				Servers:         servers,
			})
		}
	}
	return results
}

func (s *VSCodeScanner) scanWorkspaceFiles(homeDir string) []ScanResult {
	var results []ScanResult
	projectPaths := s.discoverProjects(homeDir)
	seenWorkspaces := make(map[string]bool)
	for _, projectPath := range projectPaths {
		entries, err := os.ReadDir(projectPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".code-workspace") {
				continue
			}
			workspacePath := filepath.Join(projectPath, entry.Name())
			if seenWorkspaces[workspacePath] {
				continue
			}
			seenWorkspaces[workspacePath] = true
			servers := s.parseWorkspaceFile(workspacePath)
			if len(servers) > 0 {
				results = append(results, ScanResult{
					IDE:             s.Name(),
					Scope:           "workspace",
					ConfigPath:      workspacePath,
					ConfigHash:      HashFile(workspacePath),
					ProjectPath:     projectPath,
					DiscoverySource: "workspace_file",
					Servers:         servers,
				})
			}
		}
	}
	return results
}

func (s *VSCodeScanner) parseWorkspaceFile(path string) []map[string]any {
	var workspace vscodeWorkspaceFile
	if err := ReadJSONConfig(path, &workspace); err != nil {
		return nil
	}
	names := make([]string, 0, len(workspace.Settings.MCP.Servers))
	for name := range workspace.Settings.MCP.Servers {
		names = append(names, name)
	}
	sort.Strings(names)

	var servers []map[string]any
	for _, name := range names {
		servers = append(servers, s.serverToMap(name, workspace.Settings.MCP.Servers[name]))
	}
	return servers
}

func (s *VSCodeScanner) discoverProjects(homeDir string) []string {
	seen := make(map[string]bool)
	var projects []string
	var storagePaths []string
	switch runtime.GOOS {
	case "darwin":
		storagePaths = []string{
			filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "globalStorage", "storage.json"),
			filepath.Join(homeDir, "Library", "Application Support", "Code - Insiders", "User", "globalStorage", "storage.json"),
		}
	case "linux":
		storagePaths = []string{
			filepath.Join(homeDir, ".config", "Code", "User", "globalStorage", "storage.json"),
			filepath.Join(homeDir, ".config", "Code - Insiders", "User", "globalStorage", "storage.json"),
		}
	case "windows":
		storagePaths = []string{
			filepath.Join(homeDir, "AppData", "Roaming", "Code", "User", "globalStorage", "storage.json"),
			filepath.Join(homeDir, "AppData", "Roaming", "Code - Insiders", "User", "globalStorage", "storage.json"),
		}
	}
	for _, storagePath := range storagePaths {
		var storage vscodeStorage
		if err := ReadJSONConfig(storagePath, &storage); err != nil {
			continue
		}
		for _, ws := range storage.OpenedPathsList.Workspaces3 {
			if path := UriToPath(ws); path != "" && !seen[path] {
				seen[path] = true
				projects = append(projects, path)
			}
		}
		for _, entry := range storage.OpenedPathsList.Entries {
			if path := UriToPath(entry.FolderUri); path != "" && !seen[path] {
				seen[path] = true
				projects = append(projects, path)
			}
		}
	}
	return projects
}

func (s *VSCodeScanner) parseVSCodeConfig(path string) []map[string]any {
	// Read and standardize JSON once
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	standardized, err := hujson.Standardize(data)
	if err != nil {
		standardized = data // fallback to raw
	}

	// Try standard format first: { "servers": { ... } }
	var config vscodeConfig
	if err := json.Unmarshal(standardized, &config); err == nil && len(config.Servers) > 0 {
		names := make([]string, 0, len(config.Servers))
		for name := range config.Servers {
			names = append(names, name)
		}
		sort.Strings(names)

		var servers []map[string]any
		for _, name := range names {
			servers = append(servers, s.serverToMap(name, config.Servers[name]))
		}
		return servers
	}

	// Try alternative format: { "mcp.servers": { ... } }
	var mcpConfig vscodeMCPConfig
	if err := json.Unmarshal(standardized, &mcpConfig); err == nil && len(mcpConfig.MCPServers) > 0 {
		names := make([]string, 0, len(mcpConfig.MCPServers))
		for name := range mcpConfig.MCPServers {
			names = append(names, name)
		}
		sort.Strings(names)

		var servers []map[string]any
		for _, name := range names {
			servers = append(servers, s.serverToMap(name, mcpConfig.MCPServers[name]))
		}
		return servers
	}

	return nil
}
