// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"path/filepath"
	"runtime"
	"sort"
)

type KiroScanner struct{}

func (s *KiroScanner) Name() string {
	return "Kiro"
}

func (s *KiroScanner) Scan() []ScanResult {
	return s.ScanHome("", "")
}

func (s *KiroScanner) ScanHome(homeDir, username string) []ScanResult {
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

type kiroConfig struct {
	MCPServers map[string]kiroServerConfig `json:"mcpServers"`
}

type kiroServerConfig struct {
	Command  string            `json:"command,omitempty"`
	Args     []string          `json:"args,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	URL      string            `json:"url,omitempty"`
	Disabled bool              `json:"disabled,omitempty"`
}

type kiroStorage struct {
	BackupWorkspaces struct {
		Folders []struct {
			FolderUri string `json:"folderUri"`
		} `json:"folders"`
	} `json:"backupWorkspaces"`
	ProfileAssociations struct {
		Workspaces map[string]string `json:"workspaces"`
	} `json:"profileAssociations"`
}

func (s *KiroScanner) scanUserConfig(homeDir string) []ScanResult {
	var results []ScanResult
	configPath := filepath.Join(homeDir, ".kiro", "settings", "mcp.json")
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

func (s *KiroScanner) scanProjectConfigs(homeDir string) []ScanResult {
	var results []ScanResult
	projectPaths := s.discoverProjects(homeDir)
	seenProjects := make(map[string]bool)
	for _, projectPath := range projectPaths {
		if seenProjects[projectPath] {
			continue
		}
		seenProjects[projectPath] = true
		mcpConfigPath := filepath.Join(projectPath, ".kiro", "settings", "mcp.json")
		servers := s.parseConfig(mcpConfigPath)
		if len(servers) > 0 {
			results = append(results, ScanResult{
				IDE:             s.Name(),
				Scope:           "project",
				ConfigPath:      mcpConfigPath,
				ConfigHash:      HashFile(mcpConfigPath),
				ProjectPath:     projectPath,
				DiscoverySource: "kiro_workspaces",
				Servers:         servers,
			})
		}
	}
	return results
}

func (s *KiroScanner) discoverProjects(homeDir string) []string {
	var projects []string
	var storagePaths []string
	switch runtime.GOOS {
	case "darwin":
		storagePaths = []string{
			filepath.Join(homeDir, "Library", "Application Support", "Kiro", "User", "globalStorage", "storage.json"),
		}
	case "linux":
		storagePaths = []string{
			filepath.Join(homeDir, ".config", "Kiro", "User", "globalStorage", "storage.json"),
		}
	case "windows":
		storagePaths = []string{
			filepath.Join(homeDir, "AppData", "Roaming", "Kiro", "User", "globalStorage", "storage.json"),
		}
	}
	for _, storagePath := range storagePaths {
		var storage kiroStorage
		if err := ReadJSONConfig(storagePath, &storage); err != nil {
			continue
		}
		for _, folder := range storage.BackupWorkspaces.Folders {
			if path := UriToPath(folder.FolderUri); path != "" {
				projects = append(projects, path)
			}
		}
		for uri := range storage.ProfileAssociations.Workspaces {
			if path := UriToPath(uri); path != "" {
				projects = append(projects, path)
			}
		}
	}
	return projects
}

func (s *KiroScanner) parseConfig(path string) []map[string]any {
	var config kiroConfig
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
		if server.Disabled {
			continue
		}
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

func (s *KiroScanner) determineTransport(server kiroServerConfig) (transport, host string) {
	if server.URL != "" {
		return "http", server.URL
	}
	return "stdio", ""
}
