// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"path/filepath"
	"runtime"
	"sort"
)

type GeminiScanner struct{}

func (s *GeminiScanner) Name() string {
	return "Gemini CLI"
}

func (s *GeminiScanner) Scan() []ScanResult {
	return s.ScanHome("", "")
}

func (s *GeminiScanner) ScanHome(homeDir, username string) []ScanResult {
	var results []ScanResult
	effectiveHome, err := GetEffectiveHomeDir(homeDir)
	if err != nil {
		return results
	}

	userResults := s.scanUserSettings(effectiveHome)
	// System defaults are not user-specific, so no username
	systemResults := s.scanSystemDefaults()
	projectResults := s.scanProjectSettings(effectiveHome)

	for i := range userResults {
		userResults[i].Username = username
	}
	// Note: systemResults intentionally left without username as they're system-level
	for i := range projectResults {
		projectResults[i].Username = username
	}

	results = append(results, userResults...)
	results = append(results, systemResults...)
	results = append(results, projectResults...)
	return results
}

type geminiSettings struct {
	MCPServers map[string]geminiServerConfig `json:"mcpServers"`
}

type geminiServerConfig struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Cwd     string            `json:"cwd,omitempty"`
	URL     string            `json:"url,omitempty"`
	HttpURL string            `json:"httpUrl,omitempty"`
}

// geminiStorage is an alias for the shared ideStorage type.
type geminiStorage = ideStorage

func (s *GeminiScanner) scanUserSettings(homeDir string) []ScanResult {
	var results []ScanResult
	configPath := filepath.Join(homeDir, ".gemini", "settings.json")
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

func (s *GeminiScanner) scanSystemDefaults() []ScanResult {
	var results []ScanResult
	var systemPath string
	switch runtime.GOOS {
	case "darwin":
		systemPath = "/Library/Application Support/GeminiCli/system-defaults.json"
	case "linux":
		systemPath = "/etc/gemini-cli/system-defaults.json"
	case "windows":
		systemPath = "C:\\ProgramData\\gemini-cli\\system-defaults.json"
	}
	if systemPath == "" {
		return results
	}
	servers := s.parseConfig(systemPath)
	if len(servers) > 0 {
		results = append(results, ScanResult{
			IDE:             s.Name(),
			Scope:           "system",
			ConfigPath:      systemPath,
			ConfigHash:      HashFile(systemPath),
			DiscoverySource: "direct",
			Servers:         servers,
		})
	}
	return results
}

func (s *GeminiScanner) scanProjectSettings(homeDir string) []ScanResult {
	var results []ScanResult
	projectPaths := s.discoverProjects(homeDir)
	seenProjects := make(map[string]bool)
	for _, projectPath := range projectPaths {
		if seenProjects[projectPath] {
			continue
		}
		seenProjects[projectPath] = true
		configPath := filepath.Join(projectPath, ".gemini", "settings.json")
		servers := s.parseConfig(configPath)
		if len(servers) > 0 {
			results = append(results, ScanResult{
				IDE:             s.Name(),
				Scope:           "project",
				ConfigPath:      configPath,
				ConfigHash:      HashFile(configPath),
				ProjectPath:     projectPath,
				DiscoverySource: "gemini_project",
				Servers:         servers,
			})
		}
	}
	return results
}

// discoverProjects finds project paths using VS Code's workspace storage.
// Gemini Code Assist uses VS Code's workspace storage for project tracking.
// This is intentional as Gemini operates as a VS Code extension.
func (s *GeminiScanner) discoverProjects(homeDir string) []string {
	var projects []string
	var storagePaths []string
	switch runtime.GOOS {
	case "darwin":
		storagePaths = []string{
			filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "globalStorage", "storage.json"),
		}
	case "linux":
		storagePaths = []string{
			filepath.Join(homeDir, ".config", "Code", "User", "globalStorage", "storage.json"),
		}
	case "windows":
		storagePaths = []string{
			filepath.Join(homeDir, "AppData", "Roaming", "Code", "User", "globalStorage", "storage.json"),
		}
	}
	for _, storagePath := range storagePaths {
		var storage geminiStorage
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

func (s *GeminiScanner) parseConfig(path string) []map[string]any {
	var settings geminiSettings
	if err := ReadJSONConfig(path, &settings); err != nil {
		return nil
	}
	names := make([]string, 0, len(settings.MCPServers))
	for name := range settings.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)

	var servers []map[string]any
	for _, name := range names {
		server := settings.MCPServers[name]
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
		if server.Cwd != "" {
			serverData["cwd"] = server.Cwd
		}
		// Enrich with file metadata for security auditing
		EnrichServerWithFileMetadata(serverData)
		servers = append(servers, serverData)
	}
	return servers
}

func (s *GeminiScanner) determineTransport(server geminiServerConfig) (transport, host string) {
	if server.HttpURL != "" {
		return "http", server.HttpURL
	}
	if server.URL != "" {
		return "sse", server.URL
	}
	return "stdio", ""
}
