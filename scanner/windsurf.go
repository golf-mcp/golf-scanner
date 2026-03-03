// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"path/filepath"
	"runtime"
	"sort"
)

type WindsurfScanner struct{}

func (s *WindsurfScanner) Name() string {
	return "Windsurf"
}

func (s *WindsurfScanner) Scan() []ScanResult {
	return s.ScanHome("", "")
}

func (s *WindsurfScanner) ScanHome(homeDir, username string) []ScanResult {
	var results []ScanResult
	effectiveHome, err := GetEffectiveHomeDir(homeDir)
	if err != nil {
		return results
	}

	primaryResults := s.scanPrimaryConfig(effectiveHome)
	settingsResults := s.scanSettingsConfig(effectiveHome)

	for i := range primaryResults {
		primaryResults[i].Username = username
	}
	for i := range settingsResults {
		settingsResults[i].Username = username
	}

	results = append(results, primaryResults...)
	results = append(results, settingsResults...)
	return results
}

type windsurfConfig struct {
	MCPServers map[string]windsurfServerConfig `json:"mcpServers"`
}

type windsurfServerConfig struct {
	Command     string            `json:"command,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	ServerURL   string            `json:"serverUrl,omitempty"`
	URL         string            `json:"url,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Disabled    bool              `json:"disabled,omitempty"`
	AlwaysAllow []string          `json:"alwaysAllow,omitempty"`
}

type windsurfSettings struct {
	MCP struct {
		Servers map[string]windsurfServerConfig `json:"servers"`
	} `json:"mcp"`
}

func (s *WindsurfScanner) scanPrimaryConfig(homeDir string) []ScanResult {
	var results []ScanResult
	configPath := filepath.Join(homeDir, ".codeium", "windsurf", "mcp_config.json")
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

func (s *WindsurfScanner) scanSettingsConfig(homeDir string) []ScanResult {
	var results []ScanResult
	var settingsPaths []string
	switch runtime.GOOS {
	case "darwin":
		settingsPaths = []string{
			filepath.Join(homeDir, "Library", "Application Support", "Windsurf", "User", "settings.json"),
		}
	case "linux":
		settingsPaths = []string{
			filepath.Join(homeDir, ".config", "Windsurf", "User", "settings.json"),
		}
	case "windows":
		settingsPaths = []string{
			filepath.Join(homeDir, "AppData", "Roaming", "Windsurf", "User", "settings.json"),
			filepath.Join(homeDir, "AppData", "Roaming", "Codeium", "Windsurf", "mcp_config.json"),
		}
	}
	for _, settingsPath := range settingsPaths {
		servers := s.parseSettingsConfig(settingsPath)
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

func (s *WindsurfScanner) parseConfig(path string) []map[string]any {
	var config windsurfConfig
	if err := ReadJSONConfig(path, &config); err != nil {
		return nil
	}
	return s.extractServers(config.MCPServers)
}

func (s *WindsurfScanner) parseSettingsConfig(path string) []map[string]any {
	var settings windsurfSettings
	if err := ReadJSONConfig(path, &settings); err != nil {
		return nil
	}
	return s.extractServers(settings.MCP.Servers)
}

func (s *WindsurfScanner) extractServers(servers map[string]windsurfServerConfig) []map[string]any {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	var result []map[string]any
	for _, name := range names {
		server := servers[name]
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
		result = append(result, serverData)
	}
	return result
}

func (s *WindsurfScanner) determineTransport(server windsurfServerConfig) (transport, host string) {
	if server.ServerURL != "" {
		return "http", server.ServerURL
	}
	if server.URL != "" {
		return "http", server.URL
	}
	return "stdio", ""
}
