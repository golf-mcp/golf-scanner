// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"path/filepath"
	"runtime"
	"sort"
)

type AntigravityScanner struct{}

func (s *AntigravityScanner) Name() string {
	return "Antigravity"
}

func (s *AntigravityScanner) Scan() []ScanResult {
	return s.ScanHome("", "")
}

func (s *AntigravityScanner) ScanHome(homeDir, username string) []ScanResult {
	var results []ScanResult
	effectiveHome, err := GetEffectiveHomeDir(homeDir)
	if err != nil {
		return results
	}

	userResults := s.scanUserConfig(effectiveHome)

	for i := range userResults {
		userResults[i].Username = username
	}

	results = append(results, userResults...)
	return results
}

type antigravityConfig struct {
	MCPServers map[string]antigravityServerConfig `json:"mcpServers"`
}

type antigravityServerConfig struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

func (s *AntigravityScanner) scanUserConfig(homeDir string) []ScanResult {
	var results []ScanResult
	var configPaths []string
	switch runtime.GOOS {
	case "windows":
		configPaths = []string{
			filepath.Join(homeDir, ".gemini", "antigravity", "mcp_config.json"),
		}
	default:
		configPaths = []string{
			filepath.Join(homeDir, ".config", "antigravity", "mcp.json"),
			filepath.Join(homeDir, ".gemini", "antigravity", "mcp_config.json"),
		}
	}
	for _, configPath := range configPaths {
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
			break
		}
	}
	return results
}

func (s *AntigravityScanner) parseConfig(path string) []map[string]any {
	var config antigravityConfig
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
		serverData := map[string]any{
			"name":      name,
			"transport": "stdio",
			"host":      "",
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
