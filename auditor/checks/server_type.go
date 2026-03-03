// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
)

// Package manager commands (ST-1.1)
var packageManagerCommands = map[string]bool{
	"npx": true, "npm": true, "bunx": true, "bun": true,
	"yarn": true, "pnpm": true,
	"pip": true, "pipx": true, "uvx": true, "uv": true,
}

// Container runtime commands (ST-1.2)
var containerCommands = map[string]bool{
	"docker": true, "podman": true, "nerdctl": true,
}

// Script interpreter commands (ST-1.4)
var interpreterCommands = map[string]bool{
	"python": true, "python3": true, "python2": true,
	"node": true, "nodejs": true,
	"ruby": true, "perl": true,
	"bash": true, "sh": true, "zsh": true,
	"php": true, "lua": true,
}

// Private network CIDRs
var privateNetworks []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid CIDR: " + cidr + ": " + err.Error())
		}
		privateNetworks = append(privateNetworks, ipNet)
	}
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range privateNetworks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// GetCommandBasename returns the lowercased basename of a command, stripping .exe suffix.
func GetCommandBasename(cmd string) string {
	if cmd == "" {
		return ""
	}
	basename := filepath.Base(cmd)
	if strings.HasSuffix(strings.ToLower(basename), ".exe") {
		basename = basename[:len(basename)-4]
	}
	return strings.ToLower(basename)
}

// IsContainerCommand checks if a command basename is a container runtime.
func IsContainerCommand(cmdBasename string) bool {
	return containerCommands[cmdBasename]
}

func isAbsoluteBinaryPath(cmd string) bool {
	if cmd == "" {
		return false
	}
	if strings.HasPrefix(cmd, "/") {
		return true
	}
	if len(cmd) >= 3 && cmd[1] == ':' && (cmd[2] == '/' || cmd[2] == '\\') {
		return true
	}
	return false
}

func detectStdioType(cmd string, args []string) auditor.ServerType {
	basename := GetCommandBasename(cmd)

	if packageManagerCommands[basename] {
		return auditor.ServerTypePackageManager
	}
	if containerCommands[basename] {
		return auditor.ServerTypeContainer
	}
	if interpreterCommands[basename] {
		return auditor.ServerTypeScript
	}
	if isAbsoluteBinaryPath(cmd) {
		return auditor.ServerTypeBinary
	}
	return auditor.ServerTypeUnknownStdio
}

func detectHTTPType(host string) auditor.ServerType {
	if host == "" {
		return auditor.ServerTypeUnreachable
	}

	hostname := extractHostFromURL(host)
	if hostname == "" {
		return auditor.ServerTypeUnknown
	}

	if localhostHosts[strings.ToLower(hostname)] {
		return auditor.ServerTypeLocalHTTP
	}

	if isPrivateIP(hostname) {
		return auditor.ServerTypeLocalHTTP
	}

	// Check if it's a public IP address (not a hostname)
	if ip := net.ParseIP(hostname); ip != nil {
		return auditor.ServerTypePublicHTTP
	}

	// Resolve hostname and check resulting IPs
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return auditor.ServerTypeUnknown
	}
	for _, addr := range addrs {
		if isPrivateIP(addr) {
			return auditor.ServerTypeLocalHTTP
		}
	}
	return auditor.ServerTypePublicHTTP
}

// ServerTypeCheck detects the MCP server type.
type ServerTypeCheck struct{}

func (c *ServerTypeCheck) ID() string           { return "type.detection" }
func (c *ServerTypeCheck) Name() string         { return "Server type detection" }
func (c *ServerTypeCheck) RequiresOnline() bool { return false }

func (c *ServerTypeCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	target := ctx.Target

	var serverType auditor.ServerType
	switch target.Transport {
	case "stdio":
		serverType = detectStdioType(target.Cmd, target.Args)
	case "http", "sse":
		serverType = detectHTTPType(target.Host)
	default:
		serverType = auditor.ServerTypeUnknown
	}

	ctx.SetExtension(auditor.ExtKeyServerType, serverType)

	// Build mcp.command for all STDIO servers
	if target.Transport == "stdio" && target.Cmd != "" {
		parts := append([]string{target.Cmd}, target.Args...)
		ctx.SetExtension("mcp.command", strings.Join(parts, " "))
	}

	// For package manager type, skip — package.distribution handles display
	if serverType == auditor.ServerTypePackageManager {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "Handled by package.distribution",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"detected_type": string(serverType),
				"checklist_id":  "ST-1.1",
			},
		}}
	}

	typeDescriptions := map[auditor.ServerType]string{
		auditor.ServerTypeContainer:    "Container runtime (docker, podman)",
		auditor.ServerTypeBinary:       "Local binary (absolute path executable)",
		auditor.ServerTypeScript:       "Script (interpreter + script file)",
		auditor.ServerTypeUnknownStdio: "Unknown STDIO command",
		auditor.ServerTypeLocalHTTP:    "Local HTTP (localhost or private network)",
		auditor.ServerTypePublicHTTP:   "Publicly available server",
		auditor.ServerTypeUnreachable:  "Unreachable (no valid URL)",
		auditor.ServerTypeUnknown:      "Unknown",
	}

	var severity auditor.Severity
	var displayTitle, message, remediation, checklistID string

	switch serverType {
	case auditor.ServerTypeUnknownStdio:
		severity = auditor.SeverityMedium
		displayTitle = "Unknown server type"
		message = "Command not recognized"
		remediation = "Verify the server command is correct and consider using a recognized MCP server"
		checklistID = "ST-1.5"
	case auditor.ServerTypeUnreachable:
		severity = auditor.SeverityHigh
		displayTitle = "Unreachable server"
		message = "URL missing or invalid"
		remediation = "Provide a valid URL for the HTTP/SSE server"
		checklistID = "ST-2.5"
	case auditor.ServerTypeLocalHTTP:
		severity = auditor.SeverityMedium
		displayTitle = "Local/private network server"
		message = "Local or private network server has limited security guarantees"
		remediation = "Ensure the server is from a trusted source and verify its integrity with the builder of the server"
		checklistID = "ST-2.1"
	case auditor.ServerTypeContainer:
		severity = auditor.SeverityNote
		displayTitle = "Distributed by container runtime"
		checklistID = "ST-1.2"
	case auditor.ServerTypeBinary:
		severity = auditor.SeverityNote
		displayTitle = "Local binary"
		checklistID = "ST-1.3"
	case auditor.ServerTypeScript:
		severity = auditor.SeverityMedium
		displayTitle = "Script-based server"
		checklistID = "ST-1.4"
	case auditor.ServerTypePublicHTTP:
		parsed, _ := url.Parse(target.Host)
		if parsed != nil && parsed.Scheme == "https" {
			severity = auditor.SeverityNote
			displayTitle = "Publicly available server via HTTPS"
			checklistID = "ST-2.3"
		} else {
			severity = auditor.SeverityHigh
			displayTitle = "Publicly available server without HTTPS"
			message = "Server uses unencrypted HTTP connection"
			remediation = "Enable TLS/HTTPS for all public server communications"
			checklistID = "ST-2.3"
		}
	default:
		if target.Transport == "http" || target.Transport == "sse" {
			severity = auditor.SeverityMedium
			displayTitle = "Unresolvable server"
			message = "Could not resolve hostname to determine server type"
			remediation = "Verify the hostname is correct and DNS is configured properly"
			checklistID = "ST-2.x"
		} else {
			severity = auditor.SeverityNote
			displayTitle = typeDescriptions[serverType]
			if displayTitle == "" {
				displayTitle = "Unknown server type"
			}
			checklistID = "ST-1.x"
		}
	}

	return []auditor.Finding{{
		CheckID:     c.ID(),
		Severity:    severity,
		Message:     message,
		ServerName:  target.Name,
		Location:    target.ConfigPath,
		Remediation: remediation,
		Metadata: map[string]any{
			"display_title":      displayTitle,
			"detected_type":      string(serverType),
			"detected_type_display": typeDescriptions[serverType],
			"transport":          target.Transport,
			"command":            target.Cmd,
			"host":               target.Host,
			"checklist_id":       checklistID,
		},
	}}
}
