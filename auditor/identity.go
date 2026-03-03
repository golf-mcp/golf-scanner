// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// ServerIdentity uniquely identifies an MCP server across IDE configurations.
type ServerIdentity struct {
	Type string `json:"type"` // "url", "package", "container", "command"
	Key  string `json:"key"`  // e.g., "npm:@modelcontextprotocol/server-github"
}

// IdentityKey returns the composite string key for map lookups: "type:key".
func (id ServerIdentity) IdentityKey() string {
	return id.Type + ":" + id.Key
}

// Package manager command sets for identity computation.
var (
	identityNpmCommands       = map[string]bool{"npx": true, "npm": true, "bunx": true, "bun": true, "yarn": true, "pnpm": true}
	identityPypiCommands      = map[string]bool{"pip": true, "pipx": true, "uvx": true, "uv": true}
	identityContainerCommands = map[string]bool{"docker": true, "podman": true, "nerdctl": true}
)

// npm subcommands to skip when extracting package name.
var npmSubcommands = map[string]bool{"exec": true, "run": true, "x": true, "dlx": true}

var identityPypiVersionRe = regexp.MustCompile(`^([a-zA-Z0-9._-]+)(?:\[[^\]]+\])?(?:@|[<>=!~]=?)`)

// ComputeIdentity computes a stable identity for a server configuration.
// Priority: URL > package > container > command.
// Mirrors the Python API's compute_server_identity() in inventory_identity.py.
func ComputeIdentity(transport, host, cmd string, args []string) ServerIdentity {
	// Priority 1: URL-based servers (HTTP/SSE)
	if (transport == "http" || transport == "sse") && host != "" {
		return ServerIdentity{Type: "url", Key: host}
	}

	// For STDIO servers, classify by command
	cmdBase := CommandBasename(cmd)
	if cmdBase == "" {
		if cmd != "" {
			return ServerIdentity{Type: "command", Key: cmd}
		}
		return ServerIdentity{Type: "command", Key: "unknown"}
	}

	// Priority 2: Package manager (npm ecosystem)
	if identityNpmCommands[cmdBase] {
		name := extractNpmPackageName(args)
		if name != "" && name != "****" {
			return ServerIdentity{Type: "package", Key: "npm:" + name}
		}
		return ServerIdentity{Type: "command", Key: cmd}
	}

	// Priority 2: Package manager (PyPI ecosystem)
	if identityPypiCommands[cmdBase] {
		name := extractPypiPackageName(args)
		if name != "" && name != "****" {
			return ServerIdentity{Type: "package", Key: "pypi:" + name}
		}
		return ServerIdentity{Type: "command", Key: cmd}
	}

	// Priority 3: Container
	if identityContainerCommands[cmdBase] {
		image := extractContainerImage(args)
		if image != "" && image != "****" {
			return ServerIdentity{Type: "container", Key: "docker:" + image}
		}
		return ServerIdentity{Type: "command", Key: cmd}
	}

	// Priority 4: Fallback to raw command
	return ServerIdentity{Type: "command", Key: cmd}
}

// ComputeDisplayName returns a human-readable name for a server.
// Uses the package/image/URL as the display name rather than the user-given name.
// Mirrors the Python API's compute_display_name() in display_name.py.
func ComputeDisplayName(transport, host, cmd string, args []string) string {
	// HTTP/SSE: parse URL for clean hostname + path
	if transport == "http" || transport == "sse" {
		if host == "" {
			return "unknown"
		}
		rawURL := host
		if !strings.Contains(rawURL, "://") {
			rawURL = "https://" + rawURL
		}
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return host
		}
		hostname := parsed.Hostname()
		if hostname == "" {
			return host
		}
		path := strings.TrimRight(parsed.Path, "/")
		path = strings.TrimSuffix(path, "/mcp")
		if path != "" {
			return hostname + path
		}
		return hostname
	}

	// STDIO: try to extract meaningful name
	cmdBase := CommandBasename(cmd)
	if cmdBase == "" {
		if cmd != "" {
			return cmd
		}
		return "unknown"
	}

	// Container: extract image name
	if identityContainerCommands[cmdBase] {
		image := extractContainerImage(args)
		if image != "" && image != "****" {
			return image
		}
		return cmdBase
	}

	// Package manager (npm): extract package name
	if identityNpmCommands[cmdBase] {
		name := extractNpmPackageName(args)
		if name != "" && name != "****" {
			return name
		}
	}

	// Package manager (PyPI): extract package name
	if identityPypiCommands[cmdBase] {
		name := extractPypiPackageName(args)
		if name != "" && name != "****" {
			return name
		}
	}

	// For interpreters and other commands: first non-flag arg or basename
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") && arg != "****" {
			return arg
		}
	}
	return cmdBase
}

// CommandBasename returns the lowercased basename of a command, stripping .exe suffix.
func CommandBasename(cmd string) string {
	if cmd == "" {
		return ""
	}
	basename := filepath.Base(cmd)
	if strings.HasSuffix(strings.ToLower(basename), ".exe") {
		basename = basename[:len(basename)-4]
	}
	return strings.ToLower(basename)
}

// extractNpmPackageName extracts npm package name from args, stripping version specifiers.
func extractNpmPackageName(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if npmSubcommands[arg] {
			continue
		}
		return stripNpmVersion(arg)
	}
	return ""
}

// stripNpmVersion strips version specifier from npm package name.
func stripNpmVersion(pkg string) string {
	if strings.HasPrefix(pkg, "@") {
		slashIdx := strings.Index(pkg, "/")
		if slashIdx != -1 {
			atIdx := strings.Index(pkg[slashIdx+1:], "@")
			if atIdx != -1 {
				return pkg[:slashIdx+1+atIdx]
			}
		}
	} else {
		atIdx := strings.Index(pkg, "@")
		if atIdx != -1 {
			return pkg[:atIdx]
		}
	}
	return pkg
}

// extractPypiPackageName extracts PyPI package name from args.
func extractPypiPackageName(args []string) string {
	skipNext := false
	fromNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if fromNext {
			return stripPypiVersion(arg)
		}
		if strings.HasPrefix(arg, "--from=") {
			return stripPypiVersion(strings.TrimPrefix(arg, "--from="))
		}
		if arg == "--from" {
			fromNext = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if arg == "--python" || arg == "--pip-args" {
				skipNext = true
			}
			continue
		}
		if arg == "run" {
			continue
		}
		return stripPypiVersion(arg)
	}
	return ""
}

// stripPypiVersion strips version specifier from PyPI package name.
func stripPypiVersion(pkg string) string {
	if m := identityPypiVersionRe.FindStringSubmatch(pkg); m != nil {
		return m[1]
	}
	return pkg
}

// extractContainerImage extracts the container image reference from docker/podman args.
// Simplified version of the full parser in checks/container_image.go.
func extractContainerImage(args []string) string {
	if len(args) == 0 {
		return ""
	}

	subcommands := map[string]bool{"run": true, "create": true}

	flagsWithValues := map[string]bool{
		"-v": true, "--volume": true, "-e": true, "--env": true,
		"-p": true, "--publish": true, "-w": true, "--workdir": true,
		"-u": true, "--user": true, "-m": true, "--memory": true,
		"--name": true, "--network": true, "--entrypoint": true,
		"--platform": true, "--cpus": true, "--cap-add": true,
		"--cap-drop": true, "-l": true, "--label": true,
		"--mount": true, "--device": true, "--security-opt": true,
		"--ulimit": true, "--pid": true, "--ipc": true,
		"--uts": true, "--cgroupns": true, "--hostname": true,
		"-h": true, "--dns": true, "--dns-search": true,
		"--add-host": true, "--expose": true, "--link": true,
		"--log-driver": true, "--log-opt": true, "--restart": true,
		"--stop-signal": true, "--stop-timeout": true, "--shm-size": true,
		"--tmpfs": true, "--group-add": true, "--userns": true,
		"--runtime": true, "--annotation": true, "--env-file": true,
		"--cidfile": true, "--health-cmd": true, "--health-interval": true,
		"--health-retries": true, "--health-start-period": true,
		"--health-timeout": true, "--cgroup-parent": true,
		"--cpu-period": true, "--cpu-quota": true, "--cpu-shares": true,
		"-c": true, "--cpuset-cpus": true, "--cpuset-mems": true,
		"--gpus": true, "--ip": true, "--ip6": true,
		"--mac-address": true, "--memory-swap": true, "--pids-limit": true,
		"--sysctl": true,
	}

	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		if subcommands[strings.ToLower(arg)] {
			continue
		}

		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "=") {
				continue
			}
			if flagsWithValues[arg] {
				skipNext = true
			}
			continue
		}

		return arg
	}

	return ""
}
