// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
)

// Package manager command sets for ecosystem detection.
var npmCommands = map[string]bool{"npx": true, "npm": true, "bunx": true, "bun": true, "yarn": true, "pnpm": true}
var pypiCommands = map[string]bool{"pip": true, "pipx": true, "uvx": true, "uv": true}

// isPackageManager checks if the context target is a package manager server.
func isPackageManager(ctx *auditor.AuditContext) bool {
	return ctx.GetServerType() == auditor.ServerTypePackageManager
}

// PackageInfo holds extracted package name and ecosystem.
type PackageInfo struct {
	Name      string
	Ecosystem string
}

// ExtractPackageInfo extracts package name and ecosystem from server config.
func ExtractPackageInfo(target auditor.ServerInventory) *PackageInfo {
	cmd := strings.ToLower(filepath.Base(target.Cmd))
	if strings.HasSuffix(cmd, ".exe") {
		cmd = cmd[:len(cmd)-4]
	}

	if npmCommands[cmd] {
		name := extractNpmPackage(target.Args)
		if name != "" {
			return &PackageInfo{Name: name, Ecosystem: "npm"}
		}
	}
	if pypiCommands[cmd] {
		name := extractPyPIPackage(target.Args)
		if name != "" {
			return &PackageInfo{Name: name, Ecosystem: "PyPI"}
		}
	}
	return nil
}

// extractNpmPackage extracts npm package name from args, stripping version specifiers.
func extractNpmPackage(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if arg == "exec" || arg == "run" || arg == "x" || arg == "dlx" {
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

// extractPyPIPackage extracts PyPI package name from args.
func extractPyPIPackage(args []string) string {
	skipNext := false
	fromNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if fromNext {
			return stripPyPIVersion(arg)
		}
		if strings.HasPrefix(arg, "--from=") {
			return stripPyPIVersion(strings.TrimPrefix(arg, "--from="))
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
		return stripPyPIVersion(arg)
	}
	return ""
}

var pypiVersionRe = regexp.MustCompile(`^([a-zA-Z0-9._-]+)(?:\[[^\]]+\])?(?:@|[<>=!~]=?)`)

// stripPyPIVersion strips version specifier from PyPI package name.
func stripPyPIVersion(pkg string) string {
	if m := pypiVersionRe.FindStringSubmatch(pkg); m != nil {
		return m[1]
	}
	return pkg
}

// GetEcosystem determines ecosystem from command.
func GetEcosystem(cmd string) string {
	if cmd == "" {
		return ""
	}
	basename := strings.ToLower(filepath.Base(cmd))
	if strings.HasSuffix(basename, ".exe") {
		basename = basename[:len(basename)-4]
	}
	if npmCommands[basename] {
		return "npm"
	}
	if pypiCommands[basename] {
		return "PyPI"
	}
	return ""
}

// skipFinding creates a SKIP finding for a check.
func skipFinding(checkID, checklistID, reason string, target auditor.ServerInventory) auditor.Finding {
	return auditor.Finding{
		CheckID:    checkID,
		Severity:   auditor.SeveritySkip,
		Message:    reason,
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata:   map[string]any{"checklist_id": checklistID},
	}
}
