// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
)

var (
	dangerousCapsRe   = regexp.MustCompile(`(?i)--cap-add\s+(SYS_ADMIN|ALL|SYS_PTRACE|NET_ADMIN)`)
	hostNamespacesRe  = regexp.MustCompile(`(?i)--(pid|network|ipc|uts)=host`)
	rootFSMountRe     = regexp.MustCompile(`-v\s+/:/`)
	etcMountRe        = regexp.MustCompile(`-v\s+/etc[:/]`)
	dockerSocketRe    = regexp.MustCompile(`-v\s+/var/run/docker\.sock`)
	sshMountRe        = regexp.MustCompile(`-v\s+[^\s]*\.ssh`)
	awsMountRe        = regexp.MustCompile(`-v\s+[^\s]*\.aws`)
	kubeMountRe       = regexp.MustCompile(`-v\s+[^\s]*\.kube`)
)

// ContainerIsolationCheck checks container isolation settings (CT-1.x).
type ContainerIsolationCheck struct{}

func (c *ContainerIsolationCheck) ID() string           { return "container.isolation" }
func (c *ContainerIsolationCheck) Name() string         { return "Container isolation settings" }
func (c *ContainerIsolationCheck) RequiresOnline() bool { return false }

func (c *ContainerIsolationCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if ctx.GetServerType() != auditor.ServerTypeContainer {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "Not a container server",
			ServerName: ctx.Target.Name,
			Location:   ctx.Target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "CT-1.1"},
		}}
	}

	target := ctx.Target
	argsStr := strings.Join(target.Args, " ")
	var findings []auditor.Finding

	// CT-1.1: Privileged container
	if strings.Contains(argsStr, "--privileged") {
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityCritical,
			Message:     "Container runs with --privileged flag",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Remove --privileged and use specific capabilities instead",
			Metadata:    map[string]any{"checklist_id": "CT-1.1"},
		})
	}

	// CT-1.2: Dangerous capabilities
	caps := dangerousCapsRe.FindAllStringSubmatch(argsStr, -1)
	if len(caps) > 0 {
		capNames := make([]string, len(caps))
		for i, match := range caps {
			capNames[i] = match[1]
		}
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityCritical,
			Message:     fmt.Sprintf("Container adds dangerous capabilities: %s", strings.Join(capNames, ", ")),
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Remove dangerous capabilities or justify their use",
			Metadata:    map[string]any{"checklist_id": "CT-1.2", "capabilities": capNames},
		})
	}

	// CT-1.3: Host namespace access
	nsMatches := hostNamespacesRe.FindAllStringSubmatch(argsStr, -1)
	if len(nsMatches) > 0 {
		nsNames := make([]string, len(nsMatches))
		for i, match := range nsMatches {
			nsNames[i] = match[1]
		}
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityCritical,
			Message:     fmt.Sprintf("Container shares host namespaces: %s", strings.Join(nsNames, ", ")),
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Remove host namespace sharing",
			Metadata:    map[string]any{"checklist_id": "CT-1.3", "namespaces": nsNames},
		})
	}

	// CT-1.4: Capabilities not restricted
	if !strings.Contains(argsStr, "--cap-drop") {
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityMedium,
			Message:     "Container doesn't restrict capabilities",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Add --cap-drop ALL to drop all capabilities",
			Metadata:    map[string]any{"checklist_id": "CT-1.4"},
		})
	}

	// CT-1.5: Writable filesystem
	if !strings.Contains(argsStr, "--read-only") {
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityMedium,
			Message:     "Container filesystem is writable",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Consider adding --read-only flag",
			Metadata:    map[string]any{"checklist_id": "CT-1.5"},
		})
	}

	if len(findings) == 0 {
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "Container isolation settings OK",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "CT-1.1"},
		})
	}

	return findings
}

// ContainerVolumeCheck checks container volume mounts (CT-2.x).
type ContainerVolumeCheck struct{}

func (c *ContainerVolumeCheck) ID() string           { return "container.volumes" }
func (c *ContainerVolumeCheck) Name() string         { return "Container volume mount security" }
func (c *ContainerVolumeCheck) RequiresOnline() bool { return false }

func (c *ContainerVolumeCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if ctx.GetServerType() != auditor.ServerTypeContainer {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "Not a container server",
			ServerName: ctx.Target.Name,
			Location:   ctx.Target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "CT-2.1"},
		}}
	}

	target := ctx.Target
	argsStr := strings.Join(target.Args, " ")
	var findings []auditor.Finding

	// CT-2.1: Root filesystem mounted
	if rootFSMountRe.MatchString(argsStr) {
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Container mounts root filesystem",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Mount only specific directories needed",
			Metadata:    map[string]any{"checklist_id": "CT-2.1"},
		})
	}

	// CT-2.2: System configuration mounted
	if etcMountRe.MatchString(argsStr) {
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Container mounts /etc (system configuration)",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Avoid mounting system configuration directories",
			Metadata:    map[string]any{"checklist_id": "CT-2.2"},
		})
	}

	// CT-2.3: Docker socket mounted
	if dockerSocketRe.MatchString(argsStr) {
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "Container mounts Docker socket (container escape risk)",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Remove Docker socket mount unless absolutely necessary",
			Metadata:    map[string]any{"checklist_id": "CT-2.3"},
		})
	}

	// CT-2.4: Sensitive credentials mounted
	var credMounts []string
	if sshMountRe.MatchString(argsStr) {
		credMounts = append(credMounts, "~/.ssh (SSH keys)")
	}
	if awsMountRe.MatchString(argsStr) {
		credMounts = append(credMounts, "~/.aws (AWS credentials)")
	}
	if kubeMountRe.MatchString(argsStr) {
		credMounts = append(credMounts, "~/.kube (Kubernetes config)")
	}

	if len(credMounts) > 0 {
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     fmt.Sprintf("Container mounts sensitive credentials: %s", strings.Join(credMounts, ", ")),
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Use secrets management instead of mounting credentials",
			Metadata:    map[string]any{"checklist_id": "CT-2.4", "cred_mounts": credMounts},
		})
	}

	if len(findings) == 0 {
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "Volume mount configuration OK",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "CT-2.1"},
		})
	}

	return findings
}
