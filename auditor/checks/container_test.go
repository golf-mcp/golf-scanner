// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"strings"
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
)

// --- Container Isolation ---

func TestContainerIsolation_Privileged(t *testing.T) {
	check := &ContainerIsolationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "--privileged", "myimage"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	hasCritical := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityCritical && strings.Contains(f.Message, "--privileged") {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected CRITICAL for --privileged")
	}
}

func TestContainerIsolation_DangerousCaps(t *testing.T) {
	caps := []string{"SYS_ADMIN", "ALL", "SYS_PTRACE", "NET_ADMIN"}
	for _, cap := range caps {
		t.Run(cap, func(t *testing.T) {
			check := &ContainerIsolationCheck{}
			ctx := makeCtxWithType(auditor.ServerInventory{
				Cmd: "docker", Args: []string{"run", "--cap-add", cap, "img"},
			}, auditor.ServerTypeContainer)
			findings := check.Run(ctx)
			hasCritical := false
			for _, f := range findings {
				if f.Severity == auditor.SeverityCritical && strings.Contains(f.Message, "capabilities") {
					hasCritical = true
				}
			}
			if !hasCritical {
				t.Errorf("expected CRITICAL for --cap-add %s", cap)
			}
		})
	}
}

func TestContainerIsolation_HostNamespaces(t *testing.T) {
	namespaces := []string{"--pid=host", "--network=host", "--ipc=host", "--uts=host"}
	for _, ns := range namespaces {
		t.Run(ns, func(t *testing.T) {
			check := &ContainerIsolationCheck{}
			ctx := makeCtxWithType(auditor.ServerInventory{
				Cmd: "docker", Args: []string{"run", ns, "img"},
			}, auditor.ServerTypeContainer)
			findings := check.Run(ctx)
			hasCritical := false
			for _, f := range findings {
				if f.Severity == auditor.SeverityCritical && strings.Contains(f.Message, "namespaces") {
					hasCritical = true
				}
			}
			if !hasCritical {
				t.Errorf("expected CRITICAL for %s", ns)
			}
		})
	}
}

func TestContainerIsolation_NoCapDrop(t *testing.T) {
	check := &ContainerIsolationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "--read-only", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	hasMedium := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityMedium && strings.Contains(f.Message, "capabilities") {
			hasMedium = true
		}
	}
	if !hasMedium {
		t.Error("expected MEDIUM for missing --cap-drop")
	}
}

func TestContainerIsolation_WritableFS(t *testing.T) {
	check := &ContainerIsolationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "--cap-drop", "ALL", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	hasMedium := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityMedium && strings.Contains(f.Message, "writable") {
			hasMedium = true
		}
	}
	if !hasMedium {
		t.Error("expected MEDIUM for missing --read-only")
	}
}

func TestContainerIsolation_Clean(t *testing.T) {
	check := &ContainerIsolationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "--cap-drop", "ALL", "--read-only", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityNote {
		t.Errorf("expected NOTE for clean container, got %s", findings[0].Severity)
	}
}

func TestContainerIsolation_NotContainer(t *testing.T) {
	check := &ContainerIsolationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"pkg"},
	}, auditor.ServerTypePackageManager)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeveritySkip {
		t.Errorf("expected SKIP for non-container, got %s", findings[0].Severity)
	}
}

func TestContainerIsolation_MultipleViolations(t *testing.T) {
	check := &ContainerIsolationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "--privileged", "--pid=host", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	criticalCount := 0
	for _, f := range findings {
		if f.Severity == auditor.SeverityCritical {
			criticalCount++
		}
	}
	if criticalCount < 2 {
		t.Errorf("expected at least 2 CRITICAL findings, got %d", criticalCount)
	}
}

// --- Container Volumes ---

func TestContainerVolume_RootMount(t *testing.T) {
	check := &ContainerVolumeCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "-v", "/:/host", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	hasHigh := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityHigh && strings.Contains(f.Message, "root filesystem") {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("expected HIGH for root mount")
	}
}

func TestContainerVolume_EtcMount(t *testing.T) {
	check := &ContainerVolumeCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "-v", "/etc:/etc", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	hasHigh := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityHigh && strings.Contains(f.Message, "/etc") {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("expected HIGH for /etc mount")
	}
}

func TestContainerVolume_DockerSocket(t *testing.T) {
	check := &ContainerVolumeCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	hasHigh := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityHigh && strings.Contains(f.Message, "Docker socket") {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("expected HIGH for Docker socket mount")
	}
}

func TestContainerVolume_SSHMount(t *testing.T) {
	check := &ContainerVolumeCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "-v", "/home/user/.ssh:/root/.ssh", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	hasHigh := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityHigh && strings.Contains(f.Message, "credentials") {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("expected HIGH for SSH mount")
	}
}

func TestContainerVolume_AWSMount(t *testing.T) {
	check := &ContainerVolumeCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "-v", "/home/user/.aws:/root/.aws", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	hasHigh := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityHigh && strings.Contains(f.Message, "credentials") {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("expected HIGH for AWS mount")
	}
}

func TestContainerVolume_KubeMount(t *testing.T) {
	check := &ContainerVolumeCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "-v", "/home/user/.kube:/root/.kube", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	hasHigh := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityHigh && strings.Contains(f.Message, "credentials") {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("expected HIGH for kube mount")
	}
}

func TestContainerVolume_MultipleViolations(t *testing.T) {
	check := &ContainerVolumeCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "-v", "/:/host", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", "/home/user/.ssh:/root/.ssh", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	highCount := 0
	for _, f := range findings {
		if f.Severity == auditor.SeverityHigh {
			highCount++
		}
	}
	if highCount < 3 {
		t.Errorf("expected at least 3 HIGH findings, got %d", highCount)
	}
}

func TestContainerVolume_Clean(t *testing.T) {
	check := &ContainerVolumeCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "docker", Args: []string{"run", "-v", "/data:/data", "img"},
	}, auditor.ServerTypeContainer)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityNote {
		t.Errorf("expected NOTE for clean volumes, got %s", findings[0].Severity)
	}
}

func TestContainerVolume_NotContainer(t *testing.T) {
	check := &ContainerVolumeCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"pkg"},
	}, auditor.ServerTypePackageManager)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeveritySkip {
		t.Errorf("expected SKIP for non-container, got %s", findings[0].Severity)
	}
}
