// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
)

// --- Binary Location ---

func TestBinaryLocation_ProtectedPaths(t *testing.T) {
	check := &BinaryLocationCheck{}
	paths := []string{"/usr/bin/mcp", "/usr/local/bin/mcp", "/bin/mcp", "/sbin/mcp", "/usr/sbin/mcp"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			ctx := makeCtxWithType(auditor.ServerInventory{Cmd: p}, auditor.ServerTypeBinary)
			findings := check.Run(ctx)
			if findings[0].Severity != auditor.SeverityNote {
				t.Errorf("expected NOTE for %s, got %s", p, findings[0].Severity)
			}
		})
	}
}

func TestBinaryLocation_OptPath(t *testing.T) {
	check := &BinaryLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{Cmd: "/opt/mcp/server"}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM for /opt, got %s", findings[0].Severity)
	}
}

func TestBinaryLocation_TmpPaths(t *testing.T) {
	check := &BinaryLocationCheck{}
	paths := []string{"/tmp/evil", "/var/tmp/evil", "/dev/shm/evil"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			ctx := makeCtxWithType(auditor.ServerInventory{Cmd: p}, auditor.ServerTypeBinary)
			findings := check.Run(ctx)
			if findings[0].Severity != auditor.SeverityCritical {
				t.Errorf("expected CRITICAL for %s, got %s", p, findings[0].Severity)
			}
		})
	}
}

func TestBinaryLocation_HomeLinux(t *testing.T) {
	check := &BinaryLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{Cmd: "/home/user/bin/mcp"}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM for /home/, got %s", findings[0].Severity)
	}
}

func TestBinaryLocation_HomeMacOS(t *testing.T) {
	check := &BinaryLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{Cmd: "/Users/dev/bin/mcp"}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM for /Users/, got %s", findings[0].Severity)
	}
}

func TestBinaryLocation_NotAbsolute(t *testing.T) {
	check := &BinaryLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{Cmd: "myserver"}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityHigh {
		t.Errorf("expected HIGH for non-absolute path, got %s", findings[0].Severity)
	}
}

func TestBinaryLocation_EmptyCmd(t *testing.T) {
	check := &BinaryLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{Cmd: ""}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityHigh {
		t.Errorf("expected HIGH for empty cmd, got %s", findings[0].Severity)
	}
}

func TestBinaryLocation_UnexpectedLocation(t *testing.T) {
	check := &BinaryLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{Cmd: "/srv/mcp/server"}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityHigh {
		t.Errorf("expected HIGH for unexpected location, got %s", findings[0].Severity)
	}
}

func TestBinaryLocation_NotBinary(t *testing.T) {
	check := &BinaryLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{Cmd: "npx"}, auditor.ServerTypePackageManager)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeveritySkip {
		t.Errorf("expected SKIP for non-binary, got %s", findings[0].Severity)
	}
}

// --- Binary Permissions ---

func TestBinaryPerms_WorldWritable(t *testing.T) {
	check := &BinaryPermissionsCheck{}
	mode := 0o777
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "/usr/local/bin/mcp", CmdFileMode: &mode,
	}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	hasCritical := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected CRITICAL for world-writable binary")
	}
}

func TestBinaryPerms_GroupWritable(t *testing.T) {
	check := &BinaryPermissionsCheck{}
	mode := 0o775
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "/usr/local/bin/mcp", CmdFileMode: &mode,
	}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	hasHigh := false
	for _, f := range findings {
		if f.Severity == auditor.SeverityHigh {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("expected HIGH for group-writable binary")
	}
}

func TestBinaryPerms_NormalPermissions(t *testing.T) {
	check := &BinaryPermissionsCheck{}
	mode := 0o755
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "/usr/local/bin/mcp", CmdFileMode: &mode,
	}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityNote {
		t.Errorf("expected NOTE for 0o755, got %s", findings[0].Severity)
	}
}

func TestBinaryPerms_RestrictedPermissions(t *testing.T) {
	check := &BinaryPermissionsCheck{}
	mode := 0o700
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "/usr/local/bin/mcp", CmdFileMode: &mode,
	}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityNote {
		t.Errorf("expected NOTE for 0o700, got %s", findings[0].Severity)
	}
}

func TestBinaryPerms_NoPermData(t *testing.T) {
	check := &BinaryPermissionsCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "/usr/local/bin/mcp",
	}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeveritySkip {
		t.Errorf("expected SKIP for missing permission data, got %s", findings[0].Severity)
	}
}

func TestBinaryPerms_NotBinary(t *testing.T) {
	check := &BinaryPermissionsCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{Cmd: "npx"}, auditor.ServerTypePackageManager)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeveritySkip {
		t.Errorf("expected SKIP for non-binary, got %s", findings[0].Severity)
	}
}

func TestBinaryPerms_WorldAndGroupWritable(t *testing.T) {
	// 0o777 should produce BOTH world-writable (CRITICAL) and group-writable (HIGH)
	check := &BinaryPermissionsCheck{}
	mode := 0o777
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "/usr/local/bin/mcp", CmdFileMode: &mode,
	}, auditor.ServerTypeBinary)
	findings := check.Run(ctx)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings for 0o777, got %d", len(findings))
	}
}
