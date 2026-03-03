// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
)

// --- Script Location ---

func TestScriptLocation_TmpDir(t *testing.T) {
	check := &ScriptLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/tmp/evil.py"},
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for /tmp, got %s", findings[0].Severity)
	}
}

func TestScriptLocation_VarTmpDir(t *testing.T) {
	check := &ScriptLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/var/tmp/server.py"},
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for /var/tmp, got %s", findings[0].Severity)
	}
}

func TestScriptLocation_DevShm(t *testing.T) {
	check := &ScriptLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/dev/shm/server.py"},
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for /dev/shm, got %s", findings[0].Severity)
	}
}

func TestScriptLocation_HomeLinux(t *testing.T) {
	check := &ScriptLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/home/user/script.py"},
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM for /home/, got %s", findings[0].Severity)
	}
}

func TestScriptLocation_HomeMacOS(t *testing.T) {
	check := &ScriptLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/Users/dev/mcp/server.py"},
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM for /Users/, got %s", findings[0].Severity)
	}
}

func TestScriptLocation_TildePath(t *testing.T) {
	check := &ScriptLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"~/scripts/server.py"},
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM for ~/, got %s", findings[0].Severity)
	}
}

func TestScriptLocation_SafeLocation(t *testing.T) {
	check := &ScriptLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/opt/myapp/server.py"},
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityNote {
		t.Errorf("expected NOTE for safe location, got %s", findings[0].Severity)
	}
}

func TestScriptLocation_NoScriptPath(t *testing.T) {
	check := &ScriptLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"-m", "mymodule"},
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityHigh {
		t.Errorf("expected HIGH for unextractable script path, got %s", findings[0].Severity)
	}
}

func TestScriptLocation_NotScript(t *testing.T) {
	check := &ScriptLocationCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"pkg"},
	}, auditor.ServerTypePackageManager)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeveritySkip {
		t.Errorf("expected SKIP for non-script, got %s", findings[0].Severity)
	}
}

// --- Script path extraction ---

func TestExtractScriptPath_PyFile(t *testing.T) {
	path := extractScriptPath([]string{"server.py"})
	if path != "server.py" {
		t.Errorf("expected server.py, got %s", path)
	}
}

func TestExtractScriptPath_JsFile(t *testing.T) {
	path := extractScriptPath([]string{"index.js"})
	if path != "index.js" {
		t.Errorf("expected index.js, got %s", path)
	}
}

func TestExtractScriptPath_WithSlash(t *testing.T) {
	path := extractScriptPath([]string{"/opt/myapp/server.rb"})
	if path != "/opt/myapp/server.rb" {
		t.Errorf("expected /opt/myapp/server.rb, got %s", path)
	}
}

func TestExtractScriptPath_SkipsFlags(t *testing.T) {
	path := extractScriptPath([]string{"-u", "--verbose", "/opt/server.py"})
	if path != "/opt/server.py" {
		t.Errorf("expected /opt/server.py, got %s", path)
	}
}

func TestExtractScriptPath_NoMatch(t *testing.T) {
	path := extractScriptPath([]string{"-m", "mymodule"})
	if path != "" {
		t.Errorf("expected empty, got %s", path)
	}
}

// --- Script Permissions ---

func TestScriptPerms_WorldWritable(t *testing.T) {
	check := &ScriptPermissionsCheck{}
	mode := 0o777
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/opt/server.py"}, FileMode: &mode,
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for 0o777, got %s", findings[0].Severity)
	}
}

func TestScriptPerms_GroupWritableNotWorld(t *testing.T) {
	check := &ScriptPermissionsCheck{}
	mode := 0o775
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/opt/server.py"}, FileMode: &mode,
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	// 0o775 has group-write but not world-write — should be NOTE (no world-writable check)
	if findings[0].Severity != auditor.SeverityNote {
		t.Errorf("expected NOTE for 0o775 (group-writable but not world), got %s", findings[0].Severity)
	}
}

func TestScriptPerms_NormalPermissions(t *testing.T) {
	check := &ScriptPermissionsCheck{}
	mode := 0o755
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/opt/server.py"}, FileMode: &mode,
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityNote {
		t.Errorf("expected NOTE for 0o755, got %s", findings[0].Severity)
	}
}

func TestScriptPerms_RestrictedPermissions(t *testing.T) {
	check := &ScriptPermissionsCheck{}
	mode := 0o700
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/opt/server.py"}, FileMode: &mode,
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityNote {
		t.Errorf("expected NOTE for 0o700, got %s", findings[0].Severity)
	}
}

func TestScriptPerms_NoPermData(t *testing.T) {
	check := &ScriptPermissionsCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "python", Args: []string{"/opt/server.py"},
	}, auditor.ServerTypeScript)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeverityHigh {
		t.Errorf("expected HIGH for missing permission data, got %s", findings[0].Severity)
	}
}

func TestScriptPerms_NotScript(t *testing.T) {
	check := &ScriptPermissionsCheck{}
	ctx := makeCtxWithType(auditor.ServerInventory{
		Cmd: "npx",
	}, auditor.ServerTypePackageManager)
	findings := check.Run(ctx)
	if findings[0].Severity != auditor.SeveritySkip {
		t.Errorf("expected SKIP for non-script, got %s", findings[0].Severity)
	}
}
