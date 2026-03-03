// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
)

// Shared test helpers used by all per-check test files.

func makeCtx(inv auditor.ServerInventory) *auditor.AuditContext {
	return &auditor.AuditContext{
		Target:     inv,
		Extensions: make(map[string]any),
	}
}

func makeCtxWithType(inv auditor.ServerInventory, st auditor.ServerType) *auditor.AuditContext {
	ctx := makeCtx(inv)
	ctx.SetExtension("server_type", st)
	return ctx
}

// --- Pipe Detection (internal helper) ---

func TestContainsSinglePipe(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"a | b", true},
		{"a || b", false},
		{"|", true},
		{"||", false},
		{"a|b", true},
		{"no pipes here", false},
		{"a || b | c", true},
	}
	for _, tt := range tests {
		got := containsSinglePipe(tt.input)
		if got != tt.want {
			t.Errorf("containsSinglePipe(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
