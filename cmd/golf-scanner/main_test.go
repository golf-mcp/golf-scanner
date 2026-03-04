// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/report"
)

func TestHasFindingsAtOrAbove(t *testing.T) {
	results := []report.ServerResult{
		{
			Findings: []auditor.Finding{
				{Severity: auditor.SeverityNote, Message: "note"},
				{Severity: auditor.SeverityMedium, Message: "medium"},
			},
		},
		{
			Findings: []auditor.Finding{
				{Severity: auditor.SeveritySkip, Message: "skip"},
			},
		},
	}

	// Should find medium and above
	if !hasFindingsAtOrAbove(results, auditor.SeverityMedium) {
		t.Error("expected findings at or above medium")
	}
	if !hasFindingsAtOrAbove(results, auditor.SeverityNote) {
		t.Error("expected findings at or above note")
	}

	// Should NOT find high or critical
	if hasFindingsAtOrAbove(results, auditor.SeverityHigh) {
		t.Error("should not find findings at or above high")
	}
	if hasFindingsAtOrAbove(results, auditor.SeverityCritical) {
		t.Error("should not find findings at or above critical")
	}
}

func TestHasFindingsAtOrAboveSkipsSkip(t *testing.T) {
	results := []report.ServerResult{
		{
			Findings: []auditor.Finding{
				{Severity: auditor.SeveritySkip, Message: "skip"},
			},
		},
	}

	// Even note should not match since the only finding is skip
	if hasFindingsAtOrAbove(results, auditor.SeverityNote) {
		t.Error("skip findings should not count")
	}
}

func TestHasFindingsAtOrAboveEmpty(t *testing.T) {
	var results []report.ServerResult
	if hasFindingsAtOrAbove(results, auditor.SeverityNote) {
		t.Error("empty results should not have findings")
	}
}
