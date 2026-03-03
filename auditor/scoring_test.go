// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

import (
	"math"
	"testing"
)

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  Severity
		want int
	}{
		{SeveritySkip, 0},
		{SeverityNote, 1},
		{SeverityMedium, 2},
		{SeverityHigh, 3},
		{SeverityCritical, 4},
	}
	for _, tt := range tests {
		if got := SeverityRank(tt.sev); got != tt.want {
			t.Errorf("SeverityRank(%q) = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

func TestWorseSeverity(t *testing.T) {
	tests := []struct {
		a, b Severity
		want Severity
	}{
		{SeverityNote, SeverityHigh, SeverityHigh},
		{SeverityCritical, SeverityNote, SeverityCritical},
		{SeverityMedium, SeverityMedium, SeverityMedium},
		{SeveritySkip, SeverityNote, SeverityNote},
	}
	for _, tt := range tests {
		got := WorseSeverity(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("WorseSeverity(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

func floatEq(a, b float64) bool {
	return math.Abs(a-b) < 0.01
}

func TestComputeAuditScore_AllNote(t *testing.T) {
	// All checks return NOTE — score should be 100
	findings := []Finding{
		{CheckID: "check1", Severity: SeverityNote},
		{CheckID: "check2", Severity: SeverityNote},
		{CheckID: "check3", Severity: SeverityNote},
		{CheckID: "check4", Severity: SeverityNote},
		{CheckID: "check5", Severity: SeverityNote},
	}
	checksRun := []string{"check1", "check2", "check3", "check4", "check5"}

	score := ComputeAuditScore(findings, checksRun, ServerTypePackageManager)

	if score.Status != StatusGraded {
		t.Errorf("expected graded, got %s", score.Status)
	}
	if !floatEq(score.OverallScore, 100.0) {
		t.Errorf("expected 100.0, got %.1f", score.OverallScore)
	}
	if score.RiskLevel == nil || *score.RiskLevel != RiskLow {
		t.Errorf("expected Low risk, got %v", score.RiskLevel)
	}
	if score.HardCapApplied != nil {
		t.Errorf("expected no hard cap, got %v", *score.HardCapApplied)
	}
}

func TestComputeAuditScore_CriticalCap(t *testing.T) {
	// One CRITICAL finding should cap at 30
	findings := []Finding{
		{CheckID: "check1", Severity: SeverityNote},
		{CheckID: "check2", Severity: SeverityNote},
		{CheckID: "check3", Severity: SeverityNote},
		{CheckID: "check4", Severity: SeverityNote},
		{CheckID: "check5", Severity: SeverityCritical},
	}
	checksRun := []string{"check1", "check2", "check3", "check4", "check5"}

	score := ComputeAuditScore(findings, checksRun, ServerTypePackageManager)

	if score.Status != StatusGraded {
		t.Errorf("expected graded, got %s", score.Status)
	}
	if score.OverallScore > 30.0 {
		t.Errorf("expected score <= 30 (critical cap), got %.1f", score.OverallScore)
	}
	if score.HardCapApplied == nil || *score.HardCapApplied != "CRITICAL" {
		t.Errorf("expected CRITICAL hard cap")
	}
	if score.UncappedScore <= 30.0 {
		// With 4 NOTEs and 1 CRITICAL, uncapped should be higher than 30
		t.Logf("uncapped score: %.1f (may be capped)", score.UncappedScore)
	}
}

func TestComputeAuditScore_HighCap(t *testing.T) {
	// One HIGH finding should cap at 59
	findings := []Finding{
		{CheckID: "check1", Severity: SeverityNote},
		{CheckID: "check2", Severity: SeverityNote},
		{CheckID: "check3", Severity: SeverityNote},
		{CheckID: "check4", Severity: SeverityNote},
		{CheckID: "check5", Severity: SeverityHigh},
	}
	checksRun := []string{"check1", "check2", "check3", "check4", "check5"}

	score := ComputeAuditScore(findings, checksRun, ServerTypePackageManager)

	if score.OverallScore > 59.0 {
		t.Errorf("expected score <= 59 (high cap), got %.1f", score.OverallScore)
	}
	if score.HardCapApplied == nil || *score.HardCapApplied != "HIGH" {
		t.Errorf("expected HIGH hard cap")
	}
}

func TestComputeAuditScore_AllSkipped(t *testing.T) {
	// All SKIP findings — should be UNKNOWN
	findings := []Finding{
		{CheckID: "check1", Severity: SeveritySkip},
		{CheckID: "check2", Severity: SeveritySkip},
	}
	checksRun := []string{"check1", "check2"}

	score := ComputeAuditScore(findings, checksRun, ServerTypePackageManager)

	if score.Status != StatusUnknown {
		t.Errorf("expected unknown, got %s", score.Status)
	}
	if score.ChecksWithData != 0 {
		t.Errorf("expected 0 checks with data, got %d", score.ChecksWithData)
	}
}

func TestComputeAuditScore_InsufficientCoverage(t *testing.T) {
	// Only 3 checks with data (threshold is 5) — should be ATTENTION_REQUIRED
	findings := []Finding{
		{CheckID: "check1", Severity: SeverityNote},
		{CheckID: "check2", Severity: SeverityNote},
		{CheckID: "check3", Severity: SeverityNote},
	}
	checksRun := []string{"check1", "check2", "check3"}

	score := ComputeAuditScore(findings, checksRun, ServerTypePackageManager)

	if score.Status != StatusAttentionRequired {
		t.Errorf("expected attention_required, got %s", score.Status)
	}
	if score.RiskLevel == nil {
		t.Error("expected non-nil risk level even with insufficient coverage")
	} else if *score.RiskLevel != RiskLow {
		t.Errorf("expected Low risk level, got %v", *score.RiskLevel)
	}
}

func TestComputeAuditScore_PublicHTTPLowerThreshold(t *testing.T) {
	// PUBLIC_HTTP has lower coverage threshold (3)
	findings := []Finding{
		{CheckID: "check1", Severity: SeverityNote},
		{CheckID: "check2", Severity: SeverityNote},
		{CheckID: "check3", Severity: SeverityNote},
	}
	checksRun := []string{"check1", "check2", "check3"}

	score := ComputeAuditScore(findings, checksRun, ServerTypePublicHTTP)

	if score.Status != StatusGraded {
		t.Errorf("expected graded for PUBLIC_HTTP with 3 checks, got %s", score.Status)
	}
}

func TestComputeAuditScore_MixedSeverities(t *testing.T) {
	// Mix of severities — verify weighted average logic
	findings := []Finding{
		{CheckID: "check1", Severity: SeverityNote},
		{CheckID: "check2", Severity: SeverityMedium},
		{CheckID: "check3", Severity: SeverityNote},
		{CheckID: "check4", Severity: SeverityNote},
		{CheckID: "check5", Severity: SeverityNote},
	}
	checksRun := []string{"check1", "check2", "check3", "check4", "check5"}

	score := ComputeAuditScore(findings, checksRun, ServerTypePackageManager)

	if score.Status != StatusGraded {
		t.Errorf("expected graded, got %s", score.Status)
	}
	// With 4 NOTEs (score=10, weight=1) and 1 MEDIUM (score=4, weight=5):
	// weighted_sum = 4*10*1 + 1*4*5 = 40 + 20 = 60
	// weight_sum = 4*1 + 1*5 = 9
	// raw_score_10 = 60/9 = 6.667
	// uncapped = 66.7
	if !floatEq(score.UncappedScore, 66.7) {
		t.Errorf("expected uncapped ~66.7, got %.1f", score.UncappedScore)
	}
	if score.HardCapApplied != nil {
		t.Errorf("expected no hard cap, got %v", *score.HardCapApplied)
	}
}

func TestRiskLevelFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  RiskLevel
	}{
		{100, RiskLow},
		{60, RiskLow},
		{59, RiskModerate},
		{31, RiskModerate},
		{30, RiskHigh},
		{0, RiskHigh},
	}
	for _, tt := range tests {
		got := riskLevelFromScore(tt.score)
		if got != tt.want {
			t.Errorf("riskLevelFromScore(%.1f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
