// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

import "math"

// RiskLevel for security scores.
type RiskLevel string

const (
	RiskLow      RiskLevel = "Low"
	RiskModerate RiskLevel = "Moderate"
	RiskHigh     RiskLevel = "High"
)

// ScoringStatus for coverage-gated scoring.
type ScoringStatus string

const (
	StatusGraded            ScoringStatus = "graded"
	StatusAttentionRequired ScoringStatus = "attention_required"
	StatusUnknown           ScoringStatus = "unknown"
)

// AuditScore is the complete scoring result for an audit run.
type AuditScore struct {
	Status         ScoringStatus `json:"status"`
	OverallScore   float64       `json:"overall_score"`
	RiskLevel      *RiskLevel    `json:"risk_level"`
	HardCapApplied *string       `json:"hard_cap_applied"`
	UncappedScore  float64       `json:"uncapped_score"`
	ChecksWithData int           `json:"checks_with_data"`
	ChecksTotal    int           `json:"checks_total"`
}

// Severity -> per-check score (0-10).
var severityScore = map[Severity]float64{
	SeveritySkip:     -1,
	SeverityNote:     10.0,
	SeverityMedium:   4.0,
	SeverityHigh:     2.0,
	SeverityCritical: 0.0,
}

// Severity -> weight for weighted average (worse findings weigh more).
var severityWeight = map[Severity]float64{
	SeveritySkip:     0,
	SeverityNote:     1.0,
	SeverityMedium:   5.0,
	SeverityHigh:     7.5,
	SeverityCritical: 10.0,
}

const (
	criticalCap          = 30.0
	highCap              = 59.0
	coverageThreshold    = 5
	coverageThresholdHTTP = 3
)

// worstSeverity returns the worst (highest) severity across findings.
func worstSeverity(findings []Finding) Severity {
	if len(findings) == 0 {
		return SeverityNote
	}
	worst := findings[0].Severity
	for _, f := range findings[1:] {
		if SeverityRank(f.Severity) > SeverityRank(worst) {
			worst = f.Severity
		}
	}
	return worst
}

// checkScore computes 0-10 score for a single check from its findings.
// Returns -1 if all findings are SKIP (check doesn't apply).
func checkScore(findings []Finding) float64 {
	var nonSkip []Finding
	for _, f := range findings {
		if f.Severity != SeveritySkip {
			nonSkip = append(nonSkip, f)
		}
	}
	if len(nonSkip) == 0 {
		return -1 // Sentinel: all skipped
	}
	worst := worstSeverity(nonSkip)
	score, ok := severityScore[worst]
	if !ok {
		return 5.0
	}
	return score
}

// riskLevelFromScore maps 0-100 score to risk level.
func riskLevelFromScore(score float64) RiskLevel {
	if score >= 60 {
		return RiskLow
	}
	if score > 30 {
		return RiskModerate
	}
	return RiskHigh
}

// ComputeAuditScore computes the flat audit score from findings with coverage gating.
func ComputeAuditScore(
	findings []Finding,
	checksRunIDs []string,
	serverType ServerType,
) AuditScore {
	// Group findings by check_id
	findingsByCheck := make(map[string][]Finding)
	for _, f := range findings {
		findingsByCheck[f.CheckID] = append(findingsByCheck[f.CheckID], f)
	}

	// Detect hard cap triggers
	hasCritical := false
	hasHigh := false
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			hasCritical = true
		}
		if f.Severity == SeverityHigh {
			hasHigh = true
		}
	}

	// Flat severity-weighted average across all checks
	weightedSum := 0.0
	weightSum := 0.0
	checksWithData := 0

	checksRunSet := make(map[string]bool, len(checksRunIDs))
	for _, id := range checksRunIDs {
		checksRunSet[id] = true
	}

	for checkID := range checksRunSet {
		checkFindings := findingsByCheck[checkID]
		score := checkScore(checkFindings)

		if score >= 0 { // Not all-SKIP
			checksWithData++
			// Get non-skip findings for weight calculation
			var nonSkip []Finding
			for _, f := range checkFindings {
				if f.Severity != SeveritySkip {
					nonSkip = append(nonSkip, f)
				}
			}
			worst := worstSeverity(nonSkip)
			weight := severityWeight[worst]
			if weight < 1.0 {
				weight = 1.0
			}
			weightedSum += score * weight
			weightSum += weight
		}
	}

	// Compute raw score (0-10 scale -> 0-100)
	rawScore10 := 5.0
	if weightSum > 0 {
		rawScore10 = weightedSum / weightSum
	}
	uncappedScore := math.Round(rawScore10*10.0*10) / 10 // round to 1 decimal

	// Apply hard caps
	var hardCapApplied *string
	overallScore := uncappedScore

	if hasCritical {
		overallScore = math.Min(overallScore, criticalCap)
		cap := "CRITICAL"
		hardCapApplied = &cap
	} else if hasHigh {
		overallScore = math.Min(overallScore, highCap)
		cap := "HIGH"
		hardCapApplied = &cap
	}

	overallScore = math.Round(overallScore*10) / 10

	// Coverage gate
	threshold := coverageThreshold
	switch serverType {
	case ServerTypePublicHTTP, ServerTypeLocalHTTP:
		threshold = coverageThresholdHTTP
	}

	var status ScoringStatus
	var riskLevel *RiskLevel

	if checksWithData >= threshold {
		status = StatusGraded
	} else if checksWithData > 0 {
		status = StatusAttentionRequired
	} else {
		status = StatusUnknown
	}

	// Compute risk level when we have enough data to grade,
	// but not for unrecognized server types where scoring is unreliable.
	ungradeable := serverType == ServerTypeUnknownStdio || serverType == ServerTypeUnknown
	if checksWithData > 0 && !ungradeable {
		rl := riskLevelFromScore(overallScore)
		riskLevel = &rl
	}

	return AuditScore{
		Status:         status,
		OverallScore:   overallScore,
		RiskLevel:      riskLevel,
		HardCapApplied: hardCapApplied,
		UncappedScore:  uncappedScore,
		ChecksWithData: checksWithData,
		ChecksTotal:    len(checksRunIDs),
	}
}
