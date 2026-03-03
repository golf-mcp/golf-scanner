// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"encoding/json"

	"github.com/golf-mcp/golf-scanner/auditor/httpclient"
)

const osvAPIURL = "https://api.osv.dev/v1"

// VulnerabilityInfo holds data about a single vulnerability.
type VulnerabilityInfo struct {
	ID            string   `json:"id"`
	Summary       string   `json:"summary"`
	SeverityScore *float64 `json:"severity_score"`
	IsMalware     bool     `json:"is_malware"`
	FixedVersions []string `json:"fixed_versions"`
}

// VulnerabilityResult is the result of a vulnerability lookup.
type VulnerabilityResult struct {
	Vulnerabilities []VulnerabilityInfo
	Error           string
}

// OSVClient queries the OSV vulnerability database.
type OSVClient struct{}

// QueryVulnerabilities queries OSV for package vulnerabilities.
func (c *OSVClient) QueryVulnerabilities(packageName, ecosystem string) VulnerabilityResult {
	payload := map[string]any{
		"package": map[string]string{
			"name":      packageName,
			"ecosystem": ecosystem,
		},
	}

	body, status, err := httpclient.PostJSON(osvAPIURL+"/query", payload)
	if err != nil {
		return VulnerabilityResult{Error: "OSV unreachable"}
	}
	if status >= 400 {
		return VulnerabilityResult{Error: "OSV returned error"}
	}

	var data struct {
		Vulns []json.RawMessage `json:"vulns"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return VulnerabilityResult{Error: "OSV returned invalid JSON"}
	}

	var vulns []VulnerabilityInfo
	for _, raw := range data.Vulns {
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}

		vulnID, _ := v["id"].(string)
		summary, _ := v["summary"].(string)
		score := extractCVSSScore(v)
		fixed := extractFixedVersions(v)

		vulns = append(vulns, VulnerabilityInfo{
			ID:            vulnID,
			Summary:       summary,
			SeverityScore: score,
			IsMalware:     len(vulnID) >= 4 && vulnID[:4] == "MAL-",
			FixedVersions: fixed,
		})
	}

	return VulnerabilityResult{Vulnerabilities: vulns}
}

func extractCVSSScore(vuln map[string]any) *float64 {
	severities, ok := vuln["severity"].([]any)
	if !ok {
		return nil
	}
	for _, s := range severities {
		sev, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if sev["type"] == "CVSS_V3" {
			scoreStr, ok := sev["score"].(string)
			if !ok {
				continue
			}
			if score, err := json.Number(scoreStr).Float64(); err == nil {
				return &score
			}
		}
	}
	return nil
}

func extractFixedVersions(vuln map[string]any) []string {
	var fixed []string
	affected, ok := vuln["affected"].([]any)
	if !ok {
		return fixed
	}
	for _, a := range affected {
		aMap, ok := a.(map[string]any)
		if !ok {
			continue
		}
		ranges, ok := aMap["ranges"].([]any)
		if !ok {
			continue
		}
		for _, r := range ranges {
			rMap, ok := r.(map[string]any)
			if !ok {
				continue
			}
			events, ok := rMap["events"].([]any)
			if !ok {
				continue
			}
			for _, e := range events {
				eMap, ok := e.(map[string]any)
				if !ok {
					continue
				}
				if f, ok := eMap["fixed"].(string); ok {
					fixed = append(fixed, f)
				}
			}
		}
	}
	return fixed
}
