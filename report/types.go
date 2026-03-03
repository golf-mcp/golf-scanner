// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"time"

	"github.com/golf-mcp/golf-scanner/auditor"
)

// ServerSource represents one IDE/config where a server was found.
type ServerSource struct {
	Name        string `json:"name"`
	IDE         string `json:"ide"`
	Scope       string `json:"scope"`
	ConfigPath  string `json:"config_path,omitempty"`
	ProjectPath string `json:"project_path,omitempty"`
}

// ServerIdentity is the identity of a deduplicated server.
type ServerIdentity struct {
	Type string `json:"type"`
	Key  string `json:"key"`
}

// ServerResult holds the audit results for a deduplicated server.
type ServerResult struct {
	Name          string             `json:"name"`
	Sources       []ServerSource     `json:"sources"`
	Identity      ServerIdentity     `json:"identity"`
	Type          string             `json:"type"`
	Score         auditor.AuditScore `json:"score"`
	Findings      []auditor.Finding  `json:"findings"`
	ChecksRun     []string           `json:"checks_run"`
	ChecksSkipped []string           `json:"checks_skipped"`
}

// Summary holds aggregate statistics across all audited servers.
type Summary struct {
	TotalServers int `json:"total_servers"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Note         int `json:"note"`
}

// Report is the top-level output structure for an audit run.
type Report struct {
	Version  string         `json:"version"`
	ScanTime time.Time      `json:"scan_time"`
	Servers  []ServerResult `json:"servers"`
	Summary  Summary        `json:"summary"`
}
