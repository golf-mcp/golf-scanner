// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

// Severity level for audit findings.
type Severity string

const (
	SeveritySkip     Severity = "skip"
	SeverityNote     Severity = "note"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Extension keys used across checks and the main command.
const (
	ExtKeyTypeDetection = "type.detection"
	ExtKeyDetectedType  = "detected_type"
	ExtKeyServerType    = "server_type"
)

// SeverityRank returns numeric rank for severity comparison (higher = worse).
func SeverityRank(s Severity) int {
	switch s {
	case SeveritySkip:
		return 0
	case SeverityNote:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// WorseSeverity returns the more severe of two severities.
func WorseSeverity(a, b Severity) Severity {
	if SeverityRank(a) >= SeverityRank(b) {
		return a
	}
	return b
}

// ServerType for type-specific security checks.
type ServerType string

const (
	ServerTypePackageManager ServerType = "package_manager"
	ServerTypeContainer     ServerType = "container"
	ServerTypeBinary        ServerType = "binary"
	ServerTypeScript        ServerType = "script"
	ServerTypeUnknownStdio  ServerType = "unknown_stdio"
	ServerTypeLocalHTTP     ServerType = "local_http"
	ServerTypePublicHTTP    ServerType = "public_http"
	ServerTypeUnreachable   ServerType = "unreachable"
	ServerTypeUnknown       ServerType = "unknown"
)

// DisplayName returns a human-readable label for the server type.
func (st ServerType) DisplayName() string {
	switch st {
	case ServerTypePackageManager:
		return "Package Manager"
	case ServerTypeContainer:
		return "Container"
	case ServerTypeBinary:
		return "Local Binary"
	case ServerTypeScript:
		return "Script"
	case ServerTypeUnknownStdio:
		return "Unknown Command"
	case ServerTypeLocalHTTP:
		return "Local Network"
	case ServerTypePublicHTTP:
		return "Public Server"
	case ServerTypeUnreachable:
		return "Unreachable"
	default:
		return "Unknown"
	}
}

// Finding is the result of a check.
type Finding struct {
	CheckID     string         `json:"check_id"`
	Severity    Severity       `json:"severity"`
	Message     string         `json:"message"`
	ServerName  string         `json:"server_name,omitempty"`
	Location    string         `json:"location,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// ServerInventory is built from scanner.ScanResult for audit input.
type ServerInventory struct {
	Name         string
	IDE          string
	Scope        string
	Transport    string // "stdio", "http", "sse"
	Host         string
	Cmd          string
	Args         []string
	ConfigPath   string
	ProjectPath  string
	FileMode     *int    // Script file permissions
	FileOwnerUID *int    // Script file owner UID
	FileOwner    string  // Script file owner name
	CmdFileMode  *int    // Command binary permissions
	CmdFileOwner string  // Command binary owner name
	Env          map[string]string
}

// AuditContext holds the target and inter-check extensions.
type AuditContext struct {
	Target     ServerInventory
	Extensions map[string]any
	ChecksRun  []string
}

// GetExtension returns an extension value by key.
func (ctx *AuditContext) GetExtension(key string) (any, bool) {
	v, ok := ctx.Extensions[key]
	return v, ok
}

// SetExtension sets an extension value.
func (ctx *AuditContext) SetExtension(key string, value any) {
	ctx.Extensions[key] = value
}

// GetServerType returns the detected server type from extensions.
func (ctx *AuditContext) GetServerType() ServerType {
	v, ok := ctx.Extensions[ExtKeyServerType]
	if !ok {
		return ServerTypeUnknown
	}
	st, ok := v.(ServerType)
	if !ok {
		return ServerTypeUnknown
	}
	return st
}
