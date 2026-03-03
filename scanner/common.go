// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	"github.com/tailscale/hujson"
)

type Scanner interface {
	Name() string
	Scan() []ScanResult
	// ScanHome scans a specific user's home directory.
	// If homeDir is empty, falls back to os.UserHomeDir().
	ScanHome(homeDir, username string) []ScanResult
}

type ScanResult struct {
	IDE             string                   `json:"ide"`
	Username        string                   `json:"username,omitempty"`
	Scope           string                   `json:"scope"`
	ConfigPath      string                   `json:"config_path,omitempty"`
	ConfigHash      string                   `json:"config_hash,omitempty"`
	ProjectPath     string                   `json:"project_path,omitempty"`
	DiscoverySource string                   `json:"discovery_source,omitempty"`
	Servers         []map[string]any `json:"servers"`
}

func HashFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func UriToPath(uri string) string {
	if uri == "" {
		return ""
	}
	if strings.HasPrefix(uri, "file://") {
		path := strings.TrimPrefix(uri, "file://")
		if runtime.GOOS == "windows" && len(path) > 2 && path[0] == '/' && path[2] == ':' {
			path = path[1:]
		}
		return path
	}
	if filepath.IsAbs(uri) {
		return uri
	}
	return ""
}

// ReadJSONConfig reads a JSON or JSON-with-comments config file.
// It strips comments (// and /* */) and trailing commas before parsing.
// This is a no-op for valid JSON, so it's safe for all config files.
// Returns error if file cannot be read or JSON is invalid.
func ReadJSONConfig(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Standardize: strip comments and trailing commas
	standardized, err := hujson.Standardize(data)
	if err != nil {
		// If standardization fails, try raw JSON as fallback
		// This handles edge cases where hujson might reject valid JSON
		return json.Unmarshal(data, v)
	}

	return json.Unmarshal(standardized, v)
}

var (
	macosUserPathRegex   = regexp.MustCompile(`^/Users/[^/]+/`)
	unixHomePathRegex    = regexp.MustCompile(`^/home/[^/]+/`)
	windowsUserPathRegex = regexp.MustCompile(`(?i)^[A-Z]:\\Users\\[^\\]+\\`)
	urlWithCredsRegex    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^:@/]+:[^@]+@`)
	urlWithUserRegex     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^:@/]+@`)
	apiKeyPrefixRegex    = regexp.MustCompile(`(?i)^(sk_|pk_|api_|key_|token_|bearer\s+)`)
	emailRegex           = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	envVarRegex          = regexp.MustCompile(`^\$\{[^}]+\}$|^\$[A-Z_][A-Z0-9_]*$`)
	portNumberRegex      = regexp.MustCompile(`^[0-9]{1,5}$`)
)

// sensitiveFlags lists flags whose values should always be masked.
// Note: "-p" conflicts with package managers where it means "--package".
// This conflict is resolved by the priority logic in ScrubArgs, which checks
// packageSafeFlags first for package commands before falling back to sensitiveFlags.
var sensitiveFlags = map[string]bool{
	"--password": true, "--token": true, "--secret": true, "--api-key": true,
	"--apikey": true, "--credentials": true, "--auth": true, "--key": true,
	"--pass": true, "-p": true, "--private-key": true, "--cert": true, "--certificate": true,
	"--access-token": true, "--accesstoken": true, "--bearer": true,
}

var packageCommands = map[string]bool{
	"npx": true, "npm": true, "yarn": true, "pnpm": true,
	"bunx": true, "bun": true, "uvx": true, "uv": true, "pipx": true,
}

// interpreterCommands are commands that run scripts where the first argument
// is typically a script path that should be preserved for security auditing
var interpreterCommands = map[string]bool{
	"python": true, "python3": true, "python2": true,
	"node": true, "nodejs": true,
	"ruby": true, "perl": true,
	"bash": true, "sh": true, "zsh": true,
	"php": true, "lua": true,
}

// packageSafeFlags are flags whose values should not be scrubbed for package commands
// because they contain package names, not sensitive data
var packageSafeFlags = map[string]bool{
	"--package": true, "-p": true, "--name": true, "--scope": true,
	"--registry": true, "--workspace": true, "-w": true,
}

// npmPackageRegex matches npm-style package names like @scope/package or package-name
var npmPackageRegex = regexp.MustCompile(`^(@[a-zA-Z0-9][\w.-]*/)?[a-zA-Z0-9][\w.-]*$`)

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isHighEntropy(s string) bool {
	if len(s) < 16 {
		return false
	}
	return calculateEntropy(s) > 4.0
}

func containsUserPath(s string) bool {
	return macosUserPathRegex.MatchString(s) || unixHomePathRegex.MatchString(s) || windowsUserPathRegex.MatchString(s)
}

// isPackageName checks if a value looks like an npm/Python package name
func isPackageName(value string) bool {
	// npm scoped packages: @scope/package-name
	// npm packages: package-name
	// Python packages: package-name or package_name
	return npmPackageRegex.MatchString(value)
}

// isSensitiveValue checks if a value matches known sensitive patterns
// that should always be masked regardless of context
func isSensitiveValue(value string) bool {
	return urlWithCredsRegex.MatchString(value) ||
		urlWithUserRegex.MatchString(value) ||
		containsUserPath(value) ||
		apiKeyPrefixRegex.MatchString(value) ||
		emailRegex.MatchString(value)
}

func scrubValue(value string) string {
	if envVarRegex.MatchString(value) {
		return value
	}
	if portNumberRegex.MatchString(value) {
		port := 0
		fmt.Sscanf(value, "%d", &port)
		if port >= 1 && port <= 65535 {
			return value
		}
	}
	// Check sensitive patterns BEFORE package names to ensure secrets are masked
	if urlWithCredsRegex.MatchString(value) || urlWithUserRegex.MatchString(value) {
		return "****"
	}
	if containsUserPath(value) {
		return "****"
	}
	if apiKeyPrefixRegex.MatchString(value) {
		return "****"
	}
	if emailRegex.MatchString(value) {
		return "****"
	}
	// Check for package names - they should not be masked by length/entropy checks
	if isPackageName(value) {
		return value
	}
	if len(value) > 40 {
		return "****"
	}
	if isHighEntropy(value) {
		return "****"
	}
	if len(value) > 5 {
		allDigits := true
		for _, c := range value {
			if !unicode.IsDigit(c) {
				allDigits = false
				break
			}
		}
		if allDigits {
			return "****"
		}
	}
	return value
}

func ScrubArgs(cmd string, args []string) []string {
	if len(args) == 0 {
		return args
	}
	result := make([]string, len(args))
	foundFirstPositional := false
	maskNextArg := false
	skipScrubNextArg := false
	prevWasFlag := false

	cmdBasename := cmd
	if idx := strings.LastIndex(cmd, "/"); idx >= 0 {
		cmdBasename = cmd[idx+1:]
	}
	if idx := strings.LastIndex(cmdBasename, "\\"); idx >= 0 {
		cmdBasename = cmdBasename[idx+1:]
	}
	cmdBasename = strings.ToLower(cmdBasename)
	isPackageCommand := packageCommands[cmdBasename]
	isInterpreterCommand := interpreterCommands[cmdBasename]

	for i, arg := range args {
		if maskNextArg {
			result[i] = "****"
			maskNextArg = false
			prevWasFlag = false
			continue
		}
		if skipScrubNextArg {
			// Package-safe flag value - but still check for sensitive patterns first
			if isSensitiveValue(arg) {
				result[i] = "****"
			} else if isPackageName(arg) {
				result[i] = arg
			} else {
				result[i] = scrubValue(arg)
			}
			skipScrubNextArg = false
			prevWasFlag = false
			continue
		}
		if strings.HasPrefix(arg, "-") {
			result[i] = arg
			flagName := arg
			if idx := strings.Index(arg, "="); idx >= 0 {
				flagName = arg[:idx]
				value := arg[idx+1:]
				flagNameLower := strings.ToLower(flagName)
				// For package commands, check package-safe flags first
				// This handles the -p conflict (--package vs --password)
				if isPackageCommand && packageSafeFlags[flagNameLower] {
					// Still check for sensitive patterns first
					if isSensitiveValue(value) {
						result[i] = flagName + "=****"
					} else if isPackageName(value) {
						result[i] = flagName + "=" + value
					} else {
						result[i] = flagName + "=" + scrubValue(value)
					}
				} else if sensitiveFlags[flagNameLower] {
					result[i] = flagName + "=****"
				} else {
					scrubbedValue := scrubValue(value)
					if scrubbedValue != value {
						result[i] = flagName + "=" + scrubbedValue
					}
				}
				prevWasFlag = false
			} else {
				flagNameLower := strings.ToLower(flagName)
				// For package commands, check package-safe flags first
				if isPackageCommand && packageSafeFlags[flagNameLower] {
					skipScrubNextArg = true
					prevWasFlag = false
				} else if sensitiveFlags[flagNameLower] {
					maskNextArg = true
					prevWasFlag = false
				} else {
					prevWasFlag = true
				}
			}
			continue
		}
		if prevWasFlag {
			result[i] = scrubValue(arg)
			prevWasFlag = false
			continue
		}
		if !foundFirstPositional {
			foundFirstPositional = true
			if isPackageCommand {
				result[i] = scrubValue(arg)
			} else if isInterpreterCommand {
				// Preserve script paths for interpreter commands (security auditing)
				// Still scrub sensitive patterns like credentials in the path
				result[i] = scrubValue(arg)
			} else {
				result[i] = "****"
			}
			continue
		}
		result[i] = "****"
	}
	return result
}

// GetEffectiveHomeDir returns the home directory to scan.
// If homeDir is provided, uses that; otherwise falls back to os.UserHomeDir().
func GetEffectiveHomeDir(homeDir string) (string, error) {
	if homeDir != "" {
		return homeDir, nil
	}
	return os.UserHomeDir()
}

// GetUserHomes returns a map of username to home directory path.
// When running as root on macOS/Linux, it enumerates /Users/ or /home/.
// When running as non-root, it returns only the current user's home.
func GetUserHomes() map[string]string {
	homes := make(map[string]string)

	// Check if running as root (UID 0)
	if os.Getuid() == 0 {
		// Running as root - enumerate user directories
		var usersDir string
		switch runtime.GOOS {
		case "darwin":
			usersDir = "/Users"
		case "linux":
			usersDir = "/home"
		default:
			// Windows or other - fall back to current user
			return getCurrentUserHome()
		}

		entries, err := os.ReadDir(usersDir)
		if err != nil {
			// Fall back to current user on error
			return getCurrentUserHome()
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			// Skip system/special directories
			if name == "Shared" || name == "Guest" || strings.HasPrefix(name, ".") {
				continue
			}
			// Skip common system account directories on Linux
			if runtime.GOOS == "linux" && (name == "lost+found") {
				continue
			}
			userHome := filepath.Join(usersDir, name)
			homes[name] = userHome
		}

		// If we didn't find any users, fall back
		if len(homes) == 0 {
			return getCurrentUserHome()
		}
		return homes
	}

	// Not running as root - return current user only
	return getCurrentUserHome()
}

// getCurrentUserHome returns a map with just the current user's home directory.
func getCurrentUserHome() map[string]string {
	homes := make(map[string]string)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return homes
	}
	// Extract username from home path
	username := filepath.Base(homeDir)
	// On some systems, home might be /root or similar
	if username == "root" || username == "" {
		username = os.Getenv("USER")
		if username == "" {
			username = "unknown"
		}
	}
	homes[username] = homeDir
	return homes
}

// ideStorage is the shared workspace storage type used by Cursor, VS Code, and Gemini
// for project discovery via VS Code's globalStorage/storage.json format.
type ideStorage struct {
	OpenedPathsList struct {
		Workspaces3 []string `json:"workspaces3"`
		Entries     []struct {
			FolderUri string `json:"folderUri"`
		} `json:"entries"`
	} `json:"openedPathsList"`
}

// FileMetadata holds file permission info for script/binary servers.
type FileMetadata struct {
	FileMode     int
	FileOwnerUID int
	FileOwner    string
}

// GetFileMetadata returns file metadata for a given path.
// Returns nil if path is empty or file doesn't exist.
func GetFileMetadata(path string) *FileMetadata {
	if path == "" {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil // File doesn't exist or can't access
	}

	return getFileMetadataPlatform(info)
}

// ExtractScriptPath extracts the script path from interpreter arguments.
// Returns empty string if cmd is not an interpreter or no script path found.
func ExtractScriptPath(cmd string, args []string) string {
	// Check if cmd is an interpreter
	cmdBase := filepath.Base(cmd)
	if !interpreterCommands[strings.ToLower(cmdBase)] {
		return ""
	}

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue // Skip flags
		}
		// Check if looks like a script path
		if strings.Contains(arg, "/") ||
			strings.HasSuffix(arg, ".py") ||
			strings.HasSuffix(arg, ".js") ||
			strings.HasSuffix(arg, ".rb") ||
			strings.HasSuffix(arg, ".pl") ||
			strings.HasSuffix(arg, ".sh") {
			return arg
		}
	}
	return ""
}

// EnrichServerWithFileMetadata adds file metadata to a server map for STDIO servers.
// This enriches the server data with permission information for security auditing.
func EnrichServerWithFileMetadata(serverData map[string]any) {
	transport, _ := serverData["transport"].(string)
	if transport != "stdio" {
		return // Only STDIO servers have local file metadata
	}

	cmd, _ := serverData["cmd"].(string)
	if cmd == "" {
		return
	}

	// Get args - handle both []string and []any from JSON unmarshaling
	var args []string
	if argsRaw, ok := serverData["args"]; ok {
		switch v := argsRaw.(type) {
		case []string:
			args = v
		case []any:
			for _, a := range v {
				if s, ok := a.(string); ok {
					args = append(args, s)
				}
			}
		}
	}

	// Try to get file metadata for script path (interpreter commands)
	if scriptPath := ExtractScriptPath(cmd, args); scriptPath != "" {
		if meta := GetFileMetadata(scriptPath); meta != nil {
			serverData["file_mode"] = meta.FileMode
			if meta.FileOwnerUID != 0 || meta.FileOwner != "" {
				serverData["file_owner_uid"] = meta.FileOwnerUID
			}
			if meta.FileOwner != "" {
				serverData["file_owner"] = meta.FileOwner
			}
		}
	}

	// Also get metadata for the command itself (for binary servers)
	if meta := GetFileMetadata(cmd); meta != nil {
		serverData["cmd_file_mode"] = meta.FileMode
		if meta.FileOwnerUID != 0 || meta.FileOwner != "" {
			serverData["cmd_file_owner_uid"] = meta.FileOwnerUID
		}
		if meta.FileOwner != "" {
			serverData["cmd_file_owner"] = meta.FileOwner
		}
	}
}
