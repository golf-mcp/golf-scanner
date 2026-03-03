// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"net/url"
	"regexp"
	"strings"
)

var githubNameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)
var sshGitHubRe = regexp.MustCompile(`git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$`)
var httpsGitHubRe = regexp.MustCompile(`(?i)https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`)
var pathGitHubRe = regexp.MustCompile(`(?i)github\.com/([^/]+)/([^/?#]+)`)
var npmRepoShorthandRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$`)

const githubMaxUsernameLength = 39
const githubMaxRepoLength = 100

// ValidateGitHubName validates a GitHub owner or repo name.
func ValidateGitHubName(name, field string) error {
	if name == "" {
		return &ValidationError{Message: "GitHub " + field + " cannot be empty"}
	}
	maxLen := githubMaxUsernameLength
	if field != "owner" {
		maxLen = githubMaxRepoLength
	}
	if len(name) > maxLen {
		return &ValidationError{Message: "GitHub " + field + " too long"}
	}
	if !githubNameRe.MatchString(name) {
		return &ValidationError{Message: "Invalid GitHub " + field}
	}
	return nil
}

// ValidationError for input validation failures.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

// CleanRepoURL removes git+ prefix and .git suffix.
func CleanRepoURL(u string) string {
	if u == "" {
		return u
	}
	if strings.HasPrefix(u, "git+") {
		u = u[4:]
	}
	if strings.HasSuffix(u, ".git") {
		u = u[:len(u)-4]
	}
	return u
}

// ExpandNpmRepoShorthand expands npm repository shorthand to a full URL.
func ExpandNpmRepoShorthand(repo string) string {
	repo = strings.TrimSpace(repo)
	if strings.Contains(repo, "://") || strings.HasPrefix(repo, "git@") {
		return repo
	}
	prefixes := []struct {
		prefix string
		base   string
	}{
		{"github:", "https://github.com/"},
		{"gitlab:", "https://gitlab.com/"},
		{"bitbucket:", "https://bitbucket.org/"},
	}
	for _, p := range prefixes {
		if strings.HasPrefix(repo, p.prefix) {
			return p.base + repo[len(p.prefix):]
		}
	}
	if npmRepoShorthandRe.MatchString(repo) {
		return "https://github.com/" + repo
	}
	return repo
}

// IsGitHubURL checks if a URL is a legitimate GitHub URL.
func IsGitHubURL(u string) bool {
	if u == "" {
		return false
	}
	u = strings.TrimSpace(u)
	if strings.HasPrefix(u, "git+") {
		u = u[4:]
	}
	if strings.HasPrefix(u, "git@github.com:") {
		return true
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "github.com" || host == "www.github.com"
}

// NormalizeGitHubURL normalizes a GitHub URL to https://github.com/owner/repo (lowercase).
func NormalizeGitHubURL(u string) string {
	if u == "" {
		return ""
	}
	u = strings.TrimSpace(u)
	if strings.HasPrefix(u, "git+") {
		u = u[4:]
	}
	if m := sshGitHubRe.FindStringSubmatch(u); m != nil {
		return strings.ToLower("https://github.com/" + m[1] + "/" + m[2])
	}
	if m := httpsGitHubRe.FindStringSubmatch(u); m != nil {
		return strings.ToLower("https://github.com/" + m[1] + "/" + m[2])
	}
	if IsGitHubURL(u) {
		if m := pathGitHubRe.FindStringSubmatch(u); m != nil {
			repo := m[2]
			if strings.HasSuffix(repo, ".git") {
				repo = repo[:len(repo)-4]
			}
			return strings.ToLower("https://github.com/" + m[1] + "/" + repo)
		}
	}
	return ""
}

// ParseGitHubOwnerRepo extracts owner and repo from a GitHub URL.
func ParseGitHubOwnerRepo(u string) (string, string, bool) {
	if m := httpsGitHubRe.FindStringSubmatch(u); m != nil {
		return m[1], m[2], true
	}
	if m := sshGitHubRe.FindStringSubmatch(u); m != nil {
		return m[1], m[2], true
	}
	return "", "", false
}
