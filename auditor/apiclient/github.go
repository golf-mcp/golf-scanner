// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/golf-mcp/golf-scanner/auditor/httpclient"
)

const githubAPIURL = "https://api.github.com"

// GitHubRepoMetadata holds repository trust signal data.
type GitHubRepoMetadata struct {
	Owner            string
	Name             string
	FullName         string
	Stars            int
	Forks            int
	OpenIssues       int
	CreatedAt        *time.Time
	PushedAt         *time.Time
	Archived         bool
	Disabled         bool
	LicenseName      string
	OwnerType        string
	CommitsLastMonth *int
	ContributorCount *int
}

// GitHubMetadataResult holds the result of a GitHub metadata lookup.
type GitHubMetadataResult struct {
	Metadata *GitHubRepoMetadata
	Error    string
}

// GitHubMetadataClient fetches repository metadata from GitHub.
type GitHubMetadataClient struct {
	token string
	cache map[string]*GitHubMetadataResult
	mu    sync.Mutex
}

// NewGitHubMetadataClient creates a new GitHub client.
// If token is empty, reads from GITHUB_TOKEN env var.
func NewGitHubMetadataClient(token string) *GitHubMetadataClient {
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GOLF_GITHUB_TOKEN")
	}
	return &GitHubMetadataClient{
		token: token,
		cache: make(map[string]*GitHubMetadataResult),
	}
}

// GetRepoMetadata fetches repository metadata from GitHub.
func (c *GitHubMetadataClient) GetRepoMetadata(repoURL string) *GitHubMetadataResult {
	owner, repo, ok := ParseGitHubOwnerRepo(repoURL)
	if !ok {
		return &GitHubMetadataResult{Error: fmt.Sprintf("Invalid GitHub URL: %s", repoURL)}
	}

	cacheKey := fmt.Sprintf("%s/%s", owner, repo)

	c.mu.Lock()
	if cached, ok := c.cache[cacheKey]; ok {
		c.mu.Unlock()
		return cached
	}
	c.mu.Unlock()

	result := c.fetchRepo(owner, repo)

	c.mu.Lock()
	c.cache[cacheKey] = result
	c.mu.Unlock()

	return result
}

func (c *GitHubMetadataClient) headers() map[string]string {
	h := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	if c.token != "" {
		h["Authorization"] = "Bearer " + c.token
	}
	return h
}

func (c *GitHubMetadataClient) fetchRepo(owner, repo string) *GitHubMetadataResult {
	if err := ValidateGitHubName(owner, "owner"); err != nil {
		return &GitHubMetadataResult{Error: err.Error()}
	}
	if err := ValidateGitHubName(repo, "repo"); err != nil {
		return &GitHubMetadataResult{Error: err.Error()}
	}

	safeOwner := url.PathEscape(owner)
	safeRepo := url.PathEscape(repo)
	hdrs := c.headers()

	// Fetch repo metadata
	repoBody, repoStatus, err := httpclient.GetWithHeaders(
		githubAPIURL+"/repos/"+safeOwner+"/"+safeRepo,
		hdrs,
	)
	if err != nil {
		return &GitHubMetadataResult{Error: "GitHub unreachable"}
	}
	if repoStatus == 404 {
		return &GitHubMetadataResult{Error: "Repository not found"}
	}
	if repoStatus == 403 || repoStatus == 429 {
		return &GitHubMetadataResult{Error: "GitHub API rate limit exceeded"}
	}
	if repoStatus >= 400 {
		return &GitHubMetadataResult{Error: fmt.Sprintf("GitHub returned %d", repoStatus)}
	}

	var data map[string]any
	if err := json.Unmarshal(repoBody, &data); err != nil {
		return &GitHubMetadataResult{Error: "GitHub returned invalid JSON"}
	}

	metadata := parseGitHubResponse(owner, repo, data)

	// Fetch commits from last 30 days.
	// Capped at 100 results (single page) for performance.
	sinceDate := time.Now().UTC().AddDate(0, 0, -30).Format(time.RFC3339)
	commitsBody, commitsStatus, commitsErr := httpclient.GetWithHeaders(
		githubAPIURL+"/repos/"+safeOwner+"/"+safeRepo+"/commits?since="+sinceDate+"&per_page=100",
		hdrs,
	)
	if commitsErr == nil && commitsStatus == 200 {
		var commits []any
		if json.Unmarshal(commitsBody, &commits) == nil {
			count := len(commits)
			metadata.CommitsLastMonth = &count
		}
	}

	// Fetch contributors count.
	// Capped at 100 results (single page) for performance.
	contribBody, contribStatus, contribErr := httpclient.GetWithHeaders(
		githubAPIURL+"/repos/"+safeOwner+"/"+safeRepo+"/contributors?per_page=100&anon=false",
		hdrs,
	)
	if contribErr == nil && contribStatus == 200 {
		var contributors []any
		if json.Unmarshal(contribBody, &contributors) == nil {
			count := len(contributors)
			metadata.ContributorCount = &count
		}
	}

	return &GitHubMetadataResult{Metadata: metadata}
}

func parseGitHubResponse(owner, repo string, data map[string]any) *GitHubRepoMetadata {
	m := &GitHubRepoMetadata{
		Owner:    owner,
		Name:     repo,
		FullName: owner + "/" + repo,
	}

	if v, ok := data["stargazers_count"].(float64); ok {
		m.Stars = int(v)
	}
	if v, ok := data["forks_count"].(float64); ok {
		m.Forks = int(v)
	}
	if v, ok := data["open_issues_count"].(float64); ok {
		m.OpenIssues = int(v)
	}
	if v, ok := data["archived"].(bool); ok {
		m.Archived = v
	}
	if v, ok := data["disabled"].(bool); ok {
		m.Disabled = v
	}

	if s, ok := data["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			m.CreatedAt = &t
		}
	}
	if s, ok := data["pushed_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			m.PushedAt = &t
		}
	}

	if licInfo, ok := data["license"].(map[string]any); ok {
		if spdx, ok := licInfo["spdx_id"].(string); ok && spdx != "" {
			m.LicenseName = spdx
		} else if name, ok := licInfo["name"].(string); ok {
			m.LicenseName = name
		}
	}

	if ownerInfo, ok := data["owner"].(map[string]any); ok {
		if t, ok := ownerInfo["type"].(string); ok {
			m.OwnerType = t
		}
	}
	if m.OwnerType == "" {
		m.OwnerType = "Unknown"
	}

	return m
}
