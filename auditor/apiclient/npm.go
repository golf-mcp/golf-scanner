// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/golf-mcp/golf-scanner/auditor/httpclient"
)

const npmDownloadsAPI = "https://api.npmjs.org/downloads/point/last-week"
const npmRegistryURL = "https://registry.npmjs.org"

// NpmRegistryClient queries the npm registry API.
type NpmRegistryClient struct{}

// GetDownloadCount returns the weekly download count for an npm package.
func (c *NpmRegistryClient) GetDownloadCount(packageName string) *int {
	u, err := url.JoinPath(npmDownloadsAPI, packageName)
	if err != nil {
		return nil
	}
	body, status, err := httpclient.Get(u)
	if err != nil || status != 200 {
		return nil
	}

	var data struct {
		Downloads int `json:"downloads"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	return &data.Downloads
}

// GetCreatedDate returns the creation date of an npm package.
func (c *NpmRegistryClient) GetCreatedDate(packageName string) *time.Time {
	u, err := url.JoinPath(npmRegistryURL, packageName)
	if err != nil {
		return nil
	}
	body, status, err := httpclient.Get(u)
	if err != nil || status != 200 {
		return nil
	}

	var data struct {
		Time map[string]string `json:"time"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	created, ok := data.Time["created"]
	if !ok {
		return nil
	}
	return parseTime(created, commonTimeFormats)
}

// GetRepositoryURL returns the repository URL and optional directory from npm.
func (c *NpmRegistryClient) GetRepositoryURL(packageName string) (repoURL string, directory string) {
	u, err := url.JoinPath(npmRegistryURL, packageName)
	if err != nil {
		return "", ""
	}
	body, status, err := httpclient.Get(u)
	if err != nil || status != 200 {
		return "", ""
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", ""
	}

	// Try repository field (can be string or object)
	repo := data["repository"]
	switch r := repo.(type) {
	case string:
		return CleanRepoURL(ExpandNpmRepoShorthand(r)), ""
	case map[string]any:
		repoURL, _ := r["url"].(string)
		dir, _ := r["directory"].(string)
		if repoURL != "" {
			return CleanRepoURL(repoURL), dir
		}
	}

	// Try homepage if it's a GitHub URL.
	// Currently only GitHub repository URLs are extracted. GitLab/Bitbucket support is a future enhancement.
	if homepage, ok := data["homepage"].(string); ok && IsGitHubURL(homepage) {
		return CleanRepoURL(homepage), ""
	}

	return "", ""
}
