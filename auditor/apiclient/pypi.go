// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/golf-mcp/golf-scanner/auditor/httpclient"
)

const pypistatsAPI = "https://pypistats.org/api/packages"
const pypiRegistryURL = "https://pypi.org/pypi"

// PyPIClient queries the PyPI API.
type PyPIClient struct{}

// GetDownloadCount returns the weekly download count for a PyPI package.
func (c *PyPIClient) GetDownloadCount(packageName string) *int {
	u, err := url.JoinPath(pypistatsAPI, packageName, "recent")
	if err != nil {
		return nil
	}
	body, status, err := httpclient.Get(u)
	if err != nil || status != 200 {
		return nil
	}

	var data struct {
		Data struct {
			LastWeek int `json:"last_week"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	return &data.Data.LastWeek
}

// GetCreatedDate returns the creation date of a PyPI package.
func (c *PyPIClient) GetCreatedDate(packageName string) *time.Time {
	u, err := url.JoinPath(pypiRegistryURL, packageName, "json")
	if err != nil {
		return nil
	}
	body, status, err := httpclient.Get(u)
	if err != nil || status != 200 {
		return nil
	}

	var data struct {
		Releases map[string][]struct {
			UploadTimeISO string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	var earliest *time.Time
	for _, files := range data.Releases {
		for _, f := range files {
			if f.UploadTimeISO == "" {
				continue
			}
			t := parseTime(f.UploadTimeISO, commonTimeFormats)
			if t == nil {
				continue
			}
			if earliest == nil || t.Before(*earliest) {
				tt := *t
				earliest = &tt
			}
		}
	}
	return earliest
}

// GetRepositoryURL returns the repository URL from PyPI.
func (c *PyPIClient) GetRepositoryURL(packageName string) (repoURL string, directory string) {
	u, err := url.JoinPath(pypiRegistryURL, packageName, "json")
	if err != nil {
		return "", ""
	}
	body, status, err := httpclient.Get(u)
	if err != nil || status != 200 {
		return "", ""
	}

	var data struct {
		Info struct {
			ProjectURLs map[string]string `json:"project_urls"`
			HomePage    string            `json:"home_page"`
			ProjectURL  string            `json:"project_url"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", ""
	}

	// Try project_urls first.
	// Currently only GitHub repository URLs are extracted. GitLab/Bitbucket support is a future enhancement.
	for _, key := range []string{"Source", "Source Code", "Repository", "GitHub", "Code"} {
		if u, ok := data.Info.ProjectURLs[key]; ok && IsGitHubURL(u) {
			return CleanRepoURL(u), ""
		}
	}

	if IsGitHubURL(data.Info.HomePage) {
		return CleanRepoURL(data.Info.HomePage), ""
	}
	if IsGitHubURL(data.Info.ProjectURL) {
		return CleanRepoURL(data.Info.ProjectURL), ""
	}

	return "", ""
}
