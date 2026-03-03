// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"net/url"
	"strings"
)

// localhostHosts is the canonical set of localhost identifiers.
var localhostHosts = map[string]bool{
	"localhost": true, "127.0.0.1": true, "::1": true,
	"0.0.0.0": true, "[::1]": true,
}

// isLocalhostHost checks if a hostname is a localhost address.
func isLocalhostHost(hostname string) bool {
	return localhostHosts[strings.ToLower(hostname)]
}

// extractHostFromURL extracts the hostname from a URL string.
func extractHostFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
