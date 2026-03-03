// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/httpclient"
)

var wwwAuthParamRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// Endpoint keys to extract from auth server metadata.
var oauthEndpointKeys = []string{
	"authorization_endpoint",
	"token_endpoint",
	"jwks_uri",
	"userinfo_endpoint",
	"revocation_endpoint",
	"introspection_endpoint",
}

// oauthDiscoveryResult holds OAuth metadata discovery results.
type oauthDiscoveryResult struct {
	oauthFound            bool
	initialStatusCode     int
	issuer                string
	discoveredEndpoints   map[string]string
	authServerMetadataURL string
}

// OAuthCheck checks OAuth endpoint security for HTTP MCP servers.
type OAuthCheck struct{}

func (c *OAuthCheck) ID() string           { return "http.oauth" }
func (c *OAuthCheck) Name() string          { return "OAuth" }
func (c *OAuthCheck) RequiresOnline() bool   { return true }

func (c *OAuthCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	target := ctx.Target

	// Only applies to HTTP/SSE servers
	if target.Transport != "http" && target.Transport != "sse" {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "OAuth check not applicable to STDIO servers",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"transport": target.Transport},
		}}
	}

	if target.Host == "" {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "OAuth check requires server URL",
			ServerName: target.Name,
			Location:   target.ConfigPath,
		}}
	}

	parsed, err := url.Parse(target.Host)
	if err != nil {
		return []auditor.Finding{skipFinding(c.ID(), "PH-3.1", "Invalid server URL", target)}
	}

	isLocalhost := isLocalhostHost(parsed.Hostname())
	serverType := ctx.GetServerType()
	isPublic := serverType == auditor.ServerTypePublicHTTP

	// Skip for local/private network servers
	if serverType == auditor.ServerTypeLocalHTTP {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "OAuth check skipped for local/private network server",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"reason": "Local and private network servers typically use internal authentication"},
		}}
	}

	// Skip for localhost servers
	if isLocalhost {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeveritySkip,
			Message:    "OAuth check skipped for localhost server",
			ServerName: target.Name,
			Location:   target.ConfigPath,
		}}
	}

	// SSRF validation
	if err := httpclient.ValidateURLForSSRF(target.Host, false, false, true); err != nil {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityHigh,
			Message:    "SSRF protection blocked request: " + err.Error(),
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"blocked_url": target.Host},
		}}
	}

	result := discoverOAuth(target.Host, isLocalhost)

	// Store endpoints for downstream use
	if len(result.discoveredEndpoints) > 0 {
		ctx.SetExtension("oauth.endpoints", result.discoveredEndpoints)
	}

	var findings []auditor.Finding

	if result.oauthFound {
		// OAuth authentication detected
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"display_title": "Authentication: OAuth",
				"description":   "Server implements OAuth/OpenID Connect authentication",
				"checklist_id":  "PH-3.3",
				"issuer":        result.issuer,
			},
		})

		// Check endpoint security
		findings = append(findings, checkEndpointSecurity(c.ID(), result, target, isLocalhost)...)

	} else if isPublic && (result.initialStatusCode == 401 || result.initialStatusCode == 403) {
		// Non-OAuth auth detected
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"display_title": "Authentication: Non-OAuth",
				"description":   "Server requires authentication (likely API key or custom auth)",
				"checklist_id":  "PH-3.2",
			},
		})

	} else if isPublic && result.initialStatusCode == 200 {
		// No authentication at all
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityCritical,
			Message:     "",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Require authentication for all requests",
			Metadata: map[string]any{
				"display_title": "Authentication: None",
				"description":   "Public server returns data without any authentication",
				"checklist_id":  "PH-3.1",
			},
		})

	} else if isPublic {
		// Public server with no discoverable auth
		findings = append(findings, auditor.Finding{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityHigh,
			Message:     "",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Expose OAuth discovery endpoints or ensure server responds with 401/403",
			Metadata: map[string]any{
				"display_title":       "No OAuth metadata found",
				"description":         "Public server does not expose OAuth discovery endpoints and authentication status could not be determined",
				"checklist_id":        "PH-3.4",
				"initial_status_code": result.initialStatusCode,
			},
		})

	} else {
		// Non-public server with no OAuth metadata
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"display_title": "No OAuth metadata found",
				"description":   "Server does not expose OAuth discovery endpoints",
			},
		})
	}

	return findings
}

func discoverOAuth(targetHost string, isLocalhost bool) *oauthDiscoveryResult {
	parsed, err := url.Parse(targetHost)
	if err != nil {
		return &oauthDiscoveryResult{}
	}

	var resourceMetadataURL string
	var protectedResourceMetadata map[string]any
	initialStatusCode := 0

	// Probe the server for status code and WWW-Authenticate header
	req, err := http.NewRequest("GET", targetHost, nil)
	if err == nil {
		resp, err := httpclient.DoRequest(req)
		if err == nil {
			initialStatusCode = resp.StatusCode
			resp.Body.Close()
			if resp.StatusCode == 401 {
				wwwAuth := resp.Header.Get("WWW-Authenticate")
				if wwwAuth != "" {
					params := parseWWWAuthenticate(wwwAuth)
					resourceMetadataURL = params["resource_metadata"]
				}
			}
		}
	}

	// Fetch PRM from WWW-Authenticate URL or well-known URIs
	if resourceMetadataURL != "" {
		if httpclient.ValidateURLForSSRF(resourceMetadataURL, false, isLocalhost, true) == nil {
			prmBody, prmStatus, prmErr := httpclient.Get(resourceMetadataURL)
			if prmErr == nil && prmStatus == 200 {
				if err := json.Unmarshal(prmBody, &protectedResourceMetadata); err != nil {
					protectedResourceMetadata = nil
				}
			}
		}
	}
	if protectedResourceMetadata == nil {
		for _, prmURL := range buildProtectedResourceMetadataURLs(targetHost) {
			if httpclient.ValidateURLForSSRF(prmURL, false, isLocalhost, true) != nil {
				continue
			}
			prmBody, prmStatus, prmErr := httpclient.Get(prmURL)
			if prmErr == nil && prmStatus == 200 {
				if json.Unmarshal(prmBody, &protectedResourceMetadata) == nil && protectedResourceMetadata != nil {
					break
				}
			}
		}
	}

	// Discover Authorization Server Metadata
	var authServerMetadata map[string]any
	var authServerMetadataURL string

	if protectedResourceMetadata != nil {
		if authServers, ok := protectedResourceMetadata["authorization_servers"].([]any); ok && len(authServers) > 0 {
			if authServerURL, ok := authServers[0].(string); ok {
				for _, asmURL := range buildAuthServerMetadataURLs(authServerURL) {
					if httpclient.ValidateURLForSSRF(asmURL, false, isLocalhost, true) != nil {
						continue
					}
					asmBody, asmStatus, asmErr := httpclient.Get(asmURL)
					if asmErr == nil && asmStatus == 200 {
						if json.Unmarshal(asmBody, &authServerMetadata) == nil && authServerMetadata != nil {
							authServerMetadataURL = asmURL
							break
						}
					}
				}
			}
		}
	} else {
		// No PRM - try auth server metadata directly
		baseURL := parsed.Scheme + "://" + parsed.Host
		for _, asmURL := range buildAuthServerMetadataURLs(baseURL) {
			if httpclient.ValidateURLForSSRF(asmURL, false, isLocalhost, true) != nil {
				continue
			}
			asmBody, asmStatus, asmErr := httpclient.Get(asmURL)
			if asmErr == nil && asmStatus == 200 {
				if json.Unmarshal(asmBody, &authServerMetadata) == nil && authServerMetadata != nil {
					authServerMetadataURL = asmURL
					break
				}
			}
		}
	}

	if authServerMetadata == nil {
		return &oauthDiscoveryResult{
			oauthFound:        false,
			initialStatusCode: initialStatusCode,
		}
	}

	// Extract endpoints
	discoveredEndpoints := make(map[string]string)
	for _, key := range oauthEndpointKeys {
		if v, ok := authServerMetadata[key].(string); ok && v != "" {
			discoveredEndpoints[key] = v
		}
	}

	issuer, _ := authServerMetadata["issuer"].(string)

	return &oauthDiscoveryResult{
		oauthFound:            true,
		initialStatusCode:     initialStatusCode,
		issuer:                issuer,
		discoveredEndpoints:   discoveredEndpoints,
		authServerMetadataURL: authServerMetadataURL,
	}
}

func parseWWWAuthenticate(header string) map[string]string {
	params := make(map[string]string)
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		header = header[7:]
	}
	for _, match := range wwwAuthParamRe.FindAllStringSubmatch(header, -1) {
		params[match[1]] = match[2]
	}
	return params
}

func buildProtectedResourceMetadataURLs(serverURL string) []string {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return nil
	}
	base := parsed.Scheme + "://" + parsed.Host
	path := strings.TrimRight(parsed.Path, "/")

	var urls []string
	if path != "" && path != "/" {
		urls = append(urls, base+"/.well-known/oauth-protected-resource"+path)
	}
	urls = append(urls, base+"/.well-known/oauth-protected-resource")
	return urls
}

func buildAuthServerMetadataURLs(issuerURL string) []string {
	parsed, err := url.Parse(issuerURL)
	if err != nil {
		return nil
	}
	base := parsed.Scheme + "://" + parsed.Host
	path := strings.TrimRight(parsed.Path, "/")

	var urls []string
	if path != "" && path != "/" {
		urls = append(urls, base+"/.well-known/oauth-authorization-server"+path)
		urls = append(urls, base+"/.well-known/openid-configuration"+path)
		urls = append(urls, base+path+"/.well-known/openid-configuration")
	} else {
		urls = append(urls, base+"/.well-known/oauth-authorization-server")
		urls = append(urls, base+"/.well-known/openid-configuration")
	}
	return urls
}

func checkEndpointSecurity(checkID string, result *oauthDiscoveryResult, target auditor.ServerInventory, isLocalhost bool) []auditor.Finding {
	var findings []auditor.Finding
	parsed, _ := url.Parse(target.Host)

	// Check MCP server uses HTTPS
	if !isLocalhost && parsed.Scheme != "https" {
		findings = append(findings, auditor.Finding{
			CheckID:     checkID,
			Severity:    auditor.SeverityHigh,
			Message:     "MCP server uses HTTP - auth tokens may leak",
			ServerName:  target.Name,
			Location:    target.Host,
			Remediation: "Configure MCP server to use HTTPS",
		})
	}

	// Check discovered endpoints for HTTP and reachability
	var httpIssues []string
	var unreachableEndpoints []string
	requiredEndpoints := map[string]bool{"authorization_endpoint": true, "token_endpoint": true}

	for endpointName, endpointURL := range result.discoveredEndpoints {
		epParsed, err := url.Parse(endpointURL)
		if err != nil {
			continue
		}
		epIsLocalhost := isLocalhostHost(epParsed.Hostname())

		// Check HTTPS
		if !epIsLocalhost && epParsed.Scheme != "https" {
			httpIssues = append(httpIssues, endpointName)
			continue
		}

		// Test reachability for required endpoints only
		if requiredEndpoints[endpointName] {
			if httpclient.ValidateURLForSSRF(endpointURL, false, epIsLocalhost, true) != nil {
				unreachableEndpoints = append(unreachableEndpoints, endpointName)
				continue
			}
			_, _, err := httpclient.Get(endpointURL)
			if err != nil {
				unreachableEndpoints = append(unreachableEndpoints, endpointName)
			}
		}
	}

	if len(httpIssues) > 0 {
		findings = append(findings, auditor.Finding{
			CheckID:     checkID,
			Severity:    auditor.SeverityCritical,
			Message:     "OAuth endpoints use insecure HTTP: " + strings.Join(httpIssues, ", "),
			ServerName:  target.Name,
			Location:    result.authServerMetadataURL,
			Remediation: "Configure all OAuth endpoints to use HTTPS",
			Metadata:    map[string]any{"insecure_endpoints": httpIssues},
		})
	}

	if len(unreachableEndpoints) > 0 {
		findings = append(findings, auditor.Finding{
			CheckID:     checkID,
			Severity:    auditor.SeverityHigh,
			Message:     "Required OAuth endpoints unreachable: " + strings.Join(unreachableEndpoints, ", "),
			ServerName:  target.Name,
			Location:    result.authServerMetadataURL,
			Remediation: "Verify endpoint URLs are correct and servers are running",
			Metadata:    map[string]any{"unreachable": unreachableEndpoints},
		})
	}

	return findings
}

