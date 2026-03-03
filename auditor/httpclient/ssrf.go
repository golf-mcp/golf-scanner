// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// SSRFError is returned when URL validation fails due to SSRF risk.
type SSRFError struct {
	Message string
}

func (e *SSRFError) Error() string {
	return e.Message
}

// Cloud metadata endpoints - must be blocked to prevent credential theft.
var cloudMetadataHosts = map[string]bool{
	"169.254.169.254":        true, // AWS
	"fd00:ec2::254":          true, // AWS IPv6
	"metadata.google.internal": true, // GCP
	"metadata":               true, // GCP short
	"metadata.azure.com":     true, // Azure
	"100.100.100.200":        true, // Alibaba Cloud
}

// Private network CIDRs.
var privateNetworks []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid CIDR: " + cidr + ": " + err.Error())
		}
		privateNetworks = append(privateNetworks, network)
	}
}

// Localhost identifiers.
var localhostHosts = map[string]bool{
	"localhost":           true,
	"127.0.0.1":           true,
	"::1":                 true,
	"0.0.0.0":             true,
	"[::1]":               true,
	"localhost.localdomain": true,
}

// Dangerous URL schemes.
var dangerousSchemes = map[string]bool{
	"file":   true,
	"gopher": true,
	"dict":   true,
	"ftp":    true,
	"ldap":   true,
	"tftp":   true,
}

// IsPrivateIP checks if an IP address is in a private or reserved range.
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IsCloudMetadataHost checks if hostname is a cloud metadata endpoint.
func IsCloudMetadataHost(hostname string) bool {
	return cloudMetadataHosts[strings.ToLower(hostname)]
}

// IsLocalhost checks if hostname is a localhost identifier.
func IsLocalhost(hostname string) bool {
	return localhostHosts[strings.ToLower(hostname)]
}

// ValidateURLForSSRF validates a URL against SSRF attacks.
func ValidateURLForSSRF(rawURL string, allowPrivate, allowLocalhost, resolveDNS bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return &SSRFError{Message: fmt.Sprintf("Invalid URL format: %v", err)}
	}

	scheme := strings.ToLower(parsed.Scheme)
	if dangerousSchemes[scheme] {
		return &SSRFError{Message: fmt.Sprintf("Blocked URL scheme: %s", scheme)}
	}
	if scheme != "http" && scheme != "https" {
		return &SSRFError{Message: fmt.Sprintf("Only HTTP/HTTPS URLs allowed, got: %s", scheme)}
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return &SSRFError{Message: "URL has no hostname"}
	}

	hostnameLower := strings.ToLower(hostname)

	// Always block cloud metadata
	if IsCloudMetadataHost(hostnameLower) {
		return &SSRFError{Message: fmt.Sprintf("Blocked cloud metadata endpoint: %s", hostname)}
	}

	// Check localhost
	if IsLocalhost(hostnameLower) {
		if !allowLocalhost {
			return &SSRFError{Message: fmt.Sprintf("Blocked localhost: %s", hostname)}
		}
		return nil
	}

	// Check if hostname is an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		if IsPrivateIP(hostname) && !allowPrivate {
			return &SSRFError{Message: fmt.Sprintf("Blocked private IP: %s", hostname)}
		}
		return nil
	}

	// Resolve hostname and check resulting IPs (DNS rebinding protection).
	// NOTE: There is a known TOCTOU race between DNS validation here and the
	// actual HTTP request. A malicious DNS server could return different IPs
	// between validation and connection. This is a defense-in-depth measure,
	// not a complete SSRF prevention solution.
	if resolveDNS {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupHost(ctx, hostname)
		if err == nil {
			for _, ip := range ips {
				if IsCloudMetadataHost(ip) {
					return &SSRFError{Message: fmt.Sprintf("Hostname %s resolves to cloud metadata IP: %s", hostname, ip)}
				}
				if IsPrivateIP(ip) && !allowPrivate {
					return &SSRFError{Message: fmt.Sprintf("Hostname %s resolves to private IP: %s", hostname, ip)}
				}
			}
		}
		// DNS resolution failure is not an error - host may be unreachable
	}

	return nil
}
