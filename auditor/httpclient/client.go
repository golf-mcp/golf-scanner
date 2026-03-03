// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

var defaultTimeout = 20 * time.Second
var connectTimeout = 5 * time.Second

const maxResponseSize = 10 * 1024 * 1024 // 10 MB

// defaultClient is a shared HTTP client with sane timeouts.
var defaultClient = &http.Client{
	Timeout: defaultTimeout,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: connectTimeout,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
	},
}

// Get performs an HTTP GET request and returns the response body.
// SSRF validation is the caller's responsibility — call ValidateURLForSSRF
// before using Get with user-controlled URLs.
func Get(url string) ([]byte, int, error) {
	resp, err := defaultClient.Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response from %s: %w", url, err)
	}

	return body, resp.StatusCode, nil
}

// GetWithHeaders performs an HTTP GET with custom headers.
func GetWithHeaders(url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request for %s: %w", url, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response from %s: %w", url, err)
	}

	return body, resp.StatusCode, nil
}

// PostJSON performs an HTTP POST with a JSON body.
func PostJSON(url string, payload any) ([]byte, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, fmt.Errorf("marshaling JSON for %s: %w", url, err)
	}

	resp, err := defaultClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response from %s: %w", url, err)
	}

	return body, resp.StatusCode, nil
}

// HeadWithHeaders performs an HTTP HEAD with custom headers.
func HeadWithHeaders(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), "HEAD", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HEAD request for %s: %w", url, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HEAD %s: %w", url, err)
	}
	// Note: caller must close resp.Body
	return resp, nil
}

// DoRequest performs a custom HTTP request.
func DoRequest(req *http.Request) (*http.Response, error) {
	return defaultClient.Do(req)
}

// GetJSON performs a GET and unmarshals the response into dest.
func GetJSON(url string, dest any) (int, error) {
	body, status, err := Get(url)
	if err != nil {
		return status, err
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return status, fmt.Errorf("parsing JSON from %s: %w", url, err)
	}
	return status, nil
}

// GetJSONWithHeaders performs a GET with headers and unmarshals the response.
func GetJSONWithHeaders(url string, headers map[string]string, dest any) (int, error) {
	body, status, err := GetWithHeaders(url, headers)
	if err != nil {
		return status, err
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return status, fmt.Errorf("parsing JSON from %s: %w", url, err)
	}
	return status, nil
}

// PostJSONGetJSON performs a POST with JSON body and unmarshals the response.
func PostJSONGetJSON(url string, payload any, dest any) (int, error) {
	body, status, err := PostJSON(url, payload)
	if err != nil {
		return status, err
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return status, fmt.Errorf("parsing JSON from %s: %w", url, err)
	}
	return status, nil
}
