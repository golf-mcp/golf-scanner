// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/golf-mcp/golf-scanner/auditor/httpclient"
)

// OCIRegistryError is the base error for OCI registry operations.
type OCIRegistryError struct {
	Message string
}

func (e *OCIRegistryError) Error() string { return e.Message }

// ImageNotFoundError indicates image or tag does not exist.
type ImageNotFoundError struct{ OCIRegistryError }

// RegistryUnreachableError indicates the registry cannot be reached.
type RegistryUnreachableError struct{ OCIRegistryError }

// ImageReference is a parsed container image reference.
type ImageReference struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
}

// ParseImageReference parses an image reference string.
func ParseImageReference(imageRef string) ImageReference {
	ref := strings.TrimSpace(imageRef)

	var digest string
	if idx := strings.Index(ref, "@sha256:"); idx != -1 {
		digest = ref[idx+1:]
		ref = ref[:idx]
	}

	var tag string
	if digest == "" {
		if idx := strings.LastIndex(ref, ":"); idx != -1 {
			afterColon := ref[idx+1:]
			if !strings.Contains(afterColon, "/") {
				tag = afterColon
				ref = ref[:idx]
			}
		}
	}

	parts := strings.Split(ref, "/")
	var registry, repository string

	if len(parts) == 1 {
		registry = "docker.io"
		repository = "library/" + parts[0]
	} else if len(parts) == 2 && !strings.Contains(parts[0], ".") && !strings.Contains(parts[0], ":") {
		registry = "docker.io"
		repository = ref
	} else {
		registry = parts[0]
		repository = strings.Join(parts[1:], "/")
	}

	if tag == "" && digest == "" {
		tag = "latest"
	}

	return ImageReference{
		Registry:   registry,
		Repository: repository,
		Tag:        tag,
		Digest:     digest,
	}
}

// Reference returns the tag or digest for API calls.
func (r ImageReference) Reference() string {
	if r.Digest != "" {
		return r.Digest
	}
	if r.Tag != "" {
		return r.Tag
	}
	return "latest"
}

// FullReference returns the full image reference string.
func (r ImageReference) FullReference() string {
	base := r.Registry + "/" + r.Repository
	if r.Digest != "" {
		return base + "@" + r.Digest
	}
	tag := r.Tag
	if tag == "" {
		tag = "latest"
	}
	return base + ":" + tag
}

// ManifestInfo holds container image manifest information.
type ManifestInfo struct {
	Digest      string
	MediaType   string
	Annotations map[string]string
}

// SignatureInfo holds cosign signature information.
type SignatureInfo struct {
	Exists          bool
	SignatureDigest string
	Certificate     string
	Annotations     map[string]string
}

// registryConfig holds per-registry configuration.
type registryConfig struct {
	APIBase      string
	TokenURL     string
	TokenService string
}

var registryConfigs = map[string]registryConfig{
	"docker.io": {
		APIBase:      "https://registry-1.docker.io",
		TokenURL:     "https://auth.docker.io/token",
		TokenService: "registry.docker.io",
	},
	"ghcr.io": {
		APIBase:      "https://ghcr.io",
		TokenURL:     "https://ghcr.io/token",
		TokenService: "ghcr.io",
	},
	"quay.io": {
		APIBase: "https://quay.io",
	},
	"public.ecr.aws": {
		APIBase: "https://public.ecr.aws",
	},
}

var manifestMediaTypes = strings.Join([]string{
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}, ", ")

// OCIRegistryClient supports anonymous access to public container registries.
type OCIRegistryClient struct {
	tokenCache map[string]string
	mu         sync.Mutex
}

// NewOCIRegistryClient creates a new OCI registry client.
func NewOCIRegistryClient() *OCIRegistryClient {
	return &OCIRegistryClient{
		tokenCache: make(map[string]string),
	}
}

// GetManifest fetches an image manifest from the registry.
func (c *OCIRegistryClient) GetManifest(image ImageReference) (*ManifestInfo, error) {
	return c.getManifestWithDepth(image, 0)
}

func (c *OCIRegistryClient) getManifestWithDepth(image ImageReference, depth int) (*ManifestInfo, error) {
	if depth > 3 {
		return nil, &OCIRegistryError{Message: fmt.Sprintf("manifest list recursion limit exceeded for %s", image.FullReference())}
	}
	cfg, err := c.getRegistryConfig(image.Registry)
	if err != nil {
		return nil, &RegistryUnreachableError{OCIRegistryError{Message: err.Error()}}
	}
	u := cfg.APIBase + "/v2/" + image.Repository + "/manifests/" + image.Reference()

	headers := map[string]string{"Accept": manifestMediaTypes}
	token := c.getToken(image.Registry, image.Repository)
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	body, status, err := httpclient.GetWithHeaders(u, headers)
	if err != nil {
		return nil, &RegistryUnreachableError{OCIRegistryError{Message: "Registry timeout: " + image.Registry}}
	}

	if status == 401 && token != "" {
		// Invalidate and retry
		c.mu.Lock()
		delete(c.tokenCache, image.Registry+"/"+image.Repository)
		c.mu.Unlock()
		newToken := c.getToken(image.Registry, image.Repository)
		if newToken != "" && newToken != token {
			headers["Authorization"] = "Bearer " + newToken
			body, status, err = httpclient.GetWithHeaders(u, headers)
			if err != nil {
				return nil, &RegistryUnreachableError{OCIRegistryError{Message: "Registry timeout: " + image.Registry}}
			}
		}
	}

	if status == 404 {
		return nil, &ImageNotFoundError{OCIRegistryError{Message: "Image not found: " + image.FullReference()}}
	}
	if status >= 400 {
		return nil, &OCIRegistryError{Message: fmt.Sprintf("Registry returned %d", status)}
	}

	// Calculate digest
	h := sha256.Sum256(body)
	digest := fmt.Sprintf("sha256:%x", h)

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, &OCIRegistryError{Message: "Invalid manifest JSON"}
	}

	// Handle manifest list/index - resolve to linux/amd64
	if manifests, ok := data["manifests"].([]any); ok {
		for _, m := range manifests {
			mMap, ok := m.(map[string]any)
			if !ok {
				continue
			}
			platform, _ := mMap["platform"].(map[string]any)
			if platform != nil {
				osName, _ := platform["os"].(string)
				arch, _ := platform["architecture"].(string)
				if osName == "linux" && arch == "amd64" {
					d, _ := mMap["digest"].(string)
					nested := ImageReference{
						Registry:   image.Registry,
						Repository: image.Repository,
						Digest:     d,
					}
					return c.getManifestWithDepth(nested, depth+1)
				}
			}
		}
		// Fallback to first manifest
		if len(manifests) > 0 {
			if first, ok := manifests[0].(map[string]any); ok {
				d, _ := first["digest"].(string)
				nested := ImageReference{
					Registry:   image.Registry,
					Repository: image.Repository,
					Digest:     d,
				}
				return c.getManifestWithDepth(nested, depth+1)
			}
		}
	}

	annotations := make(map[string]string)
	if ann, ok := data["annotations"].(map[string]any); ok {
		for k, v := range ann {
			if s, ok := v.(string); ok {
				annotations[k] = s
			}
		}
	}

	return &ManifestInfo{
		Digest:      digest,
		MediaType:   fmt.Sprint(data["mediaType"]),
		Annotations: annotations,
	}, nil
}

// GetSignature checks for a cosign signature in the registry.
func (c *OCIRegistryClient) GetSignature(image ImageReference) *SignatureInfo {
	if image.Digest == "" {
		return &SignatureInfo{Exists: false}
	}

	digestValue := strings.TrimPrefix(image.Digest, "sha256:")
	sigTag := "sha256-" + digestValue + ".sig"

	sigImage := ImageReference{
		Registry:   image.Registry,
		Repository: image.Repository,
		Tag:        sigTag,
	}

	manifest, err := c.GetManifest(sigImage)
	if err != nil {
		return &SignatureInfo{Exists: false}
	}

	cert := manifest.Annotations["dev.sigstore.cosign/certificate"]

	return &SignatureInfo{
		Exists:          true,
		SignatureDigest: manifest.Digest,
		Certificate:     cert,
		Annotations:     manifest.Annotations,
	}
}

func (c *OCIRegistryClient) getRegistryConfig(registry string) (registryConfig, error) {
	if cfg, ok := registryConfigs[registry]; ok {
		return cfg, nil
	}
	apiBase := "https://" + registry
	if err := httpclient.ValidateURLForSSRF(apiBase, false, false, true); err != nil {
		return registryConfig{}, fmt.Errorf("blocked registry %s: %w", registry, err)
	}
	return registryConfig{APIBase: apiBase}, nil
}

func (c *OCIRegistryClient) getToken(registry, repository string) string {
	cacheKey := registry + "/" + repository

	c.mu.Lock()
	if token, ok := c.tokenCache[cacheKey]; ok {
		c.mu.Unlock()
		return token
	}
	c.mu.Unlock()

	cfg, err := c.getRegistryConfig(registry)
	if err != nil || cfg.TokenURL == "" {
		return ""
	}

	service := cfg.TokenService
	if service == "" {
		service = registry
	}

	tokenURL := fmt.Sprintf("%s?scope=repository:%s:pull&service=%s", cfg.TokenURL, repository, service)
	body, status, err := httpclient.Get(tokenURL)
	if err != nil || status != 200 {
		return ""
	}

	var data map[string]any
	if json.Unmarshal(body, &data) != nil {
		return ""
	}

	token, _ := data["token"].(string)
	if token == "" {
		token, _ = data["access_token"].(string)
	}

	if token != "" {
		c.mu.Lock()
		c.tokenCache[cacheKey] = token
		c.mu.Unlock()
	}

	return token
}
