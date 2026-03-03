// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"errors"
	"fmt"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/apiclient"
)

// ContainerRegistryCheck verifies image exists in OCI registry (CT-5.x).
type ContainerRegistryCheck struct{}

func (c *ContainerRegistryCheck) ID() string           { return "container.registry.existence" }
func (c *ContainerRegistryCheck) Name() string          { return "Container image registry verification" }
func (c *ContainerRegistryCheck) RequiresOnline() bool   { return true }

func (c *ContainerRegistryCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if ctx.GetServerType() != auditor.ServerTypeContainer {
		return []auditor.Finding{skipFinding(c.ID(), "CT-5.1", "Not a container server", ctx.Target)}
	}

	ext, ok := ctx.GetExtension("container.image_ref")
	if !ok {
		return []auditor.Finding{skipFinding(c.ID(), "CT-5.1", "No image reference available", ctx.Target)}
	}
	imageRef, ok := ext.(string)
	if !ok || imageRef == "" {
		return []auditor.Finding{skipFinding(c.ID(), "CT-5.1", "No image reference available", ctx.Target)}
	}

	target := ctx.Target
	client := apiclient.NewOCIRegistryClient()
	image := apiclient.ParseImageReference(imageRef)

	manifest, err := client.GetManifest(image)
	if err != nil {
		ctx.SetExtension("container.registry_verified", false)

		var notFoundErr *apiclient.ImageNotFoundError
		var unreachableErr *apiclient.RegistryUnreachableError

		if errors.As(err, &notFoundErr) {
			return []auditor.Finding{{
				CheckID:     c.ID(),
				Severity:    auditor.SeverityHigh,
				Message:     fmt.Sprintf("Image not found in registry: %s", imageRef),
				ServerName:  target.Name,
				Location:    target.ConfigPath,
				Remediation: "Verify image name and tag are correct",
				Metadata:    map[string]any{"checklist_id": "CT-5.3"},
			}}
		} else if errors.As(err, &unreachableErr) {
			return []auditor.Finding{{
				CheckID:    c.ID(),
				Severity:   auditor.SeverityNote,
				Message:    fmt.Sprintf("Could not reach registry: %s", err),
				ServerName: target.Name,
				Location:   target.ConfigPath,
				Metadata:   map[string]any{"checklist_id": "CT-5.1"},
			}}
		} else {
			return []auditor.Finding{{
				CheckID:    c.ID(),
				Severity:   auditor.SeverityNote,
				Message:    fmt.Sprintf("Registry verification failed: %s", err),
				ServerName: target.Name,
				Location:   target.ConfigPath,
				Metadata:   map[string]any{"checklist_id": "CT-5.1"},
			}}
		}
	}

	ctx.SetExtension("container.manifest", manifest)
	ctx.SetExtension("container.registry_verified", true)

	// CT-5.2: Digest verification (if image was specified with digest)
	if image.Digest != "" && manifest.Digest != image.Digest {
		return []auditor.Finding{{
			CheckID:     c.ID(),
			Severity:    auditor.SeverityCritical,
			Message:     "Image digest mismatch - possible tampering",
			ServerName:  target.Name,
			Location:    target.ConfigPath,
			Remediation: "Verify image source and update digest",
			Metadata: map[string]any{
				"checklist_id":    "CT-5.2",
				"display_title":   "Image digest mismatch",
				"expected_digest": image.Digest,
				"actual_digest":   manifest.Digest,
			},
		}}
	}

	return []auditor.Finding{{
		CheckID:    c.ID(),
		Severity:   auditor.SeverityNote,
		Message:    "Image verified in registry",
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata:   map[string]any{"checklist_id": "CT-5.1"},
	}}
}
