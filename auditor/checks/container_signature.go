// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/apiclient"
)

// ContainerSignatureCheck checks for cosign signatures in registry (CT-6.x).
type ContainerSignatureCheck struct{}

func (c *ContainerSignatureCheck) ID() string           { return "container.registry.signature" }
func (c *ContainerSignatureCheck) Name() string          { return "Container image signature detection" }
func (c *ContainerSignatureCheck) RequiresOnline() bool   { return true }

func (c *ContainerSignatureCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if ctx.GetServerType() != auditor.ServerTypeContainer {
		return []auditor.Finding{skipFinding(c.ID(), "CT-6.1", "Not a container server", ctx.Target)}
	}

	imageRefExt, ok := ctx.GetExtension("container.image_ref")
	if !ok {
		return []auditor.Finding{skipFinding(c.ID(), "CT-6.1", "No image reference available", ctx.Target)}
	}
	imageRef, ok := imageRefExt.(string)
	if !ok || imageRef == "" {
		return []auditor.Finding{skipFinding(c.ID(), "CT-6.1", "Invalid image reference", ctx.Target)}
	}

	manifestExt, ok := ctx.GetExtension("container.manifest")
	if !ok || manifestExt == nil {
		return []auditor.Finding{skipFinding(c.ID(), "CT-6.1", "Manifest not available", ctx.Target)}
	}
	manifest, ok := manifestExt.(*apiclient.ManifestInfo)
	if !ok {
		return []auditor.Finding{skipFinding(c.ID(), "CT-6.1", "Invalid manifest type", ctx.Target)}
	}

	target := ctx.Target
	client := apiclient.NewOCIRegistryClient()
	image := apiclient.ParseImageReference(imageRef)

	// Use manifest digest for signature lookup
	imageWithDigest := apiclient.ImageReference{
		Registry:   image.Registry,
		Repository: image.Repository,
		Digest:     manifest.Digest,
	}

	sigInfo := client.GetSignature(imageWithDigest)
	ctx.SetExtension("container.signature", sigInfo)

	if sigInfo.Exists {
		var findings []auditor.Finding

		// CT-6.1: Signature found
		sigMetadata := map[string]any{
			"checklist_id":    "CT-6.1",
			"display_title":   "Cosign signature detected in registry",
			"has_certificate": sigInfo.Certificate != "",
		}
		if sigInfo.SignatureDigest != "" {
			sigMetadata["signature_digest"] = sigInfo.SignatureDigest
		}

		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "Cosign signature detected in registry",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   sigMetadata,
		})

		// CT-6.2: Check if keyless (has certificate)
		if sigInfo.Certificate != "" {
			findings = append(findings, auditor.Finding{
				CheckID:    c.ID(),
				Severity:   auditor.SeverityNote,
				Message:    "Keyless (Fulcio) signature with certificate",
				ServerName: target.Name,
				Location:   target.ConfigPath,
				Metadata:   map[string]any{"checklist_id": "CT-6.2"},
			})
		}

		return findings
	}

	// CT-6.3: No signature found
	return []auditor.Finding{{
		CheckID:    c.ID(),
		Severity:   auditor.SeverityMedium,
		Message:    "No cosign signature found in registry",
		ServerName: target.Name,
		Location:   target.ConfigPath,
		Metadata: map[string]any{
			"checklist_id":  "CT-6.3",
			"display_title": "No cosign signature found in registry",
		},
	}}
}
