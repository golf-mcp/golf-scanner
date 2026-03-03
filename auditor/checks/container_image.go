// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golf-mcp/golf-scanner/auditor"
	"github.com/golf-mcp/golf-scanner/auditor/httpclient"
)

// rekorAPIURL is the public Sigstore transparency log API.
const rekorAPIURL = "https://rekor.sigstore.dev/api/v1"

// ContainerImageCheck checks container image pinning and Sigstore attestation (CT-3.x, CT-4.x).
type ContainerImageCheck struct{}

func (c *ContainerImageCheck) ID() string           { return "container.image" }
func (c *ContainerImageCheck) Name() string          { return "Container image security" }
func (c *ContainerImageCheck) RequiresOnline() bool   { return true }

func (c *ContainerImageCheck) Run(ctx *auditor.AuditContext) []auditor.Finding {
	if ctx.GetServerType() != auditor.ServerTypeContainer {
		return []auditor.Finding{skipFinding(c.ID(), "CT-3.1", "Not a container server", ctx.Target)}
	}

	target := ctx.Target
	imageRef := ExtractContainerImageRef(target.Args)
	if imageRef == "" {
		return []auditor.Finding{{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "Could not extract container image reference",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "CT-3.1"},
		}}
	}

	ctx.SetExtension("container.image_ref", imageRef)

	var findings []auditor.Finding

	if strings.Contains(imageRef, "@sha256:") {
		// Pinned by digest - best practice
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityNote,
			Message:    "Image uses SHA256 digest pinning",
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata:   map[string]any{"checklist_id": "CT-3.1", "image": imageRef},
		})

		// CT-4.x: Check Sigstore attestation
		_, digest, _ := strings.Cut(imageRef, "@sha256:")
		attestationEntries := checkSigstoreAttestation(digest)
		ctx.SetExtension("container.attestation", attestationEntries)

		if len(attestationEntries) > 0 {
			findings = append(findings, auditor.Finding{
				CheckID:    c.ID(),
				Severity:   auditor.SeverityNote,
				Message:    "Image has Sigstore attestation verified",
				ServerName: target.Name,
				Location:   target.ConfigPath,
				Metadata: map[string]any{
					"checklist_id":        "CT-4.1",
					"attestation_entries": len(attestationEntries),
				},
			})
		} else {
			findings = append(findings, auditor.Finding{
				CheckID:    c.ID(),
				Severity:   auditor.SeverityNote,
				Message:    "No Sigstore attestation found for image",
				ServerName: target.Name,
				Location:   target.ConfigPath,
				Metadata: map[string]any{
					"checklist_id":  "CT-4.2",
					"display_title": "No Sigstore attestation",
				},
			})
		}

	} else if strings.Contains(imageRef, ":") && !strings.HasSuffix(imageRef, ":latest") {
		// Mutable tag
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityMedium,
			Message:    fmt.Sprintf("Image uses mutable tag: %s", imageRef),
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"checklist_id":  "CT-3.2",
				"display_title": fmt.Sprintf("Image not pinned: %s", imageRef),
				"description":   "Use @sha256:... digest to ensure immutability",
				"image":         imageRef,
			},
		})
		ctx.SetExtension("container.attestation", nil)

	} else {
		// Implicit :latest tag
		findings = append(findings, auditor.Finding{
			CheckID:    c.ID(),
			Severity:   auditor.SeverityMedium,
			Message:    fmt.Sprintf("Image uses implicit :latest tag: %s", imageRef),
			ServerName: target.Name,
			Location:   target.ConfigPath,
			Metadata: map[string]any{
				"checklist_id":  "CT-3.3",
				"display_title": fmt.Sprintf("Image not pinned: %s", imageRef),
				"description":   "Using :latest tag - specify version or @sha256:... digest",
				"image":         imageRef,
			},
		})
		ctx.SetExtension("container.attestation", nil)
	}

	return findings
}

// ExtractContainerImageRef extracts the container image reference from docker/podman args.
func ExtractContainerImageRef(args []string) string {
	if len(args) == 0 {
		return ""
	}

	subcommands := map[string]bool{"run": true, "create": true}

	flagsWithValues := map[string]bool{
		"-v": true, "--volume": true, "-e": true, "--env": true,
		"-p": true, "--publish": true, "-w": true, "--workdir": true,
		"-u": true, "--user": true, "-m": true, "--memory": true,
		"--name": true, "--network": true, "--entrypoint": true,
		"--platform": true, "--cpus": true, "--cap-add": true,
		"--cap-drop": true, "-l": true, "--label": true,
		"--mount": true, "--device": true, "--security-opt": true,
		"--ulimit": true, "--pid": true, "--ipc": true,
		"--uts": true, "--cgroupns": true, "--hostname": true,
		"-h": true, "--dns": true, "--dns-search": true,
		"--add-host": true, "--expose": true, "--link": true,
		"--log-driver": true, "--log-opt": true, "--restart": true,
		"--stop-signal": true, "--stop-timeout": true, "--shm-size": true,
		"--tmpfs": true, "--group-add": true, "--userns": true,
		"--runtime": true, "--annotation": true, "--env-file": true,
		"--cidfile": true, "--health-cmd": true, "--health-interval": true,
		"--health-retries": true, "--health-start-period": true,
		"--health-timeout": true, "--cgroup-parent": true,
		"--cpu-period": true, "--cpu-quota": true, "--cpu-shares": true,
		"-c": true, "--cpuset-cpus": true, "--cpuset-mems": true,
		"--gpus": true, "--ip": true, "--ip6": true,
		"--mac-address": true, "--memory-swap": true, "--pids-limit": true,
		"--sysctl": true,
	}

	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		if subcommands[strings.ToLower(arg)] {
			continue
		}

		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "=") {
				continue
			}
			// The arg does not contain "=" here (the "=" case continues above)
			if flagsWithValues[arg] {
				skipNext = true
			}
			continue
		}

		return arg
	}

	return ""
}

// checkSigstoreAttestation checks Rekor for image attestations.
// Returns nil for both "no attestation" and "error fetching".
// This is intentional: attestation is informational, not a security gate.
func checkSigstoreAttestation(digest string) []string {
	body, status, err := httpclient.PostJSON(
		rekorAPIURL+"/index/retrieve",
		map[string]string{"hash": "sha256:" + digest},
	)
	if err != nil || status != 200 {
		return nil
	}

	var entries []string
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}
	if len(entries) > 0 {
		return entries
	}
	return nil
}
