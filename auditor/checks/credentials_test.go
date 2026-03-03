// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"strings"
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
)

func runCredentialCheck(inv auditor.ServerInventory) ([]auditor.Finding, auditor.Severity) {
	check := &CredentialDetectionCheck{}
	ctx := makeCtx(inv)
	findings := check.Run(ctx)
	worst := auditor.SeveritySkip
	for _, f := range findings {
		if auditor.SeverityRank(f.Severity) > auditor.SeverityRank(worst) {
			worst = f.Severity
		}
	}
	return findings, worst
}

// --- Scrubbed credentials ---

func TestCredentials_ScrubbedToken(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"server", "--token", "****"},
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for scrubbed --token, got %s", sev)
	}
}

func TestCredentials_ScrubbedAPIKey(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"server", "--api-key", "****"},
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for scrubbed --api-key, got %s", sev)
	}
}

func TestCredentials_AllSensitiveFlags(t *testing.T) {
	flags := []string{
		"--api-key", "--token", "--secret", "--dsn", "--password",
		"--credentials", "--auth", "--key", "--pass", "--private-key",
		"--cert", "--api-token", "--access-key", "--secret-key",
	}
	for _, flag := range flags {
		t.Run(flag, func(t *testing.T) {
			_, sev := runCredentialCheck(auditor.ServerInventory{
				Cmd: "npx", Args: []string{"server", flag, "****"},
			})
			if sev != auditor.SeverityCritical {
				t.Errorf("expected CRITICAL for scrubbed %s, got %s", flag, sev)
			}
		})
	}
}

// --- Regex patterns ---

func TestCredentials_AWSAccessKey(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"AKIAIOSFODNN7EXAMPLE"},
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for AWS key, got %s", sev)
	}
}

func TestCredentials_GitHubTokenVariants(t *testing.T) {
	tokens := []string{
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",  // Personal
		"gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",  // OAuth
		"ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",  // User-to-server
		"ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",  // Server-to-server
	}
	for _, tok := range tokens {
		t.Run(tok[:4], func(t *testing.T) {
			_, sev := runCredentialCheck(auditor.ServerInventory{
				Cmd: "npx", Args: []string{tok},
			})
			if sev != auditor.SeverityCritical {
				t.Errorf("expected CRITICAL for %s, got %s", tok[:4], sev)
			}
		})
	}
}

func TestCredentials_StripeKey(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWX"},
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for Stripe key, got %s", sev)
	}
}

func TestCredentials_SlackToken(t *testing.T) {
	tokens := []string{
		"xoxb-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"xoxp-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"xoxs-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"xoxa-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"xoxr-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	}
	for _, tok := range tokens {
		t.Run(tok[:5], func(t *testing.T) {
			_, sev := runCredentialCheck(auditor.ServerInventory{
				Cmd: "npx", Args: []string{tok},
			})
			if sev != auditor.SeverityCritical {
				t.Errorf("expected CRITICAL for Slack token %s, got %s", tok[:5], sev)
			}
		})
	}
}

func TestCredentials_OpenAIKey(t *testing.T) {
	// 48+ characters after sk-
	key := "sk-" + strings.Repeat("A", 48)
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{key},
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for OpenAI key, got %s", sev)
	}
}

func TestCredentials_AnthropicKey(t *testing.T) {
	// 90+ chars after sk-ant-
	key := "sk-ant-" + strings.Repeat("A", 90)
	findings, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{key},
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for Anthropic key, got %s", sev)
	}
	// Verify it's classified as anthropic-key, not openai-key
	msg := findings[0].Message
	if !strings.Contains(msg, "anthropic-key") {
		t.Errorf("expected anthropic-key in message, got: %s", msg)
	}
	if strings.Contains(msg, "openai-key") {
		t.Errorf("anthropic key misclassified as openai-key: %s", msg)
	}
}

func TestCredentials_GoogleAPIKey(t *testing.T) {
	// Google API keys are AIza + 35 alphanumeric/dash/underscore characters
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"AIzaSyA01234567890123456789012345678abc"},
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for Google API key, got %s", sev)
	}
}

func TestCredentials_GitLabToken(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"glpat-ABCDEFGHIJKLMNOPQRST"},
	})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for GitLab token, got %s", sev)
	}
}

func TestCredentials_JWTToken(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{jwt},
	})
	if sev != auditor.SeverityHigh {
		t.Errorf("expected HIGH for JWT, got %s", sev)
	}
}

func TestCredentials_CredentialsInURL(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Transport: "http",
		Host:      "http://admin:s3cret@example.com",
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for credentials in URL, got %s", sev)
	}
}

func TestCredentials_GenericAPIKey(t *testing.T) {
	key := "sk-" + strings.Repeat("a", 20)
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{key},
	})
	// Could be CRITICAL (matches openai-key pattern) or MEDIUM (generic)
	if sev == auditor.SeverityNote || sev == auditor.SeveritySkip {
		t.Errorf("expected at least MEDIUM for generic API key, got %s", sev)
	}
}

// --- Environment variable scanning ---

func TestCredentials_EnvSensitiveKey(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd:  "npx",
		Args: []string{"server"},
		Env:  map[string]string{"API_KEY": "****"},
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for scrubbed env API_KEY, got %s", sev)
	}
}

func TestCredentials_EnvTokenKey(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd:  "npx",
		Args: []string{"server"},
		Env:  map[string]string{"GITHUB_TOKEN": "****"},
	})
	if sev != auditor.SeverityCritical {
		t.Errorf("expected CRITICAL for scrubbed env GITHUB_TOKEN, got %s", sev)
	}
}

func TestCredentials_EnvVarReference(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd:  "npx",
		Args: []string{"server"},
		Env:  map[string]string{"API_KEY": "${API_KEY}"},
	})
	if sev != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM for env var reference, got %s", sev)
	}
}

func TestCredentials_EnvNonSensitive(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd:  "npx",
		Args: []string{"server"},
		Env:  map[string]string{"NODE_ENV": "production"},
	})
	if sev != auditor.SeverityNote {
		t.Errorf("expected NOTE for non-sensitive env, got %s", sev)
	}
}

// --- Clean cases ---

func TestCredentials_CleanArgs(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"@modelcontextprotocol/server-github"},
	})
	if sev != auditor.SeverityNote {
		t.Errorf("expected NOTE for clean args, got %s", sev)
	}
}

func TestCredentials_NoArgsNoHostNoEnv(t *testing.T) {
	_, sev := runCredentialCheck(auditor.ServerInventory{Cmd: "npx"})
	if sev != auditor.SeveritySkip {
		t.Errorf("expected SKIP for no args/host/env, got %s", sev)
	}
}

func TestCredentials_FlagWithEnvVarValue(t *testing.T) {
	// --token followed by an env var reference is MEDIUM, not CRITICAL
	_, sev := runCredentialCheck(auditor.ServerInventory{
		Cmd: "npx", Args: []string{"server", "--token", "${GITHUB_TOKEN}"},
	})
	if sev != auditor.SeverityMedium {
		t.Errorf("expected MEDIUM for env var reference in flag, got %s", sev)
	}
}
