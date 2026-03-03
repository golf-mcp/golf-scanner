// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package checks

import (
	"testing"

	"github.com/golf-mcp/golf-scanner/auditor"
)

func TestServerType_AllPackageManagers(t *testing.T) {
	check := &ServerTypeCheck{}
	commands := []string{"npx", "npm", "bunx", "bun", "yarn", "pnpm", "pip", "pipx", "uvx", "uv"}
	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			ctx := makeCtx(auditor.ServerInventory{Transport: "stdio", Cmd: cmd, Args: []string{"some-pkg"}})
			check.Run(ctx)
			if ctx.GetServerType() != auditor.ServerTypePackageManager {
				t.Errorf("expected package_manager, got %s", ctx.GetServerType())
			}
		})
	}
}

func TestServerType_AllContainerRuntimes(t *testing.T) {
	check := &ServerTypeCheck{}
	commands := []string{"docker", "podman", "nerdctl"}
	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			ctx := makeCtx(auditor.ServerInventory{Transport: "stdio", Cmd: cmd, Args: []string{"run", "img"}})
			check.Run(ctx)
			if ctx.GetServerType() != auditor.ServerTypeContainer {
				t.Errorf("expected container, got %s", ctx.GetServerType())
			}
		})
	}
}

func TestServerType_AllInterpreters(t *testing.T) {
	check := &ServerTypeCheck{}
	commands := []string{"python", "python3", "python2", "node", "nodejs", "ruby", "perl", "bash", "sh", "zsh", "php", "lua"}
	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			ctx := makeCtx(auditor.ServerInventory{Transport: "stdio", Cmd: cmd, Args: []string{"script.py"}})
			check.Run(ctx)
			if ctx.GetServerType() != auditor.ServerTypeScript {
				t.Errorf("expected script, got %s", ctx.GetServerType())
			}
		})
	}
}

func TestServerType_AbsoluteBinaryPath(t *testing.T) {
	check := &ServerTypeCheck{}
	paths := []string{"/usr/local/bin/myserver", "/opt/mcp/server", "/home/user/bin/tool"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			ctx := makeCtx(auditor.ServerInventory{Transport: "stdio", Cmd: p})
			check.Run(ctx)
			if ctx.GetServerType() != auditor.ServerTypeBinary {
				t.Errorf("expected binary, got %s", ctx.GetServerType())
			}
		})
	}
}

func TestServerType_WindowsBinaryPath(t *testing.T) {
	check := &ServerTypeCheck{}
	ctx := makeCtx(auditor.ServerInventory{Transport: "stdio", Cmd: "C:/Program Files/mcp/server.exe"})
	check.Run(ctx)
	if ctx.GetServerType() != auditor.ServerTypeBinary {
		t.Errorf("expected binary, got %s", ctx.GetServerType())
	}
}

func TestServerType_UnknownStdio(t *testing.T) {
	check := &ServerTypeCheck{}
	ctx := makeCtx(auditor.ServerInventory{Transport: "stdio", Cmd: "unknown-command"})
	check.Run(ctx)
	if ctx.GetServerType() != auditor.ServerTypeUnknownStdio {
		t.Errorf("expected unknown_stdio, got %s", ctx.GetServerType())
	}
}

func TestServerType_LocalhostVariants(t *testing.T) {
	check := &ServerTypeCheck{}
	hosts := []string{
		"http://localhost:3000",
		"http://127.0.0.1:8080",
		"http://[::1]:9090",
		"http://0.0.0.0:4000",
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			ctx := makeCtx(auditor.ServerInventory{Transport: "http", Host: host})
			check.Run(ctx)
			if ctx.GetServerType() != auditor.ServerTypeLocalHTTP {
				t.Errorf("expected local_http, got %s", ctx.GetServerType())
			}
		})
	}
}

func TestServerType_PrivateIPs(t *testing.T) {
	check := &ServerTypeCheck{}
	hosts := []string{
		"http://10.0.0.5:8080",
		"http://172.16.0.1:3000",
		"http://192.168.1.100:9090",
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			ctx := makeCtx(auditor.ServerInventory{Transport: "http", Host: host})
			check.Run(ctx)
			if ctx.GetServerType() != auditor.ServerTypeLocalHTTP {
				t.Errorf("expected local_http, got %s", ctx.GetServerType())
			}
		})
	}
}

func TestServerType_EmptyHost(t *testing.T) {
	check := &ServerTypeCheck{}
	ctx := makeCtx(auditor.ServerInventory{Transport: "http", Host: ""})
	check.Run(ctx)
	if ctx.GetServerType() != auditor.ServerTypeUnreachable {
		t.Errorf("expected unreachable, got %s", ctx.GetServerType())
	}
}

func TestServerType_SSETransport(t *testing.T) {
	check := &ServerTypeCheck{}
	ctx := makeCtx(auditor.ServerInventory{Transport: "sse", Host: "http://localhost:3000"})
	check.Run(ctx)
	if ctx.GetServerType() != auditor.ServerTypeLocalHTTP {
		t.Errorf("expected local_http for SSE localhost, got %s", ctx.GetServerType())
	}
}

func TestServerType_UnknownTransport(t *testing.T) {
	check := &ServerTypeCheck{}
	ctx := makeCtx(auditor.ServerInventory{Transport: "grpc", Host: "localhost:3000"})
	check.Run(ctx)
	if ctx.GetServerType() != auditor.ServerTypeUnknown {
		t.Errorf("expected unknown, got %s", ctx.GetServerType())
	}
}

func TestServerType_PackageManagerSetsExtension(t *testing.T) {
	check := &ServerTypeCheck{}
	ctx := makeCtx(auditor.ServerInventory{Transport: "stdio", Cmd: "npx", Args: []string{"pkg"}})
	check.Run(ctx)
	// Package manager type sets extension
	st := ctx.GetServerType()
	if st != auditor.ServerTypePackageManager {
		t.Errorf("expected package_manager extension, got %s", st)
	}
}

func TestServerType_SetsMCPCommand(t *testing.T) {
	check := &ServerTypeCheck{}
	ctx := makeCtx(auditor.ServerInventory{Transport: "stdio", Cmd: "/usr/bin/myserver", Args: []string{"--port", "3001"}})
	check.Run(ctx)
	cmd, ok := ctx.GetExtension("mcp.command")
	if !ok {
		t.Fatal("expected mcp.command extension to be set")
	}
	if cmd != "/usr/bin/myserver --port 3001" {
		t.Errorf("expected '/usr/bin/myserver --port 3001', got %s", cmd)
	}
}

func TestServerType_CaseInsensitiveBasename(t *testing.T) {
	check := &ServerTypeCheck{}
	// On Windows, executables might be NPX.EXE
	ctx := makeCtx(auditor.ServerInventory{Transport: "stdio", Cmd: "/usr/bin/NPX.exe", Args: []string{"pkg"}})
	check.Run(ctx)
	if ctx.GetServerType() != auditor.ServerTypePackageManager {
		t.Errorf("expected package_manager for NPX.exe, got %s", ctx.GetServerType())
	}
}

func TestServerType_HTTPSPublic(t *testing.T) {
	check := &ServerTypeCheck{}
	ctx := makeCtx(auditor.ServerInventory{Transport: "http", Host: "https://1.2.3.4:443"})
	check.Run(ctx)
	st := ctx.GetServerType()
	if st != auditor.ServerTypePublicHTTP {
		t.Errorf("expected public_http for public IP, got %s", st)
	}
	// HTTPS should produce NOTE severity
	findings := check.Run(makeCtx(auditor.ServerInventory{Transport: "http", Host: "https://1.2.3.4:443"}))
	if findings[0].Severity != auditor.SeverityNote {
		t.Errorf("expected NOTE for HTTPS public, got %s", findings[0].Severity)
	}
}

func TestServerType_HTTPPublicNoTLS(t *testing.T) {
	check := &ServerTypeCheck{}
	ctx := makeCtx(auditor.ServerInventory{Transport: "http", Host: "http://1.2.3.4:80"})
	check.Run(ctx)
	findings := check.Run(makeCtx(auditor.ServerInventory{Transport: "http", Host: "http://1.2.3.4:80"}))
	if findings[0].Severity != auditor.SeverityHigh {
		t.Errorf("expected HIGH for HTTP public (no TLS), got %s", findings[0].Severity)
	}
}
