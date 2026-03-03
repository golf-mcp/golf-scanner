// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

import "testing"

func TestComputeIdentity_HTTPServer(t *testing.T) {
	id := ComputeIdentity("http", "https://example.com:8080/mcp", "", nil)
	if id.Type != "url" || id.Key != "https://example.com:8080/mcp" {
		t.Errorf("expected url identity, got %+v", id)
	}
}

func TestComputeIdentity_SSEServer(t *testing.T) {
	id := ComputeIdentity("sse", "http://localhost:3000", "", nil)
	if id.Type != "url" || id.Key != "http://localhost:3000" {
		t.Errorf("expected url identity, got %+v", id)
	}
}

func TestComputeIdentity_HTTPEmptyHost(t *testing.T) {
	id := ComputeIdentity("http", "", "", nil)
	// Falls through to command path with empty cmd
	if id.Type != "command" {
		t.Errorf("expected command identity for empty host, got %+v", id)
	}
}

func TestComputeIdentity_NpmPackage(t *testing.T) {
	tests := []struct {
		cmd  string
		args []string
		key  string
	}{
		{"npx", []string{"@modelcontextprotocol/server-github"}, "npm:@modelcontextprotocol/server-github"},
		{"npx", []string{"-y", "@modelcontextprotocol/server-github"}, "npm:@modelcontextprotocol/server-github"},
		{"npm", []string{"exec", "some-package"}, "npm:some-package"},
		{"bunx", []string{"mcp-server"}, "npm:mcp-server"},
		{"yarn", []string{"dlx", "my-pkg"}, "npm:my-pkg"},
		{"pnpm", []string{"dlx", "my-pkg"}, "npm:my-pkg"},
	}
	for _, tc := range tests {
		t.Run(tc.cmd+"_"+tc.key, func(t *testing.T) {
			id := ComputeIdentity("stdio", "", tc.cmd, tc.args)
			if id.Type != "package" || id.Key != tc.key {
				t.Errorf("expected package:%s, got %s:%s", tc.key, id.Type, id.Key)
			}
		})
	}
}

func TestComputeIdentity_NpmVersionStripping(t *testing.T) {
	tests := []struct {
		args []string
		key  string
	}{
		{[]string{"@scope/pkg@1.2.3"}, "npm:@scope/pkg"},
		{[]string{"express@4.18.2"}, "npm:express"},
		{[]string{"@mcp/server"}, "npm:@mcp/server"}, // no version
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			id := ComputeIdentity("stdio", "", "npx", tc.args)
			if id.Type != "package" || id.Key != tc.key {
				t.Errorf("expected package:%s, got %s:%s", tc.key, id.Type, id.Key)
			}
		})
	}
}

func TestComputeIdentity_PypiPackage(t *testing.T) {
	tests := []struct {
		cmd  string
		args []string
		key  string
	}{
		{"uvx", []string{"mcp-server-fetch"}, "pypi:mcp-server-fetch"},
		{"pipx", []string{"run", "mcp-server"}, "pypi:mcp-server"},
		{"uv", []string{"run", "my-tool"}, "pypi:my-tool"},
		{"pip", []string{"requests"}, "pypi:requests"},
	}
	for _, tc := range tests {
		t.Run(tc.cmd+"_"+tc.key, func(t *testing.T) {
			id := ComputeIdentity("stdio", "", tc.cmd, tc.args)
			if id.Type != "package" || id.Key != tc.key {
				t.Errorf("expected package:%s, got %s:%s", tc.key, id.Type, id.Key)
			}
		})
	}
}

func TestComputeIdentity_PypiVersionStripping(t *testing.T) {
	tests := []struct {
		args []string
		key  string
	}{
		{[]string{"requests>=2.28"}, "pypi:requests"},
		{[]string{"flask[async]@2.0"}, "pypi:flask"},
		{[]string{"mcp==1.0"}, "pypi:mcp"},
		{[]string{"mcp-server"}, "pypi:mcp-server"}, // no version
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			id := ComputeIdentity("stdio", "", "uvx", tc.args)
			if id.Type != "package" || id.Key != tc.key {
				t.Errorf("expected package:%s, got %s:%s", tc.key, id.Type, id.Key)
			}
		})
	}
}

func TestComputeIdentity_PypiFromFlag(t *testing.T) {
	// uvx --from package_name command_name
	id := ComputeIdentity("stdio", "", "uvx", []string{"--from", "my-package", "command"})
	if id.Type != "package" || id.Key != "pypi:my-package" {
		t.Errorf("expected pypi:my-package, got %s:%s", id.Type, id.Key)
	}

	// uvx --from=package_name command_name
	id = ComputeIdentity("stdio", "", "uvx", []string{"--from=other-pkg", "command"})
	if id.Type != "package" || id.Key != "pypi:other-pkg" {
		t.Errorf("expected pypi:other-pkg, got %s:%s", id.Type, id.Key)
	}
}

func TestComputeIdentity_Container(t *testing.T) {
	tests := []struct {
		cmd  string
		args []string
		key  string
	}{
		{"docker", []string{"run", "mcp/server"}, "docker:mcp/server"},
		{"podman", []string{"run", "--rm", "my-image:latest"}, "docker:my-image:latest"},
		{"nerdctl", []string{"run", "-e", "FOO=bar", "ghcr.io/org/image"}, "docker:ghcr.io/org/image"},
	}
	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			id := ComputeIdentity("stdio", "", tc.cmd, tc.args)
			if id.Type != "container" || id.Key != tc.key {
				t.Errorf("expected container:%s, got %s:%s", tc.key, id.Type, id.Key)
			}
		})
	}
}

func TestComputeIdentity_AbsolutePath(t *testing.T) {
	id := ComputeIdentity("stdio", "", "/usr/bin/my-server", nil)
	if id.Type != "command" || id.Key != "/usr/bin/my-server" {
		t.Errorf("expected command:/usr/bin/my-server, got %s:%s", id.Type, id.Key)
	}
}

func TestComputeIdentity_ScrubedArgs(t *testing.T) {
	id := ComputeIdentity("stdio", "", "npx", []string{"****"})
	if id.Type != "command" {
		t.Errorf("expected command fallback for scrubbed args, got %s", id.Type)
	}
}

func TestComputeIdentity_EmptyCmd(t *testing.T) {
	id := ComputeIdentity("stdio", "", "", nil)
	if id.Type != "command" || id.Key != "unknown" {
		t.Errorf("expected command:unknown, got %s:%s", id.Type, id.Key)
	}
}

func TestComputeIdentity_ExeSuffix(t *testing.T) {
	// Test .exe suffix stripping (cross-platform basename)
	id := ComputeIdentity("stdio", "", "npx.exe", []string{"@mcp/server"})
	if id.Type != "package" || id.Key != "npm:@mcp/server" {
		t.Errorf("expected package:npm:@mcp/server for npx.exe, got %s:%s", id.Type, id.Key)
	}
}

func TestComputeDisplayName_HTTP(t *testing.T) {
	tests := []struct {
		host     string
		expected string
	}{
		{"https://example.com:8080/api/mcp", "example.com/api"},
		{"https://firewall.sandbox.golf.dev/atlassian/mcp", "firewall.sandbox.golf.dev/atlassian"},
		{"http://localhost:3000", "localhost"},
		{"example.com", "example.com"},
		{"", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			name := ComputeDisplayName("http", tc.host, "", nil)
			if name != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, name)
			}
		})
	}
}

func TestComputeDisplayName_NpmPackage(t *testing.T) {
	name := ComputeDisplayName("stdio", "", "npx", []string{"-y", "@modelcontextprotocol/server-github"})
	if name != "@modelcontextprotocol/server-github" {
		t.Errorf("expected @modelcontextprotocol/server-github, got %q", name)
	}
}

func TestComputeDisplayName_Container(t *testing.T) {
	name := ComputeDisplayName("stdio", "", "docker", []string{"run", "--rm", "ghcr.io/org/mcp-server"})
	if name != "ghcr.io/org/mcp-server" {
		t.Errorf("expected ghcr.io/org/mcp-server, got %q", name)
	}
}

func TestComputeDisplayName_Interpreter(t *testing.T) {
	name := ComputeDisplayName("stdio", "", "python3", []string{"/path/to/server.py"})
	if name != "/path/to/server.py" {
		t.Errorf("expected /path/to/server.py, got %q", name)
	}
}

func TestComputeDisplayName_UnknownCommand(t *testing.T) {
	name := ComputeDisplayName("stdio", "", "my-tool", nil)
	if name != "my-tool" {
		t.Errorf("expected my-tool, got %q", name)
	}
}

func TestComputeDisplayName_ScrubedArgs(t *testing.T) {
	name := ComputeDisplayName("stdio", "", "npx", []string{"****"})
	if name != "npx" {
		t.Errorf("expected npx fallback for scrubbed args, got %q", name)
	}
}

func TestIdentityKey(t *testing.T) {
	id := ServerIdentity{Type: "package", Key: "npm:@mcp/server"}
	if id.IdentityKey() != "package:npm:@mcp/server" {
		t.Errorf("expected package:npm:@mcp/server, got %s", id.IdentityKey())
	}
}
