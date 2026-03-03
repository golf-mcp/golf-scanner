// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

import "testing"

func TestGroupInventory_DuplicatesAcrossIDEs(t *testing.T) {
	inventory := []ServerInventory{
		{Name: "github", IDE: "Claude", Scope: "user", Transport: "stdio", Cmd: "npx", Args: []string{"@modelcontextprotocol/server-github"}, ConfigPath: "/claude/config.json"},
		{Name: "github-mcp", IDE: "Cursor", Scope: "user", Transport: "stdio", Cmd: "npx", Args: []string{"@modelcontextprotocol/server-github"}, ConfigPath: "/cursor/config.json"},
		{Name: "github", IDE: "VSCode", Scope: "user", Transport: "stdio", Cmd: "npx", Args: []string{"@modelcontextprotocol/server-github"}, ConfigPath: "/vscode/settings.json"},
	}

	groups := GroupInventory(inventory)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}

	g := groups[0]
	if g.Identity.Type != "package" || g.Identity.Key != "npm:@modelcontextprotocol/server-github" {
		t.Errorf("unexpected identity: %+v", g.Identity)
	}
	if len(g.Sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(g.Sources))
	}
	if g.Sources[0].IDE != "Claude" || g.Sources[1].IDE != "Cursor" || g.Sources[2].IDE != "VSCode" {
		t.Errorf("unexpected source IDEs: %v, %v, %v", g.Sources[0].IDE, g.Sources[1].IDE, g.Sources[2].IDE)
	}
}

func TestGroupInventory_DifferentServers(t *testing.T) {
	inventory := []ServerInventory{
		{Name: "github", IDE: "Claude", Transport: "stdio", Cmd: "npx", Args: []string{"@modelcontextprotocol/server-github"}},
		{Name: "fetch", IDE: "Claude", Transport: "stdio", Cmd: "uvx", Args: []string{"mcp-server-fetch"}},
	}

	groups := GroupInventory(inventory)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

func TestGroupInventory_SamePackageDifferentFlags(t *testing.T) {
	// Same package with different flags (e.g., -y flag) should still group
	inventory := []ServerInventory{
		{Name: "github", IDE: "Claude", Transport: "stdio", Cmd: "npx", Args: []string{"-y", "@mcp/server"}},
		{Name: "github", IDE: "Cursor", Transport: "stdio", Cmd: "npx", Args: []string{"@mcp/server"}},
	}

	groups := GroupInventory(inventory)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group (flags should be skipped for identity), got %d", len(groups))
	}
	if len(groups[0].Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(groups[0].Sources))
	}
}

func TestGroupInventory_MixedTransports(t *testing.T) {
	inventory := []ServerInventory{
		{Name: "github", IDE: "Claude", Transport: "stdio", Cmd: "npx", Args: []string{"@mcp/server"}},
		{Name: "api", IDE: "Claude", Transport: "http", Host: "http://localhost:3000"},
	}

	groups := GroupInventory(inventory)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups for different transports, got %d", len(groups))
	}
}

func TestGroupInventory_Empty(t *testing.T) {
	groups := GroupInventory(nil)
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(groups))
	}
}

func TestGroupInventory_SingleServer(t *testing.T) {
	inventory := []ServerInventory{
		{Name: "server", IDE: "Claude", Transport: "stdio", Cmd: "npx", Args: []string{"@mcp/server"}},
	}

	groups := GroupInventory(inventory)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if len(groups[0].Sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(groups[0].Sources))
	}
}

func TestGroupInventory_PreservesDiscoveryOrder(t *testing.T) {
	inventory := []ServerInventory{
		{Name: "b-server", IDE: "Claude", Transport: "stdio", Cmd: "npx", Args: []string{"b-pkg"}},
		{Name: "a-server", IDE: "Claude", Transport: "stdio", Cmd: "npx", Args: []string{"a-pkg"}},
	}

	groups := GroupInventory(inventory)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].DisplayName != "b-pkg" {
		t.Errorf("expected first group to be b-pkg (discovery order), got %s", groups[0].DisplayName)
	}
	if groups[1].DisplayName != "a-pkg" {
		t.Errorf("expected second group to be a-pkg (discovery order), got %s", groups[1].DisplayName)
	}
}

func TestGroupInventory_DisplayName(t *testing.T) {
	inventory := []ServerInventory{
		{Name: "github", IDE: "Claude", Transport: "stdio", Cmd: "npx", Args: []string{"@modelcontextprotocol/server-github"}},
	}

	groups := GroupInventory(inventory)
	if groups[0].DisplayName != "@modelcontextprotocol/server-github" {
		t.Errorf("expected display name @modelcontextprotocol/server-github, got %s", groups[0].DisplayName)
	}
}

func TestGroupInventory_CanonicalIsFirst(t *testing.T) {
	inventory := []ServerInventory{
		{Name: "first", IDE: "Claude", Transport: "stdio", Cmd: "npx", Args: []string{"@mcp/server"}, ConfigPath: "/first"},
		{Name: "second", IDE: "Cursor", Transport: "stdio", Cmd: "npx", Args: []string{"@mcp/server"}, ConfigPath: "/second"},
	}

	groups := GroupInventory(inventory)
	if groups[0].Canonical.ConfigPath != "/first" {
		t.Errorf("canonical should be the first occurrence, got %s", groups[0].Canonical.ConfigPath)
	}
}

func TestUniqueFileMetadataInstances_AllSame(t *testing.T) {
	mode := 0644
	g := GroupedInventory{
		Canonical: ServerInventory{Name: "server", Cmd: "npx", FileMode: &mode},
		Sources: []ServerSource{
			{Name: "s1", FileMode: &mode},
			{Name: "s2", FileMode: &mode},
		},
	}

	instances := g.UniqueFileMetadataInstances()
	if len(instances) != 1 {
		t.Errorf("expected 1 unique instance (all same metadata), got %d", len(instances))
	}
}

func TestUniqueFileMetadataInstances_Different(t *testing.T) {
	mode1 := 0644
	mode2 := 0755
	g := GroupedInventory{
		Canonical: ServerInventory{Name: "server", Cmd: "npx", FileMode: &mode1},
		Sources: []ServerSource{
			{Name: "s1", FileMode: &mode1},
			{Name: "s2", FileMode: &mode2},
		},
	}

	instances := g.UniqueFileMetadataInstances()
	if len(instances) != 2 {
		t.Errorf("expected 2 unique instances (different file modes), got %d", len(instances))
	}
	// Canonical should be first
	if instances[0].Name != "server" {
		t.Errorf("expected canonical first, got %s", instances[0].Name)
	}
}

func TestUniqueFileMetadataInstances_NilMetadata(t *testing.T) {
	mode := 0644
	g := GroupedInventory{
		Canonical: ServerInventory{Name: "server", Cmd: "npx"},
		Sources: []ServerSource{
			{Name: "s1"},          // nil file mode
			{Name: "s2", FileMode: &mode}, // has file mode
		},
	}

	instances := g.UniqueFileMetadataInstances()
	if len(instances) != 2 {
		t.Errorf("expected 2 unique instances (nil vs non-nil), got %d", len(instances))
	}
}

func TestGroupInventory_SourcePreservesFileMetadata(t *testing.T) {
	mode := 0644
	uid := 1000
	inventory := []ServerInventory{
		{Name: "server", IDE: "Claude", Transport: "stdio", Cmd: "npx", Args: []string{"@mcp/server"}, FileMode: &mode, FileOwnerUID: &uid, FileOwner: "user1"},
	}

	groups := GroupInventory(inventory)
	src := groups[0].Sources[0]
	if src.FileMode == nil || *src.FileMode != 0644 {
		t.Errorf("expected FileMode 0644 preserved in source")
	}
	if src.FileOwnerUID == nil || *src.FileOwnerUID != 1000 {
		t.Errorf("expected FileOwnerUID 1000 preserved in source")
	}
	if src.FileOwner != "user1" {
		t.Errorf("expected FileOwner user1 preserved in source")
	}
}
