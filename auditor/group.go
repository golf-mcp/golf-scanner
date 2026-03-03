// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

// ServerSource represents one IDE/config where a server was found.
type ServerSource struct {
	Name         string `json:"name"`
	IDE          string `json:"ide"`
	Scope        string `json:"scope"`
	ConfigPath   string `json:"config_path,omitempty"`
	ProjectPath  string `json:"project_path,omitempty"`
	FileMode     *int   `json:"-"`
	FileOwnerUID *int   `json:"-"`
	FileOwner    string `json:"-"`
	CmdFileMode  *int   `json:"-"`
	CmdFileOwner string `json:"-"`
}

// GroupedInventory represents a deduplicated server with all its source configs.
type GroupedInventory struct {
	Identity    ServerIdentity
	DisplayName string
	Canonical   ServerInventory // Used for audit checks (first occurrence)
	Sources     []ServerSource  // All places this server was found
}

// GroupInventory groups a flat list of ServerInventory by computed identity.
// Returns one GroupedInventory per unique identity, preserving discovery order.
func GroupInventory(inventory []ServerInventory) []GroupedInventory {
	type group struct {
		identity    ServerIdentity
		displayName string
		canonical   ServerInventory
		sources     []ServerSource
	}

	seen := make(map[string]int) // identityKey → index in groups
	var groups []group

	for _, inv := range inventory {
		id := ComputeIdentity(inv.Transport, inv.Host, inv.Cmd, inv.Args)
		key := id.IdentityKey()

		source := ServerSource{
			Name:         inv.Name,
			IDE:          inv.IDE,
			Scope:        inv.Scope,
			ConfigPath:   inv.ConfigPath,
			ProjectPath:  inv.ProjectPath,
			FileMode:     inv.FileMode,
			FileOwnerUID: inv.FileOwnerUID,
			FileOwner:    inv.FileOwner,
			CmdFileMode:  inv.CmdFileMode,
			CmdFileOwner: inv.CmdFileOwner,
		}

		if idx, exists := seen[key]; exists {
			groups[idx].sources = append(groups[idx].sources, source)
		} else {
			seen[key] = len(groups)
			groups = append(groups, group{
				identity:    id,
				displayName: ComputeDisplayName(inv.Transport, inv.Host, inv.Cmd, inv.Args),
				canonical:   inv,
				sources:     []ServerSource{source},
			})
		}
	}

	result := make([]GroupedInventory, len(groups))
	for i, g := range groups {
		result[i] = GroupedInventory{
			Identity:    g.identity,
			DisplayName: g.displayName,
			Canonical:   g.canonical,
			Sources:     g.sources,
		}
	}
	return result
}

// UniqueFileMetadataInstances returns ServerInventory instances with distinct
// file metadata within the group. Used for per-instance file permission checks.
// The canonical instance is always first in the returned slice.
func (g *GroupedInventory) UniqueFileMetadataInstances() []ServerInventory {
	type fkey struct {
		fileMode     int
		hasFileMode  bool
		cmdFileMode  int
		hasCmdMode   bool
		fileOwnerUID int
		hasOwnerUID  bool
	}

	mkKey := func(src ServerSource) fkey {
		var k fkey
		if src.FileMode != nil {
			k.fileMode = *src.FileMode
			k.hasFileMode = true
		}
		if src.CmdFileMode != nil {
			k.cmdFileMode = *src.CmdFileMode
			k.hasCmdMode = true
		}
		if src.FileOwnerUID != nil {
			k.fileOwnerUID = *src.FileOwnerUID
			k.hasOwnerUID = true
		}
		return k
	}

	seen := make(map[fkey]bool)
	var instances []ServerInventory

	// Always include canonical first
	if len(g.Sources) > 0 {
		ck := mkKey(g.Sources[0])
		seen[ck] = true
	}
	instances = append(instances, g.Canonical)

	// Check remaining sources for different file metadata
	for _, src := range g.Sources[1:] {
		fk := mkKey(src)
		if !seen[fk] {
			seen[fk] = true
			// Build an inventory with the different file metadata
			inv := g.Canonical
			inv.Name = src.Name
			inv.IDE = src.IDE
			inv.Scope = src.Scope
			inv.ConfigPath = src.ConfigPath
			inv.ProjectPath = src.ProjectPath
			inv.FileMode = src.FileMode
			inv.FileOwnerUID = src.FileOwnerUID
			inv.FileOwner = src.FileOwner
			inv.CmdFileMode = src.CmdFileMode
			inv.CmdFileOwner = src.CmdFileOwner
			instances = append(instances, inv)
		}
	}

	return instances
}
