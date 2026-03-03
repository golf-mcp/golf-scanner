// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

import (
	"github.com/golf-mcp/golf-scanner/scanner"
)

// InventoryFromScanResults converts scanner results into ServerInventory items for auditing.
func InventoryFromScanResults(results []scanner.ScanResult) []ServerInventory {
	var inventory []ServerInventory
	for _, scan := range results {
		for _, server := range scan.Servers {
			inv := ServerInventory{
				Name:        getString(server, "name"),
				IDE:         scan.IDE,
				Scope:       scan.Scope,
				Transport:   getString(server, "transport"),
				Host:        getString(server, "host"),
				Cmd:         getString(server, "cmd"),
				Args:        getStringSlice(server, "args"),
				ConfigPath:  scan.ConfigPath,
				ProjectPath: scan.ProjectPath,
				Env:         getStringMap(server, "env"),
			}

			// Extract file metadata
			if v, ok := getInt(server, "file_mode"); ok {
				inv.FileMode = &v
			}
			if v, ok := getInt(server, "file_owner_uid"); ok {
				inv.FileOwnerUID = &v
			}
			inv.FileOwner = getString(server, "file_owner")

			if v, ok := getInt(server, "cmd_file_mode"); ok {
				inv.CmdFileMode = &v
			}
			inv.CmdFileOwner = getString(server, "cmd_file_owner")

			inventory = append(inventory, inv)
		}
	}
	return inventory
}

func getString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func getStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch val := v.(type) {
	case []string:
		return val
	case []any:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func getInt(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch val := v.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	}
	return 0, false
}

func getStringMap(m map[string]any, key string) map[string]string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch val := v.(type) {
	case map[string]string:
		return val
	case map[string]any:
		result := make(map[string]string, len(val))
		for k, v := range val {
			if s, ok := v.(string); ok {
				result[k] = s
			}
		}
		return result
	}
	return nil
}
