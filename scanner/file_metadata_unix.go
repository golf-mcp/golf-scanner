//go:build !windows

// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0


package scanner

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
)

// getFileMetadataPlatform returns Unix-specific file metadata.
func getFileMetadataPlatform(info os.FileInfo) *FileMetadata {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return &FileMetadata{
			FileMode: int(info.Mode().Perm()),
		}
	}

	owner := ""
	if u, err := user.LookupId(fmt.Sprintf("%d", stat.Uid)); err == nil {
		owner = u.Username
	}

	return &FileMetadata{
		FileMode:     int(info.Mode()),
		FileOwnerUID: int(stat.Uid),
		FileOwner:    owner,
	}
}
