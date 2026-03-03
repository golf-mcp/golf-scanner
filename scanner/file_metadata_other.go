//go:build windows

// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0


package scanner

import "os"

// getFileMetadataPlatform returns platform-agnostic file metadata on Windows.
func getFileMetadataPlatform(info os.FileInfo) *FileMetadata {
	return &FileMetadata{
		FileMode: int(info.Mode().Perm()),
	}
}
