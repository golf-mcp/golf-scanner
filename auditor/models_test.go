// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package auditor

import "testing"

func TestServerTypeDisplayName(t *testing.T) {
	tests := []struct {
		st       ServerType
		expected string
	}{
		{ServerTypePackageManager, "Package Manager"},
		{ServerTypeContainer, "Container"},
		{ServerTypeBinary, "Local Binary"},
		{ServerTypeScript, "Script"},
		{ServerTypeUnknownStdio, "Unknown Command"},
		{ServerTypeLocalHTTP, "Local Network"},
		{ServerTypePublicHTTP, "Public Server"},
		{ServerTypeUnreachable, "Unreachable"},
		{ServerTypeUnknown, "Unknown"},
		{ServerType("something_else"), "Unknown"},
	}
	for _, tc := range tests {
		got := tc.st.DisplayName()
		if got != tc.expected {
			t.Errorf("ServerType(%q).DisplayName() = %q, want %q", tc.st, got, tc.expected)
		}
	}
}
