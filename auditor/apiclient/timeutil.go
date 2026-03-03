// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package apiclient

import "time"

// commonTimeFormats are the time formats used by npm and PyPI registries.
var commonTimeFormats = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.000Z",
}

// parseTime attempts to parse a time string using the given formats.
// Returns nil if none of the formats match.
func parseTime(s string, formats []string) *time.Time {
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return &t
		}
	}
	return nil
}
