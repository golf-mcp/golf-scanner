// Copyright 2026 Golf
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// PrintJSON writes the audit report as formatted JSON.
func PrintJSON(w io.Writer, rpt Report) error {
	data, err := json.MarshalIndent(rpt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling report: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
