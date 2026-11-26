package main

import (
	"strings"

	"github.com/labgeek/HashHarvest/internal/extractor"
	"github.com/labgeek/HashHarvest/internal/manifest"
)

// SkippedFile is a file or folder a scan could not read, and why.
type SkippedFile = manifest.SkippedFile

// modeOf infers the scan mode of stored results, which do not record it:
// file-digest mode stores only digest rows.
func modeOf(results extractor.Results) string {
	mode := "unknown"
	for _, hits := range results {
		for _, h := range hits {
			if h.Context != extractor.DigestContext || h.Line != 0 {
				return "text"
			}
			mode = "file"
		}
	}
	return mode
}

func splitTypes(types string) []string {
	if types == "" {
		return []string{}
	}
	return strings.Split(types, ",")
}
