package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/labgeek/HashHarvest/internal/db"
	"github.com/labgeek/HashHarvest/internal/extractor"
)

// scanInfo describes the scan behind the current results, for the manifest
// written with each export.
type scanInfo struct {
	Folder       string         `json:"folder"`
	ScannedAt    string         `json:"scanned_at"`
	Mode         string         `json:"mode"` // "text", "file" or "unknown"
	HashTypes    []string       `json:"hash_types"`
	FilesScanned int            `json:"files_scanned"`
	HashesFound  int            `json:"hashes_found"`
	SkippedFiles int            `json:"skipped_files"`
	Skipped      *[]SkippedFile `json:"skipped"` // nil when not recorded (scans loaded from history)
}

type exportManifest struct {
	Tool       string     `json:"tool"`
	Version    string     `json:"version"`
	ExportedAt string     `json:"exported_at"`
	Export     exportInfo `json:"export"`
	Scan       scanInfo   `json:"scan"`
}

type exportInfo struct {
	File   string `json:"file"`
	Format string `json:"format"`
	SHA256 string `json:"sha256"`
	Rows   int    `json:"rows"`
}

// manifestPath is where the manifest of an export at path is written.
func manifestPath(path string) string { return path + ".manifest.json" }

// writeManifest records which tool, version and scan produced the export at
// path, and the export's own SHA-256, so the file can be verified later.
func writeManifest(path, format string, results extractor.Results, scan scanInfo) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return err
	}
	rows := 0
	for _, hits := range results {
		rows += len(hits)
	}
	data, err := json.MarshalIndent(exportManifest{
		Tool:       "HashHarvest",
		Version:    version,
		ExportedAt: db.NowISO(),
		Export:     exportInfo{File: filepath.Base(path), Format: format, SHA256: hex.EncodeToString(h.Sum(nil)), Rows: rows},
		Scan:       scan,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath(path), append(data, '\n'), 0o644)
}

// modeOf infers the scan mode of stored results, which do not record it:
// file-digest mode stores only "file digest" rows.
func modeOf(results extractor.Results) string {
	mode := "unknown"
	for _, hits := range results {
		for _, h := range hits {
			if h.Context != "file digest" || h.Line != 0 {
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
