// Package manifest writes the sidecar file that records which tool,
// version and scan produced an export, with the export's own SHA-256.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/labgeek/HashHarvest/internal/db"
	"github.com/labgeek/HashHarvest/internal/extractor"
	"github.com/labgeek/HashHarvest/internal/version"
)

// SkippedFile is a file or folder a scan could not read, and why.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Scan describes the scan behind an export.
type Scan struct {
	Folder       string         `json:"folder"`
	ScannedAt    string         `json:"scanned_at"`
	Mode         string         `json:"mode"` // "text", "file" or "unknown"
	HashTypes    []string       `json:"hash_types"`
	FilesScanned int            `json:"files_scanned"`
	HashesFound  int            `json:"hashes_found"`
	SkippedFiles int            `json:"skipped_files"`
	Skipped      *[]SkippedFile `json:"skipped"` // nil when not recorded (scans loaded from history)
}

type document struct {
	Tool       string     `json:"tool"`
	Version    string     `json:"version"`
	ExportedAt string     `json:"exported_at"`
	Export     exportInfo `json:"export"`
	Scan       Scan       `json:"scan"`
}

type exportInfo struct {
	File   string `json:"file"`
	Format string `json:"format"`
	SHA256 string `json:"sha256"`
	Rows   int    `json:"rows"`
}

// Path is where the manifest of an export at path is written.
func Path(path string) string { return path + ".manifest.json" }

// Write writes the manifest of the export at path, which holds results in
// the given format ("CSV" or "JSON").
func Write(path, format string, results extractor.Results, scan Scan) error {
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
	data, err := json.MarshalIndent(document{
		Tool:       "HashHarvest",
		Version:    version.Version,
		ExportedAt: db.NowISO(),
		Export:     exportInfo{File: filepath.Base(path), Format: format, SHA256: hex.EncodeToString(h.Sum(nil)), Rows: rows},
		Scan:       scan,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(Path(path), append(data, '\n'), 0o644)
}
