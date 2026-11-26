// Package scanner is the GUI-free entry point for a scan: it runs the
// extractor in text or file-digest mode and reports progress as events.
package scanner

import (
	"context"
	"sort"
	"strings"

	"github.com/labgeek/HashHarvest/internal/applog"
	"github.com/labgeek/HashHarvest/internal/extractor"
)

// loggerName is kept from the Python module so stored scan logs read the same.
const loggerName = "hashharvest.core.scanner"

// Event is one of Progress, Finding, FileSkipped, or Completed.
type Event any

// Progress is the percentage of files processed so far (0-100).
type Progress struct{ Percent int }

// Finding is one extracted hash. Hit.Line is 0 in file-digest mode.
type Finding struct {
	FilePath string
	FileType string
	extractor.Hit
}

// FileSkipped reports a file that could not be read or parsed.
type FileSkipped struct{ Message string }

// Completed is the terminal event with the scan's summary counts.
type Completed struct{ FilesScanned, HashesFound, SkippedFiles int }

// Result is the outcome of a scan.
type Result struct {
	Results extractor.Results
	Errors  []extractor.FileError
	Log     string
}

func (r *Result) FilesScanned() int { return len(r.Results) + len(r.Errors) }
func (r *Result) SkippedFiles() int { return len(r.Errors) }
func (r *Result) HashesFound() int {
	n := 0
	for _, hits := range r.Results {
		n += len(hits)
	}
	return n
}

// Scanner extracts hashes from a directory.
type Scanner struct {
	HashTypes []string // nil means all algorithms
	Mode      string   // "file" digests each file; anything else scans document text
}

// Scan walks dir and returns the result, calling onEvent (if non-nil) as it
// goes. It stops between files when ctx is cancelled and returns ctx's error.
func (s Scanner) Scan(ctx context.Context, dir string, onEvent func(Event)) (*Result, error) {
	emit := func(e Event) {
		if onEvent != nil {
			onEvent(e)
		}
	}
	cb := extractor.Callbacks{
		Progress: func(percent int) { emit(Progress{percent}) },
		Status:   func(message string) { emit(FileSkipped{message}) },
		Result: func(path, fileType string, hit extractor.Hit) {
			emit(Finding{path, fileType, hit})
		},
	}

	types := "all"
	if len(s.HashTypes) > 0 {
		sorted := append([]string(nil), s.HashTypes...)
		sort.Strings(sorted)
		types = strings.Join(sorted, ",")
	}
	stop := applog.Capture()
	applog.Info(loggerName, "Scan started: dir=%s mode=%s types=%s", dir, s.Mode, types)

	run := extractor.Extract
	if s.Mode == "file" {
		run = extractor.HashFiles
	}
	results, fileErrors, err := run(ctx, dir, s.HashTypes, cb)
	if err != nil {
		stop()
		return nil, err
	}
	result := &Result{Results: results, Errors: fileErrors}
	applog.Info(loggerName, "Scan complete: files=%d hashes=%d skipped=%d",
		result.FilesScanned(), result.HashesFound(), result.SkippedFiles())
	result.Log = stop()
	emit(Completed{result.FilesScanned(), result.HashesFound(), result.SkippedFiles()})
	return result, nil
}
