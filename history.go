package main

// The Scan History dialog: listing, loading and reading stored scans.

import (
	"fmt"
	"strings"
	"time"

	"github.com/labgeek/HashHarvest/internal/db"
	"github.com/labgeek/HashHarvest/internal/extractor"
	"github.com/labgeek/HashHarvest/internal/manifest"
)

// timeRanges are the Scan History choices; -1 days means all time.
var timeRanges = []struct {
	Label string
	Days  int
}{{"Today", 0}, {"Last 7 days", 7}, {"Last 30 days", 30}, {"Last 90 days", 90}, {"All time", -1}}

// TimeRanges lists the Scan History filter labels; index 2 is the default.
func (a *App) TimeRanges() []string {
	labels := make([]string, len(timeRanges))
	for i, r := range timeRanges {
		labels[i] = r.Label
	}
	return labels
}

// since returns the ISO lower bound for a time-range index ("" = all time).
// "N days ago" keeps the wall-clock time across daylight-saving changes, as
// stored timestamps are compared by their local date and time.
func since(index int, now time.Time) string {
	if index < 0 || index >= len(timeRanges) || timeRanges[index].Days < 0 {
		return ""
	}
	if days := timeRanges[index].Days; days > 0 {
		return db.ISO(now.AddDate(0, 0, -days))
	}
	return db.ISO(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()))
}

// HistoryRow is one line of the Scan History table.
type HistoryRow struct {
	ID        int64  `json:"id"`
	When      string `json:"when"`
	Directory string `json:"directory"`
	Files     int    `json:"files"`
	Hashes    int    `json:"hashes"`
}

// GetScans lists stored scans for a time-range index, newest first.
func (a *App) GetScans(rangeIndex int) ([]HistoryRow, error) {
	d, err := a.database()
	if err != nil {
		return nil, err
	}
	scans, err := d.GetScans(since(rangeIndex, time.Now()))
	if err != nil {
		return nil, err
	}
	rows := make([]HistoryRow, len(scans))
	for i, s := range scans {
		when := []rune(strings.Replace(s.ScannedAt, "T", " ", 1))
		if len(when) > 16 {
			when = when[:16]
		}
		rows[i] = HistoryRow{s.ID, string(when), s.Directory, s.FilesScanned, s.HashesFound}
	}
	return rows, nil
}

// LoadScan makes a stored scan the current result set and returns its rows
// for the results table.
func (a *App) LoadScan(scanID int64) (*Summary, error) {
	d, err := a.database()
	if err != nil {
		return nil, err
	}
	scans, err := d.GetScans("")
	if err != nil {
		return nil, err
	}
	var scan *db.Scan
	for i := range scans {
		if scans[i].ID == scanID {
			scan = &scans[i]
		}
	}
	if scan == nil {
		return nil, fmt.Errorf("scan %d not found", scanID)
	}
	stored, err := d.GetResults(scanID)
	if err != nil {
		return nil, err
	}

	results := extractor.Results{}
	rows := make([]Row, len(stored))
	for i, r := range stored {
		// A missing line number stays missing (file-digest rows), so exports
		// of a reloaded scan match those of the live scan.
		results[r.FilePath] = append(results[r.FilePath], extractor.Hit{
			HashType: r.HashType, HashValue: r.HashValue, Line: r.Line, Context: r.Context,
			SourceSHA256: r.SourceSHA256})
		rows[i] = Row{r.FilePath, r.FileType, r.HashType, r.HashValue, r.Line, r.Context}
	}
	for _, hits := range results {
		extractor.SortHits(hits)
	}

	day := []rune(scan.ScannedAt)
	if len(day) > 10 {
		day = day[:10]
	}
	summary := &Summary{
		FilesScanned: scan.FilesScanned,
		HashesFound:  len(rows),
		SkippedFiles: scan.SkippedFiles,
		Rows:         rows,
	}
	summary.Matches, summary.Status = a.watchlistHits(d, scanID, results,
		fmt.Sprintf("Historical scan from %s loaded.", string(day)))

	a.mu.Lock()
	a.results = results
	a.scan = manifest.Scan{Folder: scan.Directory, ScannedAt: scan.ScannedAt, Mode: modeOf(results),
		HashTypes: splitTypes(scan.HashTypes), FilesScanned: scan.FilesScanned, HashesFound: len(rows),
		SkippedFiles: scan.SkippedFiles} // the skip list itself is only in the stored log
	a.mu.Unlock()
	return summary, nil
}

// GetScanLog returns the log stored with a scan, which names every skipped
// file and why.
func (a *App) GetScanLog(scanID int64) (string, error) {
	d, err := a.database()
	if err != nil {
		return "", err
	}
	log, ok, err := d.GetScanLog(scanID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("no log is stored for scan %d", scanID)
	}
	return log, nil
}
