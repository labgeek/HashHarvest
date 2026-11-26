package main

// App is the Wails-bound backend of the HashHarvest window: the main window
// and the Scan History, Watchlist and VirusTotal dialogs.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/labgeek/HashHarvest/internal/db"
	"github.com/labgeek/HashHarvest/internal/extractor"
	"github.com/labgeek/HashHarvest/internal/manifest"
	"github.com/labgeek/HashHarvest/internal/readers"
	"github.com/labgeek/HashHarvest/internal/scanner"
)

// Dialog kinds, matching Wails' runtime.DialogType values.
const (
	dlgInfo     = "info"
	dlgWarning  = "warning"
	dlgError    = "error"
	dlgQuestion = "question"
)

// ui is the window-system side of the app. startup fills it from the Wails
// runtime; tests fill it with fakes.
type ui struct {
	emit     func(event string, data any)
	message  func(kind, title, text string) string // returns the button pressed ("Yes"/"No" for questions)
	openDir  func(title string) (string, error)
	openFile func(title string) (string, error)
	saveFile func(title, defaultName, filterName, pattern string) (string, error)
	openURL  func(url string)
}

// App holds the main window's state.
type App struct {
	ui      ui
	baseDir string // folder holding hashharvest.db and .env (next to the executable)
	db      *db.DB
	dbErr   error

	mu         sync.Mutex
	results    extractor.Results // current scan results, the source for exports and VirusTotal
	scan       manifest.Scan     // the scan behind results, for export manifests
	scanCancel context.CancelCauseFunc
	scanDone   chan struct{}
	vtCancel   context.CancelFunc
	vtDone     chan struct{}
}

// NewApp opens (or creates) the database in baseDir. A database that cannot
// be opened does not stop the app: scans still run, and each database
// operation reports the error.
func NewApp(baseDir string) *App {
	a := &App{baseDir: baseDir, results: extractor.Results{}}
	a.db, a.dbErr = db.Open(filepath.Join(baseDir, "hashharvest.db"))
	return a
}

func (a *App) database() (*db.DB, error) {
	if a.dbErr != nil {
		return nil, fmt.Errorf("database unavailable: %w", a.dbErr)
	}
	return a.db, nil
}

// Info is the header text of the main window.
type Info struct {
	Title     string `json:"title"`
	Version   string `json:"version"`
	BuildDate string `json:"buildDate"`
}

// Info returns the window title, version and build date ("build date" is
// the modification time of the executable).
func (a *App) Info() Info {
	info := Info{Title: windowTitle, Version: "v" + version}
	if exe, err := os.Executable(); err == nil {
		if st, err := os.Stat(exe); err == nil {
			info.BuildDate = "Latest build date: " + st.ModTime().Format("01/02/2006 15:04:05")
		}
	}
	return info
}

// BrowseDirectory opens a folder picker and returns the chosen path, or ""
// when cancelled.
func (a *App) BrowseDirectory() string {
	dir, err := a.ui.openDir("Select Input Directory")
	if err != nil {
		return ""
	}
	return dir
}

// Row is one line of the results table. Line is 0 when there is none.
type Row struct {
	Path      string `json:"path"`
	FileType  string `json:"fileType"`
	HashType  string `json:"hashType"`
	HashValue string `json:"hashValue"`
	Line      int    `json:"line"`
	Context   string `json:"context"`
}

// ScanStart reports whether a scan started; Status, when non-empty,
// replaces the status bar text.
type ScanStart struct {
	OK     bool   `json:"ok"`
	Status string `json:"status"`
}

// Summary is sent when a scan finishes or a historical scan is loaded.
type Summary struct {
	FilesScanned int      `json:"filesScanned"`
	HashesFound  int      `json:"hashesFound"`
	SkippedFiles int      `json:"skippedFiles"`
	Status       string   `json:"status"`
	Matches      []string `json:"matches"` // hash values found on a watchlist
	Rows         []Row    `json:"rows,omitempty"`
	// Skipped lists what a live scan could not read. It is empty for a
	// loaded historical scan, whose skips are in its stored log.
	Skipped []SkippedFile `json:"skipped,omitempty"`
}

// ResetResults forgets the current results (the window's Clear Form and
// the start of each scan).
func (a *App) ResetResults() {
	a.mu.Lock()
	a.results, a.scan = extractor.Results{}, manifest.Scan{}
	a.mu.Unlock()
}

// StartScan validates the input and runs the scan in the background. Rows,
// progress and the outcome arrive as scan:* events.
func (a *App) StartScan(directory, mode string, hashTypes []string) ScanStart {
	directory = readers.PyStrip(directory)
	a.ResetResults()
	if directory == "" {
		a.ui.message(dlgWarning, "Input Error", "Select an input directory.")
		return ScanStart{Status: "Input directory is required"}
	}
	if len(hashTypes) == 0 {
		a.ui.message(dlgWarning, "Selection Error", "Select at least one hash type.")
		return ScanStart{}
	}
	if st, err := os.Stat(directory); err != nil || !st.IsDir() {
		a.ui.message(dlgWarning, "Input Error", "The input directory does not exist.")
		return ScanStart{Status: "Input directory does not exist"}
	}
	if mode != "file" {
		mode = "text"
	}

	a.mu.Lock()
	if a.scanDone != nil {
		a.mu.Unlock()
		return ScanStart{Status: "A scan is already running"}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan struct{})
	a.scanCancel, a.scanDone = cancel, done
	a.mu.Unlock()

	go func() {
		defer func() {
			a.mu.Lock()
			a.scanCancel, a.scanDone = nil, nil
			a.mu.Unlock()
			cancel(nil)
			close(done)
		}()
		a.runScan(ctx, directory, mode, hashTypes)
	}()
	return ScanStart{OK: true, Status: "Scanning files..."}
}

// errScanCancelled is the cancel cause when the user presses Cancel, as
// opposed to the window closing.
var errScanCancelled = errors.New("scan cancelled")

// CancelScan stops the running scan, if any. It returns at once; the scan
// reports scan:cancelled when it has stopped.
func (a *App) CancelScan() {
	a.mu.Lock()
	cancel := a.scanCancel
	a.mu.Unlock()
	if cancel != nil {
		cancel(errScanCancelled)
	}
}

func (a *App) runScan(ctx context.Context, directory, mode string, hashTypes []string) {
	var pending []Row
	flush := func() {
		if len(pending) > 0 {
			a.ui.emit("scan:findings", pending)
			pending = nil
		}
	}
	// ponytail: findings are batched per file (flushed with each progress
	// event) so a large scan does not send one IPC message per hash.
	result, err := scanner.Scanner{HashTypes: hashTypes, Mode: mode}.Scan(ctx, directory, func(e scanner.Event) {
		switch e := e.(type) {
		case scanner.Finding:
			pending = append(pending, Row{e.FilePath, e.FileType, e.HashType, e.HashValue, e.Line, e.Context})
		case scanner.Progress:
			flush()
			a.ui.emit("scan:progress", e.Percent)
		case scanner.FileSkipped:
			flush()
			a.ui.emit("scan:status", e.Message)
		case scanner.Note:
			flush()
			a.ui.emit("scan:status", e.Message)
		}
	})
	flush()
	if err != nil {
		if errors.Is(context.Cause(ctx), errScanCancelled) {
			// A partial scan stored or exported as if complete would mislead.
			a.ui.emit("scan:cancelled", "Scan cancelled — nothing saved")
			return
		}
		if ctx.Err() != nil {
			return // the window is closing
		}
		a.ui.emit("scan:failed", "Scan failed")
		a.ui.message(dlgError, "Scan Error", "The scan could not be completed: "+err.Error())
		return
	}

	summary := Summary{
		FilesScanned: result.FilesScanned(),
		HashesFound:  result.HashesFound(),
		SkippedFiles: result.SkippedFiles(),
	}
	for _, e := range result.Errors {
		summary.Skipped = append(summary.Skipped, SkippedFile{Path: e.Path, Reason: e.Message})
	}
	types := append([]string(nil), hashTypes...)
	sort.Strings(types)
	scannedAt := db.NowISO()
	skipped := append([]SkippedFile{}, summary.Skipped...)
	info := manifest.Scan{Folder: directory, ScannedAt: scannedAt, Mode: mode, HashTypes: types,
		FilesScanned: summary.FilesScanned, HashesFound: summary.HashesFound, SkippedFiles: summary.SkippedFiles,
		Skipped: &skipped}
	if d, err := a.database(); err != nil {
		summary.Status = fmt.Sprintf("Scan complete (database save failed: %s)", err)
	} else if scanID, err := d.SaveScan(directory, scannedAt, strings.Join(types, ","),
		summary.FilesScanned, summary.HashesFound, summary.SkippedFiles, result.Results, result.Log); err != nil {
		summary.Status = fmt.Sprintf("Scan complete (database save failed: %s)", err)
	} else {
		summary.Status = "Scan complete — saved to database."
		summary.Matches, summary.Status = a.watchlistHits(d, scanID, result.Results, summary.Status)
	}

	a.mu.Lock()
	a.results, a.scan = result.Results, info
	a.mu.Unlock()
	a.ui.emit("scan:finished", summary)
	a.ui.message(dlgInfo, "Scan Complete", "Scan complete. Use Export CSV or Export JSON to save results.")
}

// shutdown stops any running scan or lookup and waits for it, so the
// database is never left mid-write.
func (a *App) shutdown(context.Context) {
	a.mu.Lock()
	scanCancel, scanDone := a.scanCancel, a.scanDone
	a.mu.Unlock()
	if scanCancel != nil {
		scanCancel(nil)
		<-scanDone
	}
	a.CancelLookup()
}
