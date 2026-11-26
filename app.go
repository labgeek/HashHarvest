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
	"time"

	"github.com/labgeek/HashHarvest/internal/db"
	"github.com/labgeek/HashHarvest/internal/extractor"
	"github.com/labgeek/HashHarvest/internal/keystore"
	"github.com/labgeek/HashHarvest/internal/readers"
	"github.com/labgeek/HashHarvest/internal/scanner"
	"github.com/labgeek/HashHarvest/internal/vt"
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

// SkippedFile is a file or folder a scan could not read, and why.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ResetResults forgets the current results (the window's Clear Form and
// the start of each scan).
func (a *App) ResetResults() {
	a.mu.Lock()
	a.results = extractor.Results{}
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
		summary.Skipped = append(summary.Skipped, SkippedFile{e.Path, e.Message})
	}
	types := append([]string(nil), hashTypes...)
	sort.Strings(types)
	if d, err := a.database(); err != nil {
		summary.Status = fmt.Sprintf("Scan complete (database save failed: %s)", err)
	} else if scanID, err := d.SaveScan(directory, db.NowISO(), strings.Join(types, ","),
		summary.FilesScanned, summary.HashesFound, summary.SkippedFiles, result.Results, result.Log); err != nil {
		summary.Status = fmt.Sprintf("Scan complete (database save failed: %s)", err)
	} else {
		summary.Status = "Scan complete — saved to database."
		summary.Matches, summary.Status = a.watchlistHits(d, scanID, result.Results, summary.Status)
	}

	a.mu.Lock()
	a.results = result.Results
	a.mu.Unlock()
	a.ui.emit("scan:finished", summary)
	a.ui.message(dlgInfo, "Scan Complete", "Scan complete. Use Export CSV or Export JSON to save results.")
}

// watchlistHits returns the scan's hash values that are on a watchlist and
// the status line with the hit count appended. A failed lookup is ignored,
// as in the Python app.
func (a *App) watchlistHits(d *db.DB, scanID int64, results extractor.Results, status string) ([]string, string) {
	matches, err := d.GetScanMatches(scanID)
	if err != nil || len(matches) == 0 {
		return []string{}, status
	}
	values := make([]string, 0, len(matches))
	for v := range matches {
		values = append(values, v)
	}
	sort.Strings(values)
	rows := 0 // table rows, so a hash seen in two files counts twice
	for _, hits := range results {
		for _, h := range hits {
			if matches[h.HashValue] {
				rows++
			}
		}
	}
	if rows > 0 {
		status += fmt.Sprintf(" — ⚠ %d watchlist hit%s", rows, plural(rows, "s"))
	}
	return values, status
}

func plural(n int, suffix string) string {
	if n != 1 {
		return suffix
	}
	return ""
}

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
// Like Python's naive datetime arithmetic, "N days ago" keeps the wall-clock
// time across daylight-saving changes.
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
			HashType: r.HashType, HashValue: r.HashValue, Line: r.Line, Context: r.Context})
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

// WatchlistItem is one entry of the Watchlist Manager list.
type WatchlistItem struct {
	ID    int64  `json:"id"`
	Label string `json:"label"`
}

// GetWatchlists lists watchlists by name with their entry counts.
func (a *App) GetWatchlists() ([]WatchlistItem, error) {
	d, err := a.database()
	if err != nil {
		return nil, err
	}
	lists, err := d.GetWatchlists()
	if err != nil {
		return nil, err
	}
	items := make([]WatchlistItem, len(lists))
	for i, w := range lists {
		items[i] = WatchlistItem{w.ID, fmt.Sprintf("%s  (%d hash%s)", w.Name, w.EntryCount, plural(w.EntryCount, "es"))}
	}
	return items, nil
}

// CreateWatchlist creates a watchlist; a blank name is ignored.
func (a *App) CreateWatchlist(name string) error {
	name = readers.PyStrip(name)
	if name == "" {
		return nil
	}
	d, err := a.database()
	if err != nil {
		return err
	}
	_, err = d.CreateWatchlist(name)
	return err
}

// DeleteWatchlist asks for confirmation, then deletes the watchlist and
// its entries. It reports whether anything was deleted.
func (a *App) DeleteWatchlist(id int64) (bool, error) {
	d, err := a.database()
	if err != nil {
		return false, err
	}
	lists, err := d.GetWatchlists()
	if err != nil {
		return false, err
	}
	for _, w := range lists {
		if w.ID != id {
			continue
		}
		answer := a.ui.message(dlgQuestion, "Delete Watchlist",
			fmt.Sprintf("Delete \"%s\" and all %d of its entries?", w.Name, w.EntryCount))
		if answer != "Yes" {
			return false, nil
		}
		return true, d.DeleteWatchlist(id)
	}
	return false, nil
}

// ImportResult is the Watchlist Manager's status line after an import;
// Clear tells the window to empty the paste area.
type ImportResult struct {
	Status string `json:"status"`
	Clear  bool   `json:"clear"`
}

// ImportText imports every hash found in pasted text into a watchlist.
func (a *App) ImportText(watchlistID int64, text string) ImportResult {
	if watchlistID <= 0 {
		return ImportResult{Status: "Select a watchlist first."}
	}
	if readers.PyStrip(text) == "" {
		return ImportResult{Status: "Nothing to import."}
	}
	return ImportResult{Status: a.importHashes(watchlistID, text, "paste"), Clear: true}
}

// ImportFile asks for a file and imports every hash found in it. An empty
// status means the picker was cancelled.
func (a *App) ImportFile(watchlistID int64) string {
	if watchlistID <= 0 {
		return "Select a watchlist first."
	}
	path, err := a.ui.openFile("Import Hashes From File")
	if err != nil || path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "Could not read file: " + err.Error()
	}
	return a.importHashes(watchlistID, readers.DecodeTextReplace(data), filepath.Base(path))
}

func (a *App) importHashes(watchlistID int64, text, source string) string {
	hashes := extractor.HashSet(text)
	if len(hashes) == 0 {
		return fmt.Sprintf("No valid hashes found in %s.", source)
	}
	d, err := a.database()
	if err != nil {
		return "Import failed: " + err.Error()
	}
	added, err := d.ImportHashes(watchlistID, hashes)
	if err != nil {
		return "Import failed: " + err.Error()
	}
	return fmt.Sprintf("Added %d new hash%s from %s (%d already present).",
		added, plural(added, "es"), source, len(hashes)-added)
}

// VTState is what the VirusTotal dialog shows when it opens.
type VTState struct {
	OK                bool     `json:"ok"`
	Hashes            []string `json:"hashes"`
	APIKey            string   `json:"apiKey"`
	FromEnv           bool     `json:"fromEnv"`
	KeychainAvailable bool     `json:"keychainAvailable"`
	KeyInKeychain     bool     `json:"keyInKeychain"`
}

// OpenVirusTotal returns the dialog state for the current results' unique
// hashes, or OK=false (after telling the user) when there are none.
func (a *App) OpenVirusTotal() VTState {
	a.mu.Lock()
	seen := map[string]bool{}
	for _, hits := range a.results {
		for _, h := range hits {
			seen[strings.ToLower(h.HashValue)] = true
		}
	}
	a.mu.Unlock()
	if len(seen) == 0 {
		a.ui.message(dlgInfo, "VirusTotal", "Run a scan first — there are no hashes to look up.")
		return VTState{}
	}
	hashes := make([]string, 0, len(seen))
	for h := range seen {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	return VTState{
		OK:                true,
		Hashes:            hashes,
		APIKey:            keystore.LoadKey(),
		FromEnv:           os.Getenv("VT_API_KEY") != "",
		KeychainAvailable: keystore.KeychainAvailable(),
		KeyInKeychain:     keystore.KeyInKeychain(),
	}
}

// StartLookup saves the key (unless it came from VT_API_KEY) and looks the
// hashes up in the background, reporting vt:* events.
func (a *App) StartLookup(apiKey string, secure bool, hashes []string) bool {
	apiKey = readers.PyStrip(apiKey)
	if apiKey == "" {
		a.ui.message(dlgWarning, "VirusTotal", "Enter your VirusTotal API key.")
		return false
	}
	if os.Getenv("VT_API_KEY") == "" {
		if _, err := keystore.SaveKey(apiKey, secure); err != nil {
			a.ui.message(dlgWarning, "VirusTotal",
				fmt.Sprintf("Could not save the key: %s\nUsing it for this session only.", err))
		}
	}

	a.mu.Lock()
	if a.vtDone != nil {
		a.mu.Unlock()
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a.vtCancel, a.vtDone = cancel, done
	a.mu.Unlock()

	go func() {
		defer func() {
			a.mu.Lock()
			a.vtCancel, a.vtDone = nil, nil
			a.mu.Unlock()
			cancel()
			close(done)
		}()
		_, err := vt.LookupHashes(ctx, apiKey, hashes,
			func(p int) { a.ui.emit("vt:progress", p) },
			func(hash, verdict, detail string) {
				a.ui.emit("vt:result", map[string]string{"hash": hash, "verdict": verdict, "detail": detail})
			})
		switch {
		case ctx.Err() != nil:
			// The dialog was closed; nobody is listening.
		case err != nil:
			a.ui.emit("vt:done", nil)
			a.ui.message(dlgError, "VirusTotal Error", err.Error())
		default:
			a.ui.emit("vt:done", nil)
		}
	}()
	return true
}

// CancelLookup stops a running lookup and waits for it to finish. The
// VirusTotal dialog calls it when it closes.
func (a *App) CancelLookup() {
	a.mu.Lock()
	cancel, done := a.vtCancel, a.vtDone
	a.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// OpenKeyPage opens the VirusTotal API-key page in the browser.
func (a *App) OpenKeyPage() { a.ui.openURL("https://www.virustotal.com/gui/my-apikey") }

// ExportCSV asks for a path and writes the current results as CSV. It
// returns the new status line, or "" when nothing changed.
func (a *App) ExportCSV() string {
	return a.export("CSV", "hashOutput.csv", "CSV Files (*.csv)", "*.csv", extractor.ExportCSV)
}

// ExportJSON asks for a path and writes the current results as JSON.
func (a *App) ExportJSON() string {
	return a.export("JSON", "hashOutput.json", "JSON Files (*.json)", "*.json", extractor.ExportJSON)
}

func (a *App) export(format, defaultName, filterName, pattern string, write func(string, extractor.Results) error) string {
	path, err := a.ui.saveFile("Export "+format, defaultName, filterName, pattern)
	if err != nil || path == "" {
		return ""
	}
	a.mu.Lock()
	results := a.results
	a.mu.Unlock()
	if err := write(path, results); err != nil {
		a.ui.message(dlgError, "Export Error", fmt.Sprintf("Could not save %s: %s", format, err))
		return ""
	}
	a.ui.message(dlgInfo, "Export Complete", fmt.Sprintf("%s saved to:\n%s", format, path))
	return fmt.Sprintf("Exported %s: %s", format, path)
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
