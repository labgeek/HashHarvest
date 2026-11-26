package main

// The Watchlist Manager and the matching of scan results against watchlists.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/labgeek/HashHarvest/internal/db"
	"github.com/labgeek/HashHarvest/internal/extractor"
	"github.com/labgeek/HashHarvest/internal/readers"
)

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
