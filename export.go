package main

// CSV and JSON export of the current results.

import (
	"fmt"

	"github.com/labgeek/HashHarvest/internal/extractor"
	"github.com/labgeek/HashHarvest/internal/manifest"
)

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
	results, scan := a.results, a.scan
	a.mu.Unlock()
	if err := write(path, results); err != nil {
		a.ui.message(dlgError, "Export Error", fmt.Sprintf("Could not save %s: %s", format, err))
		return ""
	}
	if err := manifest.Write(path, format, results, scan); err != nil {
		a.ui.message(dlgWarning, "Export Complete", fmt.Sprintf("%s saved to:\n%s\n\nThe manifest could not be written: %s", format, path, err))
		return fmt.Sprintf("Exported %s: %s (no manifest)", format, path)
	}
	a.ui.message(dlgInfo, "Export Complete", fmt.Sprintf("%s saved to:\n%s\n\nManifest:\n%s", format, path, manifest.Path(path)))
	return fmt.Sprintf("Exported %s: %s", format, path)
}
