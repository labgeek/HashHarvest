// Command HashHarvest is the desktop application: a Wails window over the
// scanning, history, watchlist and VirusTotal packages in internal/.
package main

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/labgeek/HashHarvest/internal/applog"
	"github.com/labgeek/HashHarvest/internal/readers"
)

const (
	version     = "0.8.0" // keep in step with wails.json
	windowTitle = "HashHarvest v" + version + " (labgeek)"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	applog.Setup()
	base := baseDir()
	loadDotenv(filepath.Join(base, ".env"))
	app := NewApp(base)

	err := wails.Run(appOptions(app))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// appOptions configures the window.
func appOptions(app *App) *options.App {
	return &options.App{
		Title:            windowTitle,
		Width:            1200,
		Height:           720,
		MinWidth:         900,
		MinHeight:        560,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 255, G: 255, B: 255, A: 1},
		OnStartup:        func(ctx context.Context) { app.ui = runtimeUI(ctx) },
		OnShutdown:       app.shutdown,
		Bind:             []any{app},
		// A file dragged onto the window would otherwise open inside it, as
		// a page that could call the bound methods.
		DragAndDrop: &options.DragAndDrop{DisableWebViewDrop: true},
	}
}

// baseDir is the folder holding hashharvest.db and .env: the executable's
// own folder.
func baseDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

// loadDotenv reads KEY=VALUE lines into the environment so VT_API_KEY can
// live in a file. Variables already set in the environment always win.
// Blank lines, # comments and lines without "=" are skipped; surrounding
// quotes are removed from values. A missing or unreadable file is ignored.
func loadDotenv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(readers.DecodeTextReplace(data), "\n") {
		line = readers.PyStrip(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		key = readers.PyStrip(key)
		value = strings.Trim(strings.Trim(readers.PyStrip(value), `"`), "'")
		if _, set := os.LookupEnv(key); !set && key != "" {
			os.Setenv(key, value)
		}
	}
}

// runtimeUI connects the app to the Wails window.
func runtimeUI(ctx context.Context) ui {
	return ui{
		emit: func(event string, data any) { runtime.EventsEmit(ctx, event, data) },
		message: func(kind, title, text string) string {
			answer, _ := runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
				Type: runtime.DialogType(kind), Title: title, Message: text})
			return answer
		},
		openDir: func(title string) (string, error) {
			return runtime.OpenDirectoryDialog(ctx, runtime.OpenDialogOptions{Title: title, DefaultDirectory: "."})
		},
		openFile: func(title string) (string, error) {
			return runtime.OpenFileDialog(ctx, runtime.OpenDialogOptions{Title: title, Filters: []runtime.FileFilter{
				{DisplayName: "Text / CSV files (*.txt *.csv *.log *.json)", Pattern: "*.txt;*.csv;*.log;*.json"},
				{DisplayName: "All files (*)", Pattern: "*.*"},
			}})
		},
		saveFile: func(title, defaultName, filterName, pattern string) (string, error) {
			return runtime.SaveFileDialog(ctx, runtime.SaveDialogOptions{Title: title, DefaultFilename: defaultName,
				Filters: []runtime.FileFilter{{DisplayName: filterName, Pattern: pattern}}})
		},
		openURL: func(url string) { runtime.BrowserOpenURL(ctx, url) },
	}
}
