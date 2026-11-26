package main

// The VirusTotal Lookup dialog.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/labgeek/HashHarvest/internal/keystore"
	"github.com/labgeek/HashHarvest/internal/readers"
	"github.com/labgeek/HashHarvest/internal/vt"
)

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
