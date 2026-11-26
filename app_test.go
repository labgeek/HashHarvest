package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labgeek/HashHarvest/internal/db"
	"github.com/labgeek/HashHarvest/internal/extractor"
	"github.com/labgeek/HashHarvest/internal/vt"
)

const (
	md5Hash  = "5d41402abc4b2a76b9719d911017c592"
	sha1Hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
)

// fakeUI records what the app shows and answers dialogs from canned values.
type fakeUI struct {
	mu       sync.Mutex
	events   []string
	payloads map[string][]any
	messages []string // "kind|title|text"
	answer   string   // reply to question dialogs
	pick     string   // path returned by file/folder pickers
	urls     []string
}

func newApp(t *testing.T) (*App, *fakeUI) {
	t.Helper()
	f := &fakeUI{payloads: map[string][]any{}, answer: "Yes"}
	a := NewApp(t.TempDir())
	if a.dbErr != nil {
		t.Fatal(a.dbErr)
	}
	a.ui = ui{
		emit: func(event string, data any) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, event)
			f.payloads[event] = append(f.payloads[event], data)
		},
		message: func(kind, title, text string) string {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.messages = append(f.messages, kind+"|"+title+"|"+text)
			if kind == dlgQuestion {
				return f.answer
			}
			return "Ok"
		},
		openDir:  func(string) (string, error) { return f.pick, nil },
		openFile: func(string) (string, error) { return f.pick, nil },
		saveFile: func(string, string, string, string) (string, error) { return f.pick, nil },
		openURL:  func(u string) { f.urls = append(f.urls, u) },
	}
	t.Setenv("VT_API_KEY", "env-key") // never touch the real keystore from tests
	return a, f
}

func (f *fakeUI) lastMessage() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.messages) == 0 {
		return ""
	}
	return f.messages[len(f.messages)-1]
}

// scanAndWait starts a scan and waits for it to finish.
func scanAndWait(t *testing.T, a *App, dir, mode string, types []string) ScanStart {
	t.Helper()
	start := a.StartScan(dir, mode, types)
	a.mu.Lock()
	done := a.scanDone
	a.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("scan did not finish")
		}
	}
	return start
}

func write(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStartScanValidation(t *testing.T) {
	a, f := newApp(t)
	file := write(t, t.TempDir(), "x.txt", "")
	cases := []struct {
		dir     string
		types   []string
		status  string
		message string
	}{
		{"   ", []string{"MD5"}, "Input directory is required", "warning|Input Error|Select an input directory."},
		{t.TempDir(), nil, "", "warning|Selection Error|Select at least one hash type."},
		{filepath.Join(t.TempDir(), "missing"), []string{"MD5"}, "Input directory does not exist", "warning|Input Error|The input directory does not exist."},
		{file, []string{"MD5"}, "Input directory does not exist", "warning|Input Error|The input directory does not exist."},
	}
	for _, tc := range cases {
		got := a.StartScan(tc.dir, "text", tc.types)
		if got.OK || got.Status != tc.status || f.lastMessage() != tc.message {
			t.Errorf("%q %v: got %+v, message %q", tc.dir, tc.types, got, f.lastMessage())
		}
	}
	if len(f.events) != 0 {
		t.Errorf("no scan may start: events %v", f.events)
	}
}

func TestScanSavesHistoryHighlightsWatchlistAndExports(t *testing.T) {
	a, f := newApp(t)
	dir := t.TempDir()
	write(t, dir, "a.txt", "md5 "+md5Hash+"\nsha1 "+sha1Hash)
	write(t, dir, "b.log", "again "+md5Hash)
	write(t, dir, "bad.json", "{")

	id, _ := a.db.CreateWatchlist("bad")
	a.db.ImportHashes(id, []string{md5Hash})

	start := scanAndWait(t, a, " "+dir+" ", "text", []string{"SHA1", "MD5"})
	if !start.OK || start.Status != "Scanning files..." {
		t.Fatalf("start = %+v", start)
	}

	// Rows arrive in batches, progress per file, skipped files as status.
	var findings int
	for _, batch := range f.payloads["scan:findings"] {
		findings += len(batch.([]Row))
	}
	if findings != 3 || len(f.payloads["scan:progress"]) != 3 || len(f.payloads["scan:status"]) != 1 {
		t.Errorf("events %v", f.events)
	}
	if f.events[len(f.events)-1] != "scan:finished" {
		t.Errorf("last event = %s", f.events[len(f.events)-1])
	}
	summary := f.payloads["scan:finished"][0].(Summary)
	want := Summary{FilesScanned: 3, HashesFound: 3, SkippedFiles: 1,
		Skipped: []SkippedFile{{filepath.Join(dir, "bad.json"), "invalid JSON"}},
		Status:  "Scan complete — saved to database. — ⚠ 2 watchlist hits", Matches: []string{md5Hash}}
	if !reflect.DeepEqual(summary, want) {
		t.Errorf("summary = %+v", summary)
	}
	if f.lastMessage() != "info|Scan Complete|Scan complete. Use Export CSV or Export JSON to save results." {
		t.Errorf("message = %q", f.lastMessage())
	}

	scans, err := a.db.GetScans("")
	if err != nil || len(scans) != 1 {
		t.Fatalf("scans = %v, %v", scans, err)
	}
	s := scans[0]
	if s.Directory != dir || s.HashTypes != "MD5,SHA1" || s.FilesScanned != 3 || s.HashesFound != 3 || s.SkippedFiles != 1 {
		t.Errorf("stored scan = %+v", s)
	}
	if log, ok, _ := a.db.GetScanLog(s.ID); !ok || !strings.Contains(log, "Scan complete: files=3 hashes=3 skipped=1") {
		t.Errorf("stored log = %q", log)
	}
	if log, err := a.GetScanLog(s.ID); err != nil || !strings.Contains(log, "Skipped "+filepath.Join(dir, "bad.json")+": invalid JSON") {
		t.Errorf("GetScanLog = %q, %v", log, err)
	}
	if _, err := a.GetScanLog(s.ID + 100); err == nil {
		t.Error("the log of a missing scan must be an error")
	}

	// Export writes exactly what the extractor's exporter produces.
	out := filepath.Join(t.TempDir(), "out.csv")
	f.pick = out
	if status := a.ExportCSV(); status != "Exported CSV: "+out {
		t.Errorf("status = %q", status)
	}
	if f.lastMessage() != "info|Export Complete|CSV saved to:\n"+out {
		t.Errorf("message = %q", f.lastMessage())
	}
	got, _ := os.ReadFile(out)
	if string(got) != string(extractor.CSVBytes(a.results)) || !strings.Contains(string(got), md5Hash) {
		t.Errorf("csv = %q", got)
	}
	f.pick = ""
	if status := a.ExportJSON(); status != "" {
		t.Errorf("cancelled export changed the status: %q", status)
	}
	f.pick = filepath.Join(t.TempDir(), "missing-dir", "out.json")
	if status := a.ExportJSON(); status != "" || !strings.HasPrefix(f.lastMessage(), "error|Export Error|Could not save JSON: ") {
		t.Errorf("failed export: status %q, message %q", status, f.lastMessage())
	}
}

func TestScanWithoutDatabaseStillCompletes(t *testing.T) {
	a, f := newApp(t)
	a.dbErr = fmt.Errorf("disk is read-only")
	dir := t.TempDir()
	write(t, dir, "a.txt", md5Hash)
	scanAndWait(t, a, dir, "file", []string{"MD5"})
	summary := f.payloads["scan:finished"][0].(Summary)
	if summary.Status != "Scan complete (database save failed: database unavailable: disk is read-only)" || summary.HashesFound != 1 {
		t.Errorf("summary = %+v", summary)
	}
	if _, err := a.GetScans(4); err == nil {
		t.Error("history must report the database error")
	}
}

func TestLoadScanRestoresResultsWithNullLines(t *testing.T) {
	a, _ := newApp(t)
	results := extractor.Results{
		"C:/ev/no_extension": {{HashType: "MD5", HashValue: strings.Repeat("c", 32), Context: "file digest"}},
		"C:/ev/a.txt": {
			{HashType: "SHA1", HashValue: strings.Repeat("e", 40), Line: 4, Context: "x"},
			{HashType: "MD5", HashValue: strings.Repeat("f", 32), Line: 2, Context: ""},
		},
	}
	id, err := a.db.SaveScan("C:/ev", "2026-10-31T09:15:00.123456", "MD5,SHA1", 5, 3, 2, results, "")
	if err != nil {
		t.Fatal(err)
	}
	wl, _ := a.db.CreateWatchlist("w")
	a.db.ImportHashes(wl, []string{strings.Repeat("c", 32)})

	summary, err := a.LoadScan(id)
	if err != nil {
		t.Fatal(err)
	}
	if summary.FilesScanned != 5 || summary.SkippedFiles != 2 || summary.HashesFound != 3 ||
		summary.Status != "Historical scan from 2026-10-31 loaded. — ⚠ 1 watchlist hit" {
		t.Errorf("summary = %+v", summary)
	}
	if r := summary.Rows[2]; r.FileType != "FILE" || r.Line != 0 {
		t.Errorf("digest row = %+v", r)
	}
	// Reloaded results equal the live shape, so exports do not write Line=0.
	extractor.SortHits(results["C:/ev/a.txt"])
	if !reflect.DeepEqual(a.results, results) {
		t.Errorf("results = %+v", a.results)
	}
	if !strings.Contains(string(extractor.CSVBytes(a.results)), "C:/ev/no_extension,MD5,"+strings.Repeat("c", 32)+",,file digest\n") {
		t.Error("reloaded digest row must export an empty Line cell")
	}
	if _, err := a.LoadScan(id + 100); err == nil {
		t.Error("loading a missing scan must fail")
	}
}

func TestHistoryRowsAndTimeRanges(t *testing.T) {
	a, _ := newApp(t)
	now := time.Now()
	for _, at := range []time.Time{now, now.AddDate(0, 0, -10), now.AddDate(0, 0, -100)} {
		if _, err := a.db.SaveScan("C:/d", db.ISO(at), "MD5", 1, 2, 0, extractor.Results{}, ""); err != nil {
			t.Fatal(err)
		}
	}
	counts := []int{}
	for i := range a.TimeRanges() {
		rows, err := a.GetScans(i)
		if err != nil {
			t.Fatal(err)
		}
		counts = append(counts, len(rows))
	}
	if want := []int{1, 1, 2, 2, 3}; !reflect.DeepEqual(counts, want) {
		t.Errorf("rows per range = %v, want %v", counts, want)
	}
	rows, _ := a.GetScans(4)
	if rows[0].When != strings.Replace(db.ISO(now)[:16], "T", " ", 1) || rows[0].Files != 1 || rows[0].Hashes != 2 {
		t.Errorf("row = %+v", rows[0])
	}

	at := time.Date(2026, 3, 9, 14, 5, 6, 0, time.Local)
	for i, want := range []string{"2026-03-09T00:00:00", "2026-03-02T14:05:06", "2026-02-07T14:05:06", "2025-12-09T14:05:06", ""} {
		if got := since(i, at); got != want {
			t.Errorf("since(%d) = %q, want %q", i, got, want)
		}
	}
}

func TestWatchlistManager(t *testing.T) {
	a, f := newApp(t)
	if err := a.CreateWatchlist("  "); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateWatchlist(" known bad "); err != nil {
		t.Fatal(err)
	}
	items, _ := a.GetWatchlists()
	if len(items) != 1 || items[0].Label != "known bad  (0 hashes)" {
		t.Fatalf("items = %+v", items)
	}
	id := items[0].ID

	if r := a.ImportText(0, md5Hash); r != (ImportResult{Status: "Select a watchlist first."}) {
		t.Errorf("no selection: %+v", r)
	}
	if r := a.ImportText(id, " \n "); r != (ImportResult{Status: "Nothing to import."}) {
		t.Errorf("blank: %+v", r)
	}
	if r := a.ImportText(id, "no hashes"); r != (ImportResult{Status: "No valid hashes found in paste.", Clear: true}) {
		t.Errorf("none: %+v", r)
	}
	if r := a.ImportText(id, "a,"+md5Hash+"\n"+strings.ToUpper(md5Hash)); r.Status != "Added 1 new hash from paste (0 already present)." {
		t.Errorf("first import: %+v", r)
	}

	f.pick = write(t, t.TempDir(), "iocs.csv", md5Hash+","+sha1Hash+"\xff\n")
	if status := a.ImportFile(id); status != "Added 1 new hash from iocs.csv (1 already present)." {
		t.Errorf("file import: %q", status)
	}
	// A UTF-16 export (as Windows tools often write) is decoded, not read as noise.
	utf16le := "\xff\xfe"
	for _, c := range "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\r\n" {
		utf16le += string([]byte{byte(c), 0})
	}
	f.pick = write(t, t.TempDir(), "iocs-utf16.txt", utf16le)
	if status := a.ImportFile(id); status != "Added 1 new hash from iocs-utf16.txt (0 already present)." {
		t.Errorf("UTF-16 file import: %q", status)
	}
	f.pick = filepath.Join(t.TempDir(), "gone.txt")
	if status := a.ImportFile(id); !strings.HasPrefix(status, "Could not read file: ") {
		t.Errorf("unreadable file: %q", status)
	}
	f.pick = ""
	if status := a.ImportFile(id); status != "" {
		t.Errorf("cancelled picker: %q", status)
	}
	if items, _ := a.GetWatchlists(); items[0].Label != "known bad  (3 hashes)" {
		t.Errorf("label = %q", items[0].Label)
	}

	f.answer = "No"
	if deleted, _ := a.DeleteWatchlist(id); deleted {
		t.Error("deleted despite answering No")
	}
	if f.lastMessage() != `question|Delete Watchlist|Delete "known bad" and all 3 of its entries?` {
		t.Errorf("confirmation = %q", f.lastMessage())
	}
	f.answer = "Yes"
	if deleted, err := a.DeleteWatchlist(id); !deleted || err != nil {
		t.Errorf("delete = %v, %v", deleted, err)
	}
	if items, _ := a.GetWatchlists(); len(items) != 0 {
		t.Errorf("items after delete = %+v", items)
	}
}

func TestVirusTotalDialog(t *testing.T) {
	a, f := newApp(t)
	if state := a.OpenVirusTotal(); state.OK || f.lastMessage() != "info|VirusTotal|Run a scan first — there are no hashes to look up." {
		t.Errorf("empty: %+v, %q", state, f.lastMessage())
	}

	a.results = extractor.Results{
		"a": {{HashType: "MD5", HashValue: strings.Repeat("b", 32)}, {HashType: "SHA1", HashValue: strings.Repeat("a", 40)}},
		"b": {{HashType: "MD5", HashValue: strings.Repeat("b", 32)}},
	}
	state := a.OpenVirusTotal()
	if !state.OK || !state.FromEnv || state.APIKey != "env-key" ||
		!reflect.DeepEqual(state.Hashes, []string{strings.Repeat("a", 40), strings.Repeat("b", 32)}) {
		t.Errorf("state = %+v", state)
	}

	if a.StartLookup("  ", false, state.Hashes) || f.lastMessage() != "warning|VirusTotal|Enter your VirusTotal API key." {
		t.Errorf("blank key: %q", f.lastMessage())
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"harmless":3}}}}`)
	}))
	defer server.Close()
	saved := vt.BaseURL
	vt.BaseURL = server.URL
	defer func() { vt.BaseURL = saved }()

	if !a.StartLookup("env-key", false, state.Hashes) {
		t.Fatal("lookup did not start")
	}
	a.mu.Lock()
	done := a.vtDone
	a.mu.Unlock()
	<-done
	results := f.payloads["vt:result"]
	if len(results) != 2 || len(f.payloads["vt:done"]) != 1 ||
		!reflect.DeepEqual(results[0], map[string]string{"hash": strings.Repeat("a", 40), "verdict": "malicious", "detail": "1/4"}) {
		t.Errorf("events %v, results %v", f.events, results)
	}
	a.CancelLookup() // nothing running: must return at once

	a.OpenKeyPage()
	if len(f.urls) != 1 || f.urls[0] != "https://www.virustotal.com/gui/my-apikey" {
		t.Errorf("urls = %v", f.urls)
	}
}

func TestShutdownStopsARunningLookup(t *testing.T) {
	a, f := newApp(t)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer func() { close(release); server.Close() }()
	saved := vt.BaseURL
	vt.BaseURL = server.URL
	defer func() { vt.BaseURL = saved }()

	if !a.StartLookup("k", false, []string{strings.Repeat("a", 32), strings.Repeat("b", 32)}) {
		t.Fatal("lookup did not start")
	}
	if a.StartLookup("k", false, []string{"x"}) {
		t.Error("a second lookup must not start while one runs")
	}
	finished := make(chan struct{})
	go func() { a.shutdown(nil); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not stop the lookup")
	}
	if len(f.payloads["vt:done"]) != 0 || len(f.messages) != 0 {
		t.Errorf("a cancelled lookup must not report: events %v, messages %v", f.events, f.messages)
	}
}

func TestLoadDotenv(t *testing.T) {
	path := write(t, t.TempDir(), ".env", "# comment\r\n\r\nHH_A=plain\r\n  HH_B = \"quoted value\" \nHH_C='single'\nHH_SET=from-file\nnoequals\nHH_D=a=b\n=novalue\nHH_E=\n")
	t.Setenv("HH_SET", "from-env")
	for _, k := range []string{"HH_A", "HH_B", "HH_C", "HH_D", "HH_E"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	loadDotenv(path)
	want := map[string]string{"HH_A": "plain", "HH_B": "quoted value", "HH_C": "single", "HH_SET": "from-env", "HH_D": "a=b", "HH_E": ""}
	for k, v := range want {
		if got, ok := os.LookupEnv(k); !ok || got != v {
			t.Errorf("%s = %q (set %v), want %q", k, got, ok, v)
		}
	}
	loadDotenv(filepath.Join(t.TempDir(), "missing")) // must not panic

	// Windows PowerShell 5.1's `>` writes UTF-16 LE with a byte-order mark.
	utf16le := "\xff\xfe"
	for _, c := range "HH_U16=from-utf16\r\n" {
		utf16le += string([]byte{byte(c), 0})
	}
	t.Setenv("HH_U16", "")
	os.Unsetenv("HH_U16")
	loadDotenv(write(t, t.TempDir(), ".env", utf16le))
	if got := os.Getenv("HH_U16"); got != "from-utf16" {
		t.Errorf("HH_U16 = %q from a UTF-16 .env", got)
	}
}

func TestInfo(t *testing.T) {
	info := (&App{}).Info()
	if info.Title != "HashHarvest v0.8.0 (labgeek)" || info.Version != "v0.8.0" || !strings.HasPrefix(info.BuildDate, "Latest build date: ") {
		t.Errorf("info = %+v", info)
	}
}
