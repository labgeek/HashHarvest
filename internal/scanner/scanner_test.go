package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	md5Hash    = "5d41402abc4b2a76b9719d911017c592"
	sha256Hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" // SHA256 of "hello"
)

func write(t *testing.T, dir, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func values(r *Result) []string {
	var out []string
	for _, hits := range r.Results {
		for _, h := range hits {
			out = append(out, h.HashValue)
		}
	}
	sort.Strings(out)
	return out
}

func scan(t *testing.T, s Scanner, dir string, onEvent func(Event)) *Result {
	t.Helper()
	result, err := s.Scan(context.Background(), dir, onEvent)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTextModeFindsHashesAndEmitsEvents(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "notes.txt", "md5 "+md5Hash+" and sha256 "+sha256Hash)

	var events []Event
	result := scan(t, Scanner{Mode: "text"}, dir, func(e Event) { events = append(events, e) })

	if got := values(result); !reflect.DeepEqual(got, []string{sha256Hash, md5Hash}) {
		t.Errorf("values = %v", got)
	}
	kinds := map[string]int{}
	for _, e := range events {
		switch e.(type) {
		case Finding:
			kinds["finding"]++
		case Progress:
			kinds["progress"]++
		}
	}
	if kinds["finding"] != 2 || kinds["progress"] != 1 {
		t.Errorf("event kinds = %v", kinds)
	}
	if last, ok := events[len(events)-1].(Completed); !ok || last != (Completed{1, 2, 0}) {
		t.Errorf("last event = %#v", events[len(events)-1])
	}
	if result.HashesFound() != 2 || result.FilesScanned() != 1 || result.SkippedFiles() != 0 {
		t.Errorf("counts = %d/%d/%d", result.HashesFound(), result.FilesScanned(), result.SkippedFiles())
	}
}

func TestHashTypesFilter(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "notes.txt", md5Hash+" "+sha256Hash)
	result := scan(t, Scanner{HashTypes: []string{"MD5"}, Mode: "text"}, dir, nil)
	if got := values(result); !reflect.DeepEqual(got, []string{md5Hash}) {
		t.Errorf("values = %v", got)
	}
}

func TestFileModeDigestsFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "payload.bin", "hello")
	result := scan(t, Scanner{HashTypes: []string{"SHA256"}, Mode: "file"}, dir, nil)
	if got := values(result); !reflect.DeepEqual(got, []string{sha256Hash}) {
		t.Errorf("values = %v", got)
	}
}

func TestSkippedFilesAreCountedAndReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "bad.json", "{")
	write(t, dir, "ok.txt", md5Hash)
	var skipped []string
	result := scan(t, Scanner{Mode: "text"}, dir, func(e Event) {
		if s, ok := e.(FileSkipped); ok {
			skipped = append(skipped, s.Message)
		}
	})
	if result.FilesScanned() != 2 || result.SkippedFiles() != 1 || len(skipped) != 1 ||
		!strings.HasPrefix(skipped[0], "Skipped "+filepath.Join(dir, "bad.json")+": ") {
		t.Errorf("files %d, skipped %d, messages %q", result.FilesScanned(), result.SkippedFiles(), skipped)
	}
}

func TestSkippedFilesAreKeptInTheScanLog(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "bad.json", "{")
	result := scan(t, Scanner{Mode: "text"}, dir, nil)
	want := " WARNING hashharvest.core.scanner: Skipped " + filepath.Join(dir, "bad.json") + ": " + result.Errors[0].Message + "\n"
	if !strings.Contains(result.Log, want) {
		t.Errorf("log = %q, want a line ending %q", result.Log, want)
	}
}

// A JSON file over the parsing limit is still scanned, as plain text, and
// the log says so.
func TestOversizedJSONIsScannedAsPlainText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`[{"md5": "` + md5Hash + `"}`)
	filler := []byte(`,{"note": "` + strings.Repeat("x", 1000) + `"}`)
	for written := 0; written <= 128<<20; written += len(filler) {
		f.Write(filler)
	}
	f.WriteString("]")
	f.Close()

	var notes []string
	result := scan(t, Scanner{Mode: "text"}, dir, func(e Event) {
		if n, ok := e.(Note); ok {
			notes = append(notes, n.Message)
		}
	})
	want := path + ": scanned as plain text: larger than the 128 MiB limit for parsing JSON files"
	if got := values(result); !reflect.DeepEqual(got, []string{md5Hash}) || result.SkippedFiles() != 0 {
		t.Errorf("values %v, skipped %d", got, result.SkippedFiles())
	}
	if !reflect.DeepEqual(notes, []string{want}) || !strings.Contains(result.Log, " WARNING hashharvest.core.scanner: "+want) {
		t.Errorf("notes %q, log %q", notes, result.Log)
	}
}

func TestScanLogIsCaptured(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "notes.txt", "no hashes here")
	result := scan(t, Scanner{HashTypes: []string{"SHA1", "MD5"}, Mode: "text"}, dir, nil)
	lines := strings.Split(strings.TrimSuffix(result.Log, "\n"), "\n")
	if len(lines) != 2 ||
		!strings.HasSuffix(lines[0], " INFO hashharvest.core.scanner: Scan started: dir="+dir+" mode=text types=MD5,SHA1") ||
		!strings.HasSuffix(lines[1], " INFO hashharvest.core.scanner: Scan complete: files=1 hashes=0 skipped=0") {
		t.Errorf("log = %q", result.Log)
	}
	if all := scan(t, Scanner{Mode: "file"}, dir, nil); !strings.Contains(all.Log, "mode=file types=all") {
		t.Errorf("log = %q", all.Log)
	}
}

func TestCancelledScanReturnsError(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "notes.txt", md5Hash)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Scanner{Mode: "text"}).Scan(ctx, dir, nil); err != context.Canceled {
		t.Errorf("err = %v", err)
	}
}

// TestCorpusMatchesExpected scans the repository's golden corpus and
// requires exactly the hashes in its manifest.
func TestCorpusMatchesExpected(t *testing.T) {
	tests := filepath.Join("..", "..", "tests")
	raw, err := os.ReadFile(filepath.Join(tests, "corpus_expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest []struct {
		File      string `json:"file"`
		HashType  string `json:"hash_type"`
		HashValue string `json:"hash_value"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	want := map[[3]string]bool{}
	for _, row := range manifest {
		want[[3]string{row.File, row.HashType, row.HashValue}] = true
	}

	result := scan(t, Scanner{Mode: "text"}, filepath.Join(tests, "corpus"), nil)
	got := map[[3]string]bool{}
	for path, hits := range result.Results {
		for _, h := range hits {
			got[[3]string{filepath.Base(path), h.HashType, h.HashValue}] = true
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if result.SkippedFiles() != 0 {
		t.Errorf("skipped %d files: %v", result.SkippedFiles(), result.Errors)
	}
}
