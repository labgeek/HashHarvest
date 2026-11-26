//go:build unix

package extractor

import (
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// runWithTimeout fails the test, instead of hanging CI, if a scan blocks on
// a special file.
func runWithTimeout(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scan blocked on a special file")
	}
}

func TestFileModeSkipsFIFO(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(pipe, 0o644); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	real := write(t, dir, "real.bin", "x")

	var results Results
	var fileErrors []FileError
	runWithTimeout(t, func() { results, fileErrors, _ = HashFiles(bg, dir, []string{"MD5"}, Callbacks{}) })

	if len(results) != 1 || results[real] == nil {
		t.Errorf("results = %v", results)
	}
	if want := []FileError{{pipe, "not a regular file"}}; !reflect.DeepEqual(fileErrors, want) {
		t.Errorf("errors = %v, want %v", fileErrors, want)
	}
}

func TestTextModeSkipsFIFOWithSupportedExtension(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pipe.txt")
	if err := syscall.Mkfifo(pipe, 0o644); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	notes := write(t, dir, "notes.txt", md5Hash)

	var results Results
	var fileErrors []FileError
	runWithTimeout(t, func() { results, fileErrors, _ = Extract(bg, dir, []string{"MD5"}, Callbacks{}) })

	if len(results) != 1 || results[notes] == nil {
		t.Errorf("results = %v", results)
	}
	if want := []FileError{{pipe, "not a regular file"}}; !reflect.DeepEqual(fileErrors, want) {
		t.Errorf("errors = %v, want %v", fileErrors, want)
	}
}
