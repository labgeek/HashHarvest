package applog

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCaptureCollectsOnlyWhileActive(t *testing.T) {
	Info("test", "before")
	stop := Capture()
	Info("hashharvest.core.scanner", "Scan started: dir=%s", "C:/ev")
	nested := Capture()
	Info("test", "both")
	inner := nested()
	Info("test", "outer only")
	outer := stop()
	Info("test", "after")

	// Python's "%(asctime)s %(levelname)s %(name)s: %(message)s".
	line := regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} INFO hashharvest\.core\.scanner: Scan started: dir=C:/ev\n`)
	if !line.MatchString(outer) || strings.Count(outer, "\n") != 3 || strings.Contains(outer, "before") || strings.Contains(outer, "after") {
		t.Errorf("outer capture = %q", outer)
	}
	if strings.Count(inner, "\n") != 1 || !strings.HasSuffix(inner, " INFO test: both\n") {
		t.Errorf("inner capture = %q", inner)
	}
}

func TestAppendRotating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	big := strings.Repeat("x", maxBytes/2)
	// Each write that would reach the limit first shifts the backups up by one.
	for i := 0; i < backupCount+4; i++ {
		appendRotating(path, big+"\n")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if info, _ := e.Info(); info.Size() >= maxBytes {
			t.Errorf("%s is %d bytes, over the limit", e.Name(), info.Size())
		}
	}
	want := []string{"app.log", "app.log.1", "app.log.2", "app.log.3", "app.log.4", "app.log.5"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("files = %v, want %v (oldest backups dropped)", names, want)
	}
}

func TestAppendRotatingToUnwritablePathIsSilent(t *testing.T) {
	appendRotating(filepath.Join(t.TempDir(), "missing", "app.log"), "dropped\n") // must not panic
}
