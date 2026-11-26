package extractor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sha256Of(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Every hit names the exact bytes it came from, whether the file was
// streamed, parsed whole, or digested (even when SHA256 is not selected).
func TestHitsCarryTheSourceSHA256(t *testing.T) {
	dir := t.TempDir()
	streamed := write(t, dir, "a.log", "x\r\n"+md5Hash+"\r\n")
	parsed := write(t, dir, "b.json", `{"h": "`+md5Hash+`"}`)
	large := filepath.Join(dir, "c.txt")
	writeLargeFile(t, large, 2<<20, md5Hash+"\n")

	for name, run := range scanModes {
		results, fileErrors, err := run(bg, dir, []string{"MD5"}, Callbacks{})
		if err != nil || len(fileErrors) != 0 {
			t.Fatalf("%s: %v %v", name, err, fileErrors)
		}
		for _, path := range []string{streamed, parsed, large} {
			if hits := results[path]; len(hits) != 1 || hits[0].SourceSHA256 != sha256Of(t, path) {
				t.Errorf("%s mode, %s: %+v, want source %s", name, filepath.Base(path), hits, sha256Of(t, path))
			}
		}
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
}

// skippedReasons maps each skipped path, relative to root, to its reason.
func skippedReasons(root string, fileErrors []FileError) map[string]string {
	out := map[string]string{}
	for _, e := range fileErrors {
		rel, _ := filepath.Rel(root, e.Path)
		out[filepath.ToSlash(rel)] = e.Message
	}
	return out
}

// Links to folders are never followed, and each one is reported.
func TestFolderLinksAreReported(t *testing.T) {
	outside := t.TempDir()
	write(t, outside, "secret.txt", md5Hash)
	dir := t.TempDir()
	write(t, dir, "ok.txt", sha256Hash)
	link := filepath.Join(dir, "elsewhere")
	if runtime.GOOS == "windows" {
		// A junction needs no special privilege, unlike a symlink.
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput(); err != nil {
			t.Skipf("mklink /J: %v %s", err, out)
		}
	} else {
		symlink(t, outside, link)
	}
	for name, run := range scanModes {
		results, fileErrors, err := run(bg, dir, nil, Callbacks{})
		if err != nil || len(results) != 1 {
			t.Fatalf("%s: %v, results %v", name, err, results)
		}
		reason := skippedReasons(dir, fileErrors)["elsewhere"]
		if !strings.HasPrefix(reason, "link to a folder is not followed") {
			t.Errorf("%s mode: skipped %v", name, fileErrors)
		}
	}
}

// A file link is followed only when its target is inside the scan folder.
func TestFileLinksStayInsideTheScanFolder(t *testing.T) {
	outside := t.TempDir()
	secret := write(t, outside, "secret.txt", md5Hash)
	dir := t.TempDir()
	inside := write(t, dir, "sub/real.txt", sha256Hash)
	symlink(t, inside, filepath.Join(dir, "inside.txt"))
	symlink(t, secret, filepath.Join(dir, "outside.txt"))
	symlink(t, secret, filepath.Join(dir, "outside.bin"))
	symlink(t, filepath.Join(dir, "gone"), filepath.Join(dir, "broken.txt"))

	for name, run := range scanModes {
		results, fileErrors, err := run(bg, dir, nil, Callbacks{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if results[filepath.Join(dir, "inside.txt")] == nil || results[inside] == nil || len(results) != 2 {
			t.Errorf("%s mode: results %v", name, results)
		}
		reasons := skippedReasons(dir, fileErrors)
		if !strings.HasPrefix(reasons["outside.txt"], "link points outside the scan folder: ") ||
			reasons["broken.txt"] != "not a regular file" {
			t.Errorf("%s mode: skipped %v", name, reasons)
		}
		// Text mode would not have read a .bin file, so it does not report it.
		if _, reported := reasons["outside.bin"]; reported != (name == "file") {
			t.Errorf("%s mode: outside.bin reported = %v", name, reported)
		}
	}
}

// The scan folder may itself be a link; its own contents are still inside it.
func TestScanFolderThatIsALink(t *testing.T) {
	real := t.TempDir()
	target := write(t, real, "a.txt", md5Hash)
	symlink(t, target, filepath.Join(real, "b.txt"))
	root := filepath.Join(t.TempDir(), "root")
	symlink(t, real, root)
	results, fileErrors, err := Extract(bg, root, nil, Callbacks{})
	if err != nil || len(fileErrors) != 0 || len(results) != 2 {
		t.Errorf("results %v, errors %v, err %v", results, fileErrors, err)
	}
}
