package main

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests pin what README.md and USAGE.md say a scan does and does not
// report. If one fails, the documented wording is wrong.

func zipText(t *testing.T, parts map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, text := range parts {
		f, err := w.Create(name)
		if err == nil {
			_, err = f.Write([]byte(text))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func wantScan(t *testing.T, wantCode, wantRows int, wantSummary string, args ...string) string {
	t.Helper()
	code, stdout, stderr := cli(args...)
	rows := strings.Count(stdout, "\n") - 1 // minus the CSV header
	if code != wantCode || rows != wantRows || !strings.Contains(stderr, wantSummary) {
		t.Errorf("%v: exit %d (want %d), %d rows (want %d), stderr %q (want %q)",
			args, code, wantCode, rows, wantRows, stderr, wantSummary)
	}
	return stderr
}

func TestTextModeExcludesOtherExtensionsWithoutASkip(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.bin", "noextension", "archive.zip", "old.doc"} {
		writeFile(t, dir, name, md5Hash)
	}
	wantScan(t, 0, 0, "Scanned 0 files, found 0 hashes, skipped 0", dir)
	wantScan(t, 0, 4, "Scanned 4 files, found 4 hashes, skipped 0", "-mode", "file", "-types", "md5", dir)
}

func TestDotFilesAndBinaryTextAreSearched(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".hidden.txt", md5Hash)
	writeFile(t, dir, "binary.txt", "\x00\x01\xfe "+md5Hash+" \x00\xff")
	wantScan(t, 0, 2, "Scanned 2 files, found 2 hashes, skipped 0", dir)
}

func TestWrongSupportedExtensionIsReported(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "plain.docx", md5Hash)
	if stderr := wantScan(t, 3, 0, "skipped 1", dir); !strings.Contains(stderr, "plain.docx") {
		t.Errorf("skip does not name the file: %q", stderr)
	}
}

func TestHashSplitAcrossLinesIsMissedWithoutASkip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "split.txt", md5Hash[:16]+"\n"+md5Hash[16:])
	wantScan(t, 0, 0, "Scanned 1 file, found 0 hashes, skipped 0", dir)
}

func TestUnsearchedOfficePartsAreNotReported(t *testing.T) {
	const ns = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`
	hidden := `<w:p ` + ns + `><w:r><w:t>` + md5Hash + `</w:t></w:r></w:p>`
	dir := t.TempDir()
	writeFile(t, dir, "a.docx", zipText(t, map[string]string{
		"word/document.xml":         `<w:document ` + ns + `><w:body/></w:document>`,
		"word/comments.xml":         hidden,
		"word/header1.xml":          hidden,
		"word/footnotes.xml":        hidden,
		"docProps/core.xml":         hidden,
		"word/embeddings/notes.txt": md5Hash,
	}))
	wantScan(t, 0, 0, "Scanned 1 file, found 0 hashes, skipped 0", dir)
}

func TestFolderLinkIsReportedNotFollowed(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "secret.txt", md5Hash)
	link := filepath.Join(dir, "link")
	if runtime.GOOS == "windows" { // a junction needs no extra rights
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput(); err != nil {
			t.Fatalf("mklink: %v: %s", err, out)
		}
	} else if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"text", "file"} {
		stderr := wantScan(t, 3, 0, "skipped 1", "-mode", mode, dir)
		if !strings.Contains(stderr, "link to a folder is not followed") {
			t.Errorf("%s mode: stderr %q", mode, stderr)
		}
	}
}

func TestOutsideFileLinks(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	target := writeFile(t, outside, "secret.txt", md5Hash)
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("cannot create file symlinks:", err)
	}
	// Text mode drops the unsupported name before looking at the link.
	wantScan(t, 0, 0, "skipped 0", dir)
	wantScan(t, 3, 0, "skipped 1", "-mode", "file", dir)
	if err := os.Rename(link, filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	wantScan(t, 3, 0, "skipped 1", dir)
}

func TestUnreadableFileIsReportedInOutputAndManifest(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "denied.txt", md5Hash)
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("icacls", path, "/deny", "*S-1-1-0:(RD)").CombinedOutput(); err != nil {
			t.Fatalf("icacls: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("icacls", path, "/remove:d", "*S-1-1-0").Run() })
	} else if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(path); err == nil {
		f.Close()
		t.Skip("this account can read the file anyway")
	}
	out := filepath.Join(t.TempDir(), "results.csv")
	for _, mode := range []string{"text", "file"} {
		code, _, stderr := cli("-mode", mode, "-o", out, "-force", dir)
		manifest, err := os.ReadFile(out + ".manifest.json")
		if code != 3 || !strings.Contains(stderr, "denied.txt") || err != nil || !bytes.Contains(manifest, []byte("denied.txt")) {
			t.Errorf("%s mode: exit %d, stderr %q, manifest %s, %v", mode, code, stderr, manifest, err)
		}
	}
}
