package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labgeek/HashHarvest/internal/version"
)

const md5Hash = "5d41402abc4b2a76b9719d911017c592"

func writeFile(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func cli(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// evidence is a folder with one hash and nothing unreadable.
func evidence(t *testing.T) string {
	dir := t.TempDir()
	writeFile(t, dir, "notes.txt", "md5 "+md5Hash+"\n")
	return dir
}

func TestCSVToStandardOutput(t *testing.T) {
	dir := evidence(t)
	code, stdout, stderr := cli(dir)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := "\uFEFFAbsolute_Path,Hash_Type,Hash_Value,Line,Context,Source_SHA256\n" +
		filepath.Join(dir, "notes.txt") + ",MD5," + md5Hash + ",1,md5 " + md5Hash + ","
	if !strings.HasPrefix(stdout, want) || strings.Count(stdout, "\n") != 2 {
		t.Errorf("stdout = %q, want prefix %q", stdout, want)
	}
	if !strings.Contains(stderr, "Scanned 1 file, found 1 hash, skipped 0") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestJSONFileWithManifest(t *testing.T) {
	out := filepath.Join(t.TempDir(), "results.json")
	code, stdout, stderr := cli("-o", out, "-types", "md5", evidence(t))
	if code != 0 || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	var rows []map[string]any
	data, err := os.ReadFile(out)
	if err != nil || json.Unmarshal(data, &rows) != nil || len(rows) != 1 || rows[0]["hash_value"] != md5Hash {
		t.Fatalf("export = %s, %v", data, err) // JSON because of the .json name
	}
	var m struct {
		Version string
		Scan    struct {
			Mode      string
			HashTypes []string `json:"hash_types"`
			Skipped   []any
		}
	}
	data, err = os.ReadFile(out + ".manifest.json")
	if err != nil || json.Unmarshal(data, &m) != nil {
		t.Fatalf("manifest %s, %v", data, err)
	}
	if m.Version != version.Version || m.Scan.Mode != "text" || strings.Join(m.Scan.HashTypes, ",") != "MD5" || m.Scan.Skipped == nil || len(m.Scan.Skipped) != 0 {
		t.Errorf("manifest = %s", data)
	}
}

func TestFileModeAndExplicitFormat(t *testing.T) {
	out := filepath.Join(t.TempDir(), "digests.txt")
	code, _, stderr := cli("-mode", "file", "-types", "SHA1,MD5", "-format", "json", "-o", out, evidence(t))
	data, _ := os.ReadFile(out)
	if code != 0 || !strings.HasPrefix(string(data), "[") || strings.Count(string(data), `"file digest"`) != 2 {
		t.Errorf("exit %d, stderr %q, export %s", code, stderr, data)
	}
}

// A scan that finished but could not read something exits 3, so a script
// cannot mistake it for a complete one.
func TestSkippedFilesExit3(t *testing.T) {
	dir := evidence(t)
	bad := writeFile(t, dir, "bad.json", "{")
	code, stdout, stderr := cli(dir)
	if code != 3 || !strings.Contains(stdout, md5Hash) {
		t.Errorf("exit %d, stdout %q", code, stdout)
	}
	if !strings.Contains(stderr, "Skipped "+bad+": invalid JSON") || !strings.Contains(stderr, "skipped 1") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestScanFailureExits1(t *testing.T) {
	code, stdout, stderr := cli(filepath.Join(t.TempDir(), "nope"))
	if code != 1 || stdout != "" || !strings.Contains(stderr, "cannot read directory") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestCancelledScanExits1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{evidence(t)}, &out, &errOut); code != 1 || out.Len() != 0 {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	dir := evidence(t)
	for name, args := range map[string][]string{
		"no folder":          {},
		"two folders":        {dir, dir},
		"flag after folder":  {dir, "-mode", "file"},
		"unknown flag":       {"-nope", dir},
		"bad mode":           {"-mode", "both", dir},
		"bad format":         {"-format", "xml", dir},
		"bad type":           {"-types", "MD5,CRC32", dir},
		"empty type list":    {"-types", "", dir},
		"force without file": {"-force", dir},
	} {
		code, stdout, stderr := cli(args...)
		if code != 2 || stdout != "" || stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
	}
}

// An output path that already exists, such as a mistyped -o naming an
// evidence file, is never overwritten without -force.
func TestRefusesToOverwrite(t *testing.T) {
	dir := evidence(t)
	victim := filepath.Join(dir, "notes.txt")
	before, _ := os.ReadFile(victim)
	code, _, stderr := cli("-o", victim, dir)
	after, _ := os.ReadFile(victim)
	if code != 2 || !strings.Contains(stderr, "already exists") || !bytes.Equal(before, after) {
		t.Errorf("exit %d, stderr %q, file changed %v", code, stderr, !bytes.Equal(before, after))
	}
	// The manifest path is protected too.
	out := filepath.Join(t.TempDir(), "r.csv")
	writeFile(t, filepath.Dir(out), "r.csv.manifest.json", "keep")
	if code, _, _ := cli("-o", out, dir); code != 2 {
		t.Errorf("existing manifest: exit %d", code)
	}
	if code, _, stderr := cli("-o", out, "-force", dir); code != 0 {
		t.Errorf("-force: exit %d, %q", code, stderr)
	}
}

func TestVersionFlag(t *testing.T) {
	code, stdout, _ := cli("-version")
	if code != 0 || stdout != "hashharvest-cli "+version.Version+"\n" {
		t.Errorf("exit %d, stdout %q", code, stdout)
	}
}

func TestHelpExitsZero(t *testing.T) {
	code, _, stderr := cli("-h")
	if code != 0 || !strings.Contains(stderr, "Exit codes:") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}
