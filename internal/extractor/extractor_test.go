package extractor

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	md5Hash    = "5d41402abc4b2a76b9719d911017c592"
	sha256Hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
)

var bg = context.Background()

func write(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFindHashes(t *testing.T) {
	h := func(c string, n int) string { return strings.Repeat(c, n) }
	cases := []struct {
		name  string
		text  string
		types []string
		want  []Hit
	}{
		{"each length", h("a", 32) + " " + h("b", 40) + " " + h("c", 64) + " " + h("d", 128), nil, []Hit{
			{"MD5", h("a", 32), 1, ""}, {"SHA1", h("b", 40), 1, ""},
			{"SHA256", h("c", 64), 1, ""}, {"SHA512", h("d", 128), 1, ""}}},
		{"lowercased", "X " + strings.ToUpper(md5Hash), nil, []Hit{{"MD5", md5Hash, 1, ""}}},
		{"one too long", h("a", 33), nil, nil},
		{"one too short", h("a", 31), nil, nil},
		{"between lengths", h("a", 41) + " " + h("a", 65) + " " + h("a", 127) + " " + h("a", 129), nil, nil},
		{"non-hex neighbors are boundaries", "g" + h("a", 32) + "g:" + h("b", 32) + "-", nil,
			[]Hit{{"MD5", h("a", 32), 1, ""}, {"MD5", h("b", 32), 1, ""}}},
		{"line numbers count newlines", "\n\n" + h("a", 32) + "\nx\n" + h("b", 40), nil,
			[]Hit{{"MD5", h("a", 32), 3, ""}, {"SHA1", h("b", 40), 5, ""}}},
		{"type filter", h("a", 32) + " " + h("b", 40), []string{"SHA1"}, []Hit{{"SHA1", h("b", 40), 1, ""}}},
		{"empty type set selects nothing", h("a", 32), []string{}, nil},
		{"fullwidth digits are not hex", strings.Repeat("\uff11", 32), nil, nil},
		{"empty", "", nil, nil},
	}
	for _, tc := range cases {
		got := FindHashes(tc.text, tc.types)
		for i := range got {
			got[i].Context = "" // contexts are covered below
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got  %+v\n want %+v", tc.name, got, tc.want)
		}
	}
}

func TestFindHashesContext(t *testing.T) {
	cases := []struct{ name, text, want string }{
		{"short text is kept whole", "MD5: " + md5Hash + " end", "MD5: " + md5Hash + " end"},
		{"60 characters each side", strings.Repeat("L", 100) + md5Hash + strings.Repeat("R", 100),
			strings.Repeat("L", 60) + md5Hash + strings.Repeat("R", 60)},
		{"window counts code points, not bytes", strings.Repeat("\u65e5", 100) + md5Hash + strings.Repeat("\U0001F642", 100),
			strings.Repeat("\u65e5", 60) + md5Hash + strings.Repeat("\U0001F642", 60)},
		{"newlines become spaces", "a\nb " + md5Hash + "\nc", "a b " + md5Hash + " c"},
		{"python whitespace is trimmed", "\x1c\u00a0\t " + md5Hash + " \x1f\n", md5Hash},
	}
	for _, tc := range cases {
		got := FindHashes(tc.text, nil)
		if len(got) != 1 || got[0].Context != tc.want {
			t.Errorf("%s:\n got  %+v\n want %q", tc.name, got, tc.want)
		}
	}
}

func TestExtractKeepsFirstOccurrencePerFile(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "notes.txt", "first "+md5Hash+"\nagain "+md5Hash+"\n"+sha256Hash)
	write(t, dir, "ignored.bin", md5Hash)
	write(t, dir, "sub/UPPER.TXT", md5Hash)

	var seen []string
	results, fileErrors, err := Extract(bg, dir, nil, Callbacks{
		Result: func(p, fileType string, hit Hit) { seen = append(seen, filepath.Base(p)+":"+fileType+":"+hit.HashType) },
	})
	if err != nil || len(fileErrors) != 0 {
		t.Fatalf("err %v, file errors %v", err, fileErrors)
	}
	// Context is 60 characters either side of the first occurrence.
	want := []Hit{
		{"MD5", md5Hash, 1, "first " + md5Hash + " again " + md5Hash + " " + sha256Hash[:20]},
		{"SHA256", sha256Hash, 3, md5Hash[12:] + " again " + md5Hash + " " + sha256Hash},
	}
	if !reflect.DeepEqual(results[path], want) {
		t.Errorf("got %+v", results[path])
	}
	if len(results) != 2 {
		t.Errorf("unsupported extensions must not be scanned: %v", results)
	}
	if want := []string{"notes.txt:TXT:MD5", "notes.txt:TXT:SHA256", "UPPER.TXT:TXT:MD5"}; !reflect.DeepEqual(seen, want) {
		t.Errorf("result callbacks = %v, want %v", seen, want)
	}
}

func TestExtractReportsUnreadableFilesAndProgress(t *testing.T) {
	dir := t.TempDir()
	bad := write(t, dir, "a.json", "{not json")
	write(t, dir, "b.txt", md5Hash)
	write(t, dir, "c.txt", "")
	var progress []int
	var status []string
	results, fileErrors, err := Extract(bg, dir, nil, Callbacks{
		Progress: func(p int) { progress = append(progress, p) },
		Status:   func(m string) { status = append(status, m) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fileErrors) != 1 || fileErrors[0].Path != bad || len(results) != 2 {
		t.Errorf("results %v, errors %v", results, fileErrors)
	}
	if len(status) != 1 || status[0] != "Skipped "+bad+": "+fileErrors[0].Message {
		t.Errorf("status = %q", status)
	}
	if want := []int{33, 66, 100}; !reflect.DeepEqual(progress, want) {
		t.Errorf("progress = %v, want %v", progress, want)
	}
}

func TestHashFilesDigestMatchesStdlib(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "a.bin", "hello world")
	results, fileErrors, err := HashFiles(bg, dir, []string{"SHA256", "MD5"}, Callbacks{})
	if err != nil || len(fileErrors) != 0 {
		t.Fatalf("err %v, file errors %v", err, fileErrors)
	}
	md5Sum, shaSum := md5.Sum([]byte("hello world")), sha256.Sum256([]byte("hello world"))
	// Same shape as text mode: no line number, fixed context.
	want := []Hit{
		{"MD5", hex.EncodeToString(md5Sum[:]), 0, "file digest"},
		{"SHA256", hex.EncodeToString(shaSum[:]), 0, "file digest"},
	}
	if !reflect.DeepEqual(results[path], want) {
		t.Errorf("got %+v, want %+v", results[path], want)
	}
}

func TestHashFilesWalksAllFileTypes(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "no_extension", "x")
	write(t, dir, "binary.exe", "y")
	write(t, dir, "deep/er/.hidden", "z")
	var types []string
	results, fileErrors, err := HashFiles(bg, dir, []string{"MD5"}, Callbacks{
		Result: func(_, fileType string, _ Hit) { types = append(types, fileType) },
	})
	if err != nil || len(fileErrors) != 0 || len(results) != 3 {
		t.Fatalf("results %v, errors %v, err %v", results, fileErrors, err)
	}
	// Sorted by full path; extensionless files report "FILE".
	if want := []string{"EXE", "FILE", "FILE"}; !reflect.DeepEqual(types, want) {
		t.Errorf("file types = %v, want %v", types, want)
	}
}

type scanFunc func(context.Context, string, []string, Callbacks) (Results, []FileError, error)

var scanModes = map[string]scanFunc{"text": Extract, "file": HashFiles}

var errDenied = errors.New("access is denied")

// denyReadDir makes listing path fail, as it does for a folder the user
// has no permission to read.
func denyReadDir(t *testing.T, path string) {
	t.Helper()
	orig := readDir
	readDir = func(dir string) ([]os.DirEntry, error) {
		if dir == path {
			return nil, errDenied
		}
		return orig(dir)
	}
	t.Cleanup(func() { readDir = orig })
}

func TestUnreadableScanFolderFailsTheScan(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	denied := t.TempDir()
	write(t, denied, "a.txt", md5Hash)
	denyReadDir(t, denied)
	for name, run := range scanModes {
		for _, dir := range []string{missing, denied} {
			results, fileErrors, err := run(bg, dir, nil, Callbacks{})
			if err == nil || !strings.HasPrefix(err.Error(), "cannot read directory: ") {
				t.Errorf("%s mode, %s: err = %v (results %v, errors %v); want the scan to fail", name, dir, err, results, fileErrors)
			}
		}
	}
}

func TestUnreadableSubfolderIsReportedAsSkipped(t *testing.T) {
	dir := t.TempDir()
	ok := write(t, dir, "ok.txt", md5Hash)
	write(t, dir, "locked/a.txt", md5Hash)
	locked := filepath.Join(dir, "locked")
	denyReadDir(t, locked)
	for name, run := range scanModes {
		var status []string
		results, fileErrors, err := run(bg, dir, nil, Callbacks{Status: func(m string) { status = append(status, m) }})
		if err != nil {
			t.Fatalf("%s mode: %v", name, err)
		}
		want := []FileError{{locked, "cannot read directory: " + errDenied.Error()}}
		if !reflect.DeepEqual(fileErrors, want) || len(results) != 1 || results[ok] == nil {
			t.Errorf("%s mode: results %v, errors %+v; want %+v", name, results, fileErrors, want)
		}
		if want := []string{"Skipped " + locked + ": cannot read directory: " + errDenied.Error()}; !reflect.DeepEqual(status, want) {
			t.Errorf("%s mode: status = %q, want %q", name, status, want)
		}
	}
}

func TestCancelledContextStopsTheScan(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.txt", md5Hash)
	write(t, dir, "b.txt", md5Hash)
	ctx, cancel := context.WithCancel(bg)
	calls := 0
	_, _, err := Extract(ctx, dir, nil, Callbacks{Progress: func(int) { calls++; cancel() }})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Errorf("err = %v after %d files; want cancellation after the first", err, calls)
	}
}

func TestJoinPath(t *testing.T) {
	sep := string(os.PathSeparator)
	cases := [][3]string{
		{"dir", "f", "dir" + sep + "f"},
		{"dir/", "f", "dir/f"},
		{"", "f", "f"},
		{"C:/ev", "a.txt", "C:/ev" + sep + "a.txt"}, // not cleaned: forward slashes survive
	}
	if os.PathSeparator == '\\' {
		cases = append(cases, [3]string{`C:\x\`, "f", `C:\x\f`}, [3]string{"C:", "f", "C:f"})
	}
	for _, c := range cases {
		if got := joinPath(c[0], c[1]); got != c[2] {
			t.Errorf("joinPath(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestCSVSafe(t *testing.T) {
	cases := map[string]string{
		"=SUM(A1)": "'=SUM(A1)", "+1": "'+1", "-1": "'-1", "@cmd": "'@cmd", "\ttab": "'\ttab", "\rcr": "'\rcr",
		"plain": "plain", "": "", "a=b": "a=b", " =lead": " =lead",
	}
	for in, want := range cases {
		if got := CSVSafe(in); got != want {
			t.Errorf("CSVSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExportCSVIsUTF8WithBOM(t *testing.T) {
	// A path outside cp1252 (the Windows locale default) must still export.
	path := "C:/cases/\u62a5\u544a.txt"
	results := Results{path: {{"MD5", strings.Repeat("a", 32), 3, "hash \u00e9\u4e2d context"}}}
	out := filepath.Join(t.TempDir(), "out.csv")
	if err := ExportCSV(out, results); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want := "Absolute_Path,Hash_Type,Hash_Value,Line,Context\n" +
		path + ",MD5," + strings.Repeat("a", 32) + ",3,hash \u00e9\u4e2d context\n"
	if !bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) || string(raw[3:]) != want {
		t.Errorf("got %q", raw)
	}
}

func TestExportFormats(t *testing.T) {
	results := Results{
		"b.txt": {{"MD5", "m", 0, "file digest"}},
		"a.txt": {{"SHA1", "s", 2, "=1+1, \"q\"\nnext"}},
	}
	wantCSV := "\xef\xbb\xbfAbsolute_Path,Hash_Type,Hash_Value,Line,Context\n" +
		"a.txt,SHA1,s,2,\"'=1+1, \"\"q\"\"\nnext\"\n" +
		"b.txt,MD5,m,,file digest\n"
	if got := string(CSVBytes(results)); got != wantCSV {
		t.Errorf("csv:\n got  %q\n want %q", got, wantCSV)
	}
	wantJSON := `[
  {
    "absolute_path": "a.txt",
    "hash_type": "SHA1",
    "hash_value": "s",
    "line": 2,
    "context": "=1+1, \"q\"\nnext"
  },
  {
    "absolute_path": "b.txt",
    "hash_type": "MD5",
    "hash_value": "m",
    "line": null,
    "context": "file digest"
  }
]`
	got := strings.ReplaceAll(string(JSONBytes(results)), "\r\n", "\n") // CRLF on Windows, as Python writes
	if got != wantJSON {
		t.Errorf("json:\n got  %s\n want %s", got, wantJSON)
	}
	if got := string(JSONBytes(Results{})); got != "[]" {
		t.Errorf("empty json = %q", got)
	}
	if got := pyJSONString("\u00e9\U0001F642\x7f\x01/<>&"); got != `"\u00e9\ud83d\ude42\u007f\u0001/<>&"` {
		t.Errorf("pyJSONString = %s", got)
	}
}

func TestHashSet(t *testing.T) {
	d, e := strings.Repeat("d", 32), strings.Repeat("E", 64)
	got := HashSet("bad: " + d + " and " + e + " plus junk, again " + strings.ToUpper(d))
	if want := []string{d, strings.ToLower(e)}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := HashSet("nothing here"); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

// A file being hashed is read through ctxReader, so Cancel stops a large
// file partway instead of after it.
func TestContextReaderStopsMidFile(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	r := ctxReader{ctx, strings.NewReader(strings.Repeat("x", 1<<20))}
	buf := make([]byte, 1024)
	if n, err := r.Read(buf); n != len(buf) || err != nil {
		t.Fatalf("first read: %d, %v", n, err)
	}
	cancel()
	if n, err := r.Read(buf); n != 0 || !errors.Is(err, context.Canceled) {
		t.Errorf("read after cancel: %d, %v", n, err)
	}
}

// Cancellation inside a file stops the scan: it is not that file failing.
func TestCancelInsideAFileIsNotASkip(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "big.bin", strings.Repeat("x", 1<<20))
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := digestFile(ctx, path, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("digestFile: %v", err)
	}
	if _, _, err := extractFile(ctx, write(t, dir, "a.txt", md5Hash), nil); !errors.Is(err, context.Canceled) {
		t.Errorf("extractFile: %v", err)
	}
}
