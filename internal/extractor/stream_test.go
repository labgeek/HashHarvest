package extractor

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/labgeek/HashHarvest/internal/readers"
)

// findHashesReference is FindHashes as it was before streaming, kept as the
// oracle the streaming finder must match.
func findHashesReference(text string, types []string) []Hit {
	runes := []rune(text)
	var hits []Hit
	line := 1
	for i := 0; i < len(runes); {
		if !isHex(runes[i]) {
			if runes[i] == '\n' {
				line++
			}
			i++
			continue
		}
		start := i
		for i < len(runes) && isHex(runes[i]) {
			i++
		}
		hashType, ok := typeByLength[i-start]
		if !ok || !selected(types, hashType) {
			continue
		}
		from, to := start-60, i+60
		if from < 0 {
			from = 0
		}
		if to > len(runes) {
			to = len(runes)
		}
		context := strings.ReplaceAll(string(runes[from:to]), "\n", " ")
		hits = append(hits, Hit{
			HashType:  hashType,
			HashValue: strings.ToLower(string(runes[start:i])),
			Line:      line,
			Context:   readers.PyStrip(context),
		})
	}
	return hits
}

// genText builds text that stresses the finder: hex runs just under, at and
// over every hash length, long runs, line breaks and multi-byte characters.
func genText(r *rand.Rand) string {
	lengths := []int{1, 31, 32, 33, 39, 40, 41, 63, 64, 65, 127, 128, 129, 200, 400}
	pieces := []string{" ", "\n", "\r\n", "é", "🙂", "-", "x", "\t", "g"}
	var b strings.Builder
	for range 1 + r.IntN(25) {
		if r.IntN(2) == 0 {
			for range lengths[r.IntN(len(lengths))] {
				b.WriteByte("0123456789abcdefABCDEF"[r.IntN(22)])
			}
		} else {
			for range 1 + r.IntN(70) {
				b.WriteString(pieces[r.IntN(len(pieces))])
			}
		}
	}
	return b.String()
}

func TestStreamingFinderMatchesReference(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for c := range 400 {
		text := genText(r)
		types := [][]string{nil, {"MD5"}, {"SHA1", "SHA512"}}[c%3]
		want := findHashesReference(text, types)
		if got := FindHashes(text, types); !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d, FindHashes(%q):\n got %+v\nwant %+v", c, text, got, want)
		}
		runes := []rune(text)
		for size := 1; size <= 9; size++ {
			var got []Hit
			f := newHashFinder(types, func(h Hit) { got = append(got, h) })
			for i := 0; i < len(runes); i += size {
				f.write(runes[i:min(i+size, len(runes))])
			}
			f.close()
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("case %d, chunks of %d runes, text %q:\n got %+v\nwant %+v", c, size, text, got, want)
			}
		}
	}
}

// writeLargeFile writes lines of filler until offset, then tail. It
// returns the number of filler lines.
func writeLargeFile(t *testing.T, path string, offset int, tail string) int {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	line := strings.Repeat("a log line without hashes ", 3) + "\n"
	lines := 0
	for written := 0; written+len(line) <= offset; written += len(line) {
		f.WriteString(line)
		lines++
	}
	f.WriteString(strings.Repeat("z", offset-lines*len(line)) + tail)
	return lines
}

// A hash that straddles a read boundary of a large text file is found, with
// its line number and context.
func TestLargeTextFileIsStreamed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")
	lines := writeLargeFile(t, path, 3<<20-16, md5Hash+" tail\n") // the hash spans the 3 MiB mark

	results, fileErrors, err := Extract(bg, dir, nil, Callbacks{})
	if err != nil || len(fileErrors) != 0 {
		t.Fatalf("err %v, errors %v", err, fileErrors)
	}
	hits := results[path]
	if len(hits) != 1 || hits[0].HashValue != md5Hash || hits[0].Line != lines+1 ||
		!strings.HasSuffix(hits[0].Context, md5Hash+" tail") {
		t.Errorf("hits = %+v, want the MD5 on line %d", hits, lines+1)
	}
}

func ExampleFindHashes() {
	for _, h := range FindHashes("md5: "+md5Hash+"\nsha256: "+sha256Hash, nil) {
		fmt.Println(h.Line, h.HashType)
	}
	// Output:
	// 1 MD5
	// 2 SHA256
}
