package readers

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// setLimit lowers a size limit for one test.
func setLimit[T int | int64](t *testing.T, limit *T, value T) {
	t.Helper()
	orig := *limit
	*limit = value
	t.Cleanup(func() { *limit = orig })
}

func streamAll(path string) (string, error) {
	var b strings.Builder
	err := StreamText(context.Background(), path, func(r []rune) { b.WriteString(string(r)) })
	return b.String(), err
}

// Streaming decodes exactly as reading the whole file did, whatever the
// read size: multi-byte characters, CRLF pairs and UTF-16 surrogate pairs
// may all be split between reads.
func TestStreamTextAtEveryReadSize(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"UTF-8 with CRLF and lone CR", []byte("a\r\nb\rc\nd\r\n€🙂é\r"), "a\nb\nc\nd\n€🙂é\n"},
		{"Latin-1 bytes", []byte("caf\xe9 \xff\r\n"), "café ÿ\n"},
		{"UTF-8 byte-order mark is kept", []byte("\xef\xbb\xbfx"), "\uFEFFx"},
		{"UTF-16 LE with BOM and a surrogate pair", utf16Bytes("a\r\n🙂b\r", false, true), "a\n🙂b\n"},
		{"UTF-16 BE without BOM", utf16Bytes("md5 "+md5Hash+"\r\n", true, false), "md5 " + md5Hash + "\n"},
		{"empty", nil, ""},
	}
	for _, size := range []int{1, 2, 3, 5, 7, 64, 1 << 20} {
		setLimit(t, &textReadSize, size)
		for _, tc := range cases {
			path := writeFile(t, "f.txt", tc.data)
			if got, err := streamAll(path); err != nil || got != tc.want {
				t.Errorf("reads of %d bytes, %s: got %q, %v; want %q", size, tc.name, got, err, tc.want)
			}
			if got, err := ReadFile(path); err != nil || got != tc.want {
				t.Errorf("ReadFile, reads of %d bytes, %s: got %q, %v; want %q", size, tc.name, got, err, tc.want)
			}
		}
	}
}

func TestStreamTextStopsWhenCancelled(t *testing.T) {
	setLimit(t, &textReadSize, 4)
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := StreamText(ctx, writeFile(t, "f.txt", []byte(strings.Repeat("x", 100))), func([]rune) {
		calls++
		cancel()
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Errorf("err = %v after %d pieces; want a stop after the first", err, calls)
	}
}

func TestStreamPlan(t *testing.T) {
	setLimit(t, &maxStructuredSize, 10)
	small := writeFile(t, "small.json", []byte("{}"))
	cases := map[string]struct {
		stream bool
		note   string
	}{
		writeFile(t, "a.txt", []byte(strings.Repeat("x", 20))):   {true, ""},
		writeFile(t, "a.LOG", []byte("x")):                       {true, ""},
		writeFile(t, "a.md", []byte("x")):                        {true, ""},
		small:                                                    {false, ""},
		writeFile(t, "a.json", []byte(`{"md5": "`+md5Hash+`"}`)): {true, "scanned as plain text: larger than the 10 bytes limit for parsing JSON files"},
		writeFile(t, "a.csv", []byte(strings.Repeat("x,", 6))):   {true, "scanned as plain text: larger than the 10 bytes limit for parsing CSV files"},
		writeFile(t, "a.xml", []byte("<r>"+md5Hash+"</r>")):      {true, "scanned as plain text: larger than the 10 bytes limit for parsing XML files"},
		writeFile(t, "a.pdf", []byte(strings.Repeat("x", 20))):   {false, ""},
		filepath.Join(t.TempDir(), "missing.json"):               {false, ""}, // the reader reports the error
	}
	for path, want := range cases {
		if stream, note := StreamPlan(path); stream != want.stream || note != want.note {
			t.Errorf("%s: StreamPlan = %v, %q; want %v, %q", filepath.Base(path), stream, note, want.stream, want.note)
		}
	}
	if sizeText(128<<20) != "128 MiB" || sizeText(1<<30) != "1024 MiB" || sizeText(10) != "10 bytes" {
		t.Error("sizeText")
	}
}

func TestZipLimits(t *testing.T) {
	para := func(text string) string {
		return `<w:document xmlns:w="` + nsWord + `"><w:body><w:p><w:r><w:t>` + text + `</w:t></w:r></w:p></w:body></w:document>`
	}
	sheet := func(text string) string {
		return `<worksheet xmlns="` + nsSheet + `"><sheetData><row><c><is><t>` + text + `</t></is></c></row></sheetData></worksheet>`
	}
	big := strings.Repeat("x", 300)

	setLimit(t, &maxZipPart, 200)
	_, err := ReadFile(writeZip(t, "a.docx", [][2]string{{"word/document.xml", para(big)}}))
	if err == nil || err.Error() != "word/document.xml expands beyond the 200 bytes limit for one part" {
		t.Errorf("docx part: %v", err)
	}
	_, err = ReadFileChunks(writeZip(t, "a.pptx", [][2]string{{"ppt/slides/slide1.xml", para(big)}}))
	if err == nil || !strings.Contains(err.Error(), "beyond the 200 bytes limit for one part") {
		t.Errorf("pptx part: %v", err)
	}
	if got, err := ReadFile(writeZip(t, "b.docx", [][2]string{{"word/document.xml", para(md5Hash)}})); err != nil || got != md5Hash {
		t.Errorf("a part under the limit: %q, %v", got, err)
	}

	setLimit(t, &maxZipPart, 1<<20)
	setLimit(t, &maxZipTotal, 600)
	_, err = ReadFile(writeZip(t, "a.xlsx", [][2]string{
		{"xl/worksheets/sheet1.xml", sheet(big)},
		{"xl/worksheets/sheet2.xml", sheet(big)},
	}))
	if err == nil || err.Error() != "decompressed content exceeds the 600 bytes limit per file" {
		t.Errorf("xlsx total: %v", err)
	}
}

func TestPDFLimits(t *testing.T) {
	pdf := func(name string) string { return filepath.Join(corpus, "pdf", name) }

	setLimit(t, &maxPDFSize, 100)
	if _, err := ReadFileChunks(pdf("simple.pdf")); err == nil || err.Error() != "PDF is larger than the 100 bytes limit" {
		t.Errorf("file size: %v", err)
	}
	setLimit(t, &maxPDFSize, 1<<30)

	// Page content (FlateDecode, LZWDecode) and object streams, whose
	// decode errors are otherwise ignored, must all report the limit.
	setLimit(t, &maxPDFStream, 8)
	for _, name := range []string{"flate.pdf", "lzw.pdf", "objstm.pdf"} {
		if _, err := ReadFileChunks(pdf(name)); err == nil || !strings.Contains(err.Error(), "a PDF stream expands beyond the 8 bytes limit") {
			t.Errorf("%s stream: %v", name, err)
		}
	}
	setLimit(t, &maxPDFStream, 1<<20)

	setLimit(t, &maxPDFTotal, 8)
	if _, err := ReadFileChunks(pdf("simple.pdf")); err == nil || !strings.Contains(err.Error(), "PDF streams expand beyond the 8 bytes limit per file") {
		t.Errorf("total: %v", err)
	}
}

func TestDecodersStopAtTheLimit(t *testing.T) {
	setLimit(t, &maxPDFStream, 100)
	// A run-length "repeat" run makes 128 bytes from 2.
	if out := runLengthDecode([]byte{129, 'x', 129, 'x'}); len(out) > 101+128 {
		t.Errorf("runLengthDecode kept going: %d bytes", len(out))
	}
	// Codes 0, 258, 259, ... each repeat the previous entry plus one byte, so
	// 3800 codes (5 KB) would expand to about 7 MB.
	bomb := lzwCodes(append([]int{0}, seq(258, 4000)...))
	if out, _ := lzwDecode(bomb, 1); len(out) > 101+4096 {
		t.Errorf("lzwDecode kept going: %d bytes", len(out))
	}
}

func seq(from, to int) []int {
	var s []int
	for i := from; i < to; i++ {
		s = append(s, i)
	}
	return s
}

// lzwCodes packs codes as lzwDecode reads them (EarlyChange 1), without the
// table growing past 4096 entries.
func lzwCodes(codes []int) []byte {
	var out []byte
	var bits uint64
	nbits, width, table := 0, 9, 258
	for i, c := range codes {
		bits = bits<<width | uint64(c)
		nbits += width
		for nbits >= 8 {
			nbits -= 8
			out = append(out, byte(bits>>nbits))
		}
		if i > 0 && table < 4096 {
			table++
		}
		if width < 12 && table+1 >= 1<<width {
			width++
		}
	}
	if nbits > 0 {
		out = append(out, byte(bits<<(8-nbits)))
	}
	return out
}
