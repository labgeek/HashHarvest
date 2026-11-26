package readers

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

const (
	md5Hash  = "5d41402abc4b2a76b9719d911017c592"
	sha1Hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
)

var corpus = "testdata"

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSplitExt(t *testing.T) {
	cases := map[string]string{
		"a.txt":             ".txt",
		"dir/a.TXT":         ".TXT",
		"archive.tar.gz":    ".gz",
		"no_extension":      "",
		".bashrc":           "",
		"dir/.hidden":       "",
		"..double":          "",
		".hidden.txt":       ".txt",
		"trailing.":         ".",
		"dir.with.dot/file": "",
		"":                  "",
	}
	for path, want := range cases {
		if got := SplitExt(path); got != want {
			t.Errorf("SplitExt(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestUnsupportedExtension(t *testing.T) {
	_, err := ReadFileChunks(writeFile(t, "a.bin", []byte("x")))
	if err == nil || err.Error() != "Unsupported file type: .bin" {
		t.Errorf("err = %v", err)
	}
}

func TestTextDecoding(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"utf8", []byte("caf\xc3\xa9"), "café"},
		{"latin1 fallback", []byte("caf\xe9 \xff"), "café ÿ"},
		{"universal newlines", []byte("a\r\nb\rc\nd\r\n\r\n"), "a\nb\nc\nd\n\n"},
		{"bom is kept", []byte("\xef\xbb\xbfx"), string(rune(0xFEFF)) + "x"},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		got, err := ReadFile(writeFile(t, "f.txt", tc.data))
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

func TestDecodeUTF8Replace(t *testing.T) {
	const r = "�"
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"a\xffb", "a" + r + "b"},
		{"\xe2\x82", r},             // truncated 3-byte sequence: one replacement
		{"\xe2\x82A", r + "A"},      // valid prefix, then ASCII
		{"\xf0\x9f\x99", r},         // truncated 4-byte sequence
		{"\xc0\x80", r + r},         // overlong: each byte is invalid
		{"\xed\xa0\x80", r + r + r}, // encoded surrogate
		{"\x80\x80", r + r},         // stray continuation bytes
		{"ok \xe2\x82\xac", "ok €"}, // valid euro sign untouched
	}
	for _, tc := range cases {
		if got := DecodeUTF8Replace([]byte(tc.in)); got != tc.want {
			t.Errorf("DecodeUTF8Replace(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPyCSVRows(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want [][]string
	}{
		{"simple", "a,b\nc,d\n", [][]string{{"a", "b"}, {"c", "d"}}},
		{"crlf and no final newline", "a,b\r\nc,d", [][]string{{"a", "b"}, {"c", "d"}}},
		{"empty lines are empty rows", "a\n\n\r\nb\n", [][]string{{"a"}, nil, nil, {"b"}}},
		{"quoted delimiter and doubled quote", `"a,b","c""d"` + "\n", [][]string{{"a,b", `c"d`}}},
		{"newline inside quotes", "\"x\r\ny\",z\n", [][]string{{"x\r\ny", "z"}}},
		{"stray quote in unquoted field", `a"b,c` + "\n", [][]string{{`a"b`, "c"}}},
		{"text after closing quote", `"a"b,c` + "\n", [][]string{{"ab", "c"}}},
		{"spaces are kept", " a , b \n", [][]string{{" a ", " b "}}},
		{"trailing delimiter", "a,\n", [][]string{{"a", ""}}},
		{"unterminated quote at end of input", "a,\"b\nc", [][]string{{"a", "b\nc"}}},
		{"empty input", "", nil},
	}
	for _, tc := range cases {
		got, err := pyCSVRows(tc.in)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	if _, err := pyCSVRows(strings.Repeat("x", csvFieldLimit+1)); err == nil {
		t.Error("a field over the size limit must be an error")
	}
}

func TestReadJSON(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"k": "v", "n": [1, 2.0, true, false, null]}`, "k\nv\nn\n1\n2.0\nTrue\nFalse"},
		{`{"a": 1, "b": 2, "a": 3}`, "a\n3\nb\n2"}, // duplicate key: first position, last value
		{`12345678901234567890123456789012`, "12345678901234567890123456789012"},
		{`[-0, -0.0, 1e16, 1.5e-5, 1E400, 0.1, 100.0, 1e15, 0.0001, 0.00001]`,
			"0\n-0.0\n1e+16\n1.5e-05\ninf\n0.1\n100.0\n1000000000000000.0\n0.0001\n1e-05"},
		{`"é🙂"`, "é\U0001F642"},
		{`null`, ""},
		{`{}`, ""},
		// Python's json accepts these non-finite literals; str() prints nan/inf/-inf.
		{`{"a": NaN, "b": [Infinity, -Infinity], "NaN": "x\"NaN", "c": {"d": NaN}}`,
			"a\nnan\nb\ninf\n-inf\nNaN\nx\"NaN\nc\nd\nnan"},
		{`NaN`, "nan"},
	}
	for _, tc := range cases {
		got, err := ReadFile(writeFile(t, "f.json", []byte(tc.in)))
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{`{"a": `, `{"a": 1} trailing`, "\xef\xbb\xbf{}", "{\"a\": \"\xff\"}", ``,
		`{NaN: 1}`, `{"a": 1, Infinity: 2}`, `-NaN`, `NaNx`, `[nan]`, `[1 NaN]`} {
		if _, err := ReadFile(writeFile(t, "f.json", []byte(bad))); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestReadXML(t *testing.T) {
	cases := []struct{ in, want string }{
		{`<r>lead<a>in</a>tail<b/>end</r>`, "lead\nin\ntail\nend"},
		{`<r>one<!-- c -->two</r>`, "onetwo"},
		{`<r><![CDATA[<raw>]]> &amp; &#233;</r>`, "<raw> & é"},
		{"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r>caf\xe9</r>", "café"},
		{`<r attr="ignored"/>`, ""},
		{"<r>\n  <a>x</a>\n</r>", "\n  \nx\n\n"},
	}
	for _, tc := range cases {
		got, err := ReadFile(writeFile(t, "f.xml", []byte(tc.in)))
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{`<r><a></r>`, `<a/><b/>`, `<a/>junk`, ``, `text only`} {
		if _, err := ReadFile(writeFile(t, "f.xml", []byte(bad))); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func writeZip(t *testing.T, name string, members [][2]string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, m := range members {
		f, err := w.Create(m[0])
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(m[1]))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return writeFile(t, name, buf.Bytes())
}

// writePPTX builds a minimal deck whose slide N contains the text SLIDEN.
func writePPTX(t *testing.T, slides int) string {
	var members [][2]string
	for n := 1; n <= slides; n++ {
		members = append(members, [2]string{
			fmt.Sprintf("ppt/slides/slide%d.xml", n),
			fmt.Sprintf(`<p:sld xmlns:p="urn:p" xmlns:a="%s"><a:p><a:t>SLIDE%d</a:t></a:p></p:sld>`, nsDraw, n),
		})
	}
	// A relationship part under ppt/slides/ must not be read as a slide.
	members = append(members, [2]string{"ppt/slides/_rels/slide1.xml.rels", "<Relationships/>"})
	return writeZip(t, "deck.pptx", members)
}

func TestPPTXSlidesOrderedAndLabeledNumerically(t *testing.T) {
	// With 10+ slides a string sort yields slide1, slide10, slide11, slide2, ...
	chunks, err := ReadFileChunks(writePPTX(t, 11))
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 11 {
		t.Fatalf("got %d chunks, want 11", len(chunks))
	}
	for i, c := range chunks {
		if c.Location != fmt.Sprintf("slide %d", i+1) || c.Text != fmt.Sprintf("SLIDE%d", i+1) {
			t.Errorf("chunk %d = %+v", i, c)
		}
	}
}

func TestReadPPTXConcatenatesInSlideOrder(t *testing.T) {
	text, err := ReadPPTX(writePPTX(t, 11))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for n := 1; n <= 11; n++ {
		want = append(want, fmt.Sprintf("SLIDE%d", n))
	}
	if !reflect.DeepEqual(strings.Split(text, "\n"), want) {
		t.Errorf("got %q", text)
	}
}

func TestPPTXWithoutTextIsOneEmptyChunk(t *testing.T) {
	chunks, err := ReadFileChunks(writeZip(t, "deck.pptx", [][2]string{{"ppt/slides/slide1.xml", `<s/>`}}))
	if err != nil || !reflect.DeepEqual(chunks, []Chunk{{}}) {
		t.Errorf("got %+v, %v", chunks, err)
	}
}

func TestDOCXParagraphs(t *testing.T) {
	doc := `<w:document xmlns:w="` + nsWord + `"><w:body>` +
		`<w:p><w:r><w:t>split </w:t></w:r><w:r><w:t>run</w:t></w:r></w:p>` +
		`<w:p/>` +
		`<w:p><w:r><w:t>outer</w:t></w:r><w:p><w:r><w:t>inner</w:t></w:r></w:p></w:p>` +
		`</w:body></w:document>`
	got, err := ReadFile(writeZip(t, "a.docx", [][2]string{{"word/document.xml", doc}}))
	// A nested paragraph's text belongs to its ancestors too, as with ElementTree.iter().
	if want := "split run\n\nouterinner\ninner"; err != nil || got != want {
		t.Errorf("got %q, %v; want %q", got, err, want)
	}
	if _, err := ReadFile(writeZip(t, "b.docx", [][2]string{{"other.xml", "<x/>"}})); err == nil {
		t.Error("a docx without word/document.xml must be an error")
	}
	if _, err := ReadFile(writeFile(t, "c.docx", []byte("not a zip"))); err == nil {
		t.Error("a non-zip docx must be an error")
	}
}

func TestXLSXSharedThenInlineInSheetOrder(t *testing.T) {
	sheet := func(text string) string {
		return `<worksheet xmlns="` + nsSheet + `"><sheetData><row><c><is><t>` + text + `</t></is></c></row></sheetData></worksheet>`
	}
	got, err := ReadFile(writeZip(t, "a.xlsx", [][2]string{
		{"xl/worksheets/sheet2.xml", sheet("two")},
		{"xl/worksheets/sheet10.xml", sheet("ten")},
		{"xl/sharedStrings.xml", `<sst xmlns="` + nsSheet + `"><si><t>shared</t></si><si><r><t>ri</t></r><r><t>ch</t></r></si></sst>`},
	}))
	// Worksheets are ordered by name as strings: sheet10 before sheet2.
	if want := "shared\nrich\nten\ntwo"; err != nil || got != want {
		t.Errorf("got %q, %v; want %q", got, err, want)
	}
}

func TestPDFFixtures(t *testing.T) {
	cases := []struct {
		file string
		want []Chunk // Text holds substrings that must appear in that page
	}{
		{"simple.pdf", []Chunk{{"Incident report\nMD5: " + md5Hash + "\n", "page 1"}}},
		{"flate.pdf", []Chunk{{"kerned " + md5Hash + "\ngap " + sha1Hash + "\nleft ", "page 1"}, {"inside form ", "page 2"}}},
		{"tounicode.pdf", []Chunk{{"second line " + md5Hash + "\né\U0001F642fi", "page 1"}}},
		{"differences.pdf", []Chunk{{"hash " + sha1Hash, "page 1"}}},
		{"filters.pdf", []Chunk{{"filter chain " + md5Hash, "page 1"}, {"predictor " + sha1Hash, "page 2"}}},
		{"objstm.pdf", []Chunk{{"object stream ", "page 1"}}},
		{"lzw.pdf", []Chunk{{"lzw tail " + md5Hash, "page 1"}, {"tiff predictor " + sha1Hash, "page 2"}}},
		{"encrypted_rc4_40.pdf", []Chunk{{"encrypted RC4-40 " + md5Hash, "page 1"}}},
		{"encrypted_rc4_128.pdf", []Chunk{{"encrypted RC4-128 " + md5Hash, "page 1"}}},
		{"encrypted_aes_128.pdf", []Chunk{{"encrypted AES-128 " + md5Hash, "page 1"}}},
		{"encrypted_aes_256_r5.pdf", []Chunk{{"encrypted AES-256-R5 " + md5Hash, "page 1"}}},
		{"encrypted_aes_256.pdf", []Chunk{{"encrypted AES-256 " + md5Hash, "page 1"}}},
		{"encrypted_owner_empty.pdf", []Chunk{{"encrypted owner-empty " + md5Hash, "page 1"}}},
		{"empty.pdf", []Chunk{{}}},
		{"edge_report.pdf", []Chunk{{"MD5 " + md5Hash + " and was first seen", "page 1"}, {"café résumé", "page 2"}}},
	}
	for _, tc := range cases {
		chunks, err := ReadFileChunks(filepath.Join(corpus, "pdf", tc.file))
		if err != nil {
			t.Errorf("%s: %v", tc.file, err)
			continue
		}
		if len(chunks) != len(tc.want) {
			t.Errorf("%s: %d chunks, want %d: %q", tc.file, len(chunks), len(tc.want), chunks)
			continue
		}
		for i, want := range tc.want {
			if chunks[i].Location != want.Location || !strings.Contains(chunks[i].Text, want.Text) {
				t.Errorf("%s chunk %d = %q, want location %q containing %q", tc.file, i, chunks[i], want.Location, want.Text)
			}
		}
	}
}

func TestPDFErrors(t *testing.T) {
	minimal := func(streamDict string) []byte {
		return []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n" +
			"2 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n" +
			"3 0 obj << /Type /Page /Contents 4 0 R >> endobj\n" +
			"4 0 obj << " + streamDict + " >>\nstream\nBT (x) Tj ET\nendstream endobj\n" +
			"trailer << /Root 1 0 R >>\n")
	}
	cases := []struct {
		name, want string
		data       []byte
	}{
		{"not a pdf", "not a PDF file", []byte("hello")},
		{"no catalog", "no document catalog", []byte("%PDF-1.4\n1 0 obj << /Type /Other >> endobj\n")},
		{"unknown filter", `unsupported PDF stream filter "JBIG2Decode"`, minimal("/Filter /JBIG2Decode")},
		{"bad flate", "PDF stream", minimal("/Filter /FlateDecode")},
		{"dangling encrypt", "damaged PDF encryption dictionary",
			[]byte("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R /Encrypt 9 0 R >>\n")},
		{"public-key handler", `unsupported PDF security handler "Adobe.PubSec"`,
			[]byte("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R /Encrypt << /Filter /Adobe.PubSec >> >>\n")},
	}
	if _, err := ReadFileChunks(filepath.Join(corpus, "pdf", "encrypted_locked.pdf")); err != errPDFPassword {
		t.Errorf("a PDF with a user password: err = %v, want %v", err, errPDFPassword)
	}
	for _, tc := range cases {
		_, err := pdfPageTexts(tc.data)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
	// The same document without a filter reads fine, with no cross-reference table at all.
	if pages, err := pdfPageTexts(minimal("")); err != nil || !reflect.DeepEqual(pages, []string{"x"}) {
		t.Errorf("unfiltered: %q, %v", pages, err)
	}
}

func TestLZWDecode(t *testing.T) {
	// The worked example from the PDF specification (§7.4.4.2), EarlyChange 1.
	got, err := lzwDecode([]byte{0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01}, 1)
	if err != nil || string(got) != "-----A---B" {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := lzwDecode([]byte{0x80, 0x7F, 0xF0}, 1); err == nil { // code 511 with a 258-entry table
		t.Error("an out-of-table code must be an error")
	}
}

func TestPDFEncodingTables(t *testing.T) {
	if pdfMacRoman[0xCA] != 0xA0 || pdfMacRoman[0xFF] != 0x2C7 || pdfMacRoman[0x80] != 0xC4 {
		t.Errorf("MacRoman table is misaligned: %U %U %U", pdfMacRoman[0xCA], pdfMacRoman[0xFF], pdfMacRoman[0x80])
	}
	if pdfWinAnsi[0x80] != 0x20AC || pdfWinAnsi[0x9F] != 0x178 || pdfWinAnsi['A'] != 'A' {
		t.Errorf("WinAnsi table is misaligned: %U %U", pdfWinAnsi[0x80], pdfWinAnsi[0x9F])
	}
	for name, want := range map[string]rune{"five": '5', "a": 'a', "F": 'F', "space": ' ', "at": '@',
		"asciitilde": '~', "uni00E9": 0xE9, "u1F642": 0x1F642, "nosuchglyph": 0xFFFD} {
		if got := glyphRune(name); got != want {
			t.Errorf("glyphRune(%q) = %U, want %U", name, got, want)
		}
	}
}

// Scanned PDFs are untrusted: no input may panic or hang the parser.
func FuzzPDF(f *testing.F) {
	entries, _ := os.ReadDir(filepath.Join(corpus, "pdf"))
	for _, e := range entries {
		if data, err := os.ReadFile(filepath.Join(corpus, "pdf", e.Name())); err == nil && len(data) < 4096 {
			f.Add(data)
		}
	}
	f.Add([]byte("%PDF-1.4\n1 0 obj " + strings.Repeat("[", 5000) + " endobj"))
	f.Add([]byte("%PDF-1.4\n1 0 obj << /Kids [1 0 R] /Type /Pages >> endobj trailer << /Root << /Pages 1 0 R >> >>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		pdfPageTexts(data)
	})
}

func TestRunLengthDecode(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{2, 'a', 'b', 'c', 254, 'x', 128, 'z'}, "abcxxx"}, // literal run, repeat run, EOD stops
		{[]byte{0, 'q'}, "q"},
		{[]byte{5, 'a', 'b'}, "ab"}, // truncated literal run keeps what is there
		{[]byte{200}, ""},           // repeat run with no byte to repeat
		{nil, ""},
	}
	for _, tc := range cases {
		if got := string(runLengthDecode(tc.in)); got != tc.want {
			t.Errorf("runLengthDecode(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// utf16Bytes encodes s as UTF-16, little- or big-endian, with or without a
// byte-order mark.
func utf16Bytes(s string, bigEndian, bom bool) []byte {
	units := utf16.Encode([]rune(s))
	if bom {
		units = append([]uint16{0xFEFF}, units...)
	}
	var b []byte
	for _, u := range units {
		if bigEndian {
			b = append(b, byte(u>>8), byte(u))
		} else {
			b = append(b, byte(u), byte(u>>8))
		}
	}
	return b
}

func TestUTF16IsDecoded(t *testing.T) {
	const text = "Windows log\r\nmd5 " + md5Hash + " café\r\n"
	want := "Windows log\nmd5 " + md5Hash + " café\n"
	for _, enc := range []struct {
		name           string
		bigEndian, bom bool
	}{{"LE with BOM", false, true}, {"BE with BOM", true, true}, {"LE without BOM", false, false}, {"BE without BOM", true, false}} {
		data := utf16Bytes(text, enc.bigEndian, enc.bom)
		for _, ext := range []string{".txt", ".log", ".md"} {
			if got, err := ReadFile(writeFile(t, "f"+ext, data)); err != nil || got != want {
				t.Errorf("%s %s: got %q, %v; want %q", enc.name, ext, got, err, want)
			}
		}
		if got, err := ReadFile(writeFile(t, "f.csv", utf16Bytes("a,"+md5Hash+"\r\n", enc.bigEndian, enc.bom))); err != nil || got != "a "+md5Hash {
			t.Errorf("%s csv: got %q, %v", enc.name, got, err)
		}
		if got, err := ReadFile(writeFile(t, "f.json", utf16Bytes(`{"md5": "`+md5Hash+`"}`, enc.bigEndian, enc.bom))); err != nil || got != "md5\n"+md5Hash {
			t.Errorf("%s json: got %q, %v", enc.name, got, err)
		}
		if got, err := ReadFile(writeFile(t, "f.xml", utf16Bytes("<r>"+md5Hash+"</r>", enc.bigEndian, enc.bom))); err != nil || got != md5Hash {
			t.Errorf("%s xml: got %q, %v", enc.name, got, err)
		}
	}
}

func TestBinaryIsNotMisreadAsUTF16(t *testing.T) {
	cases := map[string][]byte{
		"control characters":   {0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00},
		"odd length":           []byte("a\x00b\x00c\x00d\x00e"),
		"unpaired surrogate":   {'a', 0x00, 0x00, 0xD8, 'b', 0x00, 'c', 0x00},
		"NULs on both sides":   {'a', 0x00, 0x00, 'b', 'c', 0x00, 0x00, 'd'},
		"too few NUL bytes":    []byte("abcdefgh\x00ijkl"),
		"NUL character U+0000": {'a', 0x00, 0x00, 0x00, 'b', 0x00, 'c', 0x00},
	}
	for name, data := range cases {
		if got, err := ReadFile(writeFile(t, "f.txt", data)); err != nil || got != newlines.Replace(latin1(data)) {
			t.Errorf("%s: got %q, %v; want the bytes read as Latin-1", name, got, err)
		}
	}
}
