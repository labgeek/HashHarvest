// Package readers extracts text from the document types HashHarvest scans.
// Line numbers and
// context strings are derived from this text, so its exact layout matters.
package readers

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Chunk is a piece of extracted text plus a location label ("page 3",
// "slide 2", or "" when the line number alone locates a hit).
type Chunk struct {
	Text     string
	Location string
}

var dispatch = map[string]func(string) (string, error){
	".pdf":  ReadPDF,
	".txt":  readText,
	".log":  readText,
	".md":   readText,
	".csv":  readCSV,
	".json": readJSON,
	".xml":  readXML,
	".docx": readDOCX,
	".xlsx": readXLSX,
	".pptx": ReadPPTX,
}

// Supported reports whether a lowercase extension (with dot) has a reader.
func Supported(ext string) bool {
	_, ok := dispatch[ext]
	return ok
}

// SplitExt returns the extension of path with the semantics of Python's
// os.path.splitext: leading dots of the file name are not an extension
// (".bashrc" has none), unlike filepath.Ext.
func SplitExt(path string) string {
	sep := strings.LastIndexByte(path, '/')
	if os.PathSeparator == '\\' {
		if i := strings.LastIndexByte(path, '\\'); i > sep {
			sep = i
		}
	}
	dot := strings.LastIndexByte(path, '.')
	if dot > sep {
		for i := sep + 1; i < dot; i++ {
			if path[i] != '.' {
				return path[dot:]
			}
		}
	}
	return ""
}

// ReadFile returns the full extracted text of a supported file.
func ReadFile(path string) (string, error) {
	ext := strings.ToLower(SplitExt(path))
	reader, ok := dispatch[ext]
	if !ok {
		return "", fmt.Errorf("Unsupported file type: %s", ext)
	}
	return reader(path)
}

// ReadFileChunks returns one chunk per PDF page or PPTX slide, and a single
// unlabeled chunk for every other format.
func ReadFileChunks(path string) ([]Chunk, error) {
	switch strings.ToLower(SplitExt(path)) {
	case ".pdf":
		return readPDFChunks(path)
	case ".pptx":
		return readPPTXChunks(path)
	}
	text, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []Chunk{{Text: text}}, nil
}

// PyStrip trims the characters Python's str.strip() treats as whitespace
// (Go's set plus the 0x1c-0x1f separators).
func PyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
	})
}

func joinChunks(chunks []Chunk) string {
	texts := make([]string, len(chunks))
	for i, c := range chunks {
		texts[i] = c.Text
	}
	return strings.Join(texts, "\n")
}

var newlines = strings.NewReplacer("\r\n", "\n", "\r", "\n")

// readText decodes as UTF-8, falling back to Latin-1 when the bytes are not
// valid UTF-8, then applies Python's universal-newline translation.
func readText(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if utf8.Valid(data) {
		return newlines.Replace(string(data)), nil
	}
	return newlines.Replace(latin1(data)), nil
}

func latin1(data []byte) string {
	runes := make([]rune, len(data))
	for i, b := range data {
		runes[i] = rune(b)
	}
	return string(runes)
}

// DecodeUTF8Replace decodes like Python's bytes.decode("utf-8", "replace"):
// each maximal invalid subsequence becomes one U+FFFD.
func DecodeUTF8Replace(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	var sb strings.Builder
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r != utf8.RuneError || size > 1 {
			sb.WriteRune(r)
			i += size
			continue
		}
		sb.WriteRune(utf8.RuneError)
		i += invalidLen(data[i:])
	}
	return sb.String()
}

// invalidLen is the length of the ill-formed prefix of b that one U+FFFD
// replaces: the lead byte plus any continuation bytes that were still valid.
func invalidLen(b []byte) int {
	lead := b[0]
	var need int
	lo, hi := byte(0x80), byte(0xBF)
	switch {
	case lead >= 0xC2 && lead <= 0xDF:
		need = 1
	case lead >= 0xE0 && lead <= 0xEF:
		need = 2
		if lead == 0xE0 {
			lo = 0xA0
		} else if lead == 0xED {
			hi = 0x9F
		}
	case lead >= 0xF0 && lead <= 0xF4:
		need = 3
		if lead == 0xF0 {
			lo = 0x90
		} else if lead == 0xF4 {
			hi = 0x8F
		}
	default:
		return 1
	}
	n := 1
	for n <= need && n < len(b) && b[n] >= lo && b[n] <= hi {
		n++
		lo, hi = 0x80, 0xBF
	}
	return n
}

func readCSV(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	rows, err := pyCSVRows(DecodeUTF8Replace(data))
	if err != nil {
		return "", err
	}
	lines := make([]string, len(rows))
	for i, row := range rows {
		lines[i] = strings.Join(row, " ")
	}
	return strings.Join(lines, "\n"), nil
}

func readXML(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	parts, err := collectXMLText(data)
	if err != nil {
		return "", err
	}
	return strings.Join(parts, "\n"), nil
}

const (
	nsWord  = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
	nsSheet = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
	nsDraw  = "http://schemas.openxmlformats.org/drawingml/2006/main"
)

// zipEntry reads a named archive member. Like Python's zipfile, the last
// entry wins when a name is duplicated.
func zipEntry(archive *zip.ReadCloser, name string) ([]byte, error) {
	var found *zip.File
	for _, f := range archive.File {
		if f.Name == name {
			found = f
		}
	}
	if found == nil {
		return nil, fmt.Errorf("There is no item named '%s' in the archive", name)
	}
	rc, err := found.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func readDOCX(path string) (string, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	data, err := zipEntry(archive, "word/document.xml")
	if err != nil {
		return "", err
	}
	lines, err := collectOOXMLText(data, nsWord, "p")
	if err != nil {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}

// readXLSX returns shared strings first, then each worksheet's inline
// strings in worksheet-name order.
func readXLSX(path string) (string, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer archive.Close()

	var lines []string
	sheets := map[string]bool{}
	hasShared := false
	for _, f := range archive.File {
		if f.Name == "xl/sharedStrings.xml" {
			hasShared = true
		}
		if strings.HasPrefix(f.Name, "xl/worksheets/") && strings.HasSuffix(f.Name, ".xml") {
			sheets[f.Name] = true
		}
	}
	if hasShared {
		data, err := zipEntry(archive, "xl/sharedStrings.xml")
		if err != nil {
			return "", err
		}
		shared, err := collectOOXMLText(data, nsSheet, "si")
		if err != nil {
			return "", err
		}
		lines = append(lines, shared...)
	}
	names := make([]string, 0, len(sheets))
	for name := range sheets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := zipEntry(archive, name)
		if err != nil {
			return "", err
		}
		inline, err := collectOOXMLText(data, nsSheet, "is")
		if err != nil {
			return "", err
		}
		lines = append(lines, inline...)
	}
	return strings.Join(lines, "\n"), nil
}

var pptxSlideRE = regexp.MustCompile(`^ppt/slides/slide([0-9]+)\.xml$`)

// readPPTXChunks returns one chunk per slide with text, ordered and labeled
// by the number in the part name (slide10.xml sorts after slide2.xml).
func readPPTXChunks(path string) ([]Chunk, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer archive.Close()

	type slide struct {
		number int
		name   string
	}
	seen := map[string]bool{}
	var slides []slide
	for _, f := range archive.File {
		m := pptxSlideRE.FindStringSubmatch(f.Name)
		if m == nil || seen[f.Name] {
			continue
		}
		seen[f.Name] = true
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue // absurdly long slide number; not a real slide part
		}
		slides = append(slides, slide{n, f.Name})
	}
	sort.Slice(slides, func(i, j int) bool {
		if slides[i].number != slides[j].number {
			return slides[i].number < slides[j].number
		}
		return slides[i].name < slides[j].name
	})

	var chunks []Chunk
	for _, s := range slides {
		data, err := zipEntry(archive, s.name)
		if err != nil {
			return nil, err
		}
		lines, err := collectOOXMLText(data, nsDraw, "p")
		if err != nil {
			return nil, err
		}
		text := strings.Join(lines, "\n")
		if PyStrip(text) != "" {
			chunks = append(chunks, Chunk{text, fmt.Sprintf("slide %d", s.number)})
		}
	}
	if len(chunks) == 0 {
		return []Chunk{{}}, nil
	}
	return chunks, nil
}

// ReadPPTX returns the text of every slide, in slide-number order.
func ReadPPTX(path string) (string, error) {
	chunks, err := readPPTXChunks(path)
	if err != nil {
		return "", err
	}
	return joinChunks(chunks), nil
}

// ReadPDF returns the text of every page, separated by newlines.
func ReadPDF(path string) (string, error) {
	chunks, err := readPDFChunks(path)
	if err != nil {
		return "", err
	}
	return joinChunks(chunks), nil
}

func readPDFChunks(path string) ([]Chunk, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pages, err := pdfPageTexts(data)
	if err != nil {
		return nil, err
	}
	var chunks []Chunk
	for i, text := range pages {
		if PyStrip(text) != "" {
			chunks = append(chunks, Chunk{text, fmt.Sprintf("page %d", i+1)})
		}
	}
	if len(chunks) == 0 {
		return []Chunk{{}}, nil
	}
	return chunks, nil
}
