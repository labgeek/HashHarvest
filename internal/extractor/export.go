package extractor

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

func sortedPaths(results Results) []string {
	paths := make([]string, 0, len(results))
	for path := range results {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// csvField quotes like Python's csv.writer with QUOTE_MINIMAL. encoding/csv
// is not used because it also quotes fields with leading whitespace.
func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\r\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// CSVBytes renders results as UTF-8 with a BOM (so Excel decodes it) and
// LF line endings. A missing line number or source hash is an empty cell.
func CSVBytes(results Results) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
	buf.WriteString("Absolute_Path,Hash_Type,Hash_Value,Line,Context,Source_SHA256\n")
	for _, path := range sortedPaths(results) {
		for _, hit := range results[path] {
			line := ""
			if hit.Line != 0 {
				line = strconv.Itoa(hit.Line)
			}
			fields := []string{CSVSafe(path), hit.HashType, hit.HashValue, line, CSVSafe(hit.Context), hit.SourceSHA256}
			for i, field := range fields {
				fields[i] = csvField(field)
			}
			buf.WriteString(strings.Join(fields, ","))
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// pyJSONString encodes like json.dumps with ensure_ascii=True.
func pyJSONString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			sb.WriteString(`\"`)
		case r == '\\':
			sb.WriteString(`\\`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r == '\b':
			sb.WriteString(`\b`)
		case r == '\f':
			sb.WriteString(`\f`)
		case r >= 0x20 && r <= 0x7e:
			sb.WriteRune(r)
		case r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&sb, `\u%04x\u%04x`, hi, lo)
		default:
			fmt.Fprintf(&sb, `\u%04x`, r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// JSONBytes renders results exactly as Python's json.dump(rows, f, indent=2)
// does, including the platform line ending of a text-mode file (CRLF on
// Windows). A missing line number or source hash is null.
func JSONBytes(results Results) []byte {
	var rows []string
	for _, path := range sortedPaths(results) {
		for _, hit := range results[path] {
			line, source := "null", "null"
			if hit.Line != 0 {
				line = strconv.Itoa(hit.Line)
			}
			if hit.SourceSHA256 != "" {
				source = pyJSONString(hit.SourceSHA256)
			}
			rows = append(rows, "  {\n"+
				`    "absolute_path": `+pyJSONString(path)+",\n"+
				`    "hash_type": `+pyJSONString(hit.HashType)+",\n"+
				`    "hash_value": `+pyJSONString(hit.HashValue)+",\n"+
				`    "line": `+line+",\n"+
				`    "context": `+pyJSONString(hit.Context)+",\n"+
				`    "source_sha256": `+source+"\n"+
				"  }")
		}
	}
	out := "[]"
	if len(rows) > 0 {
		out = "[\n" + strings.Join(rows, ",\n") + "\n]"
	}
	if runtime.GOOS == "windows" {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	return []byte(out)
}

// ExportCSV writes results to a CSV file.
func ExportCSV(path string, results Results) error {
	return os.WriteFile(path, CSVBytes(results), 0o644)
}

// ExportJSON writes results to a JSON file.
func ExportJSON(path string, results Results) error {
	return os.WriteFile(path, JSONBytes(results), 0o644)
}
