package readers

// Ports of the Python standard-library behaviors the readers depend on:
// csv.reader's state machine, json.load + str() flattening, and
// ElementTree text collection. Go's encoding/csv and encoding/json differ in
// ways that would shift line numbers or change extracted text.

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// csvFieldLimit is Python's default csv.field_size_limit().
const csvFieldLimit = 131072

// pyCSVRows parses text like csv.reader with the default "excel" dialect.
// Unlike encoding/csv it keeps empty lines as empty rows, tolerates stray
// quotes, and never trims fields.
func pyCSVRows(text string) ([][]string, error) {
	const (
		startRecord = iota
		startField
		inField
		inQuoted
		quoteInQuoted
		eatCRNL
	)
	const eol = rune(-1)

	var (
		rows   [][]string
		fields []string
		field  []rune
		state  = startRecord
	)
	save := func() {
		fields = append(fields, string(field))
		field = field[:0]
	}
	add := func(c rune) error {
		if len(field) >= csvFieldLimit {
			return fmt.Errorf("field larger than field limit (%d)", csvFieldLimit)
		}
		field = append(field, c)
		return nil
	}
	isNL := func(c rune) bool { return c == '\n' || c == '\r' }
	endField := func(c rune) {
		save()
		if c == eol {
			state = startRecord
		} else {
			state = eatCRNL
		}
	}
	process := func(c rune) error {
		switch state {
		case startRecord:
			if c == eol {
				return nil
			}
			if isNL(c) {
				state = eatCRNL
				return nil
			}
			state = startField
			fallthrough
		case startField:
			switch {
			case isNL(c) || c == eol:
				endField(c)
			case c == '"':
				state = inQuoted
			case c == ',':
				save()
			default:
				state = inField
				return add(c)
			}
		case inField:
			switch {
			case isNL(c) || c == eol:
				endField(c)
			case c == ',':
				save()
				state = startField
			default:
				return add(c)
			}
		case inQuoted:
			switch {
			case c == eol:
			case c == '"':
				state = quoteInQuoted
			default:
				return add(c)
			}
		case quoteInQuoted:
			switch {
			case c == '"':
				state = inQuoted
				return add(c)
			case c == ',':
				save()
				state = startField
			case isNL(c) || c == eol:
				endField(c)
			default:
				state = inField
				return add(c)
			}
		case eatCRNL:
			switch {
			case isNL(c):
			case c == eol:
				state = startRecord
			default:
				return errors.New("new-line character seen in unquoted field - do you need to open the file in universal-newline mode?")
			}
		}
		return nil
	}

	lines := splitLinesKeepEnds(text)
	for i := 0; i < len(lines); {
		fields, field, state = nil, field[:0], startRecord
		for {
			if i >= len(lines) {
				// Input ended inside a record (an unterminated quoted field).
				if len(field) != 0 || state == inQuoted {
					save()
				}
				break
			}
			line := lines[i]
			i++
			for _, c := range line {
				if err := process(c); err != nil {
					return nil, err
				}
			}
			if err := process(eol); err != nil {
				return nil, err
			}
			if state == startRecord {
				break
			}
		}
		rows = append(rows, fields)
	}
	return rows, nil
}

// splitLinesKeepEnds splits on \n, \r, and \r\n, keeping the terminators,
// like iterating a Python file opened with newline="".
func splitLinesKeepEnds(text string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\r':
			if i+1 < len(text) && text[i+1] == '\n' {
				i++
			}
			fallthrough
		case '\n':
			lines = append(lines, text[start:i+1])
			start = i + 1
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

// readJSON flattens every key and non-null scalar to one line each, in
// document order, formatted as Python's str() would.
func readJSON(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if text, ok := decodeUTF16(data); ok {
		data = []byte(text)
	}
	if !utf8.Valid(data) {
		return "", errors.New("'utf-8' codec can't decode file: invalid UTF-8")
	}
	data = pyJSONNonFinite(data)
	if !json.Valid(data) {
		return "", errors.New("invalid JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	values, err := jsonValues(dec)
	if err != nil {
		return "", err
	}
	return strings.Join(values, "\n"), nil
}

// pyJSONNonFinite rewrites the NaN, Infinity and -Infinity literals Python's
// json accepts (in value position) to the strings "nan", "inf" and "-inf",
// which flatten to the same str() text. Anything else stays as written, so
// encoding/json still rejects what Python rejects.
func pyJSONNonFinite(data []byte) []byte {
	if !bytes.Contains(data, []byte("NaN")) && !bytes.Contains(data, []byte("Infinity")) {
		return data
	}
	out := make([]byte, 0, len(data)+16)
	var stack []byte // open '{' and '['
	inString, expectKey := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(data) {
				i++
				out = append(out, data[i])
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			stack, expectKey = append(stack, c), true
		case '[':
			stack = append(stack, c)
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case ',':
			expectKey = len(stack) > 0 && stack[len(stack)-1] == '{'
		case ':':
			expectKey = false
		case 'N', 'I', '-':
			if expectKey {
				break
			}
			replaced := false
			for _, lit := range [...][2]string{{"NaN", `"nan"`}, {"Infinity", `"inf"`}, {"-Infinity", `"-inf"`}} {
				if bytes.HasPrefix(data[i:], []byte(lit[0])) {
					out = append(out, lit[1]...)
					i += len(lit[0]) - 1
					replaced = true
					break
				}
			}
			if replaced {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func jsonValues(dec *json.Decoder) ([]string, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Delim:
		if v == '[' {
			var out []string
			for dec.More() {
				item, err := jsonValues(dec)
				if err != nil {
					return nil, err
				}
				out = append(out, item...)
			}
			_, err := dec.Token() // closing ]
			return out, err
		}
		// Object: a Python dict keeps a duplicated key at its first position
		// but with its last value.
		var order []string
		values := map[string][]string{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key := keyTok.(string)
			value, err := jsonValues(dec)
			if err != nil {
				return nil, err
			}
			if _, dup := values[key]; !dup {
				order = append(order, key)
			}
			values[key] = value
		}
		if _, err := dec.Token(); err != nil { // closing }
			return nil, err
		}
		var out []string
		for _, key := range order {
			out = append(out, key)
			out = append(out, values[key]...)
		}
		return out, nil
	case string:
		return []string{v}, nil
	case json.Number:
		return []string{pyNumber(string(v))}, nil
	case bool:
		if v {
			return []string{"True"}, nil
		}
		return []string{"False"}, nil
	}
	return nil, nil // null
}

// pyNumber formats a JSON number literal as str(json.loads(literal)).
func pyNumber(lit string) string {
	if !strings.ContainsAny(lit, ".eE") {
		if lit == "-0" {
			return "0"
		}
		return lit // Python ints are arbitrary precision: digits survive as-is
	}
	f, _ := strconv.ParseFloat(lit, 64) // out of range yields ±Inf, like Python
	return pyFloatRepr(f)
}

// pyFloatRepr is Python's repr(float): shortest round-trip digits, exponent
// form outside 1e-4 <= |x| < 1e16, and a trailing ".0" on integral values.
func pyFloatRepr(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	exp, _ := strconv.Atoi(sci[strings.IndexByte(sci, 'e')+1:])
	if f != 0 && (exp < -4 || exp >= 16) {
		return sci
	}
	fixed := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(fixed, ".") {
		fixed += ".0"
	}
	return fixed
}

// xmlDecoder builds a decoder that accepts UTF-8, UTF-16 (with a
// byte-order mark, or without one as decodeUTF16 detects it), Latin-1 and
// ASCII.
func xmlDecoder(data []byte) *xml.Decoder {
	if text, ok := decodeUTF16(data); ok {
		data = []byte(text)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "utf-8", "utf8", "utf-16", "utf16":
			return input, nil // UTF-16 was transcoded above
		case "iso-8859-1", "latin-1", "latin1", "us-ascii", "ascii":
			raw, err := io.ReadAll(input)
			if err != nil {
				return nil, err
			}
			return strings.NewReader(latin1(raw)), nil
		}
		return nil, fmt.Errorf("unsupported XML encoding: %s", charset)
	}
	return dec
}

// walkXML feeds element starts, ends, and in-document character data to the
// callbacks, and enforces the well-formedness rules encoding/xml skips
// (exactly one root element, no text outside it).
func walkXML(data []byte, start func(xml.StartElement), end func(), text func([]byte)) error {
	dec := xmlDecoder(data)
	depth, roots := 0, 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if roots++; roots > 1 {
					return errors.New("junk after document element")
				}
			}
			depth++
			start(t)
		case xml.EndElement:
			depth--
			end()
		case xml.CharData:
			if depth > 0 {
				text(t)
			} else if len(bytes.TrimSpace(t)) > 0 {
				return errors.New("syntax error: text outside the document element")
			}
		}
	}
	if roots == 0 {
		return errors.New("no element found")
	}
	return nil
}

// collectXMLText returns every non-empty text and tail string in document
// order, as ElementTree exposes them (comments do not split a text run).
func collectXMLText(data []byte) ([]string, error) {
	var parts []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			parts = append(parts, cur.String())
			cur.Reset()
		}
	}
	err := walkXML(data,
		func(xml.StartElement) { flush() },
		flush,
		func(b []byte) { cur.Write(b) },
	)
	return parts, err
}

// collectOOXMLText returns one string per <container> element in the given
// namespace, each the concatenation of the text of its descendant <t> runs.
func collectOOXMLText(data []byte, ns, container string) ([]string, error) {
	var (
		units   []*strings.Builder // every container, in document order
		open    []*strings.Builder // containers currently open
		isUnit  []bool             // per open element: is it a container?
		capture bool               // directly inside a <t>, before any child
	)
	err := walkXML(data,
		func(el xml.StartElement) {
			unit := el.Name.Space == ns && el.Name.Local == container
			if unit {
				sb := &strings.Builder{}
				units = append(units, sb)
				open = append(open, sb)
			}
			isUnit = append(isUnit, unit)
			capture = el.Name.Space == ns && el.Name.Local == "t"
		},
		func() {
			if isUnit[len(isUnit)-1] {
				open = open[:len(open)-1]
			}
			isUnit = isUnit[:len(isUnit)-1]
			capture = false
		},
		func(b []byte) {
			if capture {
				for _, sb := range open {
					sb.Write(b)
				}
			}
		},
	)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(units))
	for i, sb := range units {
		out[i] = sb.String()
	}
	return out, nil
}
