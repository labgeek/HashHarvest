package readers

// A standard-library-only PDF text extractor, standing in for pypdf.
//
// Scope: it recovers objects by scanning the file (so damaged or missing
// cross-reference tables do not matter), expands object streams, walks the
// page tree, and interprets the text operators of each page's content
// streams and form XObjects. Text is decoded through each font's ToUnicode
// map or its simple encoding.
//
// Encrypted documents are opened when pypdf would open them without a
// password (see pdfcrypt.go); one that needs a password is reported as an
// error, so the file is listed as skipped. Line breaks and inter-word spaces
// are inferred from text positions, so they can differ from pypdf's
// heuristics.

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

type (
	pdfName   string
	pdfRef    int
	pdfOp     string
	pdfDict   map[string]any
	pdfStream struct {
		dict     pdfDict
		raw      []byte
		num, gen int // object number and generation, which key its decryption
	}
)

// Other object kinds are plain Go values: float64, bool, nil, []byte
// (strings) and []any (arrays).

type pdfLexer struct {
	b     []byte
	pos   int
	refs  bool // recognize indirect references ("12 0 R"); off for content streams
	depth int  // current array/dictionary nesting
}

// pdfMaxDepth bounds nesting so hostile input cannot exhaust the stack.
const pdfMaxDepth = 64

func isPDFSpace(c byte) bool {
	return c == 0 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

func isPDFDelim(c byte) bool { return strings.IndexByte("()<>[]{}/%", c) >= 0 }

func (l *pdfLexer) skipSpace() {
	for l.pos < len(l.b) {
		c := l.b[l.pos]
		switch {
		case isPDFSpace(c):
			l.pos++
		case c == '%':
			for l.pos < len(l.b) && l.b[l.pos] != '\n' && l.b[l.pos] != '\r' {
				l.pos++
			}
		default:
			return
		}
	}
}

// next returns the next object, or a pdfOp for any bare keyword or
// structural closer. It returns io.EOF at the end of the data.
func (l *pdfLexer) next() (any, error) {
	l.skipSpace()
	if l.pos >= len(l.b) {
		return nil, io.EOF
	}
	c := l.b[l.pos]
	switch c {
	case '/':
		l.pos++
		return l.name(), nil
	case '(':
		return l.literal()
	case '<':
		if l.pos+1 < len(l.b) && l.b[l.pos+1] == '<' {
			l.pos += 2
			return l.dict()
		}
		l.pos++
		return l.hexString(), nil
	case '[':
		l.pos++
		return l.array()
	case '>':
		if l.pos+1 < len(l.b) && l.b[l.pos+1] == '>' {
			l.pos += 2
			return pdfOp(">>"), nil
		}
		fallthrough
	case ']', '{', '}', ')':
		l.pos++
		return pdfOp(string(c)), nil
	}
	start := l.pos
	for l.pos < len(l.b) && !isPDFSpace(l.b[l.pos]) && !isPDFDelim(l.b[l.pos]) {
		l.pos++
	}
	word := string(l.b[start:l.pos])
	if n, ok := pdfNumber(word); ok {
		if l.refs && n >= 0 && n == math.Trunc(n) && !strings.ContainsAny(word, ".+") && l.refTail() {
			return pdfRef(int(n)), nil
		}
		return n, nil
	}
	switch word {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null":
		return nil, nil
	}
	return pdfOp(word), nil
}

func pdfNumber(word string) (float64, bool) {
	digits := false
	for i := 0; i < len(word); i++ {
		c := word[i]
		if c >= '0' && c <= '9' {
			digits = true
		} else if c != '+' && c != '-' && c != '.' {
			return 0, false
		}
	}
	if !digits {
		return 0, false
	}
	n, err := strconv.ParseFloat(word, 64)
	return n, err == nil
}

// refTail consumes " <generation> R" if it follows, completing a reference.
func (l *pdfLexer) refTail() bool {
	save := l.pos
	l.skipSpace()
	start := l.pos
	for l.pos < len(l.b) && l.b[l.pos] >= '0' && l.b[l.pos] <= '9' {
		l.pos++
	}
	if l.pos > start {
		l.skipSpace()
		if l.pos < len(l.b) && l.b[l.pos] == 'R' &&
			(l.pos+1 == len(l.b) || isPDFSpace(l.b[l.pos+1]) || isPDFDelim(l.b[l.pos+1])) {
			l.pos++
			return true
		}
	}
	l.pos = save
	return false
}

func (l *pdfLexer) name() pdfName {
	var out []byte
	for l.pos < len(l.b) && !isPDFSpace(l.b[l.pos]) && !isPDFDelim(l.b[l.pos]) {
		c := l.b[l.pos]
		if c == '#' && l.pos+2 < len(l.b) {
			if v, err := strconv.ParseUint(string(l.b[l.pos+1:l.pos+3]), 16, 8); err == nil {
				out = append(out, byte(v))
				l.pos += 3
				continue
			}
		}
		out = append(out, c)
		l.pos++
	}
	return pdfName(out)
}

func (l *pdfLexer) literal() ([]byte, error) {
	l.pos++ // opening paren
	var out []byte
	depth := 1
	for l.pos < len(l.b) {
		c := l.b[l.pos]
		l.pos++
		switch c {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return out, nil
			}
		case '\\':
			if l.pos >= len(l.b) {
				return nil, io.ErrUnexpectedEOF
			}
			e := l.b[l.pos]
			l.pos++
			switch {
			case e == 'n':
				c = '\n'
			case e == 'r':
				c = '\r'
			case e == 't':
				c = '\t'
			case e == 'b':
				c = '\b'
			case e == 'f':
				c = '\f'
			case e >= '0' && e <= '7':
				v := int(e - '0')
				for i := 0; i < 2 && l.pos < len(l.b) && l.b[l.pos] >= '0' && l.b[l.pos] <= '7'; i++ {
					v = v*8 + int(l.b[l.pos]-'0')
					l.pos++
				}
				c = byte(v)
			case e == '\r':
				if l.pos < len(l.b) && l.b[l.pos] == '\n' {
					l.pos++
				}
				continue // line continuation
			case e == '\n':
				continue
			default:
				c = e
			}
		}
		out = append(out, c)
	}
	return nil, io.ErrUnexpectedEOF
}

func (l *pdfLexer) hexString() []byte {
	var digits []byte
	for l.pos < len(l.b) {
		c := l.b[l.pos]
		l.pos++
		if c == '>' {
			break
		}
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			digits = append(digits, c)
		}
	}
	return unhex(digits)
}

func unhex(digits []byte) []byte {
	if len(digits)%2 == 1 {
		digits = append(digits, '0')
	}
	out := make([]byte, len(digits)/2)
	hex.Decode(out, digits) // digits were filtered to valid hex above
	return out
}

func (l *pdfLexer) array() ([]any, error) {
	if l.depth++; l.depth > pdfMaxDepth {
		return nil, errors.New("PDF objects nested too deeply")
	}
	defer func() { l.depth-- }()
	out := []any{}
	for {
		v, err := l.next()
		if err != nil {
			return nil, err
		}
		if op, ok := v.(pdfOp); ok {
			if op == "]" {
				return out, nil
			}
			continue // stray keyword inside an array
		}
		out = append(out, v)
	}
}

func (l *pdfLexer) dict() (pdfDict, error) {
	if l.depth++; l.depth > pdfMaxDepth {
		return nil, errors.New("PDF objects nested too deeply")
	}
	defer func() { l.depth-- }()
	out := pdfDict{}
	for {
		k, err := l.next()
		if err != nil {
			return nil, err
		}
		if k == pdfOp(">>") {
			return out, nil
		}
		key, ok := k.(pdfName)
		if !ok {
			continue
		}
		v, err := l.next()
		if err != nil {
			return nil, err
		}
		if op, ok := v.(pdfOp); ok {
			if op == ">>" {
				return out, nil
			}
			v = nil
		}
		out[string(key)] = v
	}
}

type pdfDoc struct {
	objs     map[int]any
	trailers []pdfDict // trailer dictionaries and cross-reference stream dicts, in file order
	fonts    map[pdfRef]*pdfFont
	crypt    *pdfCrypt // nil for an unencrypted document
}

var pdfObjRE = regexp.MustCompile(`(?:^|[^0-9A-Za-z])([0-9]{1,10})[\x00\t\n\f\r ]+([0-9]{1,5})[\x00\t\n\f\r ]+obj|trailer`)

// parsePDF indexes every indirect object by scanning the file front to
// back. A later definition replaces an earlier one, which is also how
// incremental updates are meant to be read. Stream bodies are skipped so
// binary data cannot be mistaken for object headers.
func parsePDF(data []byte) (*pdfDoc, error) {
	head := data
	if len(head) > 1024 {
		head = head[:1024]
	}
	if !bytes.Contains(head, []byte("%PDF-")) {
		return nil, errors.New("not a PDF file (missing %PDF- header)")
	}
	doc := scanPDF(data, nil)
	enc, id, err := doc.encryption()
	if err != nil || enc == nil {
		return doc, err
	}
	c, err := doc.newCrypt(enc, id)
	if err != nil {
		return nil, err
	}
	// ponytail: rescan so object streams are expanded with the key in hand;
	// strings outside streams stay encrypted, as text extraction never reads them.
	return scanPDF(data, c), nil
}

func scanPDF(data []byte, crypt *pdfCrypt) *pdfDoc {
	doc := &pdfDoc{objs: map[int]any{}, fonts: map[pdfRef]*pdfFont{}, crypt: crypt}
	for pos := 0; pos < len(data); {
		m := pdfObjRE.FindSubmatchIndex(data[pos:])
		if m == nil {
			break
		}
		lex := pdfLexer{b: data, pos: pos + m[1], refs: true}
		if m[2] < 0 { // "trailer"
			pos = lex.pos
			if v, err := lex.next(); err == nil {
				if d, ok := v.(pdfDict); ok {
					doc.trailers = append(doc.trailers, d)
					pos = lex.pos
				}
			}
			continue
		}
		num, _ := strconv.Atoi(string(data[pos+m[2] : pos+m[3]]))
		gen, _ := strconv.Atoi(string(data[pos+m[4] : pos+m[5]]))
		pos = lex.pos
		val, err := lex.next()
		if err != nil {
			continue
		}
		pos = lex.pos
		if _, isOp := val.(pdfOp); isOp {
			val = nil // e.g. an empty "obj endobj"
		}
		if d, ok := val.(pdfDict); ok {
			lex.skipSpace()
			if bytes.HasPrefix(data[lex.pos:], []byte("stream")) {
				start := lex.pos + len("stream")
				if start < len(data) && data[start] == '\r' {
					start++
				}
				if start < len(data) && data[start] == '\n' {
					start++
				}
				stop, next := pdfStreamEnd(data, start, d)
				stream := &pdfStream{dict: d, raw: data[start:stop], num: num, gen: gen}
				val, pos = stream, next
				switch d["Type"] {
				case pdfName("ObjStm"):
					doc.expandObjStm(stream)
				case pdfName("XRef"):
					doc.trailers = append(doc.trailers, d)
				}
			}
		}
		doc.objs[num] = val
	}
	return doc
}

// pdfStreamEnd returns where the stream data stops and where scanning
// resumes. It trusts a direct /Length only when "endstream" really follows.
func pdfStreamEnd(data []byte, start int, d pdfDict) (stop, next int) {
	if start > len(data) {
		return len(data), len(data)
	}
	if n, ok := d["Length"].(float64); ok && n >= 0 && n <= float64(len(data)-start) {
		l := pdfLexer{b: data, pos: start + int(n)}
		l.skipSpace()
		if bytes.HasPrefix(data[l.pos:], []byte("endstream")) {
			return start + int(n), l.pos + len("endstream")
		}
	}
	i := bytes.Index(data[start:], []byte("endstream"))
	if i < 0 {
		return len(data), len(data)
	}
	stop = start + i
	if stop > start && data[stop-1] == '\n' {
		stop--
	}
	if stop > start && data[stop-1] == '\r' {
		stop--
	}
	return stop, start + i + len("endstream")
}

func (d *pdfDoc) expandObjStm(s *pdfStream) {
	data, err := d.decode(s)
	if err != nil {
		return
	}
	n, first := int(d.num(s.dict["N"])), int(d.num(s.dict["First"]))
	if first < 0 || first > len(data) {
		return
	}
	header := pdfLexer{b: data[:first]}
	for i := 0; i < n; i++ {
		a, _ := header.next()
		b, _ := header.next()
		num, ok1 := a.(float64)
		off, ok2 := b.(float64)
		if !ok1 || !ok2 {
			return
		}
		if p := first + int(off); p >= first && p < len(data) {
			body := pdfLexer{b: data, pos: p, refs: true}
			if v, err := body.next(); err == nil {
				if _, isOp := v.(pdfOp); !isOp {
					d.objs[int(num)] = v
				}
			}
		}
	}
}

func (d *pdfDoc) resolve(v any) any {
	for i := 0; i < 32; i++ {
		ref, ok := v.(pdfRef)
		if !ok {
			return v
		}
		v = d.objs[int(ref)]
	}
	return nil
}

// dict resolves v to a dictionary; a stream yields its own dictionary.
func (d *pdfDoc) dict(v any) (pdfDict, bool) {
	switch t := d.resolve(v).(type) {
	case pdfDict:
		return t, true
	case *pdfStream:
		return t.dict, true
	}
	return nil, false
}

func (d *pdfDoc) num(v any) float64 {
	n, _ := d.resolve(v).(float64)
	return n
}

func (d *pdfDoc) name(v any) string {
	n, _ := d.resolve(v).(pdfName)
	return string(n)
}

func (d *pdfDoc) array(v any) []any {
	a, _ := d.resolve(v).([]any)
	return a
}

// decode applies a stream's filter chain.
func (d *pdfDoc) decode(s *pdfStream) ([]byte, error) {
	filters := d.array(s.dict["Filter"])
	if filters == nil {
		if f := d.resolve(s.dict["Filter"]); f != nil {
			filters = []any{f}
		}
	}
	parms := d.array(s.dict["DecodeParms"])
	if parms == nil {
		parms = []any{s.dict["DecodeParms"]}
	}
	data := s.raw
	// ponytail: a /Crypt filter is treated as Identity (its usual use: leaving
	// metadata unencrypted); named per-stream crypt filters are not resolved.
	if d.crypt != nil && d.name(s.dict["Type"]) != "XRef" && !(len(filters) > 0 && d.name(filters[0]) == "Crypt") {
		var err error
		if data, err = d.crypt.decrypt(s.num, s.gen, data); err != nil {
			return nil, err
		}
	}
	for i, f := range filters {
		var err error
		var p pdfDict
		if i < len(parms) {
			p, _ = d.dict(parms[i])
		}
		switch name := d.name(f); name {
		case "FlateDecode", "Fl", "LZWDecode", "LZW":
			if name == "FlateDecode" || name == "Fl" {
				data, err = inflate(data)
			} else {
				early, _ := d.resolve(p["EarlyChange"]).(float64)
				if p["EarlyChange"] == nil {
					early = 1
				}
				data, err = lzwDecode(data, int(early))
			}
			if err != nil {
				return nil, err
			}
			if p != nil {
				if data, err = d.unpredict(data, p); err != nil {
					return nil, err
				}
			}
		case "Crypt":
		case "ASCIIHexDecode", "AHx":
			l := pdfLexer{b: data}
			data = l.hexString()
		case "ASCII85Decode", "A85":
			data = bytes.TrimPrefix(bytes.TrimSpace(data), []byte("<~"))
			if end := bytes.Index(data, []byte("~>")); end >= 0 {
				data = data[:end]
			}
			if data, err = io.ReadAll(ascii85.NewDecoder(bytes.NewReader(data))); err != nil {
				return nil, err
			}
		case "RunLengthDecode", "RL":
			data = runLengthDecode(data)
		default:
			return nil, fmt.Errorf("unsupported PDF stream filter %q", name)
		}
	}
	return data, nil
}

func inflate(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("PDF stream: %w", err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("PDF stream: %w", err)
	}
	return out, nil // a truncated stream still yields the text before the damage
}

func runLengthDecode(data []byte) []byte {
	var out []byte
	for i := 0; i < len(data); {
		n := int(data[i])
		i++
		switch {
		case n == 128:
			return out
		case n < 128:
			end := i + n + 1
			if end > len(data) {
				end = len(data)
			}
			out = append(out, data[i:end]...)
			i = end
		case i < len(data):
			out = append(out, bytes.Repeat(data[i:i+1], 257-n)...)
			i++
		}
	}
	return out
}

// lzwDecode expands LZWDecode data. earlyChange 1 (the PDF default) widens
// codes one entry early.
func lzwDecode(data []byte, earlyChange int) ([]byte, error) {
	table := make([][]byte, 258, 4096)
	for i := range 256 {
		table[i] = []byte{byte(i)}
	}
	var out, prev []byte
	width, bits, nbits, pos := 9, uint32(0), 0, 0
	for {
		for nbits < width {
			if pos >= len(data) {
				return out, nil // a missing EOD marker is tolerated
			}
			bits = bits<<8 | uint32(data[pos])
			pos++
			nbits += 8
		}
		nbits -= width
		code := int(bits>>nbits) & (1<<width - 1)
		var entry []byte
		switch {
		case code == 256:
			table, width, prev = table[:258], 9, nil
			continue
		case code == 257:
			return out, nil
		case code < len(table):
			entry = table[code]
		case code == len(table) && prev != nil:
			entry = append(append([]byte(nil), prev...), prev[0])
		default:
			return nil, errors.New("PDF stream: invalid LZW code")
		}
		out = append(out, entry...)
		if prev != nil && len(table) < 4096 {
			table = append(table, append(append([]byte(nil), prev...), entry[0]))
		}
		prev = entry
		if width < 12 && len(table)+earlyChange >= 1<<width {
			width++
		}
	}
}

// unpredict reverses the TIFF (2) and PNG (>= 10) predictors.
func (d *pdfDoc) unpredict(data []byte, p pdfDict) ([]byte, error) {
	predictor := int(d.num(p["Predictor"]))
	if predictor <= 1 {
		return data, nil
	}
	if predictor != 2 && predictor < 10 {
		return nil, fmt.Errorf("unsupported PDF stream predictor %d", predictor)
	}
	get := func(key string, def int) int {
		if v, ok := d.resolve(p[key]).(float64); ok && v > 0 {
			return int(v)
		}
		return def
	}
	colors, bpc, cols := get("Colors", 1), get("BitsPerComponent", 8), get("Columns", 1)
	bpp := (colors*bpc + 7) / 8
	rowLen := (colors*bpc*cols + 7) / 8
	if predictor == 2 {
		// ponytail: byte-wise differencing like pypdf; exact for 8-bit components.
		out := append([]byte(nil), data...)
		bpp = max(rowLen/cols, 1)
		for i := range out {
			if i%rowLen >= bpp {
				out[i] += out[i-bpp]
			}
		}
		return out, nil
	}
	if rowLen <= 0 || rowLen > len(data) {
		return nil, errors.New("PDF stream predictor parameters do not fit the data")
	}
	var out []byte
	prev := make([]byte, rowLen)
	for i := 0; i+1+rowLen <= len(data); i += rowLen + 1 {
		row := append([]byte(nil), data[i+1:i+1+rowLen]...)
		for j := range row {
			var left, up, upLeft int
			if j >= bpp {
				left, upLeft = int(row[j-bpp]), int(prev[j-bpp])
			}
			up = int(prev[j])
			switch data[i] {
			case 1:
				row[j] += byte(left)
			case 2:
				row[j] += byte(up)
			case 3:
				row[j] += byte((left + up) / 2)
			case 4:
				pa, pb, pc := abs(up-upLeft), abs(left-upLeft), abs(left+up-2*upLeft)
				switch {
				case pa <= pb && pa <= pc:
					row[j] += byte(left)
				case pb <= pc:
					row[j] += byte(up)
				default:
					row[j] += byte(upLeft)
				}
			}
		}
		out = append(out, row...)
		prev = row
	}
	return out, nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

type pdfPage struct{ dict, res pdfDict }

func (d *pdfDoc) pages() ([]pdfPage, error) {
	var root pdfDict
	for i := len(d.trailers) - 1; i >= 0 && root == nil; i-- {
		root, _ = d.dict(d.trailers[i]["Root"])
	}
	if root == nil { // no usable trailer: fall back to any catalog object
		nums := make([]int, 0, len(d.objs))
		for n := range d.objs {
			nums = append(nums, n)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(nums)))
		for _, n := range nums {
			if c, ok := d.objs[n].(pdfDict); ok && c["Type"] == pdfName("Catalog") {
				root = c
				break
			}
		}
	}
	if root == nil {
		return nil, errors.New("PDF has no document catalog")
	}
	var pages []pdfPage
	seen := map[pdfRef]bool{}
	var walk func(node any, res pdfDict, depth int)
	walk = func(node any, res pdfDict, depth int) {
		if ref, ok := node.(pdfRef); ok {
			if seen[ref] {
				return
			}
			seen[ref] = true
		}
		nd, ok := d.dict(node)
		if !ok || depth > 100 {
			return
		}
		if r, ok := d.dict(nd["Resources"]); ok {
			res = r
		}
		if kids := d.array(nd["Kids"]); kids != nil || d.name(nd["Type"]) == "Pages" {
			for _, kid := range kids {
				walk(kid, res, depth+1)
			}
			return
		}
		pages = append(pages, pdfPage{nd, res})
	}
	walk(root["Pages"], nil, 0)
	return pages, nil
}

func (d *pdfDoc) pageText(p pdfPage) (string, error) {
	var content []byte
	switch c := d.resolve(p.dict["Contents"]).(type) {
	case *pdfStream:
		data, err := d.decode(c)
		if err != nil {
			return "", err
		}
		content = data
	case []any:
		for _, part := range c {
			if s, ok := d.resolve(part).(*pdfStream); ok {
				data, err := d.decode(s)
				if err != nil {
					return "", err
				}
				content = append(append(content, data...), '\n')
			}
		}
	}
	in := &pdfInterp{doc: d}
	in.gs = pdfGState{ctm: pdfIdentity, hScale: 1}
	in.run(content, p.res, 0)
	return in.out.String(), nil
}

// pdfPageTexts returns the extracted text of every page, in page order.
func pdfPageTexts(data []byte) ([]string, error) {
	doc, err := parsePDF(data)
	if err != nil {
		return nil, err
	}
	pages, err := doc.pages()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(pages))
	for i, p := range pages {
		if out[i], err = doc.pageText(p); err != nil {
			return nil, fmt.Errorf("page %d: %w", i+1, err)
		}
	}
	return out, nil
}

// pdfMatrix is the affine matrix [a b c d e f] of the PDF imaging model.
type pdfMatrix [6]float64

var pdfIdentity = pdfMatrix{1, 0, 0, 1, 0, 0}

// mul returns m followed by n.
func (m pdfMatrix) mul(n pdfMatrix) pdfMatrix {
	return pdfMatrix{
		m[0]*n[0] + m[1]*n[2], m[0]*n[1] + m[1]*n[3],
		m[2]*n[0] + m[3]*n[2], m[2]*n[1] + m[3]*n[3],
		m[4]*n[0] + m[5]*n[2] + n[4], m[4]*n[1] + m[5]*n[3] + n[5],
	}
}

type pdfGState struct {
	ctm                                   pdfMatrix
	font                                  *pdfFont
	size, charSp, wordSp, hScale, leading float64
}

type pdfInterp struct {
	doc        *pdfDoc
	out        strings.Builder
	last       byte // last byte written to out
	gs         pdfGState
	stack      []pdfGState
	tm, tlm    pdfMatrix
	endX, endY float64 // device-space position just past the last shown glyph
	shown      bool
	moved      bool // an explicit positioning operator ran since the last show
}

func (in *pdfInterp) write(s string) {
	if s != "" {
		in.out.WriteString(s)
		in.last = s[len(s)-1]
	}
}

func (in *pdfInterp) run(content []byte, res pdfDict, depth int) {
	fonts := map[string]*pdfFont{}
	lex := pdfLexer{b: content}
	var args []any
	num := func(i int) float64 {
		if i < len(args) {
			f, _ := args[i].(float64)
			return f
		}
		return 0
	}
	str := func(i int) []byte {
		if i < len(args) {
			b, _ := args[i].([]byte)
			return b
		}
		return nil
	}
	move := func(tx, ty float64) {
		in.tlm = pdfMatrix{1, 0, 0, 1, tx, ty}.mul(in.tlm)
		in.tm = in.tlm
		in.moved = true
	}
	for {
		tok, err := lex.next()
		if err != nil {
			return
		}
		op, isOp := tok.(pdfOp)
		if !isOp {
			args = append(args, tok)
			continue
		}
		switch op {
		case "q":
			in.stack = append(in.stack, in.gs)
		case "Q":
			if n := len(in.stack); n > 0 {
				in.gs, in.stack = in.stack[n-1], in.stack[:n-1]
			}
		case "cm":
			in.gs.ctm = pdfMatrix{num(0), num(1), num(2), num(3), num(4), num(5)}.mul(in.gs.ctm)
		case "BT":
			in.tm, in.tlm, in.moved = pdfIdentity, pdfIdentity, true
		case "Tf":
			if len(args) >= 2 {
				name, _ := args[0].(pdfName)
				font, ok := fonts[string(name)]
				if !ok {
					fd, _ := in.doc.dict(res["Font"])
					font = in.doc.font(fd[string(name)])
					fonts[string(name)] = font
				}
				in.gs.font, in.gs.size = font, num(1)
			}
		case "Tc":
			in.gs.charSp = num(0)
		case "Tw":
			in.gs.wordSp = num(0)
		case "Tz":
			in.gs.hScale = num(0) / 100
		case "TL":
			in.gs.leading = num(0)
		case "Td":
			move(num(0), num(1))
		case "TD":
			in.gs.leading = -num(1)
			move(num(0), num(1))
		case "Tm":
			in.tlm = pdfMatrix{num(0), num(1), num(2), num(3), num(4), num(5)}
			in.tm, in.moved = in.tlm, true
		case "T*":
			move(0, -in.gs.leading)
		case "Tj":
			in.show(str(0))
		case "'":
			move(0, -in.gs.leading)
			in.show(str(0))
		case "\"":
			in.gs.wordSp, in.gs.charSp = num(0), num(1)
			move(0, -in.gs.leading)
			in.show(str(2))
		case "TJ":
			if len(args) > 0 {
				items, _ := args[0].([]any)
				for _, item := range items {
					switch v := item.(type) {
					case []byte:
						in.show(v)
					case float64:
						in.tm = pdfMatrix{1, 0, 0, 1, -v / 1000 * in.gs.size * in.gs.hScale, 0}.mul(in.tm)
					}
				}
			}
		case "Do":
			if len(args) > 0 && depth < 12 {
				name, _ := args[0].(pdfName)
				xobjects, _ := in.doc.dict(res["XObject"])
				form, ok := in.doc.resolve(xobjects[string(name)]).(*pdfStream)
				if !ok || in.doc.name(form.dict["Subtype"]) != "Form" {
					break
				}
				data, err := in.doc.decode(form)
				if err != nil {
					break
				}
				gs, tm, tlm := in.gs, in.tm, in.tlm
				if m := in.doc.array(form.dict["Matrix"]); len(m) == 6 {
					var fm pdfMatrix
					for i := range fm {
						fm[i] = in.doc.num(m[i])
					}
					in.gs.ctm = fm.mul(in.gs.ctm)
				}
				formRes, ok := in.doc.dict(form.dict["Resources"])
				if !ok {
					formRes = res
				}
				in.run(data, formRes, depth+1)
				in.gs, in.tm, in.tlm = gs, tm, tlm
			}
		case "ID": // inline image: skip the binary data up to a delimited EI
			for {
				i := bytes.Index(content[lex.pos:], []byte("EI"))
				if i < 0 {
					return
				}
				at := lex.pos + i
				lex.pos = at + 2
				if at > 0 && isPDFSpace(content[at-1]) && (lex.pos == len(content) || isPDFSpace(content[lex.pos])) {
					break
				}
			}
		}
		args = args[:0]
	}
}

// show appends the text of one string operand, first inserting a line break
// or a space when the text position jumped relative to the previous glyph.
func (in *pdfInterp) show(s []byte) {
	font := in.gs.font
	if font == nil {
		font = pdfFallbackFont
	}
	text, width := font.decode(s, &in.gs)
	m := in.tm.mul(in.gs.ctm)
	// Unit vectors of the text line and its perpendicular, in device space,
	// so rotated text is measured along its own baseline.
	lineLen, upLen := math.Hypot(m[0], m[1]), math.Hypot(m[2], m[3])
	em := upLen * in.gs.size
	if in.shown && text != "" && lineLen > 0 && upLen > 0 {
		dx, dy := m[4]-in.endX, m[5]-in.endY
		along := (dx*m[0] + dy*m[1]) / lineLen
		across := (dx*m[2] + dy*m[3]) / upLen
		switch {
		case math.Abs(across) > 0.5*em:
			if in.last != '\n' {
				in.write("\n")
			}
		case along > font.gap*em || along < -em || (font.approx && in.moved):
			if in.last != ' ' && in.last != '\n' {
				in.write(" ")
			}
		}
	}
	in.write(text)
	in.tm = pdfMatrix{1, 0, 0, 1, width, 0}.mul(in.tm)
	end := in.tm.mul(in.gs.ctm)
	in.endX, in.endY = end[4], end[5]
	in.shown, in.moved = true, false
}

type pdfFont struct {
	twoByte bool           // composite font: two-byte character codes
	toUni   map[int]string // ToUnicode CMap
	enc     *[256]rune     // simple-font encoding
	first   int
	widths  []float64
	missing float64
	cidW    map[int]float64
	gap     float64 // horizontal jump, in em, that implies a space
	// approx marks fonts whose glyph widths are unknown (the standard 14
	// fonts may omit /Widths), so advances are only estimates.
	approx bool
}

var pdfFallbackFont = &pdfFont{enc: &pdfWinAnsi, missing: 500, gap: 0.125, approx: true}

func (d *pdfDoc) font(v any) *pdfFont {
	ref, isRef := v.(pdfRef)
	if isRef {
		if f, ok := d.fonts[ref]; ok {
			return f
		}
	}
	f := d.buildFont(v)
	if isRef {
		d.fonts[ref] = f
	}
	return f
}

func (d *pdfDoc) buildFont(v any) *pdfFont {
	fd, ok := d.dict(v)
	if !ok {
		return pdfFallbackFont
	}
	f := &pdfFont{gap: 0.125}
	if tu, ok := d.resolve(fd["ToUnicode"]).(*pdfStream); ok {
		if data, err := d.decode(tu); err == nil {
			f.toUni = parseToUnicode(data)
		}
	}
	if d.name(fd["Subtype"]) == "Type0" {
		f.twoByte, f.missing = true, 1000
		if desc := d.array(fd["DescendantFonts"]); len(desc) > 0 {
			if cid, ok := d.dict(desc[0]); ok {
				if dw, ok := d.resolve(cid["DW"]).(float64); ok {
					f.missing = dw
				}
				f.cidW = d.cidWidths(cid["W"])
			}
		}
		return f
	}
	f.enc = d.encoding(fd)
	f.first = int(d.num(fd["FirstChar"]))
	for _, w := range d.array(fd["Widths"]) {
		f.widths = append(f.widths, d.num(w))
	}
	if len(f.widths) == 0 {
		f.missing, f.approx = 500, true
		if strings.Contains(d.name(fd["BaseFont"]), "Courier") {
			f.missing, f.approx = 600, false // monospaced: the width is exact
		}
	} else if desc, ok := d.dict(fd["FontDescriptor"]); ok {
		f.missing = d.num(desc["MissingWidth"])
	}
	if space := f.width(' '); space > 0 {
		f.gap = math.Min(math.Max(space/2000, 0.1), 0.3)
	}
	return f
}

func (d *pdfDoc) cidWidths(v any) map[int]float64 {
	w := d.array(v)
	out := map[int]float64{}
	for i := 0; i+1 < len(w); {
		first := int(d.num(w[i]))
		if list := d.array(w[i+1]); list != nil {
			for j, width := range list {
				out[first+j] = d.num(width)
			}
			i += 2
			continue
		}
		if i+2 >= len(w) {
			break
		}
		last, width := int(d.num(w[i+1])), d.num(w[i+2])
		for c := first; c <= last && c-first < 1<<16; c++ {
			out[c] = width
		}
		i += 3
	}
	return out
}

func (f *pdfFont) width(code int) float64 {
	if f.twoByte {
		if w, ok := f.cidW[code]; ok {
			return w
		}
		return f.missing
	}
	if i := code - f.first; i >= 0 && i < len(f.widths) {
		return f.widths[i]
	}
	return f.missing
}

// decode returns the Unicode text of a string operand and its advance in
// text-space units.
func (f *pdfFont) decode(s []byte, gs *pdfGState) (string, float64) {
	var sb strings.Builder
	var advance float64
	step := 1
	if f.twoByte {
		step = 2
	}
	for i := 0; i+step <= len(s); i += step {
		code := int(s[i])
		if step == 2 {
			code = code<<8 | int(s[i+1])
		}
		if u, ok := f.toUni[code]; ok {
			sb.WriteString(u)
		} else if f.enc != nil && f.enc[code] != 0 {
			sb.WriteRune(f.enc[code])
		}
		w := f.width(code)/1000*gs.size + gs.charSp
		if step == 1 && code == ' ' {
			w += gs.wordSp
		}
		advance += w * gs.hScale
	}
	return sb.String(), advance
}

func (d *pdfDoc) encoding(fd pdfDict) *[256]rune {
	base := &pdfWinAnsi
	pick := func(name string) {
		switch name {
		case "MacRomanEncoding":
			base = &pdfMacRoman
		case "StandardEncoding":
			base = &pdfStandard
		}
	}
	switch e := d.resolve(fd["Encoding"]).(type) {
	case pdfName:
		pick(string(e))
	case pdfDict:
		pick(d.name(e["BaseEncoding"]))
		table := *base
		code := 0
		for _, item := range d.array(e["Differences"]) {
			switch v := d.resolve(item).(type) {
			case float64:
				code = int(v)
			case pdfName:
				if code >= 0 && code < 256 {
					table[code] = glyphRune(string(v))
				}
				code++
			}
		}
		return &table
	}
	return base
}

var (
	pdfWinAnsi, pdfMacRoman, pdfStandard [256]rune
	pdfGlyphs                            = map[string]rune{}
)

func init() {
	for i := 0; i < 256; i++ {
		pdfWinAnsi[i] = rune(i)
	}
	for i, r := range []rune("€\u0081‚ƒ„…†‡ˆ‰Š‹Œ\u008dŽ\u008f\u0090‘’“”•–—˜™š›œ\u009džŸ") {
		pdfWinAnsi[0x80+i] = r
	}
	pdfMacRoman = pdfWinAnsi
	for i, r := range []rune("ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø" +
		"¿¡¬√ƒ≈∆«»…\u00a0ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄€‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ\uf8ffÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ") {
		pdfMacRoman[0x80+i] = r
	}
	// ponytail: StandardEncoding is modeled as WinAnsi plus its two differing
	// ASCII quotes; its upper half (rarely used for text) is approximate.
	pdfStandard = pdfWinAnsi
	pdfStandard[0x27], pdfStandard[0x60] = '’', '‘'

	ascii := "space exclam quotedbl numbersign dollar percent ampersand quotesingle parenleft parenright " +
		"asterisk plus comma hyphen period slash zero one two three four five six seven eight nine " +
		"colon semicolon less equal greater question at"
	for i, name := range strings.Fields(ascii) {
		pdfGlyphs[name] = rune(0x20 + i)
	}
	for i, name := range strings.Fields("bracketleft backslash bracketright asciicircum underscore grave") {
		pdfGlyphs[name] = rune(0x5B + i)
	}
	for i, name := range strings.Fields("braceleft bar braceright asciitilde") {
		pdfGlyphs[name] = rune(0x7B + i)
	}
	for c := 'A'; c <= 'Z'; c++ {
		pdfGlyphs[string(c)] = c
		pdfGlyphs[string(c+32)] = c + 32
	}
	for name, r := range map[string]rune{
		"quoteright": '’', "quoteleft": '‘', "quotedblleft": '“', "quotedblright": '”',
		"endash": '–', "emdash": '—', "bullet": '•', "minus": '−', "ellipsis": '…',
		"nbspace": '\u00a0', "fi": 'ﬁ', "fl": 'ﬂ', "hyphenminus": '-', "periodcentered": '·',
	} {
		pdfGlyphs[name] = r
	}
}

// glyphRune maps an Adobe glyph name to Unicode.
// ponytail: covers ASCII, common punctuation, and the algorithmic uniXXXX /
// uXXXX forms rather than the full 4,000-entry Adobe Glyph List; other names
// become U+FFFD. Extend pdfGlyphs if accented text in contexts matters.
func glyphRune(name string) rune {
	if r, ok := pdfGlyphs[name]; ok {
		return r
	}
	for _, prefix := range []string{"uni", "u"} {
		if rest, ok := strings.CutPrefix(name, prefix); ok && len(rest) >= 4 && len(rest) <= 6 {
			if v, err := strconv.ParseUint(rest, 16, 32); err == nil && v <= 0x10FFFF {
				return rune(v)
			}
		}
	}
	return '\ufffd'
}

// parseToUnicode reads the bfchar and bfrange sections of a ToUnicode CMap.
func parseToUnicode(data []byte) map[int]string {
	out := map[int]string{}
	code := func(b []byte) int {
		n := 0
		for _, c := range b {
			n = n<<8 | int(c)
		}
		return n
	}
	units := func(b []byte) []uint16 {
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		}
		return u
	}
	lex := pdfLexer{b: data}
	var args []any
	for {
		tok, err := lex.next()
		if err != nil {
			return out
		}
		op, isOp := tok.(pdfOp)
		if !isOp {
			args = append(args, tok)
			continue
		}
		switch op {
		case "endbfchar":
			for i := 0; i+1 < len(args); i += 2 {
				src, ok1 := args[i].([]byte)
				dst, ok2 := args[i+1].([]byte)
				if ok1 && ok2 {
					out[code(src)] = string(utf16.Decode(units(dst)))
				}
			}
		case "endbfrange":
			for i := 0; i+2 < len(args); i += 3 {
				lo, ok1 := args[i].([]byte)
				hi, ok2 := args[i+1].([]byte)
				if !ok1 || !ok2 {
					continue
				}
				first, last := code(lo), code(hi)
				switch dst := args[i+2].(type) {
				case []byte:
					u := units(dst)
					if len(u) == 0 {
						continue
					}
					for c := first; c <= last && c-first < 1<<16; c++ {
						out[c] = string(utf16.Decode(u))
						u[len(u)-1]++
					}
				case []any:
					for j, el := range dst {
						if b, ok := el.([]byte); ok {
							out[first+j] = string(utf16.Decode(units(b)))
						}
					}
				}
			}
		}
		args = args[:0]
	}
}
