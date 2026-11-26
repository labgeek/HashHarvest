package readers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// Limits that bound the memory one file can take. Anything over a limit is
// reported, never silently dropped. They are variables only so tests can
// lower them.
var (
	// maxStructuredSize is the largest .csv, .json or .xml file parsed as
	// a whole; a larger one is scanned as plain text instead.
	maxStructuredSize int64 = 128 << 20
	// maxZipPart and maxZipTotal cap the decompressed size of one part of
	// an Office file, and of all the parts read from one file.
	maxZipPart  int64 = 256 << 20
	maxZipTotal int64 = 1 << 30
	// maxPDFSize caps the PDF file itself (the parser holds it in memory);
	// maxPDFStream and maxPDFTotal cap one decoded stream and all decoded
	// streams of one file.
	maxPDFSize   int64 = 512 << 20
	maxPDFStream int64 = 64 << 20
	maxPDFTotal  int64 = 1 << 30
	// maxPDFForms caps the form XObjects drawn on one page: a form that
	// draws itself repeatedly would otherwise take effectively forever.
	maxPDFForms = 100_000
	// textReadSize is how many bytes StreamText reads at a time.
	textReadSize = 1 << 20
)

// utf16Sample is how much of a file without a byte-order mark is examined
// to decide whether it is UTF-16.
const utf16Sample = 64 << 10

// sizeText renders a limit for messages.
func sizeText(n int64) string {
	if n >= 1<<20 && n%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d bytes", n)
}

var plainText = map[string]bool{".txt": true, ".log": true, ".md": true}

var structured = map[string]string{".csv": "CSV", ".json": "JSON", ".xml": "XML"}

// StreamPlan reports whether path is scanned by streaming its text through
// StreamText rather than read whole. Plain-text files always are. CSV, JSON
// and XML files over maxStructuredSize are too, with a note saying so, so
// their hashes are still found without parsing them in memory.
func StreamPlan(path string) (stream bool, note string) {
	ext := strings.ToLower(SplitExt(path))
	if plainText[ext] {
		return true, ""
	}
	kind, ok := structured[ext]
	if !ok {
		return false, ""
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() <= maxStructuredSize {
		return false, "" // the reader reports any error
	}
	return true, fmt.Sprintf("scanned as plain text: larger than the %s limit for parsing %s files",
		sizeText(maxStructuredSize), kind)
}

// StreamText decodes a text file piece by piece and passes the text to fn,
// so memory use does not grow with the file. Decoding is that of readText:
// UTF-16 by byte-order mark or detection, else UTF-8 with each invalid byte
// read as Latin-1, and CRLF or lone CR translated to LF. fn must not keep
// the slice. StreamText stops with ctx's error when ctx is cancelled.
func StreamText(ctx context.Context, path string, fn func([]rune)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return decodeText(ctx, f, fn)
}

type textDecoder interface {
	// decode converts the next bytes; at eof it also flushes what is held
	// back. The returned slice is reused by the next call.
	decode(p []byte, eof bool) []rune
}

func decodeText(ctx context.Context, r io.Reader, fn func([]rune)) error {
	sample := make([]byte, utf16Sample)
	n, err := io.ReadFull(r, sample)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}
	whole := err != nil // the sample is the whole file
	sample = sample[:n]

	var dec textDecoder
	switch {
	case n >= 2 && sample[0] == 0xFF && sample[1] == 0xFE:
		dec, sample = &utf16Decoder{}, sample[2:]
	case n >= 2 && sample[0] == 0xFE && sample[1] == 0xFF:
		dec, sample = &utf16Decoder{bigEndian: true}, sample[2:]
	default:
		probe := sample
		if !whole {
			probe = probe[:len(probe)&^1] // a full sample may end mid code unit
		}
		switch {
		case looksUTF16(probe, false):
			dec = &utf16Decoder{}
		case looksUTF16(probe, true):
			dec = &utf16Decoder{bigEndian: true}
		default:
			dec = &utf8Decoder{}
		}
	}

	var nl newlineFilter
	emit := func(text []rune) {
		if text = nl.filter(text); len(text) > 0 {
			fn(text)
		}
	}
	in := io.MultiReader(bytes.NewReader(sample), r)
	buf := make([]byte, textReadSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := in.Read(buf)
		if n > 0 {
			emit(dec.decode(buf[:n], false))
		}
		if err == io.EOF {
			emit(dec.decode(nil, true))
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// newlineFilter applies Python's universal-newline translation in place:
// CRLF and lone CR become LF, also when CR and LF arrive in separate pieces.
type newlineFilter struct{ afterCR bool }

func (f *newlineFilter) filter(text []rune) []rune {
	out := text[:0]
	for _, r := range text {
		if f.afterCR {
			f.afterCR = false
			if r == '\n' {
				continue // the CR was already written as LF
			}
		}
		if r == '\r' {
			f.afterCR = true
			r = '\n'
		}
		out = append(out, r)
	}
	return out
}

// utf8Decoder decodes UTF-8 and reads each byte that is not part of a valid
// sequence as Latin-1. A sequence split between pieces is held back.
//
// ponytail: whole-file reading chose UTF-8 or Latin-1 for the entire file;
// per-byte fallback lets the file stream and gives the same hashes, but the
// context text of a mostly-Latin-1 file whose bytes happen to form valid
// UTF-8 can differ.
type utf8Decoder struct {
	carry []byte
	out   []rune
}

func (d *utf8Decoder) decode(p []byte, eof bool) []rune {
	data := p
	if len(d.carry) > 0 {
		data = append(d.carry, p...)
	}
	d.out = d.out[:0]
	i := 0
	for i < len(data) {
		b := data[i]
		if b < utf8.RuneSelf {
			d.out = append(d.out, rune(b))
			i++
			continue
		}
		if !eof && !utf8.FullRune(data[i:]) {
			break // the rest of this sequence is in the next piece
		}
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			r = rune(b) // not UTF-8: Latin-1
		}
		d.out = append(d.out, r)
		i += size
	}
	d.carry = append(d.carry[:0], data[i:]...)
	return d.out
}

// utf16Decoder decodes UTF-16 code units, holding back an odd byte or a
// high surrogate until the next piece. Unpaired surrogates become U+FFFD,
// and a trailing odd byte is dropped, as utf16.Decode on the whole file did.
type utf16Decoder struct {
	bigEndian bool
	carry     []byte
	high      rune // pending high surrogate, or 0
	out       []rune
}

func (d *utf16Decoder) decode(p []byte, eof bool) []rune {
	data := p
	if len(d.carry) > 0 {
		data = append(d.carry, p...)
	}
	d.out = d.out[:0]
	n := len(data) &^ 1
	for i := 0; i < n; i += 2 {
		hi, lo := data[i+1], data[i]
		if d.bigEndian {
			hi, lo = lo, hi
		}
		u := rune(hi)<<8 | rune(lo)
		if d.high != 0 {
			high := d.high
			d.high = 0
			if u >= 0xDC00 && u <= 0xDFFF {
				d.out = append(d.out, (high-0xD800)<<10+(u-0xDC00)+0x10000)
				continue
			}
			d.out = append(d.out, utf8.RuneError)
		}
		switch {
		case u >= 0xD800 && u <= 0xDBFF:
			d.high = u
		case u >= 0xDC00 && u <= 0xDFFF:
			d.out = append(d.out, utf8.RuneError)
		default:
			d.out = append(d.out, u)
		}
	}
	d.carry = append(d.carry[:0], data[n:]...)
	if eof && d.high != 0 {
		d.out = append(d.out, utf8.RuneError)
		d.high = 0
	}
	return d.out
}
