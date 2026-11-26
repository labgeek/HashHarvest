package extractor

import (
	"strings"
	"unicode/utf8"

	"github.com/labgeek/HashHarvest/internal/readers"
)

const (
	contextRunes = 60  // characters of context kept on each side of a hash
	maxHashLen   = 128 // the longest hash, SHA512, in hex digits
)

// hashFinder finds hashes in text that arrives in pieces, with exactly the
// results of one pass over the whole text: every maximal run of 32, 40, 64
// or 128 hex digits, with its 1-based line number and up to 60 characters
// of context on each side. Memory stays bounded by the piece size, however
// long the text.
type hashFinder struct {
	types     []string
	emit      func(Hit)
	buf       []rune // up to contextRunes of scanned text, then unscanned text
	pos       int    // index in buf of the next rune to scan
	line      int
	inLongRun bool // inside a hex run already too long to be a hash
}

func newHashFinder(types []string, emit func(Hit)) *hashFinder {
	return &hashFinder{types: types, emit: emit, line: 1}
}

// write scans the next piece of text. The finder copies what it keeps.
func (f *hashFinder) write(text []rune) {
	f.buf = append(f.buf, text...)
	f.scan(false)
	if drop := f.pos - contextRunes; drop > 0 { // keep only the left context
		f.buf = f.buf[:copy(f.buf, f.buf[drop:])]
		f.pos -= drop
	}
}

// close scans what was held back waiting for more text.
func (f *hashFinder) close() {
	f.scan(true)
	f.buf = nil
}

func (f *hashFinder) scan(eof bool) {
	for f.pos < len(f.buf) {
		c := f.buf[f.pos]
		if !isHex(c) {
			f.inLongRun = false
			if c == '\n' {
				f.line++
			}
			f.pos++
			continue
		}
		if f.inLongRun {
			f.pos++
			continue
		}
		end := f.pos
		for end < len(f.buf) && end-f.pos <= maxHashLen && isHex(f.buf[end]) {
			end++
		}
		if end-f.pos > maxHashLen {
			f.inLongRun = true
			f.pos = end
			continue
		}
		// The run may continue in the next piece, and its right context
		// certainly does: wait for it.
		if !eof && end+contextRunes > len(f.buf) {
			return
		}
		if hashType, ok := typeByLength[end-f.pos]; ok && selected(f.types, hashType) {
			from, to := max(f.pos-contextRunes, 0), min(end+contextRunes, len(f.buf))
			context := strings.ReplaceAll(string(f.buf[from:to]), "\n", " ")
			f.emit(Hit{
				HashType:  hashType,
				HashValue: strings.ToLower(string(f.buf[f.pos:end])),
				Line:      f.line,
				Context:   readers.PyStrip(context),
			})
		}
		f.pos = end
	}
}

// FindHashes returns, in order of appearance, every standalone run of
// exactly 32, 40, 64, or 128 hex digits in text, lowercased, with its
// 1-based line number and up to 60 characters of context on each side.
//
// Go's regexp has no lookaround, so the Python patterns
// (?<![a-fA-F0-9])[a-fA-F0-9]{N}(?![a-fA-F0-9]) are implemented as
// "a maximal hex run whose length is N", which is equivalent.
func FindHashes(text string, types []string) []Hit {
	var hits []Hit
	f := newHashFinder(types, func(h Hit) { hits = append(hits, h) })
	// Feed the text in pieces, so a large text is never all converted to
	// runes at once. Pieces end at character boundaries.
	for text != "" {
		n := min(len(text), 64<<10)
		for n < len(text) && !utf8.RuneStart(text[n]) {
			n++
		}
		f.write([]rune(text[:n]))
		text = text[n:]
	}
	f.close()
	return hits
}
