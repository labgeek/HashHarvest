// Package extractor finds hash-shaped strings in document text and computes
// file digests.
package extractor

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/labgeek/HashHarvest/internal/readers"
)

// Hit is one extracted hash. Line is 0 when there is no line number
// (file-digest mode), which Python represents as None.
type Hit struct {
	HashType  string
	HashValue string
	Line      int
	Context   string
}

// Results maps each file path to its hits, sorted by hash type then value.
type Results map[string][]Hit

// FileError records a file that could not be read.
type FileError struct {
	Path    string
	Message string
}

// Callbacks receives scan events; any field may be nil.
type Callbacks struct {
	Progress func(percent int)
	Status   func(message string)
	Result   func(path, fileType string, hit Hit)
}

// HashTypes lists the supported algorithm names in their fixed order.
var HashTypes = []string{"MD5", "SHA1", "SHA256", "SHA512"}

var typeByLength = map[int]string{32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}

var constructors = map[string]func() hash.Hash{
	"MD5": md5.New, "SHA1": sha1.New, "SHA256": sha256.New, "SHA512": sha512.New,
}

// selected reports whether name is in types; nil types means all.
func selected(types []string, name string) bool {
	if types == nil {
		return true
	}
	for _, t := range types {
		if t == name {
			return true
		}
	}
	return false
}

func isHex(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
}

// CSVSafe neutralizes spreadsheet formula injection (CWE-1236): cells that
// start with = + - @, tab or CR get a leading single quote.
func CSVSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

// FileType is the uppercase extension without its dot ("" if none).
func FileType(path string) string {
	return strings.ToUpper(strings.TrimLeft(readers.SplitExt(path), "."))
}

func requireRegularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		// Opening a FIFO, socket, or device can block forever.
		return errors.New("not a regular file")
	}
	return nil
}

// joinPath concatenates like Python's os.path.join, without cleaning, so
// stored paths match what the Python implementation recorded.
func joinPath(dir, name string) string {
	if dir == "" {
		return name
	}
	last := dir[len(dir)-1]
	if last == '/' || os.PathSeparator == '\\' && (last == '\\' || last == ':' && len(dir) == 2) {
		return dir + name
	}
	return dir + string(os.PathSeparator) + name
}

// walkFiles lists every non-directory entry below dir, sorted. Unreadable
// directories are skipped and links to directories are not followed, as
// with os.walk.
func walkFiles(dir string, keep func(name string) bool) []string {
	var paths []string
	var walk func(string)
	walk = func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			path := joinPath(dir, entry.Name())
			if entry.IsDir() {
				walk(path)
				continue
			}
			if !entry.Type().IsRegular() {
				if info, err := os.Stat(path); err == nil && info.IsDir() {
					continue // symlink or junction to a directory
				}
			}
			if keep == nil || keep(entry.Name()) {
				paths = append(paths, path)
			}
		}
	}
	walk(dir)
	sort.Strings(paths)
	return paths
}

// HashFiles digests every file under dir with the selected algorithms.
// Each hit has Line 0 and Context "file digest".
func HashFiles(ctx context.Context, dir string, types []string, cb Callbacks) (Results, []FileError, error) {
	paths := walkFiles(dir, nil)
	results := Results{}
	var fileErrors []FileError

	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		hits, err := digestFile(path, types)
		if err != nil {
			fileErrors = append(fileErrors, FileError{path, err.Error()})
			if cb.Status != nil {
				cb.Status(fmt.Sprintf("Skipped %s: %s", path, err))
			}
		} else {
			results[path] = hits
			if cb.Result != nil {
				fileType := FileType(path)
				if fileType == "" {
					fileType = "FILE"
				}
				for _, hit := range hits {
					cb.Result(path, fileType, hit)
				}
			}
		}
		if cb.Progress != nil {
			cb.Progress((i + 1) * 100 / len(paths))
		}
	}
	return results, fileErrors, nil
}

func digestFile(path string, types []string) ([]Hit, error) {
	if err := requireRegularFile(path); err != nil {
		return nil, err
	}
	var names []string
	var writers []io.Writer
	var digests []hash.Hash
	for _, name := range HashTypes {
		if selected(types, name) {
			h := constructors[name]()
			names, digests, writers = append(names, name), append(digests, h), append(writers, h)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := io.Copy(io.MultiWriter(writers...), f); err != nil {
		return nil, err
	}
	hits := []Hit{}
	for i, name := range names {
		hits = append(hits, Hit{name, hex.EncodeToString(digests[i].Sum(nil)), 0, "file digest"})
	}
	return hits, nil
}

// Extract scans the supported document types under dir for hash-shaped
// strings. Only the first occurrence of each (type, value) per file is kept.
func Extract(ctx context.Context, dir string, types []string, cb Callbacks) (Results, []FileError, error) {
	paths := walkFiles(dir, func(name string) bool {
		return readers.Supported(strings.ToLower(readers.SplitExt(name)))
	})
	results := Results{}
	var fileErrors []FileError

	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		hits, err := extractFile(path, types)
		if err != nil {
			fileErrors = append(fileErrors, FileError{path, err.Error()})
			if cb.Status != nil {
				cb.Status(fmt.Sprintf("Skipped %s: %s", path, err))
			}
		} else {
			results[path] = hits
			if cb.Result != nil {
				for _, hit := range hits {
					cb.Result(path, FileType(path), hit)
				}
			}
		}
		if cb.Progress != nil {
			cb.Progress((i + 1) * 100 / len(paths))
		}
	}
	return results, fileErrors, nil
}

func extractFile(path string, types []string) (hits []Hit, err error) {
	// Scanned files are untrusted. A parser bug must skip that one file, as
	// Python's per-file "except Exception" did, not take down the scan.
	defer func() {
		if r := recover(); r != nil {
			hits, err = nil, fmt.Errorf("internal error reading file: %v", r)
		}
	}()
	if err := requireRegularFile(path); err != nil {
		return nil, err
	}
	chunks, err := readers.ReadFileChunks(path)
	if err != nil {
		return nil, err
	}
	hits = []Hit{}
	seen := map[[2]string]bool{}
	for _, chunk := range chunks {
		for _, hit := range FindHashes(chunk.Text, types) {
			key := [2]string{hit.HashType, hit.HashValue}
			if seen[key] {
				continue
			}
			seen[key] = true
			if chunk.Location != "" {
				hit.Context = fmt.Sprintf("[%s] %s", chunk.Location, hit.Context)
			}
			hits = append(hits, hit)
		}
	}
	SortHits(hits)
	return hits, nil
}

// SortHits orders hits by hash type, then value, the order every export uses.
func SortHits(hits []Hit) {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].HashType != hits[j].HashType {
			return hits[i].HashType < hits[j].HashType
		}
		return hits[i].HashValue < hits[j].HashValue
	})
}

// FindHashes returns, in order of appearance, every standalone run of
// exactly 32, 40, 64, or 128 hex digits in text, lowercased, with its
// 1-based line number and up to 60 characters of context on each side.
//
// Go's regexp has no lookaround, so the Python patterns
// (?<![a-fA-F0-9])[a-fA-F0-9]{N}(?![a-fA-F0-9]) are implemented as
// "a maximal hex run whose length is N", which is equivalent.
func FindHashes(text string, types []string) []Hit {
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

// HashSet returns the distinct hash-shaped strings found anywhere in text,
// lowercased and sorted. Watchlist imports use it so pasted reports and CSV
// exports work without pre-processing.
func HashSet(text string) []string {
	seen := map[string]bool{}
	values := []string{}
	for _, hit := range FindHashes(text, nil) {
		if !seen[hit.HashValue] {
			seen[hit.HashValue] = true
			values = append(values, hit.HashValue)
		}
	}
	sort.Strings(values)
	return values
}
