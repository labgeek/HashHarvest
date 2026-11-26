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
	"path/filepath"
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
	// SourceSHA256 is the SHA-256 of the file the hash came from, as read
	// from disk ("" for rows stored before it was recorded).
	SourceSHA256 string
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
	Status   func(message string) // a file or folder was skipped
	Notice   func(message string) // a file was read differently, e.g. as plain text
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

// DigestContext is the context of a file-digest row.
const DigestContext = "file digest"

// RowFileType is the file type shown and stored for a row: the extension,
// or "FILE" when there is none.
func RowFileType(path string) string {
	if t := FileType(path); t != "" {
		return t
	}
	return "FILE"
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

// readDir lists a directory; tests replace it to simulate unreadable ones.
var readDir = os.ReadDir

// walkFiles lists every non-directory entry below root, sorted. Links to
// folders (symlinks, junctions) are never followed, and a link to a file is
// followed only when its target is inside root, so a scan cannot reach
// outside the folder it names. Each link not followed, and each subfolder
// that cannot be listed, is returned as a FileError, so it is reported
// rather than silently absent; a root that cannot be listed is an error.
func walkFiles(root string, keep func(name string) bool) ([]string, []FileError, error) {
	var paths []string
	var dirErrors []FileError
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		realRoot = root // readDir reports the problem
	}
	var walk func(string) error
	walk = func(dir string) error {
		entries, err := readDir(dir)
		if err != nil {
			if dir == root {
				return fmt.Errorf("cannot read directory: %w", err)
			}
			dirErrors = append(dirErrors, FileError{dir, "cannot read directory: " + err.Error()})
			return nil
		}
		for _, entry := range entries {
			path := joinPath(dir, entry.Name())
			if entry.IsDir() {
				walk(path)
				continue
			}
			if !entry.Type().IsRegular() {
				if info, err := os.Stat(path); err == nil && info.IsDir() {
					dirErrors = append(dirErrors, FileError{path, "link to a folder is not followed"})
					continue
				}
			}
			if keep != nil && !keep(entry.Name()) {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 {
				// A broken link resolves to nothing; reading it reports it.
				if target, err := filepath.EvalSymlinks(path); err == nil && !within(realRoot, target) {
					dirErrors = append(dirErrors, FileError{path, "link points outside the scan folder: " + target})
					continue
				}
			}
			paths = append(paths, path)
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)
	return paths, dirErrors, nil
}

// within reports whether path is root or below it.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// skipped records a file or directory the scan could not read.
func skipped(fileErrors []FileError, cb Callbacks, path string, err string) []FileError {
	if cb.Status != nil {
		cb.Status(fmt.Sprintf("Skipped %s: %s", path, err))
	}
	return append(fileErrors, FileError{path, err})
}

// listFiles lists the files to scan and reports unreadable subdirectories.
func listFiles(dir string, keep func(name string) bool, cb Callbacks) ([]string, []FileError, error) {
	paths, dirErrors, err := walkFiles(dir, keep)
	if err != nil {
		return nil, nil, err
	}
	var fileErrors []FileError
	for _, e := range dirErrors {
		fileErrors = skipped(fileErrors, cb, e.Path, e.Message)
	}
	return paths, fileErrors, nil
}

// HashFiles digests every file under dir with the selected algorithms.
// Each hit has Line 0 and Context "file digest".
func HashFiles(ctx context.Context, dir string, types []string, cb Callbacks) (Results, []FileError, error) {
	paths, fileErrors, err := listFiles(dir, nil, cb)
	if err != nil {
		return nil, nil, err
	}
	results := Results{}

	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		hits, err := digestFile(ctx, path, types)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err() // cancelled partway through this file
			}
			fileErrors = skipped(fileErrors, cb, path, err.Error())
		} else {
			results[path] = hits
			if cb.Result != nil {
				fileType := RowFileType(path)
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

// ctxReader fails its next Read once ctx is cancelled, so copying a large
// file stops promptly.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func digestFile(ctx context.Context, path string, types []string) ([]Hit, error) {
	if err := requireRegularFile(path); err != nil {
		return nil, err
	}
	var names []string
	var writers []io.Writer
	var digests []hash.Hash
	var source hash.Hash // SHA-256, for SourceSHA256 even when not selected
	for _, name := range HashTypes {
		if selected(types, name) {
			h := constructors[name]()
			names, digests, writers = append(names, name), append(digests, h), append(writers, h)
			if name == "SHA256" {
				source = h
			}
		}
	}
	if source == nil {
		source = sha256.New()
		writers = append(writers, source)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := io.Copy(io.MultiWriter(writers...), ctxReader{ctx, f}); err != nil {
		return nil, err
	}
	sourceSHA256 := hex.EncodeToString(source.Sum(nil))
	hits := []Hit{}
	for i, name := range names {
		hits = append(hits, Hit{HashType: name, HashValue: hex.EncodeToString(digests[i].Sum(nil)),
			Context: DigestContext, SourceSHA256: sourceSHA256})
	}
	return hits, nil
}

// Extract scans the supported document types under dir for hash-shaped
// strings. Only the first occurrence of each (type, value) per file is kept.
func Extract(ctx context.Context, dir string, types []string, cb Callbacks) (Results, []FileError, error) {
	paths, fileErrors, err := listFiles(dir, func(name string) bool {
		return readers.Supported(strings.ToLower(readers.SplitExt(name)))
	}, cb)
	if err != nil {
		return nil, nil, err
	}
	results := Results{}

	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		hits, note, err := extractFile(ctx, path, types)
		if note != "" && cb.Notice != nil {
			cb.Notice(path + ": " + note)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err() // cancelled partway through this file
			}
			fileErrors = skipped(fileErrors, cb, path, err.Error())
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

// extractFile returns the hashes in one file. note, when not empty, says
// the file was read differently than its type suggests.
func extractFile(ctx context.Context, path string, types []string) (hits []Hit, note string, err error) {
	// Scanned files are untrusted. A parser bug must skip that one file, as
	// Python's per-file "except Exception" did, not take down the scan.
	defer func() {
		if r := recover(); r != nil {
			hits, note, err = nil, "", fmt.Errorf("internal error reading file: %v", r)
		}
	}()
	if err := requireRegularFile(path); err != nil {
		return nil, "", err
	}
	// ponytail: a separate read, so the hash is of the bytes exactly as on
	// disk whatever the reader does; hash while reading if I/O ever matters.
	sourceSHA256, err := fileSHA256(ctx, path)
	if err != nil {
		return nil, "", err
	}
	hits = []Hit{}
	seen := map[[2]string]bool{}
	add := func(hit Hit, location string) {
		hit.SourceSHA256 = sourceSHA256
		key := [2]string{hit.HashType, hit.HashValue}
		if seen[key] {
			return
		}
		seen[key] = true
		if location != "" {
			hit.Context = fmt.Sprintf("[%s] %s", location, hit.Context)
		}
		hits = append(hits, hit)
	}

	if stream, note := readers.StreamPlan(path); stream {
		f := newHashFinder(types, func(hit Hit) { add(hit, "") })
		if err := readers.StreamText(ctx, path, f.write); err != nil {
			return nil, "", err
		}
		f.close()
		SortHits(hits)
		return hits, note, nil
	}

	chunks, err := readers.ReadFileChunks(path)
	if err != nil {
		return nil, "", err
	}
	for _, chunk := range chunks { // a PDF page or PPTX slide, or the whole text
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		for _, hit := range FindHashes(chunk.Text, types) {
			add(hit, chunk.Location)
		}
	}
	SortHits(hits)
	return hits, "", nil
}

// fileSHA256 hashes a file's bytes, stopping when ctx is cancelled.
func fileSHA256(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, ctxReader{ctx, f}); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
