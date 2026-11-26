package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/labgeek/HashHarvest/internal/extractor"
)

func open(t *testing.T, path string) *DB {
	t.Helper()
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func must[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// raw runs fn against the file with a plain connection, outside the DB type.
func raw(t *testing.T, path string, fn func(*sql.DB)) {
	t.Helper()
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fn(conn)
}

func userVersion(t *testing.T, path string) (version int) {
	raw(t, path, func(c *sql.DB) {
		if err := c.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
			t.Fatal(err)
		}
	})
	return version
}

func hasColumn(t *testing.T, path, table, column string) (found bool) {
	raw(t, path, func(c *sql.DB) {
		if err := c.QueryRow("SELECT COUNT(*) > 0 FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(&found); err != nil {
			t.Fatal(err)
		}
	})
	return found
}

func sampleScan(t *testing.T, d *DB, results extractor.Results, log string) int64 {
	t.Helper()
	return must(d.SaveScan("C:/ev", "2026-10-31T00:00:00", "MD5", 1, 1, 0, results, log))(t)
}

func TestEveryOperationReleasesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "close.db")
	d := open(t, path)
	id := sampleScan(t, d, extractor.Results{"C:/ev/a.txt": {{HashType: "MD5", HashValue: strings.Repeat("a", 32), Line: 1, Context: "ctx"}}}, "")
	must(d.GetScans(""))(t)
	must(d.GetResults(id))(t)
	if _, _, err := d.GetScanLog(id); err != nil {
		t.Fatal(err)
	}
	wl := must(d.CreateWatchlist("bad"))(t)
	must(d.ImportHashes(wl, []string{strings.Repeat("A", 32)}))(t)
	must(d.GetWatchlists())(t)
	must(d.GetScanMatches(id))(t)
	if err := d.DeleteWatchlist(wl); err != nil {
		t.Fatal(err)
	}
	// On Windows an open handle would make this rename fail.
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Errorf("database file is still held open: %v", err)
	}
}

func TestFailedWriteRollsBack(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "rollback.db"))
	err := d.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT INTO watchlists (name, created_at) VALUES ('x', 'now')"); err != nil {
			return err
		}
		_, err := tx.Exec("SELECT * FROM no_such_table")
		return err
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if lists := must(d.GetWatchlists())(t); len(lists) != 0 {
		t.Errorf("the insert was not rolled back: %v", lists)
	}
}

func TestStoredFileTypeAndNullLine(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "ftype.db"))
	id := sampleScan(t, d, extractor.Results{
		"C:/ev/no_extension": {{HashType: "MD5", HashValue: strings.Repeat("b", 32), Context: "file digest"}},
		"C:/ev/report.PdF":   {{HashType: "SHA1", HashValue: strings.Repeat("c", 40), Line: 4, Context: "[page 1] x"}},
	}, "")
	want := []ResultRow{
		// Same rule as the extractor: extensionless files are "FILE"; no line stays NULL.
		{"C:/ev/no_extension", "FILE", "MD5", strings.Repeat("b", 32), 0, "file digest"},
		{"C:/ev/report.PdF", "PDF", "SHA1", strings.Repeat("c", 40), 4, "[page 1] x"},
	}
	if got := must(d.GetResults(id))(t); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	var nulls int
	raw(t, d.path, func(c *sql.DB) {
		c.QueryRow("SELECT COUNT(*) FROM hash_results WHERE line_number IS NULL").Scan(&nulls)
	})
	if nulls != 1 {
		t.Errorf("%d rows have a NULL line number, want 1", nulls)
	}
}

func TestFreshDBIsCurrentVersionWithLogColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	open(t, path)
	if v := userVersion(t, path); v != SchemaVersion || !hasColumn(t, path, "scans", "log") {
		t.Errorf("user_version %d, log column %v", v, hasColumn(t, path, "scans", "log"))
	}
}

func TestLegacyV1DBIsMigrated(t *testing.T) {
	// A pre-versioning database: user_version 0, scans without a log column.
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw(t, path, func(c *sql.DB) {
		if _, err := c.Exec(`CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL, directory TEXT NOT NULL, hash_types TEXT NOT NULL,
            files_scanned INTEGER NOT NULL, hashes_found INTEGER NOT NULL, skipped_files INTEGER NOT NULL)`); err != nil {
			t.Fatal(err)
		}
	})
	if userVersion(t, path) != 0 || hasColumn(t, path, "scans", "log") {
		t.Fatal("legacy fixture is not legacy")
	}
	open(t, path)
	if v := userVersion(t, path); v != SchemaVersion || !hasColumn(t, path, "scans", "log") {
		t.Errorf("after open: user_version %d, log column %v", v, hasColumn(t, path, "scans", "log"))
	}
}

func TestWideSchemaIsMigratedToNarrow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wide.db")
	raw(t, path, func(c *sql.DB) {
		if _, err := c.Exec(`
            CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL,
                directory TEXT NOT NULL, hash_types TEXT NOT NULL, files_scanned INTEGER NOT NULL,
                hashes_found INTEGER NOT NULL, skipped_files INTEGER NOT NULL);
            CREATE TABLE hash_results (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
                file_path TEXT NOT NULL, file_type TEXT NOT NULL, md5 TEXT, sha1 TEXT, sha256 TEXT, sha512 TEXT);
            INSERT INTO scans VALUES (1, '2026-01-01T00:00:00', 'C:/old', 'MD5,SHA1', 2, 3, 0);
            INSERT INTO hash_results (scan_id, file_path, file_type, md5, sha1) VALUES (1, 'a.pdf', 'PDF', 'm1', 's1');
            INSERT INTO hash_results (scan_id, file_path, file_type, sha512) VALUES (1, 'b.txt', 'TXT', 'x5');`); err != nil {
			t.Fatal(err)
		}
	})
	d := open(t, path)
	want := []ResultRow{
		{"a.pdf", "PDF", "MD5", "m1", 0, ""},
		{"a.pdf", "PDF", "SHA1", "s1", 0, ""},
		{"b.txt", "TXT", "SHA512", "x5", 0, ""},
	}
	if got := must(d.GetResults(1))(t); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	if hasColumn(t, path, "hash_results", "md5") || userVersion(t, path) != SchemaVersion {
		t.Error("wide table was not replaced")
	}
}

func TestSaveAndReadScanLog(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "log.db"))
	id := sampleScan(t, d, extractor.Results{}, "line1\nline2")
	if log, ok, err := d.GetScanLog(id); err != nil || !ok || log != "line1\nline2" {
		t.Errorf("got %q, %v, %v", log, ok, err)
	}
	if _, ok, err := d.GetScanLog(id + 99); err != nil || ok {
		t.Errorf("missing scan: ok %v, err %v", ok, err)
	}
}

func TestReopenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.db")
	open(t, path)
	open(t, path) // must not fail on a duplicate-column ALTER
	if v := userVersion(t, path); v != SchemaVersion {
		t.Errorf("user_version = %d", v)
	}
}

func TestOpenFailsOnUnusablePath(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing-dir", "x.db")); err == nil {
		t.Error("expected an error")
	}
}

func TestGetScansNewestFirstAndSince(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "scans.db"))
	for _, at := range []string{"2026-10-01T08:00:00", "2026-10-03T08:00:00.123456", "2026-10-02T08:00:00"} {
		must(d.SaveScan("C:/ev", at, "MD5", 0, 0, 0, extractor.Results{}, ""))(t)
	}
	times := func(scans []Scan) (out []string) {
		for _, s := range scans {
			out = append(out, s.ScannedAt)
		}
		return out
	}
	if got, want := times(must(d.GetScans(""))(t)), []string{"2026-10-03T08:00:00.123456", "2026-10-02T08:00:00", "2026-10-01T08:00:00"}; !reflect.DeepEqual(got, want) {
		t.Errorf("all = %v", got)
	}
	if got, want := times(must(d.GetScans("2026-10-02T08:00:00"))(t)), []string{"2026-10-03T08:00:00.123456", "2026-10-02T08:00:00"}; !reflect.DeepEqual(got, want) {
		t.Errorf("since = %v", got)
	}
}

func TestWatchlists(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "watch.db"))
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 40)
	id := sampleScan(t, d, extractor.Results{"f.txt": {{HashType: "MD5", HashValue: a, Line: 1}, {HashType: "SHA1", HashValue: b, Line: 2}}}, "")

	zebra := must(d.CreateWatchlist("zebra"))(t)
	alpha := must(d.CreateWatchlist("alpha"))(t)
	// Values are lowercased; duplicates (within the call or already stored) are skipped.
	if added := must(d.ImportHashes(zebra, []string{strings.ToUpper(a), a, "feed"}))(t); added != 2 {
		t.Errorf("added %d, want 2", added)
	}
	if added := must(d.ImportHashes(zebra, []string{a}))(t); added != 0 {
		t.Errorf("re-import added %d, want 0", added)
	}
	lists := must(d.GetWatchlists())(t)
	if len(lists) != 2 || lists[0].Name != "alpha" || lists[0].EntryCount != 0 || lists[1].Name != "zebra" || lists[1].EntryCount != 2 {
		t.Errorf("lists = %+v", lists)
	}
	if got := must(d.GetScanMatches(id))(t); !reflect.DeepEqual(got, map[string]bool{a: true}) {
		t.Errorf("matches = %v", got)
	}
	if _, err := d.ImportHashes(9999, []string{a}); err == nil {
		t.Error("importing into a missing watchlist must fail (foreign key)")
	}
	// Deleting cascades to the entries, so the match disappears.
	if err := d.DeleteWatchlist(zebra); err != nil {
		t.Fatal(err)
	}
	if got := must(d.GetScanMatches(id))(t); len(got) != 0 {
		t.Errorf("matches after delete = %v", got)
	}
	if lists := must(d.GetWatchlists())(t); len(lists) != 1 || lists[0].ID != alpha {
		t.Errorf("lists after delete = %+v", lists)
	}
}

func TestISO(t *testing.T) {
	at := time.Date(2026, 11, 14, 10, 4, 11, 123456000, time.Local)
	if got := ISO(at); got != "2026-11-14T10:04:11.123456" {
		t.Errorf("got %q", got)
	}
	if got := ISO(at.Truncate(time.Second)); got != "2026-11-14T10:04:11" {
		t.Errorf("zero microseconds must be omitted: %q", got)
	}
}

// Stored timestamps carry their UTC offset, so a scan's time is
// unambiguous when the database moves to another machine or time zone.
func TestNowISOIncludesTheOffset(t *testing.T) {
	zoned := regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?[+-]\d\d:\d\d$`)
	if got := NowISO(); !zoned.MatchString(got) {
		t.Errorf("NowISO() = %q", got)
	}
	at := time.Date(2026, 11, 14, 10, 4, 11, 123456000, time.FixedZone("", -5*3600))
	if got := ISOWithOffset(at); got != "2026-11-14T10:04:11.123456-05:00" {
		t.Errorf("got %q", got)
	}
	if got := ISOWithOffset(at.UTC()); got != "2026-11-14T15:04:11.123456+00:00" {
		t.Errorf("UTC: %q", got)
	}
}

// History filtering compares the local date and time, so scans saved
// before timestamps had an offset and scans saved after it sort and filter
// together.
func TestGetScansMixesOldAndZonedTimestamps(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "scans.db"))
	for _, at := range []string{"2026-10-01T08:00:00", "2026-10-02T08:00:00-05:00", "2026-10-03T08:00:00.5"} {
		must(d.SaveScan("C:/ev", at, "MD5", 0, 0, 0, extractor.Results{}, ""))(t)
	}
	scans, err := d.GetScans("2026-10-02T00:00:00")
	if err != nil || len(scans) != 2 || scans[0].ScannedAt != "2026-10-03T08:00:00.5" || scans[1].ScannedAt != "2026-10-02T08:00:00-05:00" {
		t.Errorf("scans = %+v, %v", scans, err)
	}
}
