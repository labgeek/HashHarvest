// Package db is the SQLite store for scan history and watchlists. Older
// hashharvest.db files are migrated to the current schema on open.
package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"

	"github.com/labgeek/HashHarvest/internal/extractor"
)

// SchemaVersion is tracked in SQLite's PRAGMA user_version. Bump it and add
// a step to migrations whenever the schema changes.
const SchemaVersion = 2

const hashResultsTable = `(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER NOT NULL REFERENCES scans(id),
        file_path   TEXT NOT NULL,
        file_type   TEXT NOT NULL,
        hash_type   TEXT NOT NULL,
        hash_value  TEXT NOT NULL,
        line_number INTEGER,
        context     TEXT,
        annotation  TEXT,
        UNIQUE(scan_id, file_path, hash_type, hash_value)
    )`

// baseSchema is the version 1 schema, created for any fresh or
// pre-versioning database.
const baseSchema = `
    CREATE TABLE IF NOT EXISTS scans (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        scanned_at    TEXT NOT NULL,
        directory     TEXT NOT NULL,
        hash_types    TEXT NOT NULL,
        files_scanned INTEGER NOT NULL,
        hashes_found  INTEGER NOT NULL,
        skipped_files INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS hash_results ` + hashResultsTable + `;
    CREATE INDEX IF NOT EXISTS idx_hash_results_scan  ON hash_results(scan_id);
    CREATE INDEX IF NOT EXISTS idx_hash_results_value ON hash_results(hash_value);
    CREATE TABLE IF NOT EXISTS watchlists (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS watchlist_entries (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        watchlist_id INTEGER NOT NULL REFERENCES watchlists(id) ON DELETE CASCADE,
        hash_value   TEXT NOT NULL,
        label        TEXT,
        added_at     TEXT NOT NULL,
        UNIQUE(watchlist_id, hash_value)
    );
    CREATE INDEX IF NOT EXISTS idx_watchlist_entries_value ON watchlist_entries(hash_value);
`

// migrations are forward steps keyed by the version they bring the schema to.
var migrations = map[int]func(*sql.Tx) error{
	2: func(tx *sql.Tx) error { // store each scan's captured log
		cols, err := columns(tx, "scans")
		if err != nil || cols["log"] {
			return err
		}
		_, err = tx.Exec("ALTER TABLE scans ADD COLUMN log TEXT")
		return err
	},
}

// Scan is one row of scan history.
type Scan struct {
	ID           int64  `json:"id"`
	ScannedAt    string `json:"scanned_at"`
	Directory    string `json:"directory"`
	HashTypes    string `json:"hash_types"`
	FilesScanned int    `json:"files_scanned"`
	HashesFound  int    `json:"hashes_found"`
	SkippedFiles int    `json:"skipped_files"`
}

// ResultRow is one stored hash. Line is 0 and Context "" where the
// database holds NULL.
type ResultRow struct {
	FilePath  string `json:"file_path"`
	FileType  string `json:"file_type"`
	HashType  string `json:"hash_type"`
	HashValue string `json:"hash_value"`
	Line      int    `json:"line_number"`
	Context   string `json:"context"`
}

// Watchlist is a named list of known-bad hashes.
type Watchlist struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	EntryCount int    `json:"entry_count"`
}

// DB is a handle on one database file. No connection is held between
// calls: like the Python implementation, each operation opens the file,
// runs in one transaction, and closes it, so the file is never left locked.
type DB struct{ path string }

// Open prepares the database at path, creating or migrating its schema.
func Open(path string) (*DB, error) {
	d := &DB{path: path}
	return d, d.initSchema()
}

// NowISO formats the current local time with its UTC offset, the format of
// every timestamp stored from now on. Rows written before carry none.
func NowISO() string { return ISOWithOffset(time.Now()) }

// ISOWithOffset is ISO followed by t's UTC offset, as in
// 2026-11-14T10:04:11.123456-05:00.
func ISOWithOffset(t time.Time) string { return ISO(t) + t.Format("-07:00") }

// ISO formats t's date and time without an offset, like Python's
// datetime.isoformat(): microseconds are omitted when zero. History filters
// compare stored timestamps against it as text, which works for rows with
// and without an offset.
func ISO(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05")
	if micro := t.Nanosecond() / 1000; micro != 0 {
		s += fmt.Sprintf(".%06d", micro)
	}
	return s
}

// tx runs fn in a transaction on a fresh connection: committed on success,
// rolled back on error, and the connection is always closed.
func (d *DB) tx(fn func(*sql.Tx) error) (err error) {
	conn, err := sql.Open("sqlite", d.path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := conn.Close(); err == nil {
			err = cerr
		}
	}()
	conn.SetMaxOpenConns(1) // the PRAGMA below is per-connection
	if _, err = conn.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return err
	}
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func columns(tx *sql.Tx, table string) (map[string]bool, error) {
	rows, err := tx.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

func (d *DB) initSchema() error {
	return d.tx(func(tx *sql.Tx) error {
		cols, err := columns(tx, "hash_results")
		if err != nil {
			return err
		}
		if cols["md5"] {
			if _, err := tx.Exec(wideToNarrow); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(baseSchema); err != nil {
			return err
		}
		var version int
		if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		for target := version + 1; target <= SchemaVersion; target++ {
			if migrate := migrations[target]; migrate != nil {
				if err := migrate(tx); err != nil {
					return err
				}
			}
		}
		if version < SchemaVersion {
			// PRAGMA does not accept bound parameters; SchemaVersion is a constant.
			_, err = tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion))
		}
		return err
	})
}

// wideToNarrow migrates the oldest schema (one row per file with four hash
// columns) to one row per extracted hash. Existing data is preserved.
var wideToNarrow = `
    ALTER TABLE hash_results RENAME TO hash_results_old;
    CREATE TABLE hash_results ` + hashResultsTable + `;
` + narrowInsert("MD5", "md5") + narrowInsert("SHA1", "sha1") +
	narrowInsert("SHA256", "sha256") + narrowInsert("SHA512", "sha512") + `
    DROP TABLE hash_results_old;
`

func narrowInsert(hashType, column string) string {
	return fmt.Sprintf(`
    INSERT INTO hash_results (scan_id, file_path, file_type, hash_type, hash_value)
        SELECT scan_id, file_path, file_type, '%s', %s
        FROM hash_results_old WHERE %s IS NOT NULL;`, hashType, column, column)
}

// SaveScan stores a scan and its results and returns the new scan id.
func (d *DB) SaveScan(directory, scannedAt, hashTypes string, filesScanned, hashesFound, skippedFiles int,
	results extractor.Results, log string) (int64, error) {
	var scanID int64
	err := d.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(
			"INSERT INTO scans "+
				"(scanned_at, directory, hash_types, files_scanned, hashes_found, skipped_files, log) "+
				"VALUES (?,?,?,?,?,?,?)",
			scannedAt, directory, hashTypes, filesScanned, hashesFound, skippedFiles, log)
		if err != nil {
			return err
		}
		if scanID, err = res.LastInsertId(); err != nil {
			return err
		}
		stmt, err := tx.Prepare(
			"INSERT OR IGNORE INTO hash_results " +
				"(scan_id, file_path, file_type, hash_type, hash_value, line_number, context) " +
				"VALUES (?,?,?,?,?,?,?)")
		if err != nil {
			return err
		}
		defer stmt.Close()
		for path, hits := range results {
			// Same rule as the extractor: extensionless files are "FILE".
			fileType := extractor.FileType(path)
			if fileType == "" {
				fileType = "FILE"
			}
			for _, hit := range hits {
				var line any // NULL when there is no line number
				if hit.Line != 0 {
					line = hit.Line
				}
				if _, err := stmt.Exec(scanID, path, fileType, hit.HashType, hit.HashValue, line, hit.Context); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return scanID, err
}

// GetScans returns scans newest first; a non-empty since keeps only scans
// at or after that ISO timestamp.
func (d *DB) GetScans(since string) ([]Scan, error) {
	scans := []Scan{}
	err := d.tx(func(tx *sql.Tx) error {
		query := "SELECT id, scanned_at, directory, hash_types, " +
			"files_scanned, hashes_found, skipped_files FROM scans "
		var args []any
		if since != "" {
			query += "WHERE scanned_at >= ? "
			args = append(args, since)
		}
		rows, err := tx.Query(query+"ORDER BY scanned_at DESC", args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s Scan
			if err := rows.Scan(&s.ID, &s.ScannedAt, &s.Directory, &s.HashTypes,
				&s.FilesScanned, &s.HashesFound, &s.SkippedFiles); err != nil {
				return err
			}
			scans = append(scans, s)
		}
		return rows.Err()
	})
	return scans, err
}

// GetResults returns a scan's rows ordered by file path, then hash type.
func (d *DB) GetResults(scanID int64) ([]ResultRow, error) {
	results := []ResultRow{}
	err := d.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(
			"SELECT file_path, file_type, hash_type, hash_value, line_number, context "+
				"FROM hash_results WHERE scan_id=? ORDER BY file_path, hash_type", scanID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ResultRow
			var line sql.NullInt64
			var context sql.NullString
			if err := rows.Scan(&r.FilePath, &r.FileType, &r.HashType, &r.HashValue, &line, &context); err != nil {
				return err
			}
			r.Line, r.Context = int(line.Int64), context.String
			results = append(results, r)
		}
		return rows.Err()
	})
	return results, err
}

// GetScanLog returns the captured log for a scan; ok is false when the scan
// does not exist or has no stored log.
func (d *DB) GetScanLog(scanID int64) (log string, ok bool, err error) {
	err = d.tx(func(tx *sql.Tx) error {
		var value sql.NullString
		err := tx.QueryRow("SELECT log FROM scans WHERE id = ?", scanID).Scan(&value)
		if err == sql.ErrNoRows {
			return nil
		}
		log, ok = value.String, value.Valid
		return err
	})
	return log, ok, err
}

// GetWatchlists returns all watchlists with their entry counts, by name.
func (d *DB) GetWatchlists() ([]Watchlist, error) {
	lists := []Watchlist{}
	err := d.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`
            SELECT w.id, w.name, w.created_at, COUNT(we.id) AS entry_count
            FROM watchlists w
            LEFT JOIN watchlist_entries we ON we.watchlist_id = w.id
            GROUP BY w.id ORDER BY w.name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var w Watchlist
			if err := rows.Scan(&w.ID, &w.Name, &w.CreatedAt, &w.EntryCount); err != nil {
				return err
			}
			lists = append(lists, w)
		}
		return rows.Err()
	})
	return lists, err
}

// CreateWatchlist creates a named watchlist and returns its id.
func (d *DB) CreateWatchlist(name string) (int64, error) {
	var id int64
	err := d.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec("INSERT INTO watchlists (name, created_at) VALUES (?, ?)", name, NowISO())
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// DeleteWatchlist deletes a watchlist and, by cascade, all its entries.
func (d *DB) DeleteWatchlist(id int64) error {
	return d.tx(func(tx *sql.Tx) error {
		_, err := tx.Exec("DELETE FROM watchlists WHERE id = ?", id)
		return err
	})
}

// ImportHashes adds hash values (lowercased) to a watchlist, skipping
// duplicates, and returns how many were inserted.
func (d *DB) ImportHashes(watchlistID int64, hashValues []string) (int, error) {
	now := NowISO()
	added := 0
	err := d.tx(func(tx *sql.Tx) error {
		added = 0
		for _, value := range hashValues {
			res, err := tx.Exec(
				"INSERT OR IGNORE INTO watchlist_entries "+
					"(watchlist_id, hash_value, added_at) VALUES (?, ?, ?)",
				watchlistID, strings.ToLower(value), now)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			added += int(n)
		}
		return nil
	})
	return added, err
}

// GetScanMatches returns the hash values from a scan that appear on any
// watchlist.
func (d *DB) GetScanMatches(scanID int64) (map[string]bool, error) {
	matches := map[string]bool{}
	err := d.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`
            SELECT DISTINCT hr.hash_value
            FROM hash_results hr
            JOIN watchlist_entries we ON we.hash_value = hr.hash_value
            WHERE hr.scan_id = ?`, scanID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				return err
			}
			matches[value] = true
		}
		return rows.Err()
	})
	return matches, err
}
