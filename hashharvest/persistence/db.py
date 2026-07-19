import os
import sqlite3
from datetime import datetime

# Schema version tracked via SQLite's native PRAGMA user_version (no bespoke table).
# Bump this and add a step to _MIGRATIONS whenever the schema changes.
SCHEMA_VERSION = 2

# Version 1 schema: created for any fresh or pre-versioning database.
_BASE_SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        scanned_at    TEXT NOT NULL,
        directory     TEXT NOT NULL,
        hash_types    TEXT NOT NULL,
        files_scanned INTEGER NOT NULL,
        hashes_found  INTEGER NOT NULL,
        skipped_files INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS hash_results (
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
    );
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
"""


def _migrate_v2_add_scan_log(conn):
    """v2: store each scan's captured log alongside its record."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
    if 'log' not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN log TEXT")


# Forward migrations keyed by the version they bring the schema TO.
_MIGRATIONS = {
    2: _migrate_v2_add_scan_log,
}


class HashDatabase:
    def __init__(self, db_path):
        self._db_path = db_path
        self._init_schema()

    def _connect(self):
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self):
        with self._connect() as conn:
            existing_cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(hash_results)").fetchall()
            }
            if 'md5' in existing_cols:
                self._migrate_wide_to_narrow(conn)

            conn.executescript(_BASE_SCHEMA)

            version = conn.execute("PRAGMA user_version").fetchone()[0]
            for target in range(version + 1, SCHEMA_VERSION + 1):
                migrate = _MIGRATIONS.get(target)
                if migrate is not None:
                    migrate(conn)
            if version < SCHEMA_VERSION:
                # PRAGMA does not accept bound parameters; SCHEMA_VERSION is a trusted int.
                conn.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)

    def _migrate_wide_to_narrow(self, conn):
        """Migrate the old wide schema (one row per file, four hash columns) to the
        narrow schema (one row per extracted hash). Called once on first open after upgrade.
        Existing data is preserved; the old single-hash-per-algorithm-per-file limitation
        was a write-time bug so no data that was never stored can be recovered."""
        conn.executescript("""
            ALTER TABLE hash_results RENAME TO hash_results_old;

            CREATE TABLE hash_results (
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
            );

            INSERT INTO hash_results (scan_id, file_path, file_type, hash_type, hash_value)
                SELECT scan_id, file_path, file_type, 'MD5', md5
                FROM hash_results_old WHERE md5 IS NOT NULL;

            INSERT INTO hash_results (scan_id, file_path, file_type, hash_type, hash_value)
                SELECT scan_id, file_path, file_type, 'SHA1', sha1
                FROM hash_results_old WHERE sha1 IS NOT NULL;

            INSERT INTO hash_results (scan_id, file_path, file_type, hash_type, hash_value)
                SELECT scan_id, file_path, file_type, 'SHA256', sha256
                FROM hash_results_old WHERE sha256 IS NOT NULL;

            INSERT INTO hash_results (scan_id, file_path, file_type, hash_type, hash_value)
                SELECT scan_id, file_path, file_type, 'SHA512', sha512
                FROM hash_results_old WHERE sha512 IS NOT NULL;

            DROP TABLE hash_results_old;
        """)

    def save_scan(self, directory, scanned_at, hash_types, files_scanned,
                  hashes_found, skipped_files, results, log=None):
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans "
                "(scanned_at, directory, hash_types, files_scanned, hashes_found, skipped_files, log) "
                "VALUES (?,?,?,?,?,?,?)",
                (scanned_at, directory, hash_types,
                 files_scanned, hashes_found, skipped_files, log)
            )
            scan_id = cursor.lastrowid
            for file_path, hash_pairs in results.items():
                file_type = os.path.splitext(file_path)[1].lstrip('.').upper()
                for hash_type, hash_value, line_no, context in hash_pairs:
                    conn.execute(
                        "INSERT OR IGNORE INTO hash_results "
                        "(scan_id, file_path, file_type, hash_type, hash_value, line_number, context) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (scan_id, file_path, file_type, hash_type, hash_value, line_no, context)
                    )
        return scan_id

    def get_scans(self, since=None):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            if since is None:
                rows = conn.execute(
                    "SELECT id, scanned_at, directory, hash_types, "
                    "files_scanned, hashes_found, skipped_files "
                    "FROM scans ORDER BY scanned_at DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, scanned_at, directory, hash_types, "
                    "files_scanned, hashes_found, skipped_files "
                    "FROM scans WHERE scanned_at >= ? ORDER BY scanned_at DESC",
                    (since,)
                ).fetchall()
        return [dict(row) for row in rows]

    def get_results(self, scan_id):
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT file_path, file_type, hash_type, hash_value, line_number, context "
                "FROM hash_results WHERE scan_id=? ORDER BY file_path, hash_type",
                (scan_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scan_log(self, scan_id):
        """Return the captured log text for a scan, or None if none was stored."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT log FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        return row[0] if row else None

    # --- Watchlist methods ---

    def get_watchlists(self):
        """Return all watchlists with their entry counts."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT w.id, w.name, w.created_at, COUNT(we.id) AS entry_count
                FROM watchlists w
                LEFT JOIN watchlist_entries we ON we.watchlist_id = w.id
                GROUP BY w.id ORDER BY w.name
            """).fetchall()
        return [dict(row) for row in rows]

    def create_watchlist(self, name):
        """Create a named watchlist and return its id."""
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO watchlists (name, created_at) VALUES (?, ?)",
                (name, datetime.now().isoformat())
            )
            return cursor.lastrowid

    def delete_watchlist(self, watchlist_id):
        """Delete a watchlist and all its entries (CASCADE)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM watchlists WHERE id = ?", (watchlist_id,))

    def import_hashes(self, watchlist_id, hash_values):
        """Add hash_values to a watchlist, skipping duplicates. Returns count inserted."""
        now = datetime.now().isoformat()
        added = 0
        with self._connect() as conn:
            for hv in hash_values:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO watchlist_entries "
                    "(watchlist_id, hash_value, added_at) VALUES (?, ?, ?)",
                    (watchlist_id, hv.lower(), now)
                )
                added += cur.rowcount
        return added

    def get_scan_matches(self, scan_id):
        """Return the set of hash_values from this scan that match any watchlist entry."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT DISTINCT hr.hash_value
                FROM hash_results hr
                JOIN watchlist_entries we ON we.hash_value = hr.hash_value
                WHERE hr.scan_id = ?
            """, (scan_id,)).fetchall()
        return {row[0] for row in rows}
