import os
import sqlite3


class HashDatabase:
    def __init__(self, db_path):
        self._db_path = db_path
        self._init_schema()

    def _connect(self):
        return sqlite3.connect(self._db_path)

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript("""
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
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id    INTEGER NOT NULL REFERENCES scans(id),
                    file_path  TEXT NOT NULL,
                    file_type  TEXT NOT NULL,
                    md5        TEXT,
                    sha1       TEXT,
                    sha256     TEXT,
                    sha512     TEXT
                );
            """)

    def save_scan(self, directory, scanned_at, hash_types, files_scanned,
                  hashes_found, skipped_files, results):
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans "
                "(scanned_at, directory, hash_types, files_scanned, hashes_found, skipped_files) "
                "VALUES (?,?,?,?,?,?)",
                (scanned_at, directory, hash_types,
                 files_scanned, hashes_found, skipped_files)
            )
            scan_id = cursor.lastrowid
            for file_path, hash_pairs in results.items():
                pair_map = {h_type: h_val for h_type, h_val in hash_pairs}
                file_type = os.path.splitext(file_path)[1].lstrip('.').upper()
                conn.execute(
                    "INSERT INTO hash_results "
                    "(scan_id, file_path, file_type, md5, sha1, sha256, sha512) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (scan_id, file_path, file_type,
                     pair_map.get('MD5'), pair_map.get('SHA1'),
                     pair_map.get('SHA256'), pair_map.get('SHA512'))
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
                "SELECT file_path, file_type, md5, sha1, sha256, sha512 "
                "FROM hash_results WHERE scan_id=? ORDER BY file_path",
                (scan_id,)
            ).fetchall()
        return [dict(row) for row in rows]
