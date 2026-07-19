"""Tests for SQLite schema versioning, migrations, and per-scan log storage."""

import sqlite3

from hashharvest.persistence.db import HashDatabase, SCHEMA_VERSION


def _user_version(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


def _columns(path, table):
    conn = sqlite3.connect(path)
    try:
        return {row[1] for row in conn.execute("PRAGMA table_info(%s)" % table)}
    finally:
        conn.close()


def test_fresh_db_is_current_version_with_log_column(tmp_path):
    db_path = str(tmp_path / "fresh.db")
    HashDatabase(db_path)
    assert _user_version(db_path) == SCHEMA_VERSION
    assert "log" in _columns(db_path, "scans")


def test_legacy_v1_db_is_migrated(tmp_path):
    """A pre-versioning database (user_version 0, scans without a log column) upgrades."""
    db_path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL, directory TEXT NOT NULL, hash_types TEXT NOT NULL,
            files_scanned INTEGER NOT NULL, hashes_found INTEGER NOT NULL, skipped_files INTEGER NOT NULL
        );
    """)
    conn.commit()
    conn.close()
    assert _user_version(db_path) == 0
    assert "log" not in _columns(db_path, "scans")

    HashDatabase(db_path)  # opening runs the migration

    assert _user_version(db_path) == SCHEMA_VERSION
    assert "log" in _columns(db_path, "scans")


def test_save_and_read_scan_log(tmp_path):
    db = HashDatabase(str(tmp_path / "log.db"))
    scan_id = db.save_scan(
        directory="C:/ev", scanned_at="2026-07-19T00:00:00", hash_types="SHA256",
        files_scanned=1, hashes_found=0, skipped_files=0, results={}, log="line1\nline2",
    )
    assert db.get_scan_log(scan_id) == "line1\nline2"


def test_reopen_is_idempotent(tmp_path):
    db_path = str(tmp_path / "reopen.db")
    HashDatabase(db_path)
    HashDatabase(db_path)  # must not raise (no duplicate-column ALTER)
    assert _user_version(db_path) == SCHEMA_VERSION
