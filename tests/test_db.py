"""Tests for HashDatabase connection handling and stored result fields."""

import sqlite3

import pytest

import hashharvest.persistence.db as db_module
from hashharvest.persistence.db import HashDatabase


def test_every_connection_is_closed(tmp_path, monkeypatch):
    opened = []
    real_connect = sqlite3.connect

    def tracking_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(db_module.sqlite3, "connect", tracking_connect)

    db = HashDatabase(str(tmp_path / "close.db"))
    scan_id = db.save_scan(
        directory="C:/ev", scanned_at="2026-10-31T00:00:00", hash_types="MD5",
        files_scanned=1, hashes_found=1, skipped_files=0,
        results={"C:/ev/a.txt": {("MD5", "a" * 32, 1, "ctx")}},
    )
    db.get_scans()
    db.get_results(scan_id)
    db.get_scan_log(scan_id)
    wl = db.create_watchlist("bad")
    db.import_hashes(wl, ["A" * 32])
    db.get_watchlists()
    db.get_scan_matches(scan_id)
    db.delete_watchlist(wl)

    assert opened
    for conn in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")  # raises only on a closed connection


def test_failed_write_rolls_back_and_closes(tmp_path):
    db = HashDatabase(str(tmp_path / "rollback.db"))
    with pytest.raises(sqlite3.OperationalError):
        with db._connect() as conn:
            conn.execute("INSERT INTO watchlists (name, created_at) VALUES ('x', 'now')")
            conn.execute("SELECT * FROM no_such_table")
    assert db.get_watchlists() == []


def test_extensionless_file_type_matches_extractor(tmp_path):
    db = HashDatabase(str(tmp_path / "ftype.db"))
    scan_id = db.save_scan(
        directory="C:/ev", scanned_at="2026-10-31T00:00:00", hash_types="MD5",
        files_scanned=1, hashes_found=1, skipped_files=0,
        results={"C:/ev/no_extension": {("MD5", "b" * 32, None, "file digest")}},
    )
    (row,) = db.get_results(scan_id)
    assert row["file_type"] == "FILE"
    assert row["line_number"] is None
