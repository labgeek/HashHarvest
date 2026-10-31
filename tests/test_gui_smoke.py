"""Headless GUI smoke tests — verify the PyQt6 migration builds every widget.

Runs offscreen (no display needed). Constructing the main window and each dialog
exercises the scoped-enum call sites that PyQt6 requires (alignment, window flags,
header resize modes, selection modes, echo mode), so a bad enum reference fails here.
"""

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

# The binding under test must be PyQt6 — assert before importing the app module.
import hashharvest.main as hh
from hashharvest.persistence.db import HashDatabase


def test_binding_is_pyqt6():
    assert hh.Qt.__module__.startswith("PyQt6"), hh.Qt.__module__


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture
def db(tmp_path):
    return HashDatabase(str(tmp_path / "smoke.db"))


def test_main_window_constructs(app):
    win = hh.pdfAnalysis()
    # Invariants that depend on the migrated enum/setup code running.
    assert win.results_table.columnCount() == 6
    assert all(chk.isChecked() for chk in
               (win.chk_md5, win.chk_sha1, win.chk_sha256, win.chk_sha512))
    assert not win.export_csv_btn.isEnabled()
    win.close()


def test_add_result_and_toggle_context(app):
    win = hh.pdfAnalysis()
    win.add_result("C:/ev/a.txt", "txt", "SHA256", "a" * 64, 3, "ctx")
    assert win.results_table.rowCount() == 1
    # Exercises QHeaderView.ResizeMode.* swap on the hidden Line/Context columns.
    win.show_context_chk.setChecked(True)
    assert not win.results_table.isColumnHidden(5)
    win.show_context_chk.setChecked(False)
    assert win.results_table.isColumnHidden(5)
    win._filter_results("nomatch")
    assert win.results_table.isRowHidden(0)
    win._filter_results("")
    assert not win.results_table.isRowHidden(0)
    win.close()


def test_dialogs_construct(app, db):
    hh.ScanHistoryDialog(db).close()
    hh.WatchlistDialog(db).close()
    # VirusTotalDialog exercises QLineEdit.EchoMode.Password on the key field.
    hh.VirusTotalDialog({"a" * 64, "b" * 32}).close()


def test_gui_export_csv_is_utf8_with_bom(app, tmp_path, monkeypatch):
    import codecs

    out = str(tmp_path / "gui.csv")
    errors = []
    monkeypatch.setattr(hh.QFileDialog, "getSaveFileName", lambda *a, **k: (out, ""))
    monkeypatch.setattr(hh.QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(hh.QMessageBox, "critical", lambda *a, **k: errors.append(a))

    win = hh.pdfAnalysis()
    # "报告" is not encodable in cp1252, the Windows locale default.
    win.scan_results = {"C:/cases/\u62a5\u544a.txt": {("MD5", "a" * 32, 1, "ctx")}}
    win.export_csv()
    win.close()

    assert errors == []
    with open(out, "rb") as fh:
        raw = fh.read()
    assert raw.startswith(codecs.BOM_UTF8)
    assert "\u62a5\u544a" in raw.decode("utf-8-sig")


def test_historical_file_digest_scan_keeps_null_line(app, db):
    results = {"C:/ev/no_extension": {("MD5", "c" * 32, None, "file digest")}}
    scan_id = db.save_scan(
        directory="C:/ev", scanned_at="2026-10-31T00:00:00", hash_types="MD5",
        files_scanned=1, hashes_found=1, skipped_files=0, results=results,
    )
    scan = next(s for s in db.get_scans() if s["id"] == scan_id)

    win = hh.pdfAnalysis()
    win.db = db
    win._load_historical_results(scan, db.get_results(scan_id))

    # Reloaded results must match the live shape, so exports don't write Line=0.
    assert win.scan_results == results
    assert win.results_table.item(0, 1).text() == "FILE"
    assert win.results_table.item(0, 4).text() == ""
    win.close()


def test_watchlist_hash_extraction():
    text = "bad: %s and %s plus junk" % ("d" * 32, "e" * 64)
    found = hh.WatchlistDialog._extract_hashes(text)
    assert found == {"d" * 32, "e" * 64}
