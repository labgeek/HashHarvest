# Changelog

All notable changes to this project are documented here.
Format: `MM-DD-YYYY HH:MM:SS` timestamps, sections: Added / Changed / Fixed / Removed.

---

## [06-20-2026 11:41:46]

### Added
- Full source file path is now shown as a tooltip on hover over the Source File column, so elided paths remain readable (`main.py`)

### Changed
- Results table columns are all user-resizable (`Interactive`) with sensible default widths; the last column stretches to fill leftover space (`main.py`)
- Results table now elides long text in the middle (`ElideMiddle`) so the drive root and filename of a path stay visible when a column is narrow (`main.py`)
- README documents the new `.docx`/`.xlsx`/`.pptx` parsing (file-types table and scope notes), notes that Office parsing adds no runtime dependencies, adds `requirements-dev.txt` install instructions, and corrects the `SUPPORTED_EXTENSIONS` example (`README.md`)

---

## [v0.5.1] - 06-20-2026 10:48:37

### Changed
- Version bumped to v0.5.1 in version label and window title (`main.py`)
- `SUPPORTED_EXTENSIONS` in `readers.py` is now derived from `_DISPATCH` keys, eliminating the risk of the two sets drifting out of sync
- Directory existence check in `search()` replaced with `os.path.isdir()` directly, removing a redundant `HashExtractor` instantiation

### Fixed
- Added `closeEvent` to `pdfAnalysis` that stops and waits for any running scan thread before the dialog closes, preventing a crash on close during an active scan
- SQLite foreign key enforcement enabled via `PRAGMA foreign_keys = ON` in `HashDatabase._connect()` — the `REFERENCES scans(id)` constraint on `hash_results` was previously decorative only
- Removed truncated/broken comment block in `db.py` that was left mid-sentence above the `HashDatabase` class definition

---

## [[v0.5.0] - 06-19-2026 18:21:48]

### Added
- `persistence/` package (`persistence/db.py`, `persistence/__init__.py`) with `HashDatabase` class — SQLite-backed store for scan metadata and per-file hash results
- `ScanHistoryDialog` — modal dialog listing past scans with time-range filtering (Today / 7 / 30 / 90 days / All time) and a "Load Selected" action to restore historical results into the main UI
- "Scan History" button in the main toolbar that opens `ScanHistoryDialog`
- `open_scan_history()` and `_load_historical_results()` methods on `pdfAnalysis` to launch the dialog and repopulate results from a historical scan record

### Changed
- `scan_complete()` now persists each finished scan to the SQLite database; status label updates to "Scan complete — saved to database." on success, or shows the error on failure
- `.gitignore` updated to exclude `*.db` files and moved `tests/` to an explicit bottom-of-file entry

## [v0.4.0] — 06-18-2026 17:16:48

### Added
- `Export CSV` button in the GUI that opens a save-file dialog and writes scan results as a CSV file (`Absolute_Path`, `Hash_Type`, `Hash_Value` columns)
- `Export JSON` button in the GUI that opens a save-file dialog and writes scan results as a JSON array of objects (`absolute_path`, `hash_type`, `hash_value` keys)
- `export_csv(path)` and `export_json(path)` methods on `HashExtractor` for programmatic export after extraction
- Export buttons are disabled until a scan completes successfully; `Clear Form` resets them back to disabled

### Changed
- `HashExtractor.__init__` no longer accepts a `save_path` parameter — the extractor is now solely responsible for scanning, not writing output
- `ScanWorker` no longer accepts or stores `save_path`; `scan_finished` signal simplified from `(dict, int, str)` to `(dict, int)`
- `scan_complete()` now stores results in `self.scan_results` and enables export buttons instead of reporting an auto-generated file path
- Status bar updates to show the path of the last exported file after a successful export
- Completion dialog now instructs the user to use the export buttons rather than reporting an output file path

### Removed
- Automatic `hashOutput.txt` file generation on scan completion
- `write_data()` method from `HashExtractor`
- Output Directory input field and "Select Output Folder" button from the File Scan Configuration panel
- "Output File" row from the Scan Summary panel
- Output directory validation and `os.makedirs` call from the scan startup logic in `search()`
