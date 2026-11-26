# Changelog

All notable changes to this project are documented here.
Format: `MM-DD-YYYY HH:MM:SS` timestamps, sections: Added / Changed / Fixed / Removed.

---

## [11-26-2026 13:09:04]

### Changed
- `README.md`: "Build from source" now starts from cloning the repository, shows where each program is written, and writes the command-line tool to `dist\`; the download note says no release is published yet
- `USAGE.md`: new "Building from Source" section covering requirements, both programs, building without the Wails CLI, running from source, tests and release packaging
- `USAGE.md`: troubleshooting for a missing `wails` command, a locked `HashHarvest.exe`, and the test cleanup error caused by antivirus

## [11-26-2026 11:36:03] — v1.0.0

### Added
- GitHub Actions: CI (checks, Wails build, GUI smoke test, Linux tests), CodeQL, and a release workflow that creates a draft release with checksums
- **Cancel Scan** button that stops a scan, even inside a large file
- A list of skipped files with reasons (**View list**), and **View Log** in Scan History
- Each result records its source file's SHA-256 (`Source_SHA256` / `source_sha256` export column; database schema 3)
- A `<export>.manifest.json` next to every export, with the tool version, export time, export SHA-256 and scan details
- `hashharvest-cli`, a command-line scanner
- Synthetic sample evidence and a watchlist in `samples/`
- `.env.example`

### Changed
- Version 1.0.0
- Memory use is bounded: text files are streamed (a 1 GB log needs about 15 MB); CSV, JSON and XML over 128 MiB are scanned as plain text; Office and PDF files have size limits
- Timestamps and log lines include the UTC offset
- A missing or unreadable scan folder is now an error; unreadable subfolders count as skipped files
- Links to folders are reported; links to files outside the scan folder are no longer followed
- `README.md` rewritten; detail moved to `USAGE.md` and `GO_PORT.md`
- `app.go` split by feature; shared version and manifest code moved into `internal/`

### Fixed
- UTF-16 text files were read as noise, so their hashes were missed with nothing reported
- Unreadable folders disappeared from scans without being reported
- JSON with a byte-order mark, JSON Lines, and CSV cells over 131072 characters caused the whole file to be skipped
- A PDF form that draws itself could hang a scan

### Security
- Wails upgraded from v2.15.0 to v2.17.1: v2.17.0 closes a hole in `wails dev` through which any web page open in the developer's browser could call the app's methods (released builds were not affected), and v2.17.1 fixes a Linux-only issue
- Added a Content-Security-Policy to the app window and disabled opening files by dropping them on it

## [11-26-2026 08:27:40]

### Added
- `internal/db/smoke_test.go`: database check used by `scripts/smoke-gui.ps1` in place of a Python snippet

### Changed
- HashHarvest is now Go only. `README.md`, `USAGE.md`, `GO_PORT.md` and code comments no longer describe a Python edition
- PDF test files moved to `internal/readers/testdata/pdf/`

### Removed
- The Python application (`hashharvest/`), its tests (`tests/*.py`), `pyproject.toml`, `requirements.txt`, `HashHarvest.spec` and the PyInstaller hooks
- The Python/Go differential tests (`internal/compat/`) and the two Python key-store interop tests; the `-RequirePython` switch of `scripts/check.ps1`
- Unused files: `Author.txt`, `coverage.out`, `__pycache__` folders, and Python entries in `.gitignore`

## [11-26-2026 08:24:36]

### Added
- `README.md`: Go requirements, a Go quick start with both the `wails build` and plain `go build -tags desktop,production` commands, and a License section
- `USAGE.md`: "Running the Go App" section (build, launch, runtime file locations) and a Troubleshooting section

### Changed
- `README.md` and `USAGE.md` now present the Go edition first and note where the Python edition differs (PDF extraction, long-path truncation, watchlist naming, key storage, VirusTotal dependencies)

### Fixed
- Removed instructions in `README.md` and `USAGE.md` to copy a `.env.example` file that is not in the repository

## [11-14-2026 21:30:00]

### Added
- **Go / Wails port** of the whole application (`main.go`, `app.go`, `frontend/`, `internal/`): scanning in both modes, all document readers including a standard-library PDF extractor, CSV/JSON export, scan history, watchlists, VirusTotal lookups, key storage compatible with the Python app's registry and Credential Manager entries, and the same SQLite schema. See `GO_PORT.md`
- Python/Go differential test harness (`internal/compat/`) with a generated fixture corpus, plus unit, integration, fuzz, and opt-in OS key-store tests
- `scripts/check.ps1` (local CI equivalent), `scripts/smoke-gui.ps1` (UI Automation smoke test of the built exe), and the `Go port` GitHub Actions workflow (`.github/workflows/go.yml`)

## [10-31-2026 10:34:39]

### Fixed
- **PPTX slide order and labels** — slides were sorted as strings (`slide1, slide10, slide11, slide2, …`) and labeled by position, so in a deck with 10+ slides `[slide N]` pointed at the wrong slide. Slides are now ordered and labeled by the number in their part name (`readers.py`)
- **CSV export on Windows** — exports were written in the locale encoding (cp1252 on Windows) and failed with `UnicodeEncodeError` when a path or context contained characters outside it (e.g. CJK). Both the GUI export and `HashHarvest.export_csv()` now write UTF-8 with a BOM so Excel opens them correctly (`main.py`, `extractor.py`)
- **Scans hanging on special files** — a FIFO, socket, or device node under the scanned folder blocked the scan forever when opened. Both scan modes now skip anything that is not a regular file and report it as skipped (`extractor.py`)
- **Leaked SQLite connections** — every `HashDatabase` call left its connection open until garbage collection (the `sqlite3` context manager commits but never closes), holding a handle on `hashharvest.db`. `_connect()` now commits or rolls back and always closes (`db.py`)
- **Reloaded scans differing from live scans** — loading a file-digest scan from Scan History turned its empty line number into `0`, so exports wrote `Line=0`; extensionless files were stored with an empty file type instead of `FILE` (`main.py`, `db.py`)

### Added
- Regression tests for each fix: `tests/test_readers.py`, `tests/test_export.py`, `tests/test_db.py`, plus new cases in `tests/test_hash_files.py` and `tests/test_gui_smoke.py`

## [07-18-2026 17:01:08]

### Added
- **File-digest scan mode** — `hash_files()` in `extractor.py` computes each file's own MD5/SHA1/SHA256/SHA512 digest, walking **all** files under the folder (not just supported document types) and returning the same result shape as `extract()` (`line_no=None`, `"file digest"` context). Exposed in the GUI as a *Find hashes in text* / *Hash the files* radio, wired through `ScanWorker` via a new `mode` parameter (`extractor.py`, `main.py`)
- **VirusTotal lookup** — new `vt_lookup.py` (`lookup_hashes`, `verdict_from_stats`) queries VirusTotal via `vt-py`; new `VirusTotalDialog` and `VTLookupWorker` plus a "VirusTotal" toolbar button check the current scan's unique hashes in a worker thread, showing per-hash malicious / suspicious / clean / not-found / error verdicts with detection counts, color-coded. SHA512 hashes are labeled `n/a` and skipped without an API call, since VirusTotal indexes only MD5/SHA1/SHA256 (`vt_lookup.py`, `main.py`)
- **API-key storage with two backends** — new `keystore.py` resolves the VirusTotal key from the `VT_API_KEY` environment variable, then the OS keychain (`keyring`), then `QSettings`; `save_key()` writes to the OS keychain (encrypted at rest) or `QSettings` (plaintext) and removes the copy from the other backend. A "Store key in OS keychain (encrypted at rest)" checkbox opts in when `keyring` is available (`keystore.py`, `main.py`)
- **`.env` support** — `_load_dotenv()` loads `VT_API_KEY` (and other `KEY=VALUE` lines) from a `.env` file next to the app at startup, so the key can live in a git-ignored file instead of the GUI; environment variables take precedence (`main.py`)
- **"Latest build date" label** in the header showing the executable's (or source file's) modification time as `MM/DD/YYYY HH:MM:SS` (`main.py`)
- `HashHarvest.spec` PyInstaller build file with UPX compression, Qt/stdlib exclusions, and `vt` / `keyring.backends.Windows` declared as hidden imports so packaged builds include the optional features (`HashHarvest.spec`)

### Changed
- Version bumped to **v0.8.0** in the GUI version label and window title (`main.py`)
- `requirements.txt` — added `vt-py`, plus optional `keyring` for encrypted key storage
- `README.md` and `USAGE.md` — documented the two scan modes, VirusTotal lookup, API-key configuration (env var / `.env` / GUI field) and plaintext-vs-encrypted storage, and rewrote the build section for the spec + UPX workflow with shipping guidance (ship only the `.exe`; the empty database is created on first run)

### Removed
- Calendar date label ("Month D, YYYY") from the header, replaced by the build-date label (`main.py`)

## [06-23-2026 18:12:53]

### Changed
- Version bumped to v0.7.0 in the GUI version label and window title (`main.py`)

## [06-23-2026 18:10:22]

### Added
- **Local Watchlist with Auto-Matching**: import known-bad hashes from paste, TXT, CSV, or any free text into named watchlists; after each scan (and when loading historical scans), extracted hashes are joined against all watchlist entries via a SQLite query and matching rows are highlighted red in the results table with a `⚠ N watchlist hits` badge in the status bar (`db.py`, `main.py`)
- `WatchlistDialog` class — modal dialog for creating/deleting named watchlists and importing hashes; any MD5/SHA1/SHA256/SHA512 hex string found anywhere in pasted text or a browsed file is extracted automatically, so structured formats (CSV with labels, threat-intel reports) work without pre-processing (`main.py`)
- `watchlists` and `watchlist_entries` tables added to the SQLite schema with `ON DELETE CASCADE` so deleting a watchlist removes its entries, and an index on `hash_value` for fast post-scan join (`db.py`)
- Five new `HashDatabase` methods: `get_watchlists()`, `create_watchlist(name)`, `delete_watchlist(watchlist_id)`, `import_hashes(watchlist_id, hash_values)`, `get_scan_matches(scan_id)` (`db.py`)
- "Watchlist" button in the main toolbar that opens `WatchlistDialog` (`main.py`)

### Changed
- `scan_complete()` now captures the `scan_id` returned by `save_scan()` and passes it to `_apply_watchlist_highlights()` after a successful save (`main.py`)
- `_load_historical_results()` calls `_apply_watchlist_highlights()` after populating the results table so historical scans also show watchlist hits (`main.py`)

## [06-23-2026 16:44:25]

### Fixed
- `hash_results` schema data loss: the old wide schema (one row per file, four nullable hash columns) silently dropped all but one hash per algorithm per file when a document contained multiple hashes of the same type — a threat report with 15 MD5 values would persist only one (`db.py`)
- `save_scan()` now writes one row per extracted hash via `INSERT OR IGNORE`, so every hash found is stored regardless of how many share the same algorithm for the same file (`db.py`)
- `_load_historical_results()` rewritten to read the new narrow `hash_type`/`hash_value` columns instead of pivoting four wide nullable columns; also fixed a bug where `scan_results[path] = set()` reset the set on every row for the same file, discarding previously accumulated hashes (`main.py`)

### Changed
- `hash_results` table restructured from wide format to narrow format: columns `md5`, `sha1`, `sha256`, `sha512` replaced by `hash_type TEXT NOT NULL` and `hash_value TEXT NOT NULL`, with a `UNIQUE(scan_id, file_path, hash_type, hash_value)` constraint (`db.py`)
- `hash_results` gains `line_number`, `context`, and `annotation` columns (nullable) to support future context-capture and analyst annotation features (`db.py`)
- Added indexes `idx_hash_results_scan` and `idx_hash_results_value` on `hash_results` for faster per-scan queries and cross-scan hash lookups (`db.py`)
- `_init_schema()` now runs a one-time automatic migration via `_migrate_wide_to_narrow()` when an existing database with the old wide schema is detected, preserving historical scan data (`db.py`)
- `get_results()` query updated to select `hash_type, hash_value` and order by `file_path, hash_type` (`db.py`)

## [v0.6.0] - 06-20-2026 12:01:57

Renamed the tool from Cryptographic Hash Extractor to HashHarvest - 6/20/2026

### Added
- Full source file path is now shown as a tooltip on hover over the Source File column, so elided paths remain readable (`main.py`)

### Changed
- Version bumped to v0.6.0 in the GUI version label and window title (`main.py`), with the window-title test updated to match (`test_main.py`)
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
