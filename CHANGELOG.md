# Changelog

All notable changes to this project are documented here.
Format: `MM-DD-YYYY HH:MM:SS` timestamps, sections: Added / Changed / Fixed / Removed.

---

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
