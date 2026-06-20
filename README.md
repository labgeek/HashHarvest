# HashHarvest

Author: labgeek@gmail.com (JD Durick)

`HashHarvest` is a PyQt5 desktop application for extracting cryptographic hashes from a folder of files. It scans recursively across PDF, text, log, CSV, JSON, XML, Markdown, and Microsoft Office files (Word `.docx`, Excel `.xlsx`, PowerPoint `.pptx`) — detecting MD5, SHA1, SHA256, and SHA512 values using exact hex-length matching with negative lookaround so shorter patterns never collide with longer ones. Results are displayed live as the scan runs, exportable to CSV or JSON, and automatically persisted to a local SQLite database. A built-in Scan History dialog lets you filter past scans by date range and reload any previous result set into the main UI for re-inspection or re-export.

<img width="1907" height="837" alt="image" src="https://github.com/user-attachments/assets/ca34ed55-b0fb-48be-9817-0e56cb9bae1c" />




## Supported File Types

| Extension | How text is extracted |
|-----------|----------------------|
| `.pdf`    | Page text via `pypdf` |
| `.txt`    | Plain text, UTF-8 with latin-1 fallback |
| `.log`    | Plain text, UTF-8 with latin-1 fallback |
| `.md`     | Plain text, UTF-8 with latin-1 fallback |
| `.csv`    | All cell values joined as searchable text |
| `.json`   | Recursive walk — all keys and scalar values |
| `.xml`    | All element text and tail text |
| `.docx`   | Word document body — paragraph text from `word/document.xml` |
| `.xlsx`   | Excel cell text — both the shared-string table and inline worksheet strings |
| `.pptx`   | PowerPoint slide text — paragraph runs from every `ppt/slides/slideN.xml` |

Extensions are matched case-insensitively. Files with other extensions are ignored.

The Office formats (`.docx`, `.xlsx`, `.pptx`) are read directly from their underlying OpenXML zip packages using the Python standard library — no third-party Office libraries are required at runtime. Text split across multiple runs within a paragraph or cell is reassembled, so a hash broken into pieces by the authoring tool is still matched. Scope notes: `.docx` reads the main document body (not headers, footers, or footnotes); `.xlsx` reads string cells from all worksheets (numeric cells never hold hash strings); `.pptx` reads slide bodies (not speaker notes or masters).


## Supported Hash Types

| Algorithm | Hex length |
|-----------|-----------|
| MD5       | 32        |
| SHA1      | 40        |
| SHA256    | 64        |
| SHA512    | 128       |


## Features

- Detects MD5, SHA1, SHA256, and SHA512 hashes across all supported file types in a single scan.
- Recursive directory search — all supported files under the selected folder are included.
- Threaded extraction keeps the GUI responsive during long scans.
- Results table with four columns: **Source File**, **File Type**, **Hash Type**, and **Hash Value**.
- Alternating row colors, and every column is user-resizable by dragging its header border.
- Long source paths are middle-elided (drive and filename stay visible) and the full path is shown as a tooltip on hover.
- Progress bar that updates per file processed.
- Scan summary panel showing files scanned, hashes found, and skipped files.
- **Export CSV** button saves results to a CSV file of your choosing after the scan completes.
- **Export JSON** button saves results to a JSON file of your choosing after the scan completes.
- Export buttons are disabled until a scan finishes successfully; loading a historical scan re-enables them.
- **Scan History** button opens a filterable list of past scans stored in the local database.
- Every completed scan is automatically persisted to a local SQLite database (`hashharvest.db`).
- Historical scan results can be loaded back into the main UI and exported like a fresh scan.
- Clear Form button resets all inputs, results, progress, summary fields, and export buttons.
- Duplicate hashes within the same file are written once.
- Skipped files (unreadable or malformed) are counted but do not stop the scan.


## Requirements

- Python 3
- `pypdf`
- `PyQt5`

Office (`.docx`/`.xlsx`/`.pptx`) parsing uses only the Python standard library, so it adds no runtime dependencies.

Install dependencies from the project root:

```powershell
python -m pip install -r requirements.txt
```

## Running the App

```powershell
cd C:\path\to\HashHarvest
python -m hashharvest.main
```

> Run as a module with `-m` from the project root so the `hashharvest` package imports resolve.

### GUI Controls

| Control | Description |
|---------|-------------|
| **Input Directory** field | Type or browse to the folder containing files to scan. |
| **Select Input Folder** | Opens a folder picker for the input directory. |
| **Hash Types** checkboxes | Choose which algorithms to scan for (MD5, SHA1, SHA256, SHA512). All checked by default. |
| **Start Scan** | Validates the input directory and begins the threaded scan. |
| **Clear Form** | Resets all fields, the results table, the progress bar, and summary counts. |
| **Scan History** | Opens the Scan History dialog to browse and reload past scans. |
| **Export CSV** | Opens a save dialog and writes the current results to a CSV file. Enabled after a successful scan or after loading history. |
| **Export JSON** | Opens a save dialog and writes the current results to a JSON file. Enabled after a successful scan or after loading history. |

You can type a path directly into the Input Directory field instead of using the folder picker.


## Scan History

Every time a scan completes, the results are saved automatically to `hashharvest.db` (a SQLite file written next to the executable or script). Click **Scan History** to open the history dialog.

### History Dialog

| Column | Description |
|--------|-------------|
| Date / Time | Timestamp when the scan ran (truncated to the minute). |
| Directory | Input directory that was scanned. |
| Files | Number of files processed. |
| Hashes Found | Total number of hashes extracted. |

Use the **Show** drop-down to filter by time range:

| Option | Shows scans from |
|--------|-----------------|
| Today | Midnight of the current day |
| Last 7 days | Rolling 7-day window |
| Last 30 days | Rolling 30-day window (default) |
| Last 90 days | Rolling 90-day window |
| All time | Entire database |

Select a row and click **Load Selected** to restore those results into the main window. The results table, summary counts, and export buttons are all populated exactly as they would be after a live scan.


## Exporting Results

No file is written automatically. After a scan completes (or after loading a historical scan), use the export buttons to save results in your preferred format.

### CSV

Columns: `Absolute_Path`, `Hash_Type`, `Hash_Value`.

```csv
Absolute_Path,Hash_Type,Hash_Value
C:\path\to\report.pdf,MD5,44d88612fea8a8f36de82e1278abb02f
C:\path\to\alerts.log,SHA1,da39a3ee5e6b4b0d3255bfef95601890afd80709
C:\path\to\iocs.json,SHA256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### JSON

A flat array of objects, one entry per hash found.

```json
[
  {
    "absolute_path": "C:\\path\\to\\report.pdf",
    "hash_type": "MD5",
    "hash_value": "44d88612fea8a8f36de82e1278abb02f"
  },
  {
    "absolute_path": "C:\\path\\to\\alerts.log",
    "hash_type": "SHA1",
    "hash_value": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
  }
]
```

| Field | Description |
|-------|-------------|
| `absolute_path` / `Absolute_Path` | Full file system path of the source file containing the hash. |
| `hash_type` / `Hash_Type` | Algorithm matched: `MD5`, `SHA1`, `SHA256`, or `SHA512`. |
| `hash_value` / `Hash_Value` | Lowercase hexadecimal hash string. |

## Implementation Notes

`HashHarvest` in [extractor.py](hashharvest/extractor.py) has no GUI dependency and can be used independently.

```python
from hashharvest.extractor import HashHarvest

extractor = HashHarvest(directory="/path/to/files")
results = extractor.extract()
# results: {file_path: set of (hash_type, hash_value) tuples}

extractor.export_csv("/path/to/output.csv")
extractor.export_json("/path/to/output.json")
```

File reading is handled by [readers.py](hashharvest/readers.py), which can also be used directly:

```python
from hashharvest.readers import read_file, SUPPORTED_EXTENSIONS

text = read_file("/path/to/report.json")   # returns extracted text as a string
print(SUPPORTED_EXTENSIONS)               # {'.pdf', '.txt', '.log', '.md', '.csv', '.json', '.xml', '.docx', '.xlsx', '.pptx'}
```

Database persistence is handled by [persistence/db.py](hashharvest/persistence/db.py):

```python
from hashharvest.persistence.db import HashDatabase

db = HashDatabase("hashharvest.db")

# Retrieve all scans from the last 30 days
scans = db.get_scans(since="2026-05-01T00:00:00")

# Retrieve per-file hash rows for a given scan id
rows = db.get_results(scan_id=1)
```

### Key methods — HashHarvest

| Method | Description |
|--------|-------------|
| `dir_exists()` | Returns `True` if the configured input directory exists. |
| `read_dir()` | Recursively finds all supported files under the input directory, sorted. |
| `extract(...)` | Runs the full scan, fires optional callbacks, and returns results. |
| `export_csv(path)` | Writes the current results to a CSV file at the given path. |
| `export_json(path)` | Writes the current results to a JSON file at the given path. |

`extract()` accepts three optional callbacks:

| Callback | Signature | Fired when |
|----------|-----------|------------|
| `progress_callback` | `(int)` | After each file is processed (0–100). |
| `status_callback` | `(str)` | When a file is skipped due to an error. |
| `result_callback` | `(file_path, file_type, hash_type, hash_value)` | For each hash found. |

### Key methods — HashDatabase

| Method | Description |
|--------|-------------|
| `save_scan(...)` | Persists scan metadata and all per-file hash results to the database. |
| `get_scans(since=None)` | Returns a list of scan records, optionally filtered by ISO-format timestamp. |
| `get_results(scan_id)` | Returns all per-file hash rows for the given scan id. |

The GUI in [main.py](hashharvest/main.py) wires these callbacks to PyQt5 signals emitted by a `ScanWorker` running in a `QThread`.

## Building a Standalone Executable

```powershell
python -m PyInstaller --clean --onefile --windowed --name HashHarvest --hidden-import PyQt5.sip hashharvest/main.py
```

The database file (`hashharvest.db`) is written next to the compiled executable at runtime.
