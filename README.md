# HashExtractor

Author: labgeek@gmail.com (JD Durick)

`HashExtractor` is a PyQt5 desktop application that scans a folder of files for cryptographic hash values and lets you export the results as CSV or JSON. It detects MD5, SHA1, SHA256, and SHA512 hashes by matching exact hexadecimal lengths using negative lookaround so shorter patterns never match inside longer ones.

<img width="1708" height="427" alt="image" src="https://github.com/user-attachments/assets/da370fad-035d-4576-96d4-5546f9c58823" />



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

Extensions are matched case-insensitively. Files with other extensions are ignored.


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
- Alternating row colors and resizable columns for readability.
- Progress bar that updates per file processed.
- Scan summary panel showing files scanned, hashes found, and skipped files.
- **Export CSV** button saves results to a CSV file of your choosing after the scan completes.
- **Export JSON** button saves results to a JSON file of your choosing after the scan completes.
- Export buttons are disabled until a scan finishes successfully.
- Clear Form button resets all inputs, results, progress, summary fields, and export buttons.
- README viewer opens this file in a separate read-only window from within the app.
- Duplicate hashes within the same file are written once.
- Skipped files (unreadable or malformed) are counted but do not stop the scan.


## Requirements

- Python 3
- `pypdf`
- `PyQt5`

Install dependencies from the project root:

```powershell
python -m pip install -r requirements.txt
```


## Running the App

```powershell
cd C:\HashExtractor
python hashExtractor.py
```

### GUI Controls

| Control | Description |
|---------|-------------|
| **Input Directory** field | Type or browse to the folder containing files to scan. |
| **Select Input Folder** | Opens a folder picker for the input directory. |
| **Hash Types** checkboxes | Choose which algorithms to scan for (MD5, SHA1, SHA256, SHA512). All checked by default. |
| **Start Scan** | Validates the input directory and begins the threaded scan. |
| **Clear Form** | Resets all fields, the results table, the progress bar, and summary counts. |
| **Open README** | Opens this file in a read-only viewer. Click again to close it. |
| **Export CSV** | Opens a save dialog and writes the current results to a CSV file. Enabled after a successful scan. |
| **Export JSON** | Opens a save dialog and writes the current results to a JSON file. Enabled after a successful scan. |

You can type a path directly into the Input Directory field instead of using the folder picker.


## Exporting Results

No file is written automatically. After a scan completes, use the export buttons to save results in your preferred format.

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

`HashExtractor` in [extractor.py](extractor.py) has no GUI dependency and can be used independently.

```python
from extractor import HashExtractor

extractor = HashExtractor(directory="/path/to/files")
results = extractor.extract()
# results: {file_path: set of (hash_type, hash_value) tuples}

extractor.export_csv("/path/to/output.csv")
extractor.export_json("/path/to/output.json")
```

File reading is handled by [readers.py](readers.py), which can also be used directly:

```python
from readers import read_file, SUPPORTED_EXTENSIONS

text = read_file("/path/to/report.json")   # returns extracted text as a string
print(SUPPORTED_EXTENSIONS)               # {'.pdf', '.txt', '.log', '.md', '.csv', '.json', '.xml'}
```

### Key methods

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

The GUI in [hashExtractor.py](hashExtractor.py) wires these callbacks to PyQt5 signals emitted by a `ScanWorker` running in a `QThread`.

## Building a Standalone Executable

```powershell
python -m PyInstaller --clean --onefile --windowed --name HashExtractor --hidden-import PyQt5.sip --add-data "README.md;." hashExtractor.py
```

`--add-data "README.md;."` bundles this README so the in-app README viewer works from the compiled executable.
