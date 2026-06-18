# HashExtractor

Author: labgeek@gmail.com (JD Durick)

`HashExtractor` is a PyQt5 desktop application that scans a folder of files for cryptographic hash values and writes the results to a CSV-formatted output file. It detects MD5, SHA1, SHA256, and SHA512 hashes by matching exact hexadecimal lengths using negative lookaround so shorter patterns never match inside longer ones.

<img width="1477" height="552" alt="image" src="https://github.com/user-attachments/assets/0c8baa4d-1057-4550-ac72-7472a5ecdd8a" />


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
- Scan summary panel showing files scanned, hashes found, skipped files, and output path.
- Read-only output path field with a tooltip for long paths.
- Clear Form button resets all inputs, results, progress, and summary fields.
- README viewer opens this file in a separate read-only window from within the app.
- Output directory is created automatically if it does not already exist.
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
cd C:\data\projects\md5Extractor
python hashExtractor.py
```

### GUI Controls

| Control | Description |
|---------|-------------|
| **Input Directory** field | Type or browse to the folder containing files to scan. |
| **Select Input Folder** | Opens a folder picker for the input directory. |
| **Output Directory** field | Type or browse to the folder where `hashOutput.txt` will be written. |
| **Select Output Folder** | Opens a folder picker for the output directory. |
| **Start Scan** | Validates inputs and begins the threaded scan. |
| **Clear Form** | Resets all fields, the results table, the progress bar, and summary counts. |
| **Open README** | Opens this file in a read-only viewer. Click again to close it. |

You can type paths directly into either directory field instead of using the folder pickers.


## Output File

Results are written to:

```text
<selected output directory>\hashOutput.txt
```

The file uses CSV format with three columns:

```csv
Absolute_Path,Hash_Type,Hash_Value
C:\path\to\report.pdf,MD5,44d88612fea8a8f36de82e1278abb02f
C:\path\to\alerts.log,SHA1,da39a3ee5e6b4b0d3255bfef95601890afd80709
C:\path\to\iocs.json,SHA256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
C:\path\to\report.xml,SHA512,cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
```

| Column | Description |
|--------|-------------|
| `Absolute_Path` | Full file system path of the source file containing the hash. |
| `Hash_Type` | Algorithm matched: `MD5`, `SHA1`, `SHA256`, or `SHA512`. |
| `Hash_Value` | Lowercase hexadecimal hash string. |

Each unique hash found in a file produces one row. If the same hash appears more than once in the same file, it is written once. Each scan session appends to the file and writes its own header row.


## Important Behavior

- Hashes are matched by hexadecimal length and character set only. The app does not verify that a matched value is the actual hash of any file.
- A 64-character hex string is classified as SHA256, not as two MD5 values. Exact-length negative lookaround prevents shorter patterns from matching inside longer ones.
- Hash values are normalized to lowercase before being stored and written.
- Files that cannot be opened or read are skipped and counted in the scan summary without stopping the scan.
- Malformed JSON and XML files are skipped with an error recorded in the scan summary.
- `hashOutput.txt` is opened in append mode, so results from previous scans are preserved.
- Controls are disabled while a scan is running and re-enabled on completion or failure.
- Image-only or scanned PDFs will not yield results unless OCR is applied beforehand.


## Project Layout

```text
hashExtractor.py        PyQt5 GUI, worker thread, and README viewer
extractor.py            HashExtractor class — file discovery, regex matching, CSV output
readers.py              File readers and read_file() dispatcher for all supported formats
requirements.txt        Runtime dependencies (pypdf, PyQt5)
scripts/
  createhash.py         Utility script that generates a sample PDF containing test hashes
testPDF/                Sample PDF for manual testing
testFiles/              Sample files for each supported format (csv, json, log, md, txt, xml)
docs/
  FEATURE_ROADMAP.md    Longer-horizon feature ideas
TODO.md                 Near-term implementation backlog
howtobuild.md           PyInstaller build command reference
README.md               This file
```


## Implementation Notes

`HashExtractor` in [extractor.py](extractor.py) has no GUI dependency and can be used independently.

```python
from extractor import HashExtractor

extractor = HashExtractor(directory="/path/to/files", save_path="/path/to/hashOutput.txt")
results = extractor.extract()
# results: {file_path: set of (hash_type, hash_value) tuples}
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
| `extract(...)` | Runs the full scan, fires optional callbacks, writes output, returns results. |
| `write_data()` | Appends the current results dict to the output file in CSV format. |

`extract()` accepts three optional callbacks:

| Callback | Signature | Fired when |
|----------|-----------|------------|
| `progress_callback` | `(int)` | After each file is processed (0–100). |
| `status_callback` | `(str)` | When a file is skipped due to an error. |
| `result_callback` | `(file_path, file_type, hash_type, hash_value)` | For each hash found. |

The GUI in [hashExtractor.py](hashExtractor.py) wires these callbacks to PyQt5 signals emitted by a `ScanWorker` running in a `QThread`.


## Generating Test Fixtures

`scripts/createhash.py` uses `reportlab` to generate a sample PDF containing MD5, SHA1, SHA256, and SHA512 hash values for manual testing.

```powershell
pip install reportlab
python scripts/createhash.py
```

The script writes `hash_test_file.pdf` to the current directory.


## Building a Standalone Executable

```powershell
python -m PyInstaller --clean --onefile --windowed --name HashExtractor --hidden-import PyQt5.sip --add-data "README.md;." hashExtractor.py
```

`--add-data "README.md;."` bundles this README so the in-app README viewer works from the compiled executable.
