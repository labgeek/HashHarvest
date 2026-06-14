# HashExtractor

Author: labgeek@gmail.com (JD Durick)

`HashExtractor` is a PyQt5 desktop application that scans a folder of PDF files for cryptographic hash values and writes the results to a CSV-formatted output file. It detects MD5, SHA1, SHA256, and SHA512 hashes by matching exact hexadecimal lengths using negative lookaround so shorter patterns never match inside longer ones.

<img width="1180" height="499" alt="image" src="https://github.com/user-attachments/assets/01e3a331-6647-4066-95ff-b11f7d476922" />


## Supported Hash Types

| Algorithm | Hex length |
|-----------|-----------|
| MD5       | 32        |
| SHA1      | 40        |
| SHA256    | 64        |
| SHA512    | 128       |


## Features

- Detects MD5, SHA1, SHA256, and SHA512 hashes in a single scan pass.
- Recursive PDF search — all `.pdf` files under the selected folder are included.
- Threaded extraction keeps the GUI responsive during long scans.
- Results table with three columns: **PDF File**, **Hash Type**, and **Hash Value**.
- Alternating row colors and resizable columns for readability.
- Progress bar that updates per file processed.
- Scan summary panel showing PDFs scanned, hashes found, skipped files, and output path.
- Read-only output path field with a tooltip for long paths.
- Clear Form button resets all inputs, results, progress, and summary fields.
- README viewer opens this file in a separate read-only window from within the app.
- Output directory is created automatically if it does not already exist.
- Duplicate hashes within the same PDF are written once.
- Skipped files (unreadable PDFs) are counted but do not stop the scan.


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
| **Input PDF Directory** field | Type or browse to the folder containing PDFs. |
| **Select Input Folder** | Opens a folder picker for the PDF directory. |
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
C:\path\to\file.pdf,MD5,44d88612fea8a8f36de82e1278abb02f
C:\path\to\file.pdf,SHA1,da39a3ee5e6b4b0d3255bfef95601890afd80709
C:\path\to\file.pdf,SHA256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
C:\path\to\file.pdf,SHA512,cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
```

| Column | Description |
|--------|-------------|
| `Absolute_Path` | Full file system path of the PDF containing the hash. |
| `Hash_Type` | Algorithm matched: `MD5`, `SHA1`, `SHA256`, or `SHA512`. |
| `Hash_Value` | Lowercase hexadecimal hash string. |

Each unique hash found in a PDF produces one row. If the same hash appears more than once in the same PDF, it is written once. Each scan session appends to the file and writes its own header row.


## Important Behavior

- Hashes are matched by hexadecimal length and character set only. The app does not verify that a matched value is the actual hash of any file.
- A 64-character hex string is classified as SHA256, not as two MD5 values. Exact-length negative lookaround prevents shorter patterns from matching inside longer ones.
- Hash values are normalized to lowercase before being stored and written.
- PDFs that cannot be opened or read are skipped and counted in the scan summary without stopping the scan.
- `hashOutput.txt` is opened in append mode, so results from previous scans are preserved.
- Controls are disabled while a scan is running and re-enabled on completion or failure.
- Image-only or scanned PDFs will not yield results unless OCR is applied beforehand.


## Project Layout

```text
hashExtractor.py     PyQt5 GUI, worker thread, and README viewer
extractor.py         HashExtractor class — PDF walking, regex matching, CSV output
requirements.txt     Runtime dependencies (pypdf, PyQt5)
testpdf.pdf          Sample PDF for manual testing
README.md            This file
contributors.txt     Contributor information
```


## Implementation Notes

`HashExtractor` in [extractor.py](extractor.py) is the core class. It has no GUI dependency and can be used independently.

```python
from extractor import HashExtractor

extractor = HashExtractor(directory="/path/to/pdfs", save_path="/path/to/hashOutput.txt")
results = extractor.extract()
# results: {pdf_path: set of (hash_type, hash_value) tuples}
```

### Key methods

| Method | Description |
|--------|-------------|
| `dir_exists()` | Returns `True` if the configured input directory exists. |
| `read_dir()` | Recursively finds all `.pdf` files under the input directory, sorted. |
| `get_pdf_content(path)` | Extracts plain text from every page of a PDF using `pypdf`. |
| `extract(...)` | Runs the full scan, fires optional callbacks, writes output, returns results. |
| `write_data()` | Appends the current results dict to `hashOutput.txt` in CSV format. |

`extract()` accepts three optional callbacks:

| Callback | Signature | Fired when |
|----------|-----------|------------|
| `progress_callback` | `(int)` | After each PDF is processed (0–100). |
| `status_callback` | `(str)` | When a PDF is skipped due to an error. |
| `result_callback` | `(pdf_path, hash_type, hash_value)` | For each hash found. |

The GUI in [hashExtractor.py](hashExtractor.py) wires these callbacks to PyQt5 signals emitted by a `ScanWorker` running in a `QThread`.


## Development Validation

Syntax check:

```powershell
python -m py_compile hashExtractor.py extractor.py
```

Build a standalone Windows executable:

```powershell
python -m PyInstaller --clean --onefile --windowed --name HashExtractor --hidden-import PyQt5.sip --add-data "README.md;." hashExtractor.py
```

`--add-data "README.md;."` bundles this README so the in-app README viewer works from the compiled executable.
