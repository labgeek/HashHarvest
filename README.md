# HashExtractor

Author: labgeek@gmail.com (JD Durick)

`HashExtractor` is a simple PyQt5 desktop application that scans PDF files for MD5, SHA1, SHA256, and SHA512 hash values and writes the results to `hashOutput.txt`.

The app recursively searches a selected input folder for PDF files, extracts page text with `pypdf`, finds hexadecimal hash values of the expected lengths, and writes one row per PDF/hash pair.

<img width="1180" height="499" alt="image" src="https://github.com/user-attachments/assets/01e3a331-6647-4066-95ff-b11f7d476922" />


## Features

- Branded PyQt5 interface with the application title, version, author, and current launch date.
- Input folder picker for the PDF directory.
- Output folder picker for the generated `hashOutput.txt` file.
- Threaded PDF scanning so the GUI remains responsive during extraction.
- Progress bar that updates as PDFs are processed.
- Results table with separate columns for:
  - PDF file path
  - Hash type (MD5, SHA1, SHA256, SHA512)
  - Hash value
- Scan summary showing:
  - PDFs scanned
  - hashes found
  - skipped files
  - output file path
- Read-only output path field with copy support and tooltip for long paths.
- Clear Form button to reset inputs, results, progress, and summary data.
- README button that opens or closes this README in a separate read-only window.
- Professional validation messages for input, output, and scan errors.
- Duplicate hash values are collapsed per PDF.
- Output directory creation when the selected output directory does not already exist.

## Requirements

- Python 3
- `pypdf`
- `PyQt5`

Install dependencies from the project root:

```powershell
python -m pip install -r requirements.txt
```

## Running the App

From the project directory:

```powershell
cd C:\data\projects\md5Extractor
python hashExtractor.py
```

The application window provides:

- `Select Input Folder`: choose the folder containing PDFs to scan.
- `Select Output Folder`: choose where `hashOutput.txt` should be written.
- `Start Scan`: begin scanning PDFs.
- `Clear Form`: clear the selected paths, results table, progress bar, and scan summary.
- `Open README`: open this README in a separate window. Click the button again to close it.

You can also type paths directly into the input fields.

## Output File

The output file is always named:

```text
hashOutput.txt
```

It is written inside the selected output directory. For example, if the output directory is:

```text
C:\data\projects\md5Extractor\out
```

the final output path is:

```text
C:\data\projects\md5Extractor\out\hashOutput.txt
```

The output uses CSV-style rows:

```csv
Absolute_Path,Hash_Type,Hash_Value
C:\path\to\file.pdf,MD5,44d88612fea8a8f36de82e1278abb02f
C:\path\to\file.pdf,SHA256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Each row contains:

- `Absolute_Path`: the full path of the PDF where the hash was found.
- `Hash_Type`: the algorithm matched (`MD5`, `SHA1`, `SHA256`, or `SHA512`).
- `Hash_Value`: the matched hexadecimal hash string.

If a PDF contains more than one unique matching hash, each hash is written on its own row. If the same hash appears multiple times in the same PDF, it is written once for that PDF.

## Important Behavior

- The app matches hash-shaped strings by length and character set. It does not verify that a value is actually the hash of a file.
- PDFs that cannot be read are skipped and counted in the scan summary.
- Existing `hashOutput.txt` files are appended to because the writer opens the file in append mode.
- Each scan writes a header row before writing results.
- Scanning runs in a worker thread and controls are disabled during an active scan.
- The GUI remains open after extraction completes.
- Image-only or scanned PDFs may not produce text unless OCR is added separately.

## Project Layout

```text
hashExtractor.py     PyQt5 GUI entry point and README viewer
extractor.py         PDF scanning, hash extraction, and output writing
requirements.txt     Runtime dependencies
testpdf.pdf          Sample PDF fixture
README.md            Current documentation
contributors.txt     Contributor information
```

## Implementation Notes

The main extraction class is `HashExtractor` in `extractor.py`.

Key methods:

- `dir_exists()` checks whether the PDF input directory exists.
- `read_dir()` recursively finds PDF files and returns them in sorted order.
- `get_pdf_content()` extracts text from a PDF.
- `extract()` coordinates scanning, matching, progress updates, status updates, result callbacks, and output writing.
- `write_data()` writes results to `hashOutput.txt`.

The GUI in `hashExtractor.py`:

- builds the final output path by joining the selected output directory with `hashOutput.txt`
- displays results in a table
- tracks scan progress and summary counts
- runs extraction through a `QThread` worker
- opens and closes `README.md` in a separate read-only window

## Development Validation

Run syntax validation after changing Python files:

```powershell
python -m py_compile hashExtractor.py extractor.py
```

Build a Windows executable with PyInstaller:

```powershell
python -m PyInstaller --clean --onefile --windowed --name HashExtractor --hidden-import PyQt5.sip --add-data "README.md;." hashExtractor.py
```

The `--add-data "README.md;."` option bundles this README so the in-app README button works from the compiled executable.

If tests are added later, run the project test command documented with those tests.
