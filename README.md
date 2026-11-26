# HashHarvest v0.8.0

Author: labgeek@gmail.com

`HashHarvest` (v0.8.0) is a desktop application for extracting cryptographic hashes from a folder of files. It scans recursively across PDF, text, log, CSV, JSON, XML, Markdown, and Microsoft Office files (Word `.docx`, Excel `.xlsx`, PowerPoint `.pptx`) — detecting MD5, SHA1, SHA256, and SHA512 values using exact hex-length matching with negative lookaround so shorter patterns never collide with longer ones. Results are displayed live as the scan runs with the line number and surrounding context for each hit, and can be filtered in real time, right-click copied, exported to CSV or JSON, and automatically persisted to a local SQLite database. A built-in Watchlist lets you import known-bad hash lists and instantly highlights any matches red after each scan. A Scan History dialog lets you filter past scans by date range and reload any previous result set into the main UI for re-inspection or re-export.

> HashHarvest is written in Go with a [Wails](https://wails.io) desktop UI. See [USAGE.md](USAGE.md) for how to use the app and [GO_PORT.md](GO_PORT.md) for development and testing notes.

HashHarvest has **two scan modes**: *Find hashes in text* (the default — detect hash-shaped strings inside document text) and *Hash the files* (compute each file's own MD5/SHA1/SHA256/SHA512 digest). Whichever mode you use, the resulting hashes can be checked against **VirusTotal** from inside the app for a malicious / suspicious / clean verdict.

<img width="1616" height="804" alt="image" src="https://github.com/user-attachments/assets/5ccdb12f-0cd3-4b75-b203-bb4968d71571" />

## Supported File Types

| Extension | How text is extracted |
|-----------|----------------------|
| `.pdf`    | Page text via a built-in extractor; location label shows page number in context |
| `.txt`    | Plain text, UTF-8 with latin-1 fallback |
| `.log`    | Plain text, UTF-8 with latin-1 fallback |
| `.md`     | Plain text, UTF-8 with latin-1 fallback |
| `.csv`    | All cell values joined as searchable text |
| `.json`   | Recursive walk — all keys and scalar values |
| `.xml`    | All element text and tail text |
| `.docx`   | Word document body — paragraph text from `word/document.xml` |
| `.xlsx`   | Excel cell text — both the shared-string table and inline worksheet strings |
| `.pptx`   | PowerPoint slide text — paragraph runs from every `ppt/slides/slideN.xml`; location label shows slide number in context |

Extensions are matched case-insensitively. Files with other extensions are ignored.

The Office formats (`.docx`, `.xlsx`, `.pptx`) are read directly from their underlying OpenXML zip packages using the Go standard library — no third-party Office libraries are required at runtime. Text split across multiple runs within a paragraph or cell is reassembled, so a hash broken into pieces by the authoring tool is still matched. Scope notes: `.docx` reads the main document body (not headers, footers, or footnotes); `.xlsx` reads string cells from all worksheets (numeric cells never hold hash strings); `.pptx` reads slide bodies (not speaker notes or masters).


## Supported Hash Types

| Algorithm | Hex length |
|-----------|-----------|
| MD5       | 32        |
| SHA1      | 40        |
| SHA256    | 64        |
| SHA512    | 128       |


## Features

- Detects MD5, SHA1, SHA256, and SHA512 hashes across all supported file types in a single scan.
- **Two scan modes** — *Find hashes in text* (detect hash strings inside documents) or *Hash the files* (compute each file's own digest). File-digest mode walks **all** files under the folder, not just the supported document types, and reports one row per file per selected algorithm.
- **VirusTotal lookup** — after a scan, check the results' unique hashes against VirusTotal and see a malicious / suspicious / clean verdict with detection counts, color-coded in a dialog. MD5, SHA1, and SHA256 are looked up; SHA512 is labeled n/a because VirusTotal does not index it.
- Recursive directory search — all supported files under the selected folder are included.
- Background extraction keeps the GUI responsive during long scans.
- **Results table** with six columns: **Source File**, **File Type**, **Hash Type**, **Hash Value**, **Line**, and **Context**.
- **Line number** and **surrounding context** (up to 60 characters either side of the match) captured for every hash; PDF and PPTX hits include a `[page N]` / `[slide N]` prefix in the context string.
- **Show Context** checkbox toggles the Line and Context columns; column stretch shifts automatically so the table always fills the window cleanly.
- **Filter bar** above the results table — type any text to instantly hide non-matching rows across all columns; cleared automatically on each new scan.
- **Right-click context menu** on any result row: **Copy Hash** copies the hash value; **Copy Row** copies all visible columns as tab-separated text.
- Column sorting by clicking any header (disabled during a live scan to prevent row-jump artifacts; re-enabled on completion).
- Alternating row colors, and every column is user-resizable by dragging its header border.
- Long source paths are truncated and the full path is shown as a tooltip on hover.
- Progress bar that updates per file processed.
- Scan summary panel showing files scanned, hashes found, and skipped files.
- **Export CSV** button saves results to a CSV file of your choosing after the scan completes (includes Line and Context columns).
- **Export JSON** button saves results to a JSON file of your choosing after the scan completes (includes `line` and `context` fields).
- Export buttons are disabled until a scan finishes successfully; loading a historical scan re-enables them.
- **Scan History** button opens a filterable list of past scans stored in the local database.
- Every completed scan is automatically persisted to a local SQLite database (`hashharvest.db`).
- Historical scan results can be loaded back into the main UI, including watchlist highlights, and exported like a fresh scan.
- **Watchlist** — import known-bad hash lists from paste, TXT, CSV, or any structured text; after every scan (and when reloading history), matching rows are highlighted red and a hit count badge appears in the status bar.
- Clear Form button resets all inputs, results, progress, summary fields, and export buttons.
- Only the first occurrence of each (algorithm, hash value) pair per file is kept — duplicates within the same file are not repeated.
- Skipped files (unreadable or malformed) are counted but do not stop the scan.


## Requirements

- Windows 10/11 (other platforms: the `internal/` packages compile, but the GUI is not supported)
- Go 1.26 or newer
- Wails CLI v2.15.0
- Microsoft Edge WebView2 Runtime (ships with Windows 10 21H2+ and Windows 11)

No C compiler, Node.js or npm is needed.

## Quick Start

From the project root:

```powershell
go install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0
wails build -trimpath
```

The executable is written to `packaging\wails\bin\HashHarvest.exe`.

To build with the Go toolchain alone (no Wails CLI):

```powershell
go build -tags desktop,production -trimpath -ldflags "-w -s -H windowsgui" -o HashHarvest.exe .
```

The `desktop,production` tags are required: without them the program compiles but only shows a build-tags error at startup. This route also leaves out the icon, manifest and version info from `packaging/wails/`, so use `wails build` for releases.

Then run it:

```powershell
.\packaging\wails\bin\HashHarvest.exe
```

For development with live reload, use `wails dev`. To run the tests, use `go test ./...`.

### GUI Controls

| Control | Description |
|---------|-------------|
| **Input Directory** field | Type or browse to the folder containing files to scan. |
| **Select Input Folder** | Opens a folder picker for the input directory. |
| **Scan Mode** | *Find hashes in text* scans document text for hash-shaped strings; *Hash the files* computes each file's own digest. |
| **Hash Types** checkboxes | Choose which algorithms to scan for (MD5, SHA1, SHA256, SHA512). All checked by default. |
| **Start Scan** | Validates the input directory and begins the background scan. |
| **Clear Form** | Resets all fields, the results table, the progress bar, and summary counts. |
| **Scan History** | Opens the Scan History dialog to browse and reload past scans. |
| **Watchlist** | Opens the Watchlist Manager to create watchlists and import known-bad hashes. |
| **VirusTotal** | Opens the VirusTotal Lookup dialog to check the current results' hashes against VirusTotal. |
| **Export CSV** | Opens a save dialog and writes the current results to a CSV file. Enabled after a successful scan or after loading history. |
| **Export JSON** | Opens a save dialog and writes the current results to a JSON file. Enabled after a successful scan or after loading history. |

You can type a path directly into the Input Directory field instead of using the folder picker.


## Results Table

The results table has six columns:

| Column | Description |
|--------|-------------|
| **Source File** | Path of the file containing the hash. Truncated when long; full path shown as tooltip. |
| **File Type** | File extension in uppercase (e.g. `PDF`, `LOG`, `DOCX`). |
| **Hash Type** | Algorithm: `MD5`, `SHA1`, `SHA256`, or `SHA512`. |
| **Hash Value** | Lowercase hexadecimal hash string. This column stretches to fill available width by default. |
| **Line** | Line number within the file where the hash first appears (hidden by default). |
| **Context** | Up to 60 characters on either side of the match, with newlines collapsed. PDF pages prefixed `[page N]`, PPTX slides prefixed `[slide N]`. Stretches to fill width when visible. |

**Line** and **Context** are hidden by default. Toggle them with the **Show Context** checkbox above the table.

### Filtering

Type any text into the filter bar above the table to hide rows that do not match. Filtering is applied across all columns simultaneously. The filter is cleared automatically at the start of each new scan.

### Right-click actions

Right-click any row for:

| Action | Copies |
|--------|--------|
| **Copy Hash** | The hash value from the selected row. |
| **Copy Row** | All visible columns of the selected row, tab-separated. |


## Watchlist

The Watchlist turns HashHarvest from a pure extraction tool into a triage tool: load a list of known-bad hashes and any matches found during a scan are immediately highlighted.

### Opening the Watchlist Manager

Click **Watchlist** in the toolbar. The Watchlist Manager dialog lists all saved watchlists with their entry counts.

### Creating a watchlist

Enter a name (e.g. `Incident 2026-06`, `IOC Feed`) in the **Watchlist name** field and click **New…**. The new watchlist appears in the list.

### Importing hashes

1. Select a watchlist in the list.
2. Either paste hashes into the text area or click **Browse File…** to load a TXT, CSV, or log file.
3. Click **Import from Text** (or browse — file imports run immediately).

Any MD5, SHA1, SHA256, or SHA512 hex string found anywhere in the input is extracted automatically. You can paste raw hash lists, threat-intel CSV exports, log excerpts — the importer finds the hashes and ignores everything else. Duplicate entries within the same watchlist are silently skipped.

### Matching

After every scan completes, all extracted hashes are joined against all watchlist entries in a single SQLite query. Matching rows in the results table are highlighted **red**. The status bar shows a `⚠ N watchlist hits` badge. Watchlist highlights are also applied when loading a historical scan from Scan History.

### Deleting a watchlist

Select the watchlist and click **Delete Selected**. A confirmation prompt warns you that all entries will be removed. Deletion cannot be undone.


## VirusTotal Lookup

After any scan, click **VirusTotal** to check the results' unique hashes against [VirusTotal](https://www.virustotal.com). The lookup dialog lists each hash with a verdict and detection count, color-coded:

| Verdict | Meaning | Color |
|---------|---------|-------|
| `malicious` | One or more engines flag it as malicious | Red |
| `suspicious` | Flagged suspicious but not malicious | Amber |
| `clean` | Known to VirusTotal, no detections | Green |
| `not found` | VirusTotal has no record of this hash | (none) |
| `n/a` | SHA512 — not indexed by VirusTotal, so it is skipped | (none) |
| `error` | Lookup failed (rate limit, network, etc.) — the reason is shown | (none) |

VirusTotal identifies files by **MD5, SHA1, and SHA256** only. SHA512 hashes are labeled `n/a` and never sent, so they don't waste an API call. The dialog is self-contained — it does not modify the results table, database, or exports.

> **Free-tier rate limit:** public VirusTotal API keys allow roughly 4 lookups/minute and 500/day. Beyond that, rows come back as `error: QuotaExceededError`. Look up smaller batches, or use a premium key.

### API Key

The lookup needs a VirusTotal API key (get one at <https://www.virustotal.com/gui/my-apikey>). HashHarvest resolves the key in this order:

1. **`VT_API_KEY` environment variable** — if set, the key field is pre-filled and locked.
2. **`.env` file** — a `VT_API_KEY=...` line in a `.env` file next to the executable. Create the file yourself; it is git-ignored.
3. **The dialog's API Key field** — type or paste the key once and it is saved for next time (see storage options below).

You only need one of these. The `.env` and environment-variable options keep the key out of the GUI entirely; the field method is the quickest for one-off use.

### Key storage: plaintext vs. encrypted

When you save a key from the dialog field, HashHarvest offers two backends via the **"Store key in OS keychain (encrypted at rest)"** checkbox:

| Storage | Where the key lives | At-rest encryption | Needs |
|---------|--------------------|--------------------|-------|
| **Settings** (default, unchecked) | Windows registry `HKCU\Software\HashHarvest\HashHarvest` | No — plaintext | Nothing |
| **OS keychain** (checked) | Windows Credential Manager | Yes | Nothing extra on Windows |

For a free VirusTotal key, the plaintext default is fine — it's a low-value, revocable, rate-limited secret. If you use a **premium key** or a **shared machine**, tick the box for encrypted, login-tied storage. The checkbox is disabled with a hint when encrypted storage is unavailable. Switching backends moves the key and clears the copy from the other one, so it's never stored in both places. A key supplied via `VT_API_KEY` or `.env` is never written to either store.

## Scan History

Every time a scan completes, the results are saved automatically to `hashharvest.db` (a SQLite file written next to the executable). Click **Scan History** to open the history dialog.

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

Select a row and click **Load Selected** to restore those results into the main window. The results table, summary counts, export buttons, and any watchlist highlights are all populated exactly as they would be after a live scan.


## Exporting Results

No file is written automatically. After a scan completes (or after loading a historical scan), use the export buttons to save results in your preferred format.

### CSV

Columns: `Absolute_Path`, `Hash_Type`, `Hash_Value`, `Line`, `Context`.

```csv
Absolute_Path,Hash_Type,Hash_Value,Line,Context
C:\path\to\report.pdf,MD5,44d88612fea8a8f36de82e1278abb02f,12,[page 1] Hash: 44d88612fea8a8f36de82e1278abb02f found in
C:\path\to\alerts.log,SHA1,da39a3ee5e6b4b0d3255bfef95601890afd80709,47,process exited with hash da39a3ee5e6b4b0d3255bfef9560189
C:\path\to\iocs.json,SHA256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,3,"sha256": "e3b0c44298fc1c149afbf4c8996fb924
```

### JSON

A flat array of objects, one entry per hash found.

```json
[
  {
    "absolute_path": "C:\\path\\to\\report.pdf",
    "hash_type": "MD5",
    "hash_value": "44d88612fea8a8f36de82e1278abb02f",
    "line": 12,
    "context": "[page 1] Hash: 44d88612fea8a8f36de82e1278abb02f found in"
  },
  {
    "absolute_path": "C:\\path\\to\\alerts.log",
    "hash_type": "SHA1",
    "hash_value": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "line": 47,
    "context": "process exited with hash da39a3ee5e6b4b0d3255bfef9560189"
  }
]
```

| Field | Description |
|-------|-------------|
| `absolute_path` / `Absolute_Path` | Full file system path of the source file. |
| `hash_type` / `Hash_Type` | Algorithm: `MD5`, `SHA1`, `SHA256`, or `SHA512`. |
| `hash_value` / `Hash_Value` | Lowercase hexadecimal hash string. |
| `line` / `Line` | Line number within the file where the hash first appears. |
| `context` / `Context` | Surrounding text snippet (up to 60 chars each side of the match). |


## Building a Standalone Executable

`wails build -trimpath` (see [Quick Start](#quick-start)) produces a single executable, `packaging\wails\bin\HashHarvest.exe`. Ship only that file, and not any `hashharvest.db` or `.env` next to it. The target machine needs the WebView2 Runtime. Run it from a writable folder, since it writes `hashharvest.db` beside itself.

The code layout is described in [GO_PORT.md](GO_PORT.md#layout).

## License

MIT. See [LICENSE](LICENSE).
