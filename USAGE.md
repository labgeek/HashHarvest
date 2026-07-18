# HashHarvest — Usage Guide

HashHarvest (v0.8.0) is a desktop GUI tool for working with cryptographic hashes (MD5, SHA1, SHA256, SHA512). It can either **find hashes written inside files** or **compute each file's own digest**, then triage the results — including a **VirusTotal** reputation check — and export them. It is designed for incident response, forensics, and threat intelligence workflows.

---

## Table of Contents

1. [Running from Source](#running-from-source)
2. [Running from the Executable](#running-from-the-executable)
3. [Running a Scan](#running-a-scan)
4. [Results Table](#results-table)
5. [Watchlist](#watchlist)
6. [VirusTotal Lookup](#virustotal-lookup)
7. [Scan History](#scan-history)
8. [Exporting Results](#exporting-results)

---

## Running from Source

### Prerequisites

- Python 3.9 or later
- pip

### Setup

```bash
git clone https://github.com/labgeek/HashHarvest.git
cd HashHarvest
pip install -r requirements.txt
```

### Launch

```bash
python -m hashharvest.main
```

> Run it as a module with `-m` from the project root. Running the file directly (`python hashharvest/main.py`) will fail because the package uses absolute imports that require the project root on `sys.path`.

---

## Running from the Executable

Download the latest `HashHarvest.exe` from the [Releases](https://github.com/labgeek/HashHarvest/releases) page, or build it yourself:

### Build from Source

The build is driven by the included `HashHarvest.spec` (one-file, windowed, UPX-compressed, with the optional `vt` and `keyring` dependencies declared as hidden imports so the VirusTotal and keychain features work in the packaged app).

```powershell
pip install pyinstaller
python -m PyInstaller --clean --upx-dir "C:\path\to\upx" HashHarvest.spec
```

The executable is written to `dist\HashHarvest.exe`.

- **UPX** compression is enabled in the spec — point PyInstaller at your UPX folder with `--upx-dir`, or add it to `PATH` and omit the flag.
- When building from the `.spec`, command-line packaging flags (`--onefile`, `--windowed`, `--name`, `--hidden-import`) are ignored; those live in the spec. Only build-time flags like `--clean` and `--upx-dir` apply.

### Launch

Double-click `HashHarvest.exe` — no Python installation required.

> The `hashharvest.db` scan database is created (empty) in the same folder as the executable on first run.

### Shipping the Executable

Ship **only `HashHarvest.exe`** — it is self-contained. Do **not** include:

- **`hashharvest.db`** — it isn't needed (the app creates a fresh empty one on first run), and shipping your own copy would expose your scan history.
- **`.env`** — it holds your VirusTotal API key. Each user provides their own key.

Run the executable from a writable location (your own folder, Desktop, Downloads), since it writes `hashharvest.db` beside itself.

> **Tip:** after building, test the packaged `.exe` itself — run a scan, do a **VirusTotal** lookup, and confirm the **"Store key in OS keychain"** option is available. These verify the bundled optional dependencies.

---

## Running a Scan

### 1. Select an Input Directory

Click **Select Input Folder** and choose the directory containing the files you want to scan. HashHarvest walks the directory recursively and processes every supported file it finds.

**Supported file types:** PDF, TXT, LOG, MD, CSV, JSON, XML, DOCX, XLSX, PPTX

> Microsoft Office files (`.docx`, `.xlsx`, `.pptx`) are parsed directly from their OpenXML contents — no Office installation or extra libraries required. Text split across runs within a paragraph or cell is reassembled before matching. Word reads the document body; Excel reads string cells across all worksheets; PowerPoint reads slide text.

### 2. Choose a Scan Mode

Pick one of the two **Scan Mode** radio buttons:

- **Find hashes in text** (default) — scans the *text content* of supported document types for hash-shaped strings. Use this to pull hashes (IOCs) out of reports, logs, and threat-intel files. Only the supported file types listed above are read.
- **Hash the files** — computes each file's own MD5/SHA1/SHA256/SHA512 digest. This walks **every** file under the folder, not just the supported document types, so you can fingerprint a directory of samples or evidence.

### 3. Choose Hash Types

Check or uncheck **MD5**, **SHA1**, **SHA256**, and **SHA512** to control which algorithms to scan for. All four are selected by default. Deselect algorithms you don't need to speed up large scans.

### 4. Run the Scan

Click **Start Scan**. The progress bar updates as each file is processed. Files that cannot be read are skipped and counted under **Skipped Files** — the scan always continues to completion.

Results appear in the table as they are found, in real time.

### 5. Clear and Re-scan

Click **Clear Form** to reset all fields, results, progress, and summary counts before starting a new scan.

---

## Results Table

The results table has six columns:

| Column | Description |
|--------|-------------|
| **Source File** | Absolute path to the file containing the hash. Long paths are middle-elided; hover for the full path tooltip. |
| **File Type** | File extension in uppercase (PDF, LOG, DOCX, etc.). |
| **Hash Type** | Algorithm: MD5, SHA1, SHA256, or SHA512. |
| **Hash Value** | Lowercase hexadecimal hash string. Stretches to fill the window by default. |
| **Line** | Line number within the file where the hash first appears. Hidden by default. |
| **Context** | Up to 60 characters on either side of the match, with newlines collapsed to spaces. PDF and PPTX hits include a `[page N]` or `[slide N]` prefix. Stretches to fill width when visible. |

Only the first occurrence of each (algorithm, value) pair per file is shown — a hash that appears multiple times on different lines is recorded once, at its first position.

### Showing Line and Context

Check **Show Context** above the table to reveal the **Line** and **Context** columns. Uncheck to hide them again. The column that fills available horizontal space switches automatically between Hash Value and Context so the table always fills the window cleanly.

### Filtering Results

Type any text into the filter bar above the table to hide rows that do not match. The filter is applied across all columns simultaneously — you can filter by file name, hash type, hash value fragment, or any context text. The filter clears automatically at the start of each new scan.

### Sorting

Click any column header to sort by that column. Click again to reverse the sort. Sorting is re-enabled automatically after each scan completes.

### Right-click Actions

Right-click any row for quick copy actions:

| Action | Copies to clipboard |
|--------|-------------------|
| **Copy Hash** | The hash value from the selected row. |
| **Copy Row** | All visible columns of the selected row, tab-separated. |

---

## Watchlist

The Watchlist is the triage layer on top of extraction. Load known-bad hash lists before or after a scan and any matching rows are immediately highlighted red.

### Opening the Watchlist Manager

Click **Watchlist** in the toolbar to open the Watchlist Manager.

### Creating a Watchlist

Click **New…**, type a name (e.g. `Incident 2026-06`, `IOC Feed`), and press OK. You can maintain multiple named watchlists simultaneously — all active lists are checked after every scan.

### Importing Hashes

1. Select a watchlist from the list on the left.
2. **Paste method** — paste any text containing hashes into the text area, then click **Import from Text**.
3. **File method** — click **Browse File…** and select a `.txt`, `.csv`, or `.log` file; hashes are extracted and imported immediately without filling the text area.

The importer finds any valid MD5 / SHA1 / SHA256 / SHA512 hex string in the input and discards everything else. You can paste raw hash lists, threat-intel CSV exports, STIX excerpts, log lines — it will extract the hashes and ignore labels, commas, whitespace, and prose. Duplicate entries within the same watchlist are silently skipped; the status line reports how many new hashes were added.

### How Matching Works

After every scan completes, all extracted hashes are joined against all watchlist entries in a single SQLite query. Any matching row in the results table is highlighted **red** (white text on a red background). The status bar shows a `⚠ N watchlist hits` count. Watchlist highlights are also applied when loading a historical scan from Scan History.

### Deleting a Watchlist

Select it and click **Delete Selected**. A confirmation prompt will appear. Deletion removes the watchlist and all of its entries and cannot be undone.

---

## VirusTotal Lookup

The Watchlist checks hashes against *your own* known-bad lists. The **VirusTotal** button checks them against VirusTotal's global reputation database instead.

### Setting Up an API Key

You need a free VirusTotal API key — sign in at <https://www.virustotal.com/gui/my-apikey> and copy your key. HashHarvest looks for the key in three places, in order:

1. **`VT_API_KEY` environment variable.** If set, the dialog's key field is pre-filled and locked.

   ```powershell
   $env:VT_API_KEY = "your-key-here"; python -m hashharvest.main
   ```

2. **A `.env` file** next to the app (project root, or beside `HashHarvest.exe` when packaged). Copy the provided `.env.example` to `.env` and fill in your key:

   ```
   VT_API_KEY=your-key-here
   ```

   The `.env` file is git-ignored, so your key is never committed.

3. **The dialog's API Key field.** Paste the key once and it is saved for next time — you won't need to re-enter it.

You only need **one** of these. The first two keep your key out of the GUI entirely.

#### Plaintext vs. encrypted storage (dialog field)

When you save a key from the field, the **"Store key in OS keychain (encrypted at rest)"** checkbox controls where it goes:

- **Unchecked (default):** saved via `QSettings` (Windows registry / plist / ini) as **plaintext**. Fine for a free key — it's low-value, rate-limited, and revocable.
- **Checked:** saved to the **OS keychain** (Windows Credential Manager / macOS Keychain / Linux Secret Service), **encrypted at rest** and tied to your login. Requires `pip install keyring`; if it isn't installed the box is disabled with a hint.

Recommended if you use a **premium key** or a **shared machine**. Switching the box moves the key and removes the copy from the other store, so it's never in both. A key from `VT_API_KEY` or `.env` is never written to either store.

### Running a Lookup

1. Run a scan (either mode) so the results table has hashes.
2. Click **VirusTotal**.
3. Confirm the API key is present (or paste it), then click **Look Up N Hashes**.

Each unique hash is queried and given a verdict:

| Verdict | Meaning | Row color |
|---------|---------|-----------|
| `malicious` | One or more engines flag it as malicious | Red |
| `suspicious` | Flagged suspicious but not malicious | Amber |
| `clean` | Known to VirusTotal with no detections | Green |
| `not found` | VirusTotal has no record of this hash | (none) |
| `n/a` | SHA512 — VirusTotal doesn't index it, so it's skipped | (none) |
| `error` | Lookup failed; the reason (e.g. rate limit) is shown | (none) |

> VirusTotal identifies files by **MD5, SHA1, and SHA256** only — SHA512 hashes are skipped automatically and never use an API call.

> **Rate limits:** free API keys allow about **4 lookups per minute** and 500 per day. Larger batches will start returning `error: QuotaExceededError` — look up a handful at a time, or use a premium key.

> The lookup feature requires the `vt-py` package (installed by `pip install -r requirements.txt`). If it's missing, the dialog tells you to run `pip install vt-py`. The lookup dialog does not change the results table, database, or exports.

---

## Scan History

Every completed scan is automatically saved to `hashharvest.db`. Click **Scan History** to view and reload past scans.

### History Dialog

| Column | Description |
|--------|-------------|
| Date / Time | When the scan ran (truncated to the minute). |
| Directory | Input directory that was scanned. |
| Files | Number of files processed. |
| Hashes Found | Total hashes extracted. |

Use the **Show** drop-down to filter by time range:

| Option | Shows scans from |
|--------|-----------------|
| Today | Midnight of the current day |
| Last 7 days | Rolling 7-day window |
| Last 30 days | Rolling 30-day window (default) |
| Last 90 days | Rolling 90-day window |
| All time | Entire database |

Select a row and click **Load Selected** to restore that scan into the main window. The results table, summary counts, export buttons, and any watchlist highlights are all populated exactly as they would be after a live scan.

---

## Exporting Results

No file is written automatically. After a scan completes (or after loading a historical scan), use the export buttons to save results. Both buttons are disabled until there are results to export.

### Export CSV

Columns: `Absolute_Path`, `Hash_Type`, `Hash_Value`, `Line`, `Context`

```csv
Absolute_Path,Hash_Type,Hash_Value,Line,Context
C:\evidence\report.pdf,MD5,44d88612fea8a8f36de82e1278abb02f,12,[page 1] Hash: 44d88612fea8a8f36de82e1278abb02f found in
C:\evidence\alerts.log,SHA1,da39a3ee5e6b4b0d3255bfef95601890afd80709,47,process exited with hash da39a3ee5e6b4b0d3255bfef9560189
C:\evidence\iocs.json,SHA256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,3,"sha256": "e3b0c44298fc1c149afbf4c8996fb924
```

### Export JSON

A flat array of objects, one entry per hash found.

```json
[
  {
    "absolute_path": "C:\\evidence\\report.pdf",
    "hash_type": "MD5",
    "hash_value": "44d88612fea8a8f36de82e1278abb02f",
    "line": 12,
    "context": "[page 1] Hash: 44d88612fea8a8f36de82e1278abb02f found in"
  },
  {
    "absolute_path": "C:\\evidence\\alerts.log",
    "hash_type": "SHA1",
    "hash_value": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "line": 47,
    "context": "process exited with hash da39a3ee5e6b4b0d3255bfef9560189"
  }
]
```

| Field | Description |
|-------|-------------|
| `Absolute_Path` / `absolute_path` | Full filesystem path of the source file. |
| `Hash_Type` / `hash_type` | Algorithm: `MD5`, `SHA1`, `SHA256`, or `SHA512`. |
| `Hash_Value` / `hash_value` | Lowercase hexadecimal hash string. |
| `Line` / `line` | Line number within the file where the hash first appears. |
| `Context` / `context` | Surrounding text snippet; PDF/PPTX hits include a page or slide prefix. |
