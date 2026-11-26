# HashHarvest — Usage Guide

HashHarvest (v1.0.0) is a desktop tool for working with cryptographic hashes (MD5, SHA1, SHA256, SHA512). It can either **find hashes written inside files** or **compute each file's own digest**, then triage the results — including a **VirusTotal** reputation check — and export them. It is designed for incident response, forensics, and threat intelligence workflows.

---

## Table of Contents

1. [Running the App](#running-the-app)
2. [Running a Scan](#running-a-scan)
3. [Results Table](#results-table)
4. [Watchlist](#watchlist)
5. [VirusTotal Lookup](#virustotal-lookup)
6. [Scan History](#scan-history)
7. [Exporting Results](#exporting-results)
8. [Command Line](#command-line)
9. [What Is Read and Skipped](#what-is-read-and-skipped)
10. [Troubleshooting](#troubleshooting)

---

## Running the App

### Prerequisites

Windows 10/11 with the WebView2 Runtime (included in Windows 10 21H2+ and Windows 11). To build, you also need Go 1.26 or newer and the Wails CLI v2.15.0.

### Build

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

### Launch

Double-click `HashHarvest.exe`, or during development run `wails dev` from the project root.

### Files

| File | Location |
|------|----------|
| `hashharvest.db` | Next to the executable (created on first run) |
| `.env` (optional) | Next to the executable; copy [`.env.example`](.env.example) to start |
| Logs | `%USERPROFILE%\.hashharvest\logs\hashharvest.log` (rotates at 1 MB, 5 backups) |

Run the executable from a writable folder, since the database is written beside it. When sharing the app, ship only `HashHarvest.exe` — never your `hashharvest.db` or `.env`.

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

Click **Start Scan**. The progress bar updates as each file is processed, and results appear in the table as they are found.

**Cancel Scan** appears while a scan runs and stops it, even partway through a large file. A cancelled scan is not saved and leaves nothing to export.

Files and folders that cannot be read are skipped, counted under **Skipped Files**, and the scan continues. Click **View list** next to the count to see each path and why it was skipped. See [What Is Read and Skipped](#what-is-read-and-skipped).

### 5. Clear and Re-scan

Click **Clear Form** to reset all fields, results, progress, and summary counts before starting a new scan.

---

## Results Table

The results table has six columns:

| Column | Description |
|--------|-------------|
| **Source File** | Absolute path to the file containing the hash. Long paths are truncated; hover for the full path tooltip. |
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

Type a name (e.g. `Incident 2026-06`, `IOC Feed`) in the **Watchlist name** field and click **New…** or press Enter. You can maintain multiple named watchlists simultaneously — all active lists are checked after every scan.

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
   $env:VT_API_KEY = "your-key-here"
   .\packaging\wails\bin\HashHarvest.exe
   ```

2. **A `.env` file** beside `HashHarvest.exe`. Copy [`.env.example`](.env.example) to `.env` and set the key:

   ```
   VT_API_KEY=your-key-here
   ```

   The `.env` file is git-ignored, so your key is never committed.

3. **The dialog's API Key field.** Paste the key once and it is saved for next time — you won't need to re-enter it.

You only need **one** of these. The first two keep your key out of the GUI entirely.

#### Plaintext vs. encrypted storage (dialog field)

When you save a key from the field, the **"Store key in OS keychain (encrypted at rest)"** checkbox controls where it goes:

- **Unchecked (default):** saved to the Windows registry as **plaintext**. Fine for a free key — it's low-value, rate-limited, and revocable.
- **Checked:** saved to the **OS keychain** (Windows Credential Manager), **encrypted at rest** and tied to your login. Nothing extra is needed on Windows; where no keychain is available the box is disabled with a hint.

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

> The VirusTotal client is built in. The lookup dialog does not change the results table, database, or exports, and closing it stops a running lookup.

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

Select a row and click **View Log** to read the scan's stored log, which lists every skipped file and why. Click **Load Selected** to restore that scan into the main window. The results table, summary counts, export buttons, and any watchlist highlights are all populated exactly as they would be after a live scan.

---

## Exporting Results

No file is written automatically. After a scan completes (or after loading a historical scan), use the export buttons to save results. Both buttons are disabled until there are results to export.

### Export CSV

Columns: `Absolute_Path`, `Hash_Type`, `Hash_Value`, `Line`, `Context`, `Source_SHA256`. The file is UTF-8 with a byte-order mark so Excel reads it correctly. Cells that start like a spreadsheet formula get a leading `'`.

```csv
Absolute_Path,Hash_Type,Hash_Value,Line,Context,Source_SHA256
C:\evidence\alerts.log,SHA1,da39a3ee5e6b4b0d3255bfef95601890afd80709,47,process exited with hash da39a3ee5e6b4b0d3255bfef95601890afd80709,6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
```

### Export JSON

A flat array of objects, one entry per hash found.

```json
[
  {
    "absolute_path": "C:\\evidence\\alerts.log",
    "hash_type": "SHA1",
    "hash_value": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "line": 47,
    "context": "process exited with hash da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "source_sha256": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
  }
]
```

| Field | Description |
|-------|-------------|
| `Absolute_Path` / `absolute_path` | Full filesystem path of the source file. |
| `Hash_Type` / `hash_type` | Algorithm: `MD5`, `SHA1`, `SHA256`, or `SHA512`. |
| `Hash_Value` / `hash_value` | Lowercase hexadecimal hash string. |
| `Line` / `line` | Line number where the hash first appears; empty or `null` for file digests. For CSV, JSON, XML and Office files it counts lines of the extracted text, not of the original file. |
| `Context` / `context` | Surrounding text; PDF and PPTX hits start with a page or slide number. |
| `Source_SHA256` / `source_sha256` | SHA-256 of the source file as stored on disk; empty or `null` for scans saved before it was recorded. |

### The manifest

Every export also writes `<export>.manifest.json` next to it. It records the tool and version, the export time with its UTC offset, the export's file name, format, row count and **SHA-256**, and the scan: folder, time, mode, hash types, counts and skipped files with reasons. To check an export has not changed, compare its SHA-256 with `export.sha256` in the manifest:

```powershell
(Get-FileHash .\results.csv -Algorithm SHA256).Hash.ToLower()
```

For a scan reloaded from history, `skipped` is `null` because the list was not stored (the scan log still names each file), and `mode` is inferred from the results.

---

## Command Line

`hashharvest-cli.exe` runs the same scan as the app. It does not save to scan history.

```
hashharvest-cli [flags] <folder>
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-mode` | `text` | `text` finds hashes in documents; `file` hashes every file. |
| `-types` | all four | Comma-separated list, such as `MD5,SHA256`. |
| `-format` | from `-o` | `csv` or `json`. Without it, `json` if `-o` ends in `.json`, else `csv`. |
| `-o` | standard output | Write results to this file, plus `<file>.manifest.json`. |
| `-force` | off | Let `-o` overwrite existing files. Without it, an existing export or manifest is never overwritten. |
| `-version` | | Print the version. |

Flags go before the folder. Skipped files are listed on standard error. No manifest is written when results go to standard output.

| Exit code | Meaning |
|-----------|---------|
| `0` | Everything was scanned. |
| `1` | The scan or writing its output failed, or it was cancelled with Ctrl+C. |
| `2` | The command was wrong, or `-o` names an existing file. |
| `3` | The scan finished, but something was skipped. |

```powershell
.\hashharvest-cli.exe -o results.csv C:\cases\evidence
.\hashharvest-cli.exe -mode file -types SHA256 -o digests.json C:\cases\evidence
```

---

## What Is Read and Skipped

### Formats

| Extension | What is searched |
|-----------|------------------|
| `.txt`, `.log`, `.md` | The text. UTF-8, UTF-16 (with a byte-order mark, or plainly UTF-16 without one), and otherwise Latin-1 for bytes that are not UTF-8. Any size. |
| `.csv` | All cells, as text. |
| `.json` | All keys and values. One JSON document, or JSON Lines. |
| `.xml` | All element text. |
| `.pdf` | Page text, with the page number in the context. Opens encrypted PDFs whose password is empty; skips ones that need a password. |
| `.docx` | The document body (not headers, footers or footnotes). |
| `.xlsx` | Text cells of every sheet (numeric cells never hold hashes). |
| `.pptx` | Slide text (not speaker notes or masters), with the slide number in the context. |

Extensions are matched without regard to case. Text mode reads only these; file mode hashes every file. A hash split across formatting runs in an Office file is rejoined. A hash is a run of exactly 32, 40, 64 or 128 hex digits, so a longer run never produces a shorter hash. The first occurrence of each hash in a file is reported.

UTF-16 without a byte-order mark that is mostly non-Latin text is not detected, and neither is UTF-32.

### Links

Links to folders (symbolic links and junctions) are never followed. A link to a file is followed only when its target is inside the scan folder. Every link that is not followed is reported as skipped.

### Limits

Memory use is bounded. Anything over a limit is reported, never silently dropped.

| What | Limit | Over the limit |
|------|-------|----------------|
| `.txt`, `.log`, `.md` | none | read in pieces |
| `.csv`, `.json`, `.xml` | 128 MiB | scanned as plain text, noted in the status bar and scan log |
| Office files | 256 MiB per decompressed part, 1 GiB per file | skipped |
| PDF | 512 MiB per file; 64 MiB per decoded stream; 1 GiB of decoded streams; 100,000 forms drawn per page | skipped |

---

## Troubleshooting

| Problem | Cause and fix |
|---------|---------------|
| The app exits at startup with a message about Wails build tags | It was built with plain `go build`. Use `wails build`, or add `-tags desktop,production`. |
| `database unavailable: …` or `Scan complete (database save failed: …)` | `hashharvest.db` can't be opened or written. Move the executable to a writable folder. Scans and exports still work. |
| `Select an input directory.` / `The input directory does not exist.` | Choose an existing folder before starting the scan. |
| `Run a scan first — there are no hashes to look up.` | Run a scan or load one from Scan History before opening VirusTotal. |
| `QuotaExceededError` in the VirusTotal results | The API rate limit was reached. Wait, or look up fewer hashes. |

| `... already exists; use -force to overwrite it` (command line) | `-o` names a file that exists. Choose another name or add `-force`. |

For skipped files, click **View list**, or **View Log** in Scan History. Each log line, including the `WARNING` line for each skipped file, carries the local time and UTC offset. The log file is listed under [Files](#files).
