# HashExtractor — Usage Guide

HashExtractor is a desktop GUI tool for extracting cryptographic hashes (MD5, SHA1, SHA256, SHA512) from files. It is designed for incident response, forensics, and threat intelligence workflows.

---

## Table of Contents

1. [Running from Source](#running-from-source)
2. [Running from the Executable](#running-from-the-executable)
3. [Using the Tool](#using-the-tool)
4. [VirusTotal Integration](#virustotal-integration)
5. [Exporting Results](#exporting-results)
6. [Scan History](#scan-history)

---

## Running from Source

### Prerequisites

- Python 3.9 or later
- pip

### Setup

```bash
git clone https://github.com/labgeek/HashExtractor.git
cd HashExtractor
pip install -r requirements.txt
```

### Launch

```bash
python -m hashextractor.main
```

Or equivalently:

```bash
python hashextractor/main.py
```

---

## Running from the Executable

Download the latest `HashExtractor.exe` from the [Releases](https://github.com/labgeek/HashExtractor/releases) page, or build it yourself:

### Build from Source

Requires PyInstaller:

```bash
pip install pyinstaller
pyinstaller HashExtractor.spec
```

The executable is written to `dist\HashExtractor.exe`.

### Launch

Double-click `HashExtractor.exe` — no Python installation required.

> **Note:** The `hashextractor.db` scan database and the `.env` config file (for VirusTotal) are stored in the same folder as the executable. Keep them together.

---

## Using the Tool

### 1. Select an Input Directory

Click **Select Input Folder** and choose the directory containing files you want to scan. HashExtractor walks the directory recursively.

**Supported file types:** PDF, TXT, LOG, MD, CSV, JSON, XML

### 2. Choose Hash Types

Check or uncheck **MD5**, **SHA1**, **SHA256**, and **SHA512** to control which algorithms to scan for. All four are selected by default.

### 3. Run the Scan

Click **Start Scan**. The progress bar updates as each file is processed. Files that cannot be read are skipped and counted under **Skipped Files**.

### 4. Review Results

The results table shows:

| Column | Description |
|--------|-------------|
| Source File | Absolute path to the file containing the hash |
| File Type | Extension of the source file (PDF, TXT, etc.) |
| Hash Type | Algorithm (MD5, SHA1, SHA256, SHA512) |
| Hash Value | The extracted hash string |

### 5. Clear and Re-scan

Click **Clear Form** to reset all fields and results before starting a new scan.

---

## VirusTotal Integration

HashExtractor supports on-demand VirusTotal lookups for extracted hashes.

### Setup

Create a `.env` file in the project root (or the same folder as `HashExtractor.exe`) with your VT API key:

```
VT_API_KEY=your_api_key_here
```

You can get a free API key at [virustotal.com](https://www.virustotal.com).

> If `VT_API_KEY` is missing or empty, the **Lookup on VirusTotal** menu item will appear disabled.

### Performing a Lookup

Right-click any row in the results table and select **Lookup on VirusTotal**. The lookup runs in the background and the row updates with a colored status badge:

| Badge | Meaning |
|-------|---------|
| Malicious (red) | One or more engines flagged this hash |
| Suspicious (yellow) | Flagged as suspicious |
| Clean (green) | Known to VT, zero detections |
| Not Found (gray) | Hash not in VT database |
| Error (orange) | API call failed |

An enrichment panel opens to the right of the table showing:

- Detection ratio (e.g., `14 / 72 engines`)
- Threat names from detecting engines
- File type and size
- First seen / Last seen dates
- Link to open the full report in your browser

> **SHA512 hashes** cannot be looked up — VirusTotal does not support 128-character hashes. The menu item is disabled for SHA512 rows.

### Rate Limits

The free VT tier allows 4 requests per minute. The on-demand model (one lookup per right-click) keeps usage within this limit under normal IR workflows.

### Cached Results

Results are cached locally in `hashextractor.db`. Re-looking up the same hash returns the cached result instantly without consuming an API call. Use the **Refresh** button in the enrichment panel to force a fresh lookup.

---

## Exporting Results

After a scan completes, the **Export CSV** and **Export JSON** buttons become active.

**CSV format:**

```
Absolute_Path,Hash_Type,Hash_Value
/path/to/file.pdf,SHA256,e3b0c44298fc1c149afb...
```

**JSON format:**

```json
[
  {
    "absolute_path": "/path/to/file.pdf",
    "hash_type": "SHA256",
    "hash_value": "e3b0c44298fc1c149afb..."
  }
]
```

---

## Scan History

Click **Scan History** to view previous scans stored in the local database. Filter by time range (Today, Last 7 days, Last 30 days, Last 90 days, All time). Select any past scan and click **Load Selected** to reload its results into the main table for review or export.
