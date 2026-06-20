# HashHarvest — Usage Guide

HashHarvest is a desktop GUI tool for extracting cryptographic hashes (MD5, SHA1, SHA256, SHA512) from files. It is designed for incident response, forensics, and threat intelligence workflows.

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
python -m hashharvest.main
```

> Run it as a module with `-m` from the project root. Running the file directly (`python hashharvest/main.py`) will fail, because the package uses absolute imports that require the project root on `sys.path`.

---

## Running from the Executable

Download the latest `HashHarvest.exe` from the [Releases](https://github.com/labgeek/HashExtractor/releases) page, or build it yourself:

### Build from Source

Requires PyInstaller:

```bash
pip install pyinstaller
pyinstaller HashHarvest.spec
```

The executable is written to `dist\HashHarvest.exe`.

### Launch

Double-click `HashHarvest.exe` — no Python installation required.

> **Note:** The `hashharvest.db` scan database and the `.env` config file (for VirusTotal) are stored in the same folder as the executable. Keep them together.

---

## Using the Tool

### 1. Select an Input Directory

Click **Select Input Folder** and choose the directory containing files you want to scan. HashHarvest walks the directory recursively.

**Supported file types:** PDF, TXT, LOG, MD, CSV, JSON, XML, DOCX, XLSX, PPTX

> Microsoft Office files (Word `.docx`, Excel `.xlsx`, PowerPoint `.pptx`) are parsed directly from their OpenXML contents — no Office install or extra libraries required. Text split across runs is reassembled, so a hash broken into pieces by the authoring tool is still detected. Word reads the document body, Excel reads string cells across all worksheets, and PowerPoint reads slide text.

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

Every column is resizable — drag a column header's border to widen it. If a source path is too long to fit, it is shortened in the middle (keeping the drive and filename visible); hover over the cell to see the full path in a tooltip.

### 5. Clear and Re-scan

Click **Clear Form** to reset all fields and results before starting a new scan.

---

## VirusTotal Integration

HashHarvest supports on-demand VirusTotal lookups for extracted hashes.

### Setup

Create a `.env` file in the project root (or the same folder as `HashHarvest.exe`) with your VT API key:

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

Results are cached locally in `hashharvest.db`. Re-looking up the same hash returns the cached result instantly without consuming an API call. Use the **Refresh** button in the enrichment panel to force a fresh lookup.

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
