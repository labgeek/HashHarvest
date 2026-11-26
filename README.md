# HashHarvest

Find every MD5, SHA1, SHA256 and SHA512 hash in a folder of evidence, or hash its files, and triage the results against your watchlists.

**[Download the latest release](https://github.com/labgeek/HashHarvest/releases/latest)** (Windows 10/11; the link works once v1.0.0 is published)

> **Demo:** _screenshot or short recording to come._
<!-- TODO: add a demo image or GIF of a scan of samples/evidence. -->

## What it does

- **Two scan modes:** find hashes written inside documents, or compute each file's own digest.
- **Reads** PDF, TXT, LOG, MD, CSV, JSON (including JSON Lines), XML, DOCX, XLSX and PPTX, including UTF-16 text.
- **Misses nothing silently:** every file or folder it can't read is listed with the reason, and kept in the scan log.
- **Triage:** watchlists highlight known-bad hashes, and VirusTotal lookup is optional.
- **Provenance:** each result carries its source file's SHA-256, and each export gets a manifest with the tool version, time and the export's own SHA-256.
- **History:** scans are saved locally and can be reloaded and re-exported.
- **Command line:** `hashharvest-cli` runs the same scan for scripts.

## Install

1. Download `HashHarvest.exe` (and, if you want it, `hashharvest-cli.exe`) and `SHA256SUMS.txt` from the [latest release](https://github.com/labgeek/HashHarvest/releases/latest).
2. Check the download. The output should match the line for that file in `SHA256SUMS.txt`:

   ```powershell
   (Get-FileHash .\HashHarvest.exe -Algorithm SHA256).Hash.ToLower()
   Get-Content .\SHA256SUMS.txt
   ```

3. Put it in a folder you can write to (it saves `hashharvest.db` beside itself) and run it. It needs the Microsoft Edge WebView2 Runtime, which Windows 10 21H2+ and Windows 11 include.

The programs are not code-signed, so Windows SmartScreen may warn you before the first run.

## Try it

The [samples](samples/) folder holds made-up evidence. Scan `samples/evidence` in the app, import `samples/watchlist.txt` into a new watchlist, and scan again to see the matches highlighted. One damaged file is there on purpose, so you can see how skipped files are reported.

## Command line

```powershell
hashharvest-cli.exe -o results.csv C:\cases\evidence
```

It exits `0` if everything was scanned and `3` if something was skipped. See [Command line](USAGE.md#command-line) for all flags and exit codes.

## Build from source

You need Go 1.26 or newer and the Wails CLI v2.17.1. No C compiler, Node.js or npm is needed.

```powershell
go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1
wails build -trimpath                      # packaging\wails\bin\HashHarvest.exe
go build -trimpath ./cmd/hashharvest-cli   # hashharvest-cli.exe
go test ./...
```

## Documentation

- [USAGE.md](USAGE.md): using the app and command line, what is read and skipped, limits, exports and troubleshooting.
- [GO_PORT.md](GO_PORT.md): code layout, development commands, tests and releases.
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE). Author: labgeek@gmail.com
