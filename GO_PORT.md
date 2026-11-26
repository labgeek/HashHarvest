# HashHarvest — development notes

HashHarvest is a Go application with a [Wails v2](https://wails.io) desktop UI.

## Layout

| Path | Contents |
|---|---|
| `main.go`, `app.go` | Wails entry point and the window's backend: startup, scan, cancel |
| `history.go`, `watchlist.go`, `virustotal.go`, `export.go`, `manifest.go` | The backend of each dialog and of export |
| `cmd/hashharvest-cli` | The command-line scanner |
| `internal/version` | The release version (keep `wails.json` in step) |
| `internal/manifest` | The manifest written next to each export |
| `frontend/dist/` | The UI: plain HTML/CSS/JS, embedded into the exe, no npm build |
| `internal/scanner` | GUI-free scan entry point and event stream |
| `internal/extractor` | Hash detection, file digests, CSV/JSON export |
| `internal/readers` | Document readers, including a standard-library PDF text extractor |
| `internal/db` | SQLite scan history and watchlists, with schema migrations |
| `internal/keystore` | VirusTotal key storage: registry and Windows Credential Manager |
| `internal/vt` | VirusTotal v3 lookups over `net/http` |
| `internal/applog` | Rotating log file and per-scan log capture |
| `packaging/wails/` | Wails build assets (icon, manifest, version resource) |
| `scripts/check.ps1`, `scripts/smoke-gui.ps1` | Local checks and the GUI smoke test |
| `scripts/package-release.ps1` | Collects release files and `SHA256SUMS.txt` |
| `.github/workflows` | CI, CodeQL and the release workflow |
| `samples/` | Synthetic evidence and watchlist, checked by a scanner test |
| `tests/corpus` | Sample files for the scanner test and the GUI smoke test |

Production dependencies: `github.com/wailsapp/wails/v2` (the UI) and `modernc.org/sqlite` (pure-Go SQLite,
no cgo). Everything else uses the standard library. That includes PDF parsing, the Windows registry and
Credential Manager calls (`syscall`), and the VirusTotal client.

## Prerequisites

- **Go 1.26 or newer.** `go.mod` declares 1.26, the minimum `modernc.org/sqlite` requires.
- **Wails CLI v2.17.1**, the same version as in `go.mod`:
  `go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1`
- **Microsoft Edge WebView2 Runtime.** It ships with Windows 10 (21H2+) and 11.
- *Optional, for `go test -race`:* a 64-bit MinGW gcc (`x86_64-w64-mingw32`) on `PATH`, with `CGO_ENABLED=1`.
  `winget install BrechtSanders.WinLibs.POSIX.UCRT` provides one; `scripts\check.ps1` finds it even when
  an older 32-bit MinGW comes first on `PATH`.

No C compiler is needed to build or to run the normal test suite.

## Commands

```powershell
# Build the app  ->  packaging\wails\bin\HashHarvest.exe
wails build -trimpath

# Run it from source with live reload
wails dev

# All local checks (gofmt, vet, tests + coverage, race if possible, cross-compiles, wails build)
powershell -ExecutionPolicy Bypass -File scripts\check.ps1

# Individual checks
gofmt -l .
go vet ./...
go test ./...
go test "-coverprofile=coverage.out" ./... ; go tool cover "-func=coverage.out"
$env:CGO_ENABLED=1; go test -race ./...          # needs a 64-bit gcc

# End-to-end smoke test of the built exe (needs a desktop session)
powershell -ExecutionPolicy Bypass -File scripts\smoke-gui.ps1
```

In Windows PowerShell 5.1, quote flags that contain a `.` (`"-coverprofile=coverage.out"`). Otherwise
PowerShell splits the argument.

## Runtime files

| File | Location | Notes |
|---|---|---|
| `hashharvest.db` | next to `HashHarvest.exe` | Schema `user_version` 3. Older files are upgraded when opened; migrations are in `internal/db`. |
| `.env` | next to `HashHarvest.exe` | `KEY=VALUE` lines; real environment variables win. Typically holds `VT_API_KEY`. |
| logs | `%USERPROFILE%\.hashharvest\logs\hashharvest.log` | Rotates at 1 MB, keeps 5 backups. |
| VirusTotal key (plaintext) | `HKCU\Software\HashHarvest\HashHarvest\vt_api_key` |  |
| VirusTotal key (encrypted) | Credential Manager, target `HashHarvest`, user `vt_api_key` |  |

The key is read from `VT_API_KEY`, then the keychain, then the registry.

## Releases

1. Set the version in `internal/version/version.go` and `wails.json` (a test checks they match), and
   update `CHANGELOG.md`.
2. Push a tag `v<version>` on a commit on `main`. The release workflow runs all checks, refuses a tag
   that does not match the code, and creates a **draft** release with `HashHarvest.exe`,
   `hashharvest-cli.exe` and `SHA256SUMS.txt`.
3. Review the draft and publish it.

Running the release workflow by hand builds the same files as a workflow artifact without creating a
release. The programs are not code-signed.

## Tests

| Suite | Command | Needs |
|---|---|---|
| Unit and integration tests (all packages) | `go test ./...` | nothing |
| Real registry / Credential Manager | `$env:HASHHARVEST_OS_STORE_TEST=1; go test ./internal/keystore/` | Windows; writes and removes test-only entries |
| FIFO handling (special files are skipped, not opened) | `go test ./internal/extractor/` | Linux/macOS |
| PDF parser fuzzing | `go test -fuzz=FuzzPDF ./internal/readers/` | nothing |
| GUI smoke test of the built exe | `scripts\smoke-gui.ps1` | a desktop session and Go |

Default tests never use the network or real credentials. VirusTotal is exercised against local
`httptest` servers.

## Platform support

| Target | Status |
|---|---|
| Windows 10/11 amd64 | Supported. Built, unit-, integration- and GUI-smoke-tested. |
| Windows arm64 / 386 | Cross-compiles; not run. |
| Linux, macOS | The `internal/...` core and the command line cross-compile. The GUI is not built or supported there; key storage falls back to a plaintext file with no keychain option. |

## PDF support

`internal/readers/pdf.go` is a standard-library-only text extractor. It opens encrypted PDFs (RC4,
AES-128, AES-256) whose user or owner password is empty, and skips ones that need a password. Line
numbers and context text inside PDFs come from text-layout heuristics. Decoded streams and the number of
forms drawn per page are capped (see the limits in [USAGE.md](USAGE.md#limits)). It has not been
compared against another PDF library on a corpus of real files.
