# TODO

Actionable backlog for upcoming HashExtractor releases. Broader product ideas live in
[FEATURE_ROADMAP.md](FEATURE_ROADMAP.md).

## Next Release

- [ ] Add a `Cancel Scan` button that stops the worker cleanly between files.
- [ ] Show file-count progress, such as `Processing 12 of 100`.
- [ ] Add a skipped-files table with PDF path and failure reason.
- [ ] Add selectable output mode:
  - append to existing `hashOutput.txt`
  - overwrite existing `hashOutput.txt`
  - append without writing duplicate header rows
- [ ] Add a button to open the output folder after a scan.
- [ ] Rename stale MD5-oriented symbols, comments, and docs to HashExtractor naming.

## Backend Improvements

- [ ] Track page number for each hash match.
- [ ] Capture a short text snippet around each match.
- [ ] Count duplicate appearances per PDF/hash pair.
- [ ] Continue scanning remaining pages if one PDF page fails.
- [ ] Detect encrypted PDFs and report them separately.
- [ ] Detect image-only PDFs that contain no extractable text.
- [ ] Add configurable hash type selection in the extraction layer.
- [ ] Add structured result objects instead of returning raw tuple sets.
- [ ] Add an option to export JSON in addition to CSV.
- [ ] Add deterministic output ordering by PDF path, hash type, page, and value.

## Frontend Improvements

- [ ] Add search/filter controls for the results table.
- [ ] Add copy actions:
  - copy selected row
  - copy selected hash
  - copy all results
- [ ] Add drag-and-drop support for PDF folders.
- [ ] Allow selecting individual PDF files in addition to folders.
- [ ] Remember the last used input and output directories.
- [ ] Add a recent folders menu.
- [ ] Add a menu bar with File, View, Tools, and Help menus.
- [ ] Add an About dialog with version, author, license, and GitHub URL.
- [ ] Add an application icon.
- [ ] Add sortable columns for file, hash type, hash value, and page number.

## Testing and Quality

- [ ] Add automated tests for `extractor.py`.
- [ ] Add fixtures for known MD5, SHA1, SHA256, and SHA512 values.
- [ ] Add tests for recursive PDF discovery.
- [ ] Add tests for duplicate hash collapsing and duplicate counts.
- [ ] Add tests for skipped PDF tracking.
- [ ] Add tests for CSV output modes.
- [ ] Add linting or formatting checks.
- [ ] Add GitHub Actions CI for syntax checks and tests.

## Packaging and Release

- [ ] Add a repeatable release build script for PyInstaller.
- [ ] Decide whether `HashExtractor.spec` should be tracked as release configuration.
- [ ] Add version metadata to the Windows executable.
- [ ] Add a GitHub release checklist.
- [ ] Include release notes guidance for each version.
- [ ] Add a release download section to `README.md`.

## Documentation

- [ ] Add updated screenshots of the current GUI.
- [ ] Add build-from-source instructions.
- [ ] Add troubleshooting notes for PyInstaller and missing dependencies.
- [ ] Document output modes and append behavior.
- [ ] Document current limitations for scanned/image-only PDFs.
