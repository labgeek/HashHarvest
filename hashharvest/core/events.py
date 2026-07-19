"""Plain-Python events emitted by :class:`hashharvest.core.scanner.Scanner`.

These carry no Qt types, so the GUI, a CLI, or a test can all consume a scan the
same way. The GUI marshals them onto Qt signals; the CLI prints them.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanProgress:
    """Percentage of files processed so far (0-100)."""
    percent: int


@dataclass
class Finding:
    """One extracted hash. ``line`` is None for file-digest mode."""
    file_path: str
    file_type: str
    hash_type: str
    hash_value: str
    line: Optional[int]
    context: str


@dataclass
class FileSkipped:
    """A file that could not be read or parsed during the scan."""
    message: str


@dataclass
class ScanCompleted:
    """Terminal event with the scan's summary counts."""
    files_scanned: int
    hashes_found: int
    skipped_files: int
