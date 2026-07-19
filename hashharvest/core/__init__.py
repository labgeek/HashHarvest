"""Qt-free scanning core: the embeddable heart of HashHarvest.

Importing this package must never pull in PyQt, so a CLI, the Python API, or a test
runner can use :class:`Scanner` headlessly.
"""

from hashharvest.core.events import (
    Finding,
    FileSkipped,
    ScanCompleted,
    ScanProgress,
)
from hashharvest.core.logging_setup import capture_logs, setup_logging
from hashharvest.core.scanner import Scanner, ScanResult

__all__ = [
    "Scanner",
    "ScanResult",
    "ScanProgress",
    "Finding",
    "FileSkipped",
    "ScanCompleted",
    "setup_logging",
    "capture_logs",
]
