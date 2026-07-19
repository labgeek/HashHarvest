"""Qt-free scanning core — the public entry point for extraction.

``Scanner`` wraps the deterministic extractors (:class:`hashharvest.extractor.HashHarvest`
for text mode, :func:`hashharvest.extractor.hash_files` for file-digest mode) behind an
event stream so the GUI, a future CLI, and tests all drive a scan identically. It imports
no Qt, satisfying the Phase 0 exit criterion ``from hashharvest.core import Scanner``.

Multithreading and cancellation are deliberately absent here — they belong to the Phase 1
engine. This class keeps today's single-threaded behavior, just decoupled from Qt.
"""

import logging

from hashharvest.extractor import HashHarvest, hash_files
from hashharvest.core.events import Finding, FileSkipped, ScanCompleted, ScanProgress
from hashharvest.core.logging_setup import capture_logs

log = logging.getLogger(__name__)


class ScanResult:
    """Outcome of a scan: the results mapping, read errors, and the captured log."""

    def __init__(self, results, errors, log_text=""):
        self.results = results
        self.errors = errors
        self.log = log_text

    @property
    def files_scanned(self):
        return len(self.results) + len(self.errors)

    @property
    def hashes_found(self):
        return sum(len(hashes) for hashes in self.results.values())

    @property
    def skipped_files(self):
        return len(self.errors)


class Scanner:
    """Extract hashes from a directory, emitting events as it goes.

    Args:
        hash_types: Optional set of algorithm names (e.g. ``{"MD5", "SHA256"}``);
            None means all.
        mode: ``"text"`` to find hash-shaped strings in document text, or ``"file"``
            to compute each file's own digest.
    """

    def __init__(self, hash_types=None, mode="text"):
        self.hash_types = hash_types
        self.mode = mode

    def scan(self, directory, on_event=None):
        """Scan ``directory`` and return a :class:`ScanResult`.

        Args:
            directory: Directory to scan.
            on_event: Optional callable receiving :mod:`hashharvest.core.events` objects.

        Returns:
            A :class:`ScanResult`.
        """
        emit = on_event if on_event is not None else (lambda event: None)

        def progress_cb(percent):
            emit(ScanProgress(percent))

        def status_cb(message):
            emit(FileSkipped(message))

        def result_cb(file_path, file_type, hash_type, hash_value, line_no, context):
            emit(Finding(file_path, file_type, hash_type, hash_value, line_no, context or ""))

        with capture_logs() as buffer:
            log.info(
                "Scan started: dir=%s mode=%s types=%s",
                directory, self.mode,
                ",".join(sorted(self.hash_types)) if self.hash_types else "all",
            )
            if self.mode == "file":
                results, error_list = hash_files(
                    directory, progress_cb, status_cb, result_cb, hash_types=self.hash_types
                )
            else:
                extractor = HashHarvest(directory)
                results = extractor.extract(
                    progress_cb, status_cb, result_cb, hash_types=self.hash_types
                )
                error_list = extractor.errors
            result = ScanResult(results, error_list, "")
            log.info(
                "Scan complete: files=%d hashes=%d skipped=%d",
                result.files_scanned, result.hashes_found, result.skipped_files,
            )
        result.log = buffer.getvalue()
        emit(ScanCompleted(result.files_scanned, result.hashes_found, result.skipped_files))
        return result
