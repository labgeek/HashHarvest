import csv
import hashlib
import json
import os
import re

from hashharvest.readers import read_file_chunks, SUPPORTED_EXTENSIONS


def csv_safe(value):
    """Neutralize spreadsheet formula injection (CWE-1236) in a CSV field.

    Excel/LibreOffice treat cells starting with = + - @ (or tab/CR) as formulas.
    Scanned-file content and filenames are untrusted, so prefix a single quote.
    """
    value = str(value)
    if value.startswith(('=', '+', '-', '@', '\t', '\r')):
        return "'" + value
    return value


# Constructors for the file-digest mode, keyed by the same names the GUI uses.
_HASHLIB_ALGOS = {
    'MD5': hashlib.md5,
    'SHA1': hashlib.sha1,
    'SHA256': hashlib.sha256,
    'SHA512': hashlib.sha512,
}


def hash_files(directory, progress_callback=None, status_callback=None,
               result_callback=None, hash_types=None):
    """Digest every file under ``directory`` with the selected algorithms.

    Unlike :meth:`HashHarvest.extract`, this walks *all* files (not just
    supported document types) and computes each file's own hash rather than
    scanning its text for hash-shaped strings.

    Args:
        progress_callback: Optional callable receiving an integer percentage.
        status_callback: Optional callable receiving skipped-file messages.
        result_callback: Optional callable receiving
            ``(file_path, file_type, hash_type, hash_value, line_no, context)``.
        hash_types: Optional set of algorithm names (e.g. ``{'MD5', 'SHA256'}``).
            Defaults to all algorithms when ``None``.

    Returns:
        A ``(results, errors)`` tuple. ``results`` maps each file path to a set of
        ``(hash_type, hash_value, None, "file digest")`` tuples — the same shape
        :meth:`HashHarvest.extract` returns, with a null line number. ``errors`` is
        a list of ``(path, message)`` tuples for files that could not be read.
    """
    algos = [
        (name, ctor) for name, ctor in _HASHLIB_ALGOS.items()
        if hash_types is None or name in hash_types
    ]
    paths = sorted(
        os.path.join(root, filename)
        for root, _, files in os.walk(directory)
        for filename in files
    )
    total = len(paths)
    results = {}
    errors = []

    for count, path in enumerate(paths, start=1):
        try:
            digests = {name: ctor() for name, ctor in algos}
            with open(path, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 16), b""):
                    for digest in digests.values():
                        digest.update(block)
        except Exception as error:
            errors.append((path, str(error)))
            if status_callback is not None:
                status_callback("Skipped %s: %s" % (path, error))
        else:
            results[path] = {
                (name, digest.hexdigest(), None, "file digest")
                for name, digest in digests.items()
            }
            if result_callback is not None:
                file_type = os.path.splitext(path)[1].lstrip('.').upper() or "FILE"
                for hash_type, hash_value, line_no, context in sorted(results[path]):
                    result_callback(path, file_type, hash_type, hash_value, line_no, context)

        if progress_callback is not None and total > 0:
            progress_callback(int(count * 100 / total))

    return results, errors


class HashHarvest:
    """Extract MD5, SHA1, SHA256, and SHA512 hashes from supported files."""

    # Ordered largest-first so exact-length negative lookaround prevents overlap.
    HASH_PATTERNS = {
        'SHA512': r'(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])',
        'SHA256': r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])',
        'SHA1':   r'(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])',
        'MD5':    r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])',
    }

    def __init__(self, directory):
        """Create an extractor for the given input directory."""
        self.directory = directory
        self.results = {}
        self.errors = []

    def dir_exists(self):
        """Return True when the configured input directory exists."""
        return os.path.isdir(self.directory)

    def read_dir(self):
        """Return a sorted list of supported file paths found below the input directory."""
        paths = []
        for root, _, files in os.walk(self.directory):
            for filename in files:
                if os.path.splitext(filename)[1].lower() in SUPPORTED_EXTENSIONS:
                    paths.append(os.path.join(root, filename))
        return sorted(paths)

    def extract(self, progress_callback=None, status_callback=None, result_callback=None, hash_types=None):
        """Scan supported files, emit optional callbacks, and return results.

        Args:
            progress_callback: Optional callable receiving an integer percentage.
            status_callback: Optional callable receiving skipped-file messages.
            result_callback: Optional callable receiving
                ``(file_path, file_type, hash_type, hash_value, line_no, context)``.
            hash_types: Optional set of algorithm names to scan for (e.g. ``{'MD5', 'SHA256'}``).
                        Defaults to all supported algorithms when ``None``.

        Returns:
            A dictionary mapping file paths to sets of
            ``(hash_type, hash_value, line_no, context)`` tuples. Only the first
            occurrence of each (hash_type, hash_value) pair per file is kept.
        """
        self.results = {}
        self.errors = []
        patterns = {
            k: v for k, v in self.HASH_PATTERNS.items()
            if hash_types is None or k in hash_types
        }
        paths = self.read_dir()
        total = len(paths)

        for count, path in enumerate(paths, start=1):
            try:
                chunks = read_file_chunks(path)
                found = {}  # (hash_type, hash_value) -> (line_no, context)
                for chunk_text, location in chunks:
                    for hash_type, pattern in patterns.items():
                        for match in re.finditer(pattern, chunk_text):
                            key = (hash_type, match.group().lower())
                            if key not in found:
                                line_no = chunk_text[:match.start()].count('\n') + 1
                                ctx_start = max(0, match.start() - 60)
                                ctx_end = min(len(chunk_text), match.end() + 60)
                                ctx = chunk_text[ctx_start:ctx_end].replace('\n', ' ').strip()
                                if location:
                                    ctx = "[%s] %s" % (location, ctx)
                                found[key] = (line_no, ctx)
                self.results[path] = {
                    (ht, hv, ln, ctx) for (ht, hv), (ln, ctx) in found.items()
                }
            except Exception as error:
                self.errors.append((path, str(error)))
                if status_callback is not None:
                    status_callback("Skipped %s: %s" % (path, error))
            else:
                if result_callback is not None:
                    file_type = os.path.splitext(path)[1].lstrip('.').upper()
                    for hash_type, hash_value, line_no, context in sorted(self.results[path]):
                        result_callback(path, file_type, hash_type, hash_value, line_no, context)

            if progress_callback is not None and total > 0:
                progress_callback(int(count * 100 / total))

        return self.results

    def export_csv(self, path):
        """Write results to a CSV file at the given path."""
        with open(path, mode='w', newline='') as f:
            writer = csv.writer(f, lineterminator='\n')
            writer.writerow(['Absolute_Path', 'Hash_Type', 'Hash_Value', 'Line', 'Context'])
            for file_path, hashes in sorted(self.results.items()):
                for hash_type, hash_value, line_no, context in sorted(hashes):
                    writer.writerow([csv_safe(file_path), hash_type, hash_value,
                                     line_no, csv_safe(context)])

    def export_json(self, path):
        """Write results to a JSON file at the given path."""
        rows = []
        for file_path, hashes in sorted(self.results.items()):
            for hash_type, hash_value, line_no, context in sorted(hashes):
                rows.append({
                    "absolute_path": file_path,
                    "hash_type": hash_type,
                    "hash_value": hash_value,
                    "line": line_no,
                    "context": context,
                })
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(rows, f, indent=2)
