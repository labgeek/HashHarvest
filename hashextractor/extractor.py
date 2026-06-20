import csv
import json
import os
import re

from hashextractor.readers import read_file, SUPPORTED_EXTENSIONS


class HashExtractor:
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
            result_callback: Optional callable receiving each ``file_path, file_type, hash_type, hash_value`` tuple.
            hash_types: Optional set of algorithm names to scan for (e.g. ``{'MD5', 'SHA256'}``).
                        Defaults to all supported algorithms when ``None``.

        Returns:
            A dictionary mapping file paths to sets of (hash_type, hash_value) tuples.
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
                content = read_file(path)
                found = set()
                for hash_type, pattern in patterns.items():
                    for value in re.findall(pattern, content):
                        found.add((hash_type, value.lower()))
                self.results[path] = found
            except Exception as error:
                self.errors.append((path, str(error)))
                if status_callback is not None:
                    status_callback("Skipped %s: %s" % (path, error))
            else:
                if result_callback is not None:
                    file_type = os.path.splitext(path)[1].lstrip('.').upper()
                    for hash_type, hash_value in sorted(self.results[path]):
                        result_callback(path, file_type, hash_type, hash_value)

            if progress_callback is not None and total > 0:
                progress_callback(int(count * 100 / total))

        return self.results

    def export_csv(self, path):
        """Write results to a CSV file at the given path."""
        with open(path, mode='w', newline='') as f:
            writer = csv.writer(f, lineterminator='\n')
            writer.writerow(['Absolute_Path', 'Hash_Type', 'Hash_Value'])
            for file_path, hashes in sorted(self.results.items()):
                for hash_type, hash_value in sorted(hashes):
                    writer.writerow([file_path, hash_type, hash_value])

    def export_json(self, path):
        """Write results to a JSON file at the given path."""
        rows = []
        for file_path, hashes in sorted(self.results.items()):
            for hash_type, hash_value in sorted(hashes):
                rows.append({"absolute_path": file_path, "hash_type": hash_type, "hash_value": hash_value})
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(rows, f, indent=2)
