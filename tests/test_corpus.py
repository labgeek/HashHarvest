"""Golden-corpus integration test.

Scans tests/corpus/ with the Qt-free Scanner and asserts the extracted hashes match
tests/corpus/expected.json exactly. This is the regression net for the extraction
pipeline as new indicator types and file readers land in Phase 2.
"""

import json
import os

from hashharvest.core import Scanner

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "corpus")
# The manifest lives outside CORPUS_DIR so text mode does not scan it as evidence.
EXPECTED_FILE = os.path.join(os.path.dirname(__file__), "corpus_expected.json")


def _expected():
    with open(EXPECTED_FILE, encoding="utf-8") as fh:
        return {(row["file"], row["hash_type"], row["hash_value"]) for row in json.load(fh)}


def test_corpus_matches_expected():
    result = Scanner(mode="text").scan(CORPUS_DIR)
    actual = {
        (os.path.basename(path), hash_type, hash_value)
        for path, hashes in result.results.items()
        for (hash_type, hash_value, _line, _ctx) in hashes
    }
    assert actual == _expected()
    assert result.skipped_files == 0
