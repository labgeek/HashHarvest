"""Self-check for file-digest mode. Run: python test_hash_files.py"""
import hashlib
import os
import tempfile
import threading

import pytest

from hashharvest.extractor import HashHarvest, hash_files


def test_digest_matches_hashlib():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "a.bin")
    with open(path, "wb") as fh:
        fh.write(b"hello world")

    results, errors = hash_files(d, hash_types={"SHA256", "MD5"})
    assert not errors, errors
    got = {ht: hv for ht, hv, ln, ctx in results[path]}
    assert got["SHA256"] == hashlib.sha256(b"hello world").hexdigest()
    assert got["MD5"] == hashlib.md5(b"hello world").hexdigest()
    # Shape must match extract(): line_no None, fixed context.
    assert all(ln is None and ctx == "file digest"
               for _, _, ln, ctx in results[path])


def test_walks_all_file_types():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "no_extension"), "wb").write(b"x")
    open(os.path.join(d, "binary.exe"), "wb").write(b"y")
    results, errors = hash_files(d, hash_types={"MD5"})
    assert not errors
    assert len(results) == 2  # unsupported/extensionless files are still hashed


def _run_with_timeout(func, timeout=10):
    """Run ``func`` in a daemon thread; fail (instead of hanging CI) if it blocks."""
    outcome = {}
    thread = threading.Thread(target=lambda: outcome.setdefault("value", func()), daemon=True)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), "scan blocked on a special file"
    return outcome["value"]


needs_fifo = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo unavailable")


@needs_fifo
def test_file_mode_skips_fifo(tmp_path):
    os.mkfifo(str(tmp_path / "pipe"))
    (tmp_path / "real.bin").write_bytes(b"x")

    results, errors = _run_with_timeout(lambda: hash_files(str(tmp_path), hash_types={"MD5"}))

    assert list(results) == [str(tmp_path / "real.bin")]
    assert errors == [(str(tmp_path / "pipe"), "not a regular file")]


@needs_fifo
def test_text_mode_skips_fifo_with_supported_extension(tmp_path):
    os.mkfifo(str(tmp_path / "pipe.txt"))
    (tmp_path / "notes.txt").write_text("5d41402abc4b2a76b9719d911017c592", encoding="utf-8")
    extractor = HashHarvest(str(tmp_path))

    results = _run_with_timeout(lambda: extractor.extract(hash_types={"MD5"}))

    assert list(results) == [str(tmp_path / "notes.txt")]
    assert extractor.errors == [(str(tmp_path / "pipe.txt"), "not a regular file")]


if __name__ == "__main__":
    test_digest_matches_hashlib()
    test_walks_all_file_types()
    print("ok")
