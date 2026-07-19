"""Self-check for file-digest mode. Run: python test_hash_files.py"""
import hashlib
import os
import tempfile

from hashharvest.extractor import hash_files


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


if __name__ == "__main__":
    test_digest_matches_hashlib()
    test_walks_all_file_types()
    print("ok")
