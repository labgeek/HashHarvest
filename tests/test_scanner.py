"""Unit tests for the Qt-free core Scanner, event stream, and log capture."""

import os
import subprocess
import sys

from hashharvest.core import Finding, ScanCompleted, ScanProgress, Scanner


def test_core_imports_without_qt():
    # The whole point of the core split: no Qt in the import graph. Checked in a
    # fresh interpreter, since sibling GUI tests import Qt into this process.
    # Put the repo root on the subprocess PYTHONPATH so this holds regardless of cwd.
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    code = (
        "import sys, hashharvest.core; "
        "assert 'PyQt6' not in sys.modules and 'PyQt5' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", code], check=True, env=env)


def _write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")


def test_text_mode_finds_hashes_and_emits_events(tmp_path):
    md5 = "5d41402abc4b2a76b9719d911017c592"
    sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    _write(tmp_path, "notes.txt", "md5 %s and sha256 %s" % (md5, sha256))

    events = []
    result = Scanner(mode="text").scan(str(tmp_path), events.append)

    values = {hv for hashes in result.results.values() for (_ht, hv, _l, _c) in hashes}
    assert values == {md5, sha256}
    assert any(isinstance(e, Finding) for e in events)
    assert any(isinstance(e, ScanProgress) for e in events)
    assert isinstance(events[-1], ScanCompleted)
    assert result.hashes_found == 2


def test_hash_types_filter(tmp_path):
    md5 = "5d41402abc4b2a76b9719d911017c592"
    sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    _write(tmp_path, "notes.txt", "%s %s" % (md5, sha256))

    result = Scanner(hash_types={"MD5"}, mode="text").scan(str(tmp_path))
    values = {hv for hashes in result.results.values() for (_ht, hv, _l, _c) in hashes}
    assert values == {md5}


def test_file_mode_digests_files(tmp_path):
    _write(tmp_path, "payload.bin", "hello")
    result = Scanner(hash_types={"SHA256"}, mode="file").scan(str(tmp_path))
    # SHA256 of "hello".
    digests = {hv for hashes in result.results.values() for (_ht, hv, _l, _c) in hashes}
    assert "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" in digests


def test_scan_log_is_captured(tmp_path):
    _write(tmp_path, "notes.txt", "no hashes here")
    result = Scanner(mode="text").scan(str(tmp_path))
    assert "Scan started" in result.log
    assert "Scan complete" in result.log
