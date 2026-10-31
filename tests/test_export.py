"""CSV export must be UTF-8 (with BOM for Excel) regardless of the OS locale.

On Windows the locale default is cp1252, so a path or context containing a
character outside it (e.g. CJK) used to raise UnicodeEncodeError mid-export.
"""

import codecs
import csv

from hashharvest.extractor import HashHarvest

NON_LATIN_PATH = "C:/cases/\u62a5\u544a.txt"  # "报告" is not encodable in cp1252
CONTEXT = "hash \u00e9\u4e2d context"


def _read_csv(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    assert raw.startswith(codecs.BOM_UTF8)
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.reader(fh))


def test_extractor_export_csv_is_utf8_with_bom(tmp_path):
    extractor = HashHarvest(str(tmp_path))
    extractor.results = {NON_LATIN_PATH: {("MD5", "a" * 32, 3, CONTEXT)}}
    out = str(tmp_path / "out.csv")

    extractor.export_csv(out)

    rows = _read_csv(out)
    assert rows[0] == ["Absolute_Path", "Hash_Type", "Hash_Value", "Line", "Context"]
    assert rows[1] == [NON_LATIN_PATH, "MD5", "a" * 32, "3", CONTEXT]
