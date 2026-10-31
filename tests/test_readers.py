"""Tests for the document readers in hashharvest.readers."""

import zipfile

from hashharvest.readers import read_file_chunks, read_pptx

_A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"


def _write_pptx(path, slide_count):
    """Build a minimal .pptx whose slide N contains the text ``SLIDEN``."""
    with zipfile.ZipFile(path, "w") as archive:
        for number in range(1, slide_count + 1):
            archive.writestr(
                "ppt/slides/slide%d.xml" % number,
                '<p:sld xmlns:p="urn:p" xmlns:a="%s"><a:p><a:t>SLIDE%d</a:t></a:p></p:sld>'
                % (_A_NS, number),
            )
        # A relationship part under ppt/slides/ must not be read as a slide.
        archive.writestr("ppt/slides/_rels/slide1.xml.rels", "<Relationships/>")


def test_pptx_slides_ordered_and_labeled_numerically(tmp_path):
    # With 10+ slides a string sort yields slide1, slide10, slide11, slide2, ...
    path = str(tmp_path / "deck.pptx")
    _write_pptx(path, 11)

    chunks = read_file_chunks(path)

    assert [loc for _text, loc in chunks] == ["slide %d" % n for n in range(1, 12)]
    for text, loc in chunks:
        assert text == "SLIDE%s" % loc.split()[1]


def test_read_pptx_concatenates_in_slide_order(tmp_path):
    path = str(tmp_path / "deck.pptx")
    _write_pptx(path, 11)
    assert read_pptx(path).split("\n") == ["SLIDE%d" % n for n in range(1, 12)]
