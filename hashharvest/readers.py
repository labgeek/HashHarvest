import csv
import json
import os
import xml.etree.ElementTree as ET
import zipfile

import pypdf


def read_pdf(path):
    """Extract text from a PDF file, concatenating all pages.

    Args:
        path: Path to the PDF file.

    Returns:
        A string containing the extracted text from every page, separated by newlines.
    """
    content = ""
    with open(path, "rb") as fh:
        reader = pypdf.PdfReader(fh)
        for page in reader.pages:
            content += (page.extract_text() or "") + "\n"
    return content


def read_text(path):
    """Read a plain-text file, falling back to latin-1 if UTF-8 decoding fails.

    Args:
        path: Path to the text file.

    Returns:
        The full contents of the file as a string.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError:
        with open(path, "r", encoding="latin-1") as fh:
            return fh.read()


def read_csv(path):
    """Read a CSV file and return all cell values as space-joined rows.

    Args:
        path: Path to the CSV file.

    Returns:
        A string where each row's cells are joined by spaces and rows are separated by newlines.
    """
    lines = []
    with open(path, "r", encoding="utf-8", newline="", errors="replace") as fh:
        for row in csv.reader(fh):
            lines.append(" ".join(row))
    return "\n".join(lines)


def _collect_json_values(obj):
    """Recursively yield all keys and scalar values from a JSON-decoded object.

    Args:
        obj: A dict, list, or scalar value produced by json.load.

    Yields:
        String representations of every key and non-null leaf value in the structure.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key)
            yield from _collect_json_values(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _collect_json_values(item)
    elif obj is not None:
        yield str(obj)


def read_json(path):
    """Extract all keys and values from a JSON file as a flat newline-delimited string.

    Args:
        path: Path to the JSON file.

    Returns:
        A string with every key and scalar value on its own line.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return "\n".join(_collect_json_values(data))


def _collect_xml_text(element):
    """Recursively collect all text content from an XML element and its descendants.

    Captures both element text and tail text (the text that follows a closing tag
    but precedes the next sibling).

    Args:
        element: An xml.etree.ElementTree.Element node.

    Returns:
        A list of non-empty text strings in document order.
    """
    parts = []
    if element.text:
        parts.append(element.text)
    for child in element:
        parts.extend(_collect_xml_text(child))
        if child.tail:
            parts.append(child.tail)
    return parts


def read_xml(path):
    """Extract all text content from an XML file.

    Args:
        path: Path to the XML file.

    Returns:
        A string containing all text nodes joined by newlines.
    """
    tree = ET.parse(path)
    root = tree.getroot()
    return "\n".join(_collect_xml_text(root))


_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_S_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_A_NS = "{http://schemas.openxmlformats.org/drawingml/2006/main}"


def read_docx(path):
    """Extract paragraph text from a .docx file.

    Parses the OOXML word/document.xml entry inside the ZIP archive and
    reassembles each ``<w:p>`` paragraph from its ``<w:t>`` text runs.

    Args:
        path: Path to the .docx file.

    Returns:
        A string with one paragraph per line.
    """
    with zipfile.ZipFile(path) as archive:
        with archive.open("word/document.xml") as fh:
            tree = ET.parse(fh)
    root = tree.getroot()
    lines = []
    for paragraph in root.iter(_W_NS + "p"):
        text = "".join(node.text or "" for node in paragraph.iter(_W_NS + "t"))
        lines.append(text)
    return "\n".join(lines)


def _collect_ooxml_text(root, ns, container):
    """Collect text from OOXML container elements by reassembling their ``<t>`` runs.

    Args:
        root: The root Element of an already-parsed OOXML XML tree.
        ns: The namespace prefix string (e.g. ``_S_NS`` for SpreadsheetML).
        container: The local element name whose ``<t>`` children form one text unit
            (e.g. ``"si"`` for shared strings, ``"is"`` for inline strings, ``"p"`` for
            DrawingML paragraphs).

    Returns:
        A list of strings, one per matching container element.
    """
    return [
        "".join(node.text or "" for node in item.iter(ns + "t"))
        for item in root.iter(ns + container)
    ]


def read_xlsx(path):
    """Extract text from an .xlsx file, covering both shared and inline string storage.

    Excel stores text cells in either the shared-string table (``xl/sharedStrings.xml``,
    ``<si>`` elements) or inline in each worksheet (``<is>`` elements, used by openpyxl
    and similar tools). Both sources are read so no string content is missed.

    Args:
        path: Path to the .xlsx file.

    Returns:
        A string with one text entry per line, shared strings first then per-worksheet
        inline strings in worksheet sort order.
    """
    lines = []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if "xl/sharedStrings.xml" in names:
            with archive.open("xl/sharedStrings.xml") as fh:
                root = ET.parse(fh).getroot()
            lines.extend(_collect_ooxml_text(root, _S_NS, "si"))
        worksheets = sorted(
            name for name in names
            if name.startswith("xl/worksheets/") and name.endswith(".xml")
        )
        for name in worksheets:
            with archive.open(name) as fh:
                root = ET.parse(fh).getroot()
            lines.extend(_collect_ooxml_text(root, _S_NS, "is"))
    return "\n".join(lines)


def read_pptx(path):
    """Extract paragraph text from all slides in a .pptx file.

    Iterates over slide XML files in slide-number order and reassembles each
    DrawingML ``<a:p>`` paragraph from its ``<a:t>`` text runs.

    Args:
        path: Path to the .pptx file.

    Returns:
        A string with one paragraph per line across all slides.
    """
    lines = []
    with zipfile.ZipFile(path) as archive:
        slides = sorted(
            name for name in archive.namelist()
            if name.startswith("ppt/slides/slide") and name.endswith(".xml")
        )
        for name in slides:
            with archive.open(name) as fh:
                tree = ET.parse(fh)
            for paragraph in tree.getroot().iter(_A_NS + "p"):
                text = "".join(node.text or "" for node in paragraph.iter(_A_NS + "t"))
                lines.append(text)
    return "\n".join(lines)


_DISPATCH = {
    ".pdf":  read_pdf,
    ".txt":  read_text,
    ".log":  read_text,
    ".md":   read_text,
    ".csv":  read_csv,
    ".json": read_json,
    ".xml":  read_xml,
    ".docx": read_docx,
    ".xlsx": read_xlsx,
    ".pptx": read_pptx,
}

SUPPORTED_EXTENSIONS = set(_DISPATCH.keys())


def read_file(path):
    """Dispatch to the appropriate reader based on the file's extension.

    Args:
        path: Path to the file to read.

    Returns:
        The extracted text content as a string.

    Raises:
        ValueError: If the file extension is not in ``SUPPORTED_EXTENSIONS``.
    """
    ext = os.path.splitext(path)[1].lower()
    reader = _DISPATCH.get(ext)
    if reader is None:
        raise ValueError("Unsupported file type: %s" % ext)
    return reader(path)
