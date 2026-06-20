import csv
import json
import os
import xml.etree.ElementTree as ET

import pypdf


SUPPORTED_EXTENSIONS = {".pdf", ".txt", ".log", ".md", ".csv", ".json", ".xml"}


def read_pdf(path):
    content = ""
    with open(path, "rb") as fh:
        reader = pypdf.PdfReader(fh)
        for page in reader.pages:
            content += (page.extract_text() or "") + "\n"
    return content


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError:
        with open(path, "r", encoding="latin-1") as fh:
            return fh.read()


def read_csv(path):
    lines = []
    with open(path, "r", encoding="utf-8", newline="", errors="replace") as fh:
        for row in csv.reader(fh):
            lines.append(" ".join(row))
    return "\n".join(lines)


def _collect_json_values(obj):
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
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return "\n".join(_collect_json_values(data))


def _collect_xml_text(element):
    parts = []
    if element.text:
        parts.append(element.text)
    for child in element:
        parts.extend(_collect_xml_text(child))
        if child.tail:
            parts.append(child.tail)
    return parts


def read_xml(path):
    tree = ET.parse(path)
    root = tree.getroot()
    return "\n".join(_collect_xml_text(root))


_DISPATCH = {
    ".pdf":  read_pdf,
    ".txt":  read_text,
    ".log":  read_text,
    ".md":   read_text,
    ".csv":  read_csv,
    ".json": read_json,
    ".xml":  read_xml,
}


def read_file(path):
    ext = os.path.splitext(path)[1].lower()
    reader = _DISPATCH.get(ext)
    if reader is None:
        raise ValueError("Unsupported file type: %s" % ext)
    return reader(path)
