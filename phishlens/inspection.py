"""Inert attachment inspection: magic-byte type identification.

Reads the first bytes of a payload to identify the real file type. Nothing
here executes, renders or decompresses the content.
"""

from __future__ import annotations

_MAGIC: list[tuple[bytes, str]] = [
    (b"MZ", "Windows executable (PE)"),
    (b"\x7fELF", "Linux executable (ELF)"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive or Office document"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Legacy Office document (OLE)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"%!PS", "PostScript"),
]

_TEXT_MARKERS = (b"<html", b"<!doctype html", b"<svg", b"<?xml", b"<script")


def detect_type(data: bytes) -> str:
    """Best-effort file type from magic bytes. 'unknown' when unidentified."""
    if not data:
        return "empty"
    head = data[:512]
    for magic, label in _MAGIC:
        if data.startswith(magic):
            return label
    stripped = head.lstrip().lower()
    for marker in _TEXT_MARKERS:
        if stripped.startswith(marker):
            return "HTML/markup content"
    if all(byte in b"\t\n\r" or 32 <= byte < 127 for byte in head):
        return "plain text"
    return "unknown"
