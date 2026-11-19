"""Attachment evidence: filenames that carry risk. Contents are never opened."""

from __future__ import annotations

from ..models import Finding, ParsedEmail

_EXECUTABLE = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd",
               ".ps1", ".jar", ".msi", ".com", ".pif", ".lnk", ".hta"}
_ARCHIVE_OR_CONTAINER = {".zip", ".rar", ".7z", ".iso", ".img", ".gz", ".cab"}
_DOCUMENT_WITH_MACROS = {".docm", ".xlsm", ".pptm"}
_HTML_SMUGGLING = {".html", ".htm", ".svg"}


def _ext(name: str) -> str:
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


def check(msg: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for name in msg.attachment_names:
        ext = _ext(name)
        # Double extensions like invoice.pdf.exe
        parts = name.lower().split(".")
        double_ext = len(parts) > 2 and f".{parts[-1]}" in _EXECUTABLE

        if ext in _EXECUTABLE or double_ext:
            findings.append(
                Finding(
                    code="executable_attachment",
                    severity="high",
                    title="Attachment is an executable or script",
                    detail=f"{name} — files like this can run code when opened.",
                )
            )
        elif ext in _HTML_SMUGGLING:
            findings.append(
                Finding(
                    code="html_attachment",
                    severity="medium",
                    title="Attachment is an HTML/SVG file",
                    detail=(
                        f"{name} — often used to smuggle fake login pages "
                        "past mail filters."
                    ),
                )
            )
        elif ext in _ARCHIVE_OR_CONTAINER:
            findings.append(
                Finding(
                    code="archive_attachment",
                    severity="medium",
                    title="Attachment is an archive or disk image",
                    detail=f"{name} — contents cannot be assessed without opening it.",
                )
            )
        elif ext in _DOCUMENT_WITH_MACROS:
            findings.append(
                Finding(
                    code="macro_document",
                    severity="medium",
                    title="Attachment is a macro-enabled document",
                    detail=f"{name} — macros are a classic malware delivery path.",
                )
            )
    return findings
