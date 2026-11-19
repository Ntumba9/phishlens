"""Attachment rules: filename risk plus inert magic-byte content checks.

Contents are never executed, rendered or decompressed. Type identification
reads only the first bytes of the payload.
"""

from __future__ import annotations

from ..models import Attachment, Finding
from .base import AnalysisContext, Rule

_EXECUTABLE = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd",
               ".ps1", ".jar", ".msi", ".com", ".pif", ".lnk", ".hta"}
_ARCHIVE_OR_CONTAINER = {".zip", ".rar", ".7z", ".iso", ".img", ".gz", ".cab"}
_DOCUMENT_WITH_MACROS = {".docm", ".xlsm", ".pptm"}
_HTML_SMUGGLING = {".html", ".htm", ".svg"}

_EXECUTABLE_TYPES = {"Windows executable (PE)", "Linux executable (ELF)"}

# Extension -> the magic-byte type an honest file of that extension shows.
_EXPECTED_TYPE = {
    ".pdf": {"PDF document"},
    ".docx": {"ZIP archive or Office document"},
    ".xlsx": {"ZIP archive or Office document"},
    ".pptx": {"ZIP archive or Office document"},
    ".doc": {"Legacy Office document (OLE)"},
    ".xls": {"Legacy Office document (OLE)"},
    ".ppt": {"Legacy Office document (OLE)"},
    ".jpg": {"JPEG image"},
    ".jpeg": {"JPEG image"},
    ".png": {"PNG image"},
    ".gif": {"GIF image"},
    ".zip": {"ZIP archive or Office document", "ZIP archive (empty)"},
    ".rar": {"RAR archive"},
    ".gz": {"gzip archive"},
    ".txt": {"plain text", "empty"},
    ".html": {"HTML/markup content", "plain text"},
    ".htm": {"HTML/markup content", "plain text"},
    ".svg": {"HTML/markup content"},
}


def _ext(name: str) -> str:
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _filename_findings(attachment: Attachment) -> list[Finding]:
    """The original filename-based signals, one finding at most per name."""
    name = attachment.filename
    ext = _ext(name)
    parts = name.lower().split(".")
    double_ext = len(parts) > 2 and f".{parts[-1]}" in _EXECUTABLE

    if ext in _EXECUTABLE or double_ext:
        return [
            Finding(
                code="executable_attachment",
                severity="high",
                title="Attachment is an executable or script",
                detail=f"{name} — files like this can run code when opened.",
            )
        ]
    if ext in _HTML_SMUGGLING:
        return [
            Finding(
                code="html_attachment",
                severity="medium",
                title="Attachment is an HTML/SVG file",
                detail=(
                    f"{name} — often used to smuggle fake login pages "
                    "past mail filters."
                ),
            )
        ]
    if ext in _ARCHIVE_OR_CONTAINER:
        return [
            Finding(
                code="archive_attachment",
                severity="medium",
                title="Attachment is an archive or disk image",
                detail=f"{name} — contents cannot be assessed without opening it.",
            )
        ]
    if ext in _DOCUMENT_WITH_MACROS:
        return [
            Finding(
                code="macro_document",
                severity="medium",
                title="Attachment is a macro-enabled document",
                detail=f"{name} — macros are a classic malware delivery path.",
            )
        ]
    return []


def _run_filename_rule(rule_id: str):
    def run(ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for attachment in ctx.parsed.attachments:
            findings.extend(
                f for f in _filename_findings(attachment) if f.code == rule_id
            )
        return findings

    return run


def _executable_content(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for attachment in ctx.parsed.attachments:
        if attachment.truncated:
            continue
        if attachment.detected_type in _EXECUTABLE_TYPES:
            findings.append(
                Finding(
                    code="executable_content",
                    severity="high",
                    title="Attachment content is executable code",
                    detail=(
                        f"{attachment.filename} — the file's own bytes "
                        f"identify it as a {attachment.detected_type}, "
                        "regardless of its name."
                    ),
                )
            )
    return findings


def _type_mismatch(ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    for attachment in ctx.parsed.attachments:
        if attachment.truncated:
            continue
        ext = _ext(attachment.filename)
        expected = _EXPECTED_TYPE.get(ext)
        if (
            expected
            and attachment.detected_type != "unknown"
            and attachment.detected_type not in expected
        ):
            findings.append(
                Finding(
                    code="attachment_type_mismatch",
                    severity="medium",
                    title="Attachment content does not match its extension",
                    detail=(
                        f"{attachment.filename} is named like a {ext} file "
                        f"but its bytes look like: {attachment.detected_type}."
                    ),
                )
            )
    return findings


RULES = [
    Rule(
        id="executable_attachment",
        name="Executable attachment name",
        category="attachments",
        rationale=(
            "Treat unexpected executables and scripts in email as hostile "
            "until proven otherwise. Double extensions (invoice.pdf.exe) "
            "exist to hide what the file really is."
        ),
        reference="MITRE ATT&CK T1566.001 (Spearphishing Attachment)",
        run=_run_filename_rule("executable_attachment"),
    ),
    Rule(
        id="html_attachment",
        name="HTML/SVG attachment",
        category="attachments",
        rationale=(
            "An HTML attachment opens locally, outside the mail filter's "
            "view, and renders a fake login page that steals credentials."
        ),
        reference="MITRE ATT&CK T1566.001 (Spearphishing Attachment)",
        run=_run_filename_rule("html_attachment"),
    ),
    Rule(
        id="archive_attachment",
        name="Archive or disk image",
        category="attachments",
        rationale=(
            "Archives and disk images wrap payloads so filename checks "
            "cannot see inside. Treat as uninspected, not safe."
        ),
        run=_run_filename_rule("archive_attachment"),
    ),
    Rule(
        id="macro_document",
        name="Macro-enabled document",
        category="attachments",
        rationale=(
            "Macros are a long-standing malware delivery path; a document "
            "that can run code is not just a document."
        ),
        reference="MITRE ATT&CK T1566.001 (Spearphishing Attachment)",
        run=_run_filename_rule("macro_document"),
    ),
    Rule(
        id="executable_content",
        name="Executable content in attachment",
        category="attachments",
        rationale=(
            "The file's own magic bytes say it is a program. Renaming "
            "malware to invoice.pdf does not change what it does when "
            "opened."
        ),
        reference="MITRE ATT&CK T1566.001 (Spearphishing Attachment)",
        run=_executable_content,
    ),
    Rule(
        id="attachment_type_mismatch",
        name="Attachment type mismatch",
        category="attachments",
        rationale=(
            "When a file's bytes disagree with its extension, the name was "
            "chosen to disguise it - a deliberate act worth an analyst's "
            "attention."
        ),
        run=_type_mismatch,
    ),
]
