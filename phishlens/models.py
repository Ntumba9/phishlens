"""Data shapes shared across the analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Link:
    """One URL found in the message body."""

    url: str
    anchor_text: Optional[str] = None  # visible text when the link came from HTML
    source: str = "body"  # "html" or "text"


@dataclass
class ParsedEmail:
    """What the parser could pull out of the raw message."""

    subject: str = ""
    from_header: str = ""
    reply_to: str = ""
    return_path: str = ""
    date: str = ""
    message_id: str = ""
    authentication_results: list[str] = field(default_factory=list)
    received_chain: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = field(default_factory=list)
    attachment_names: list[str] = field(default_factory=list)
    raw_headers: dict[str, list[str]] = field(default_factory=dict)

    def header_all(self, name: str) -> list[str]:
        return self.raw_headers.get(name.lower(), [])

    def header(self, name: str) -> str:
        values = self.header_all(name)
        return values[0] if values else ""


@dataclass
class Finding:
    """One piece of evidence. Code names the check; detail shows the proof."""

    code: str
    severity: str  # "info", "low", "medium", "high"
    title: str
    detail: str


@dataclass
class Report:
    """The analyst-facing result."""

    subject: str
    from_header: str
    verdict: str  # "likely_phish", "suspicious", "no_strong_signals"
    score: int
    findings: list[Finding] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    attachment_names: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
