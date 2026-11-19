"""Data shapes shared across PhishLens."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Link:
    """One URL found in the message body."""

    url: str
    anchor_text: str | None = None  # visible text when the link came from HTML
    source: str = "body"  # "html" or "text"


@dataclass
class Attachment:
    """An attachment, inspected inertly: metadata, hashes, magic bytes only.

    The content is never executed, rendered or sent anywhere. When the
    payload was too large to hash honestly, ``truncated`` is set and the
    hashes are empty rather than hashes of a partial file.
    """

    filename: str
    content_type: str
    size: int
    md5: str = ""
    sha256: str = ""
    detected_type: str = "unknown"
    truncated: bool = False


@dataclass
class Hop:
    """One relay hop parsed from a Received header, origin-first order."""

    index: int
    raw: str
    from_host: str = ""
    by_host: str = ""
    timestamp: datetime | None = None


@dataclass
class IocSet:
    """Indicators of compromise extracted from one message.

    These are observables for blocking and pivoting, not proof of malice.
    """

    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    file_hashes: list[dict] = field(default_factory=list)  # {filename, md5, sha256}


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
    attachments: list[Attachment] = field(default_factory=list)
    raw_headers: dict[str, list[str]] = field(default_factory=dict)

    def header_all(self, name: str) -> list[str]:
        return self.raw_headers.get(name.lower(), [])

    def header(self, name: str) -> str:
        values = self.header_all(name)
        return values[0] if values else ""


@dataclass
class Finding:
    """One piece of evidence. ``code`` names the rule; ``detail`` shows the proof.

    ``why`` is the rule's rationale: what this signal means to an analyst.
    ``reference`` carries an external framework reference only where the
    mapping is direct (e.g. ATT&CK T1566.001 for a malicious attachment),
    never as decoration.
    """

    code: str
    severity: str  # "info", "low", "medium", "high"
    title: str
    detail: str
    category: str = ""
    why: str = ""
    reference: str = ""


@dataclass
class Report:
    """The analyst-facing result."""

    subject: str
    from_header: str
    verdict: str  # "likely_phish", "suspicious", "no_strong_signals"
    score: int
    case_id: str = ""
    created_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    iocs: IocSet = field(default_factory=IocSet)
    notes: list[str] = field(default_factory=list)
